package proxy

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

type GitHubProxy struct {
	config       *Config
	transport    *http.Transport
	authManager  *AuthManager
	dialer       *net.Dialer
	hostMap      map[string]string       // target host -> IP/CNAME
	pathProxy    *pathProxyConfig
	frontingMap  map[string]string       // target host -> front SNI
	frontingSANs map[string][]string     // target host -> allowed SANs
	mu           sync.RWMutex
}

type pathProxyConfig struct {
	prefixTargets []prefixTarget         // sorted by prefix length desc
	defaultHost   string                 // "github.com"
}

type prefixTarget struct {
	prefix string
	target string
}

func NewGitHubProxy(config *Config) (*GitHubProxy, error) {
	p := &GitHubProxy{
		config: config,
		dialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		hostMap:      config.Upstream.Hosts,
		frontingMap:  config.TLS.FrontingMap,
		frontingSANs: config.TLS.FrontingSANs,
	}

	pp := &pathProxyConfig{defaultHost: "github.com"}
	type mapping struct {
		prefix string
		target string
	}
	var mappings []mapping
	for prefix, target := range config.PathProxy.Paths {
		mappings = append(mappings, mapping{prefix, target})
	}
	sort.Slice(mappings, func(i, j int) bool {
		return len(mappings[i].prefix) > len(mappings[j].prefix)
	})
	for _, m := range mappings {
		pp.prefixTargets = append(pp.prefixTargets, prefixTarget{
			prefix: m.prefix,
			target: m.target,
		})
	}
	p.pathProxy = pp

	if err := p.initTransport(); err != nil {
		return nil, err
	}
	p.authManager = NewAuthManager(config)
	return p, nil
}

func (p *GitHubProxy) initTransport() error {
	p.transport = &http.Transport{
		DialTLSContext:        p.dialTLSContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	if err := http2.ConfigureTransport(p.transport); err != nil {
		return fmt.Errorf("HTTP/2 configuration failed: %v", err)
	}
	return nil
}

func (p *GitHubProxy) dialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, _ := net.SplitHostPort(addr)
	if port == "" {
		port = "443"
	}

	dialAddr := addr
	if dst, ok := p.hostMap[host]; ok {
		if ip := net.ParseIP(dst); ip != nil {
			dialAddr = net.JoinHostPort(dst, port)
		} else {
			ips, err := net.DefaultResolver.LookupHost(ctx, dst)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("resolve %s: %v", dst, err)
			}
			dialAddr = net.JoinHostPort(ips[0], port)
		}
	}

	sni := host
	var allowedSANs []string
	p.mu.RLock()
	if front, ok := p.frontingMap[host]; ok {
		sni = front
		if sans, exists := p.frontingSANs[host]; exists {
			allowedSANs = sans
		} else {
			allowedSANs = []string{host}
		}
	}
	p.mu.RUnlock()

	rawConn, err := p.dialer.DialContext(ctx, network, dialAddr)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		ServerName:         sni,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			certs := make([]*x509.Certificate, len(rawCerts))
			for i, asn1 := range rawCerts {
				c, err := x509.ParseCertificate(asn1)
				if err != nil {
					return err
				}
				certs[i] = c
			}
			opts := x509.VerifyOptions{
				Intermediates: x509.NewCertPool(),
				CurrentTime:   time.Now(),
			}
			for _, c := range certs[1:] {
				opts.Intermediates.AddCert(c)
			}
			roots, _ := x509.SystemCertPool()
			opts.Roots = roots

			if sni == host {
				opts.DNSName = host
				_, err := certs[0].Verify(opts)
				return err
			}
			if _, err := certs[0].Verify(opts); err != nil {
				return err
			}
			for _, san := range certs[0].DNSNames {
				for _, allowed := range allowedSANs {
					if matchSAN(san, allowed) {
						return nil
					}
				}
			}
			return fmt.Errorf("SAN %v not allowed", certs[0].DNSNames)
		},
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func matchSAN(san, pattern string) bool {
	if pattern == san {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(san, suffix) && strings.Count(san, ".") == strings.Count(suffix, ".")
	}
	return false
}

func (p *GitHubProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.handleCookieSetup(w, r) {
		return
	}
	if !p.authManager.CheckAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	p.stripAuthCookies(r)

	var targetHost string
	var matchedPrefix string
	for _, pt := range p.pathProxy.prefixTargets {
		if strings.HasPrefix(r.URL.Path, pt.prefix) && len(pt.prefix) > len(matchedPrefix) {
			matchedPrefix = pt.prefix
			targetHost = pt.target
		}
	}
	if targetHost == "" {
		targetHost = p.pathProxy.defaultHost
	} else {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, matchedPrefix)
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
		r.RequestURI = ""
	}

	outReq := p.buildUpstreamRequest(r, targetHost)
	p.proxyRequest(w, r, outReq)
}

func (p *GitHubProxy) handleCookieSetup(w http.ResponseWriter, r *http.Request) bool {
	cfg := p.config.Auth.Cookie
	if !cfg.Enabled || cfg.SetupPath == "" || r.URL.Path != cfg.SetupPath {
		return false
	}
	if r.URL.Query().Get(cfg.SetupParam) == "" {
		http.Error(w, "Missing auth parameter", http.StatusBadRequest)
		return true
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    cfg.CookieValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400 * 30,
	})
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Auth cookie set"))
	return true
}

func (p *GitHubProxy) buildUpstreamRequest(r *http.Request, targetHost string) *http.Request {
	outReq := r.Clone(r.Context())
	outReq.URL.Scheme = "https"
	outReq.URL.Host = targetHost
	outReq.Host = targetHost
	outReq.RequestURI = ""

	// 删除代理专用头
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authenticate")
	outReq.Header.Del("Proxy-Authorization")

	// 强制所有请求使用 github.com 的 Origin 和 Referer（绕过子域 CSRF）
	outReq.Header.Set("Origin", "https://github.com")
	outReq.Header.Set("Referer", "https://github.com/")

	// 禁止上游压缩，方便内容重写
	outReq.Header.Set("Accept-Encoding", "identity")
	return outReq
}

func (p *GitHubProxy) proxyRequest(w http.ResponseWriter, r *http.Request, outReq *http.Request) {
	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		log.Printf("Proxy error: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	proxyHost := r.Host

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" {
			resp.Header.Set("Location", p.rewriteURL(loc, proxyHost))
		}
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	rewriteCookies(resp, proxyHost)

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if !isTextContent(ct) {
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	body, err := readResponseBody(resp)
	if err != nil {
		log.Printf("Read body error: %v", err)
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}

	newBody := p.rewriteContent(body, proxyHost)
	resp.Header.Del("Content-Encoding")
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(newBody)))
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	w.Write(newBody)
}

func rewriteCookies(resp *http.Response, proxyHost string) {
	for i, c := range resp.Header["Set-Cookie"] {
		c = strings.ReplaceAll(c, "domain=github.com", "domain="+proxyHost)
		c = strings.ReplaceAll(c, "domain=.github.com", "domain=."+proxyHost)
		resp.Header["Set-Cookie"][i] = c
	}
}

func (p *GitHubProxy) rewriteContent(body []byte, proxyHost string) []byte {
	s := string(body)
	s = strings.ReplaceAll(s, "https://github.com", "https://"+proxyHost)
	s = strings.ReplaceAll(s, "http://github.com", "http://"+proxyHost)
	re := regexp.MustCompile(`https://([a-zA-Z0-9-]+)\.github\.com`)
	s = re.ReplaceAllString(s, "https://"+proxyHost+"/$1")

	replacements := map[string]string{
		"https://raw.githubusercontent.com":          "https://" + proxyHost + "/raw",
		"https://gist.github.com":                    "https://" + proxyHost + "/gist",
		"https://codeload.github.com":                "https://" + proxyHost + "/codeload",
		"https://avatars.githubusercontent.com":       "https://" + proxyHost + "/avatars",
		"https://release-assets.githubusercontent.com": "https://" + proxyHost + "/release-assets",
	}
	for old, new := range replacements {
		s = strings.ReplaceAll(s, old, new)
	}
	return []byte(s)
}

func (p *GitHubProxy) rewriteURL(urlStr, proxyHost string) string {
	rules := map[string]string{
		"https://github.com":                              "https://" + proxyHost,
		"https://raw.githubusercontent.com":               "https://" + proxyHost + "/raw",
		"https://gist.github.com":                         "https://" + proxyHost + "/gist",
		"https://codeload.github.com":                     "https://" + proxyHost + "/codeload",
		"https://avatars.githubusercontent.com":            "https://" + proxyHost + "/avatars",
		"https://release-assets.githubusercontent.com":     "https://" + proxyHost + "/release-assets",
	}
	for old, new := range rules {
		if strings.HasPrefix(urlStr, old) {
			return strings.Replace(urlStr, old, new, 1)
		}
	}
	re := regexp.MustCompile(`^https://([a-zA-Z0-9-]+)\.github\.com(.*)`)
	if m := re.FindStringSubmatch(urlStr); len(m) == 3 {
		return "https://" + proxyHost + "/" + m[1] + m[2]
	}
	return urlStr
}

func isTextContent(ct string) bool {
	for _, prefix := range []string{"text/", "application/json", "application/javascript", "application/xml", "application/x-javascript"} {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	return false
}

func readResponseBody(resp *http.Response) ([]byte, error) {
	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer gzr.Close()
		reader = gzr
	}
	return io.ReadAll(reader)
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (p *GitHubProxy) stripAuthCookies(r *http.Request) {
	if !p.config.Security.StripAuthCookies {
		return
	}
	var cookies []*http.Cookie
	for _, c := range r.Cookies() {
		if c.Name != p.config.Auth.Cookie.CookieName {
			cookies = append(cookies, c)
		}
	}
	r.Header.Del("Cookie")
	for _, c := range cookies {
		r.AddCookie(c)
	}
}

func (p *GitHubProxy) GetTLSConfig() (*tls.Config, error) {
	cfg := p.config
	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if cfg.Auth.MTLS.Enabled {
		caCert, err := os.ReadFile(cfg.Auth.MTLS.ClientCAFile)
		if err != nil {
			return nil, err
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("client CA parse error")
		}
		tlsCfg.ClientCAs = caPool
		if cfg.Auth.MTLS.VerifyClientCert {
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsCfg.ClientAuth = tls.RequireAnyClientCert
		}
	}
	return tlsCfg, nil
}