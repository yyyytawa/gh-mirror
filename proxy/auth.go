package proxy

import (
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"strings"
)

type AuthManager struct {
	config    *Config
	ipChecker *IPChecker
	uaChecker *UAChecker
}

func NewAuthManager(config *Config) *AuthManager {
	return &AuthManager{
		config:    config,
		ipChecker: NewIPChecker(config.Auth.IPWhitelist),
		uaChecker: NewUAChecker(config.Auth.UserAgent),
	}
}

func (am *AuthManager) CheckAuth(r *http.Request) bool {
	if !am.config.Auth.EnableAuth {
		return true
	}
	if am.config.Auth.RequireAny {
		return am.checkAny(r)
	}
	return am.checkAll(r)
}

func (am *AuthManager) checkAny(r *http.Request) bool {
	checks := []func(*http.Request) bool{
		am.checkIP,
		am.checkCookie,
		am.checkMTLS,
		am.checkUserAgent,
	}
	for _, check := range checks {
		if check(r) {
			return true
		}
	}
	return false
}

func (am *AuthManager) checkAll(r *http.Request) bool {
	if am.config.Auth.IPWhitelist.Enabled && !am.checkIP(r) {
		return false
	}
	if am.config.Auth.Cookie.Enabled && !am.checkCookie(r) {
		return false
	}
	if am.config.Auth.MTLS.Enabled && !am.checkMTLS(r) {
		return false
	}
	if am.config.Auth.UserAgent.Enabled && !am.checkUserAgent(r) {
		return false
	}
	return true
}

func (am *AuthManager) getClientIP(r *http.Request) string {
	cfg := am.config.Auth.IPWhitelist
	if !cfg.TrustProxyHeaders {
		return directIP(r)
	}
	direct := directIP(r)
	if !am.isTrustedProxy(direct) {
		return direct
	}
	for _, header := range cfg.TrustedHeaders {
		val := r.Header.Get(header)
		if val == "" {
			continue
		}
		if header == "X-Forwarded-For" {
			parts := strings.Split(val, ",")
			if len(parts) > 0 {
				return strings.TrimSpace(parts[0])
			}
		}
		return strings.TrimSpace(val)
	}
	return direct
}

func directIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (am *AuthManager) isTrustedProxy(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range am.config.Auth.IPWhitelist.TrustedProxyIPs {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil && n.Contains(parsed) {
			return true
		}
	}
	return false
}

func (am *AuthManager) checkIP(r *http.Request) bool {
	if !am.config.Auth.IPWhitelist.Enabled {
		return false
	}
	ip := am.getClientIP(r)
	return am.ipChecker.IsAllowed(ip)
}

func (am *AuthManager) checkCookie(r *http.Request) bool {
	cfg := am.config.Auth.Cookie
	if !cfg.Enabled {
		return false
	}
	c, err := r.Cookie(cfg.CookieName)
	if err != nil {
		return false
	}
	return c.Value == cfg.CookieValue
}

func (am *AuthManager) checkMTLS(r *http.Request) bool {
	cfg := am.config.Auth.MTLS
	if !cfg.Enabled {
		return false
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	if cfg.VerifyClientCert {
		caCert, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			return false
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return false
		}
		opts := x509.VerifyOptions{
			Roots:     caPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if _, err := r.TLS.PeerCertificates[0].Verify(opts); err != nil {
			return false
		}
		if cfg.RequireOU != "" {
			found := false
			for _, ou := range r.TLS.PeerCertificates[0].Subject.OrganizationalUnit {
				if ou == cfg.RequireOU {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

func (am *AuthManager) checkUserAgent(r *http.Request) bool {
	if !am.config.Auth.UserAgent.Enabled {
		return false
	}
	return am.uaChecker.IsAllowed(r.UserAgent())
}

type IPChecker struct {
	nets []*net.IPNet
}

func NewIPChecker(cfg IPWhitelistConfig) *IPChecker {
	checker := &IPChecker{}
	for _, cidr := range cfg.IPs {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil {
			checker.nets = append(checker.nets, n)
		}
	}
	return checker
}

func (c *IPChecker) IsAllowed(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range c.nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

type UAChecker struct {
	allowed map[string]bool
}

func NewUAChecker(cfg UserAgentConfig) *UAChecker {
	u := &UAChecker{allowed: make(map[string]bool)}
	for _, ua := range cfg.AllowedUAs {
		u.allowed[ua] = true
	}
	return u
}

func (u *UAChecker) IsAllowed(ua string) bool {
	return u.allowed[ua]
}