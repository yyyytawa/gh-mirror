package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// CertReloader 实现证书热加载（Xray 风格）
type CertReloader struct {
	certFile string
	keyFile  string

	mu      sync.RWMutex
	cert    *tls.Certificate
	certPEM []byte
	keyPEM  []byte

	// mTLS 相关
	clientCAFile     string
	verifyClientCert bool
	requireOU        string
}

func NewCertReloader(certFile, keyFile string) (*CertReloader, error) {
	cr := &CertReloader{
		certFile: certFile,
		keyFile:  keyFile,
	}
	if err := cr.load(); err != nil {
		return nil, err
	}
	go cr.watch()
	return cr, nil
}

func (cr *CertReloader) SetClientCA(caFile string, verify bool, requireOU string) {
	cr.clientCAFile = caFile
	cr.verifyClientCert = verify
	cr.requireOU = requireOU
}

func (cr *CertReloader) load() error {
	newCertPEM, err := os.ReadFile(cr.certFile)
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}
	newKeyPEM, err := os.ReadFile(cr.keyFile)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}

	cr.mu.RLock()
	same := bytes.Equal(cr.certPEM, newCertPEM) && bytes.Equal(cr.keyPEM, newKeyPEM)
	cr.mu.RUnlock()
	if same {
		return nil
	}

	newCert, err := tls.X509KeyPair(newCertPEM, newKeyPEM)
	if err != nil {
		return fmt.Errorf("parse cert: %w", err)
	}

	cr.mu.Lock()
	cr.cert = &newCert
	cr.certPEM, cr.keyPEM = newCertPEM, newKeyPEM
	cr.mu.Unlock()
	log.Println("证书已热加载")
	return nil
}

// GetCertificate 每次 TLS 握手调用，实现零停机热更新
func (cr *CertReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	_ = cr.load() // 尝试重载（失败不影响旧证书）
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return cr.cert, nil
}

func (cr *CertReloader) watch() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if err := cr.load(); err != nil {
			log.Printf("证书轮询重载失败: %v", err)
		}
	}
}

// GetServerTLSConfig 构建完整的服务端 TLS 配置
func (cr *CertReloader) GetServerTLSConfig() *tls.Config {
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: cr.GetCertificate,
	}

	if cr.clientCAFile != "" {
		caCert, err := os.ReadFile(cr.clientCAFile)
		if err != nil {
			log.Printf("mTLS CA 读取失败: %v", err)
			return cfg
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			log.Printf("mTLS CA 解析失败")
			return cfg
		}
		cfg.ClientCAs = pool
		if cr.verifyClientCert {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			cfg.ClientAuth = tls.RequireAnyClientCert
		}
	}
	return cfg
}