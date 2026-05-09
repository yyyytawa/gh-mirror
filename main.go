package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"crypto/tls"
	"os/signal"
	"syscall"

	"github-proxy/proxy"

	"github.com/BurntSushi/toml"
)

func main() {
	configPath := flag.String("c", "config.toml", "配置文件路径")
	flag.Parse()

	// 配置文件不存在时自动生成默认配置
	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		if err := generateDefaultConfig(*configPath); err != nil {
			log.Fatalf("生成默认配置失败: %v", err)
		}
		fmt.Printf("默认配置文件已生成: %s\n请修改后重新运行。\n", *configPath)
		return
	}

	var cfg proxy.Config
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		log.Fatalf("解析配置失败: %v", err)
	}

	p, err := proxy.NewGitHubProxy(&cfg)
	if err != nil {
		log.Fatalf("初始化代理失败: %v", err)
	}

	tlsCfg := p.GetTLSConfig()

	server := &http.Server{
		Handler:   p,
		TLSConfig: tlsCfg,
	}

	errCh := make(chan error, 2)

	if cfg.Server.EnableTCP {
		go func() {
			fmt.Printf("TCP 监听 %s\n", cfg.Server.TCPAddress)
			ln, err := tls.Listen("tcp", cfg.Server.TCPAddress, tlsCfg)
			if err != nil {
				errCh <- err
				return
			}
			errCh <- server.Serve(ln)
		}()
	}

	if cfg.Server.EnableUnixSocket {
		go func() {
			_ = os.Remove(cfg.Server.UnixSocketPath)
			ln, err := net.Listen("unix", cfg.Server.UnixSocketPath)
			if err != nil {
				errCh <- err
				return
			}
			// 解析八进制权限字符串
			if perm, err := parseUnixPerm(cfg.Server.UnixSocketPermission); err == nil {
				if err := os.Chmod(cfg.Server.UnixSocketPath, perm); err != nil {
					log.Printf("设置 socket 权限失败: %v", err)
				}
			} else {
				log.Printf("无效的 socket 权限字符串 %s: %v", cfg.Server.UnixSocketPermission, err)
			}
			fmt.Printf("Unix socket 监听 %s\n", cfg.Server.UnixSocketPath)
			tlsLn := tls.NewListener(ln, tlsCfg)
			errCh <- server.Serve(tlsLn)
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				log.Println("收到 SIGHUP，重载证书...")
				if err := p.ReloadCertificate(); err != nil {
					log.Printf("证书重载失败: %v", err)
				} else {
					log.Println("证书重载成功")
				}
			default:
				log.Printf("收到信号 %v，关闭服务\n", sig)
				server.Close()
				return
			}
		}
	}()

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("服务错误: %v", err)
		}
	}
}

func generateDefaultConfig(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	defaultCfg := `# GitHub 反代工具配置文件
[server]
tcp_address = ":443"
unix_socket_path = "/var/run/github-proxy.sock"
unix_socket_permission = "0660"
enable_tcp = true
enable_unix_socket = false
fallback_host = "github.com"

[tls]
cert_file = "/etc/ssl/certs/fullchain.pem"
key_file = "/etc/ssl/private/privkey.pem"

# 域前置（可选）
[tls.fronting_map]
# "github.com" = "github-ech.com"
# "objects.githubusercontent.com" = "github-ech.com"
# "raw.githubusercontent.com" = "github-ech.com"
# "release-assets.githubusercontent.com" = "github-ech.com"
# 未出现在此表中的主机将直连（SNI = Host）

[tls.fronting_sans]
# "github.com" = ["github.com", "www.github.com"]
# "objects.githubusercontent.com" = ["github.com", "*.github.com"]
# "release-assets.githubusercontent.com" = ["github.com", "*.github.com"]

[upstream.hosts]
# 域名 -> 目标地址（支持 IP 或 CNAME 域名）
# "github.com" = "20.27.177.113"
# "avatars.githubusercontent.com" = "185.199.111.133"
# "raw.githubusercontent.com" = "185.199.110.133"
# "release-assets.githubusercontent.com" = "185.199.111.133"

[path_proxy]
enabled = true
[path_proxy.paths]
"/raw/" = "raw.githubusercontent.com"
"/gist/" = "gist.github.com"
"/avatars/" = "avatars.githubusercontent.com"
"/release-assets/" = "release-assets.githubusercontent.com"

[replacements]
# "raw.githubusercontent.com" = "raw.example.com"
# "camo.githubusercontent.com" = "/camo/"
# "github.com" = "host"

[auth]
enable_auth = true
require_any = true

[auth.ip_whitelist]
enabled = false
ips = ["10.0.0.0/8"]
trust_proxy_headers = false
trusted_proxy_ips = []
trusted_headers = ["X-Real-IP", "X-Forwarded-For"]

[auth.cookie]
enabled = false
cookie_name = "proxy_auth_token"
cookie_value = "change-me"
setup_path = "/auth"
setup_param = "sk"

[auth.mtls]
enabled = false
client_ca_file = ""
verify_client_cert = true

[auth.user_agent]
enabled = false
allowed_uas = []

[security]
strip_auth_cookies = true
`
	_, err = f.WriteString(defaultCfg)
	return err
}

// parseUnixPerm 解析八进制权限字符串 ("777" 或 "0777")
func parseUnixPerm(s string) (os.FileMode, error) {
	if len(s) > 1 && s[0] == '0' {
		s = s[1:]
	}
	var perm uint64
	_, err := fmt.Sscanf(s, "%o", &perm)
	if err != nil {
		return 0, err
	}
	return os.FileMode(perm), nil
}