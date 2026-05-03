package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github-proxy/proxy"

	"github.com/BurntSushi/toml"
)

func main() {
	var cfg proxy.Config
	if _, err := toml.DecodeFile("config.toml", &cfg); err != nil {
		log.Fatalf("Config error: %v", err)
	}

	p, err := proxy.NewGitHubProxy(&cfg)
	if err != nil {
		log.Fatalf("Init proxy: %v", err)
	}

	tlsCfg, err := p.GetTLSConfig()
	if err != nil {
		log.Fatalf("TLS config: %v", err)
	}

	server := &http.Server{
		Handler:   p,
		TLSConfig: tlsCfg,
	}

	errCh := make(chan error, 2)

	if cfg.Server.EnableTCP {
		go func() {
			fmt.Printf("TCP listening on %s\n", cfg.Server.TCPAddress)
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
			os.Remove(cfg.Server.UnixSocketPath)
			ln, err := net.Listen("unix", cfg.Server.UnixSocketPath)
			if err != nil {
				errCh <- err
				return
			}
			if err := os.Chmod(cfg.Server.UnixSocketPath, os.FileMode(cfg.Server.UnixSocketPermission)); err != nil {
				errCh <- err
				return
			}
			fmt.Printf("Unix socket listening on %s\n", cfg.Server.UnixSocketPath)
			tlsLn := tls.NewListener(ln, tlsCfg)
			errCh <- server.Serve(tlsLn)
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	case sig := <-sigCh:
		fmt.Printf("Signal %v, shutting down\n", sig)
		server.Close()
	}
}