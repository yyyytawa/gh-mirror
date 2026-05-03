package proxy

type Config struct {
	Server    ServerConfig      `toml:"server"`
	TLS       TLSConfig         `toml:"tls"`
	Upstream  UpstreamConfig    `toml:"upstream"`
	PathProxy PathProxyConfig   `toml:"path_proxy"`
	Auth      AuthConfig        `toml:"auth"`
	Security  SecurityConfig    `toml:"security"`
}

type ServerConfig struct {
	TCPAddress           string `toml:"tcp_address"`
	UnixSocketPath       string `toml:"unix_socket_path"`
	UnixSocketPermission uint32 `toml:"unix_socket_permission"`
	EnableTCP            bool   `toml:"enable_tcp"`
	EnableUnixSocket     bool   `toml:"enable_unix_socket"`
}

type TLSConfig struct {
	CertFile     string              `toml:"cert_file"`
	KeyFile      string              `toml:"key_file"`
	FrontingMap  map[string]string   `toml:"fronting_map"`
	FrontingSANs map[string][]string `toml:"fronting_sans"`
}

type UpstreamConfig struct {
	Hosts map[string]string `toml:"hosts"`
}

type PathProxyConfig struct {
	Enabled bool              `toml:"enabled"`
	Paths   map[string]string `toml:"paths"`
}

type AuthConfig struct {
	EnableAuth  bool              `toml:"enable_auth"`
	RequireAny  bool              `toml:"require_any"`
	IPWhitelist IPWhitelistConfig `toml:"ip_whitelist"`
	Cookie      CookieAuthConfig  `toml:"cookie"`
	MTLS        MTLSConfig        `toml:"mtls"`
	UserAgent   UserAgentConfig   `toml:"user_agent"`
}

type IPWhitelistConfig struct {
	Enabled           bool     `toml:"enabled"`
	IPs               []string `toml:"ips"`
	TrustProxyHeaders bool     `toml:"trust_proxy_headers"`
	TrustedProxyIPs   []string `toml:"trusted_proxy_ips"`
	TrustedHeaders    []string `toml:"trusted_headers"`
}

type CookieAuthConfig struct {
	Enabled    bool   `toml:"enabled"`
	CookieName string `toml:"cookie_name"`
	CookieValue string `toml:"cookie_value"`
	SetupPath  string `toml:"setup_path"`
	SetupParam string `toml:"setup_param"`
}

type MTLSConfig struct {
	Enabled          bool   `toml:"enabled"`
	ClientCAFile     string `toml:"client_ca_file"`
	VerifyClientCert bool   `toml:"verify_client_cert"`
	RequireOU        string `toml:"require_ou"`
}

type UserAgentConfig struct {
	Enabled    bool     `toml:"enabled"`
	AllowedUAs []string `toml:"allowed_uas"`
}

type SecurityConfig struct {
	StripAuthCookies bool `toml:"strip_auth_cookies"`
}