package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a YAML-unmarshallable time.Duration supporting strings like "10s".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		// Try numeric (nanoseconds) fallback.
		var n int64
		if err2 := value.Decode(&n); err2 != nil {
			return fmt.Errorf("invalid duration: %v", value.Value)
		}
		*d = Duration(time.Duration(n))
		return nil
	}
	v, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) Std() time.Duration { return time.Duration(d) }

// Listen holds the local proxy listener addresses. A nil address means
// "unset" (receives the default); an explicit empty string disables that
// protocol. At least one protocol must remain enabled.
type Listen struct {
	HTTP   *string `yaml:"http"`
	SOCKS5 *string `yaml:"socks5"`
}

// Websocket holds the single upstream Worker endpoint shared by all local
// listeners. The per-connection destination travels as control metadata.
type Websocket struct {
	URL   string `yaml:"url"`
	Token string `yaml:"token"`
}

// Relay holds transport tuning.
type Relay struct {
	FrameSize          int      `yaml:"frame_size"`
	ConnectTimeout     Duration `yaml:"connect_timeout"`
	IdleTimeout        Duration `yaml:"idle_timeout"`
	MaxSessionDuration Duration `yaml:"max_session_duration"`
	PingInterval       Duration `yaml:"ping_interval"`
	MaxConnections     int      `yaml:"max_connections"`
}

// Socks5Auth configures the SOCKS5 listener authentication.
type Socks5Auth struct {
	// Mode is "none" or "password".
	Mode     string `yaml:"mode"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// Socks5 holds SOCKS5-specific settings.
type Socks5 struct {
	Auth Socks5Auth `yaml:"auth"`
}

// Security mirrors the Worker destination policy so obviously forbidden
// targets fail fast locally. The Worker always re-validates.
type Security struct {
	AllowPrivateNetworks bool     `yaml:"allow_private_networks"`
	AllowLoopback        bool     `yaml:"allow_loopback"`
	AllowLinkLocal       bool     `yaml:"allow_link_local"`
	AllowedDomains       []string `yaml:"allowed_domains"`
	BlockedDomains       []string `yaml:"blocked_domains"`
	AllowedPorts         []int    `yaml:"allowed_ports"`
}

// TCP holds socket tuning.
type TCP struct {
	KeepAlive  Duration `yaml:"keepalive"`
	TCPNoDelay bool     `yaml:"tcp_nodelay"`
}

// Logging holds log settings.
type Logging struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Management holds the private admin interface.
type Management struct {
	Address string `yaml:"address"`
}

// Config is the full relay-client configuration.
type Config struct {
	Listen     Listen     `yaml:"listen"`
	Websocket  Websocket  `yaml:"websocket"`
	Relay      Relay      `yaml:"relay"`
	Socks5     Socks5     `yaml:"socks5"`
	Security   Security   `yaml:"security"`
	TCP        TCP        `yaml:"tcp"`
	Logging    Logging    `yaml:"logging"`
	Management Management `yaml:"management"`
}

// Defaults.
const (
	DefaultFrameSize          = 16384
	DefaultConnectTimeout     = 10 * time.Second
	DefaultIdleTimeout        = 10 * time.Minute
	DefaultPingInterval       = 30 * time.Second
	DefaultMaxConnections     = 100
	DefaultKeepAlive          = 30 * time.Second
	DefaultManagementAddr     = "127.0.0.1:9090"
	DefaultHTTPAddr           = "127.0.0.1:8080"
	DefaultSOCKS5Addr         = "127.0.0.1:1080"
	DefaultMaxSessionDuration = time.Duration(0) // 0 = unlimited
)

func strptr(s string) *string { return &s }

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Load reads, expands ${ENV} references, parses, validates, and applies defaults.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	expanded := os.ExpandEnv(string(raw))
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(expanded))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := c.ApplyDefaults(); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// ApplyDefaults fills zero values.
func (c *Config) ApplyDefaults() error {
	if c.Listen.HTTP == nil && c.Listen.SOCKS5 == nil {
		c.Listen.HTTP = strptr(DefaultHTTPAddr)
		c.Listen.SOCKS5 = strptr(DefaultSOCKS5Addr)
	}
	if c.Relay.FrameSize == 0 {
		c.Relay.FrameSize = DefaultFrameSize
	}
	if time.Duration(c.Relay.ConnectTimeout) == 0 {
		c.Relay.ConnectTimeout = Duration(DefaultConnectTimeout)
	}
	if time.Duration(c.Relay.IdleTimeout) == 0 {
		c.Relay.IdleTimeout = Duration(DefaultIdleTimeout)
	}
	if time.Duration(c.Relay.PingInterval) == 0 {
		c.Relay.PingInterval = Duration(DefaultPingInterval)
	}
	if c.Relay.MaxConnections == 0 {
		c.Relay.MaxConnections = DefaultMaxConnections
	}
	if c.Socks5.Auth.Mode == "" {
		c.Socks5.Auth.Mode = "none"
	}
	if time.Duration(c.TCP.KeepAlive) == 0 {
		c.TCP.KeepAlive = Duration(DefaultKeepAlive)
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.Management.Address == "" {
		c.Management.Address = DefaultManagementAddr
	}
	return nil
}

// Validate checks semantic correctness.
func (c *Config) Validate() error {
	if deref(c.Listen.HTTP) == "" && deref(c.Listen.SOCKS5) == "" {
		return fmt.Errorf("at least one of listen.http or listen.socks5 is required")
	}
	if c.Websocket.URL == "" {
		return fmt.Errorf("websocket.url is required")
	}
	if !strings.HasPrefix(c.Websocket.URL, "wss://") && !strings.HasPrefix(c.Websocket.URL, "ws://") {
		return fmt.Errorf("websocket.url must start with ws:// or wss://")
	}
	if strings.HasPrefix(c.Websocket.URL, "ws://") && !strings.HasPrefix(c.Websocket.URL, "ws://127.0.0.1") && !strings.HasPrefix(c.Websocket.URL, "ws://localhost") {
		// Allow ws:// only for loopback (tests). Production must be wss://.
		return fmt.Errorf("non-TLS ws:// is only allowed for loopback test URLs")
	}
	if c.Websocket.Token == "" {
		return fmt.Errorf("websocket.token is required (set RELAY_TOKEN env or inline token)")
	}
	if c.Relay.FrameSize < 1024 || c.Relay.FrameSize > 4*1024*1024 {
		return fmt.Errorf("relay.frame_size must be between 1024 and 4194304, got %d", c.Relay.FrameSize)
	}
	if c.Relay.MaxConnections < 1 || c.Relay.MaxConnections > 10000 {
		return fmt.Errorf("relay.max_connections must be between 1 and 10000, got %d", c.Relay.MaxConnections)
	}
	if time.Duration(c.Relay.ConnectTimeout) <= 0 {
		return fmt.Errorf("relay.connect_timeout must be positive")
	}
	if time.Duration(c.Relay.IdleTimeout) < 0 {
		return fmt.Errorf("relay.idle_timeout must not be negative")
	}
	if time.Duration(c.Relay.MaxSessionDuration) < 0 {
		return fmt.Errorf("relay.max_session_duration must not be negative")
	}
	switch strings.ToLower(c.Socks5.Auth.Mode) {
	case "none", "password":
	default:
		return fmt.Errorf("socks5.auth.mode must be none or password, got %q", c.Socks5.Auth.Mode)
	}
	if strings.ToLower(c.Socks5.Auth.Mode) == "password" && c.Socks5.Auth.Username == "" {
		return fmt.Errorf("socks5.auth.username is required when mode is password")
	}
	for _, p := range c.Security.AllowedPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("security.allowed_ports contains invalid port %d", p)
		}
	}
	switch strings.ToLower(c.Logging.Level) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("logging.level must be one of debug|info|warn|error, got %q", c.Logging.Level)
	}
	switch strings.ToLower(c.Logging.Format) {
	case "json", "text":
	default:
		return fmt.Errorf("logging.format must be json or text, got %q", c.Logging.Format)
	}
	return nil
}
