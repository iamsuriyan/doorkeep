// Package config loads doorkeep's configuration from an optional YAML file
// and DOORKEEP_* environment variables, and provisions secrets on first run
// so a single binary works with no setup.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Config is the runtime configuration.
type Config struct {
	Listen         string        `yaml:"listen"`
	DataDir        string        `yaml:"data_dir"`
	PublicURL      string        `yaml:"public_url"`
	TrustedProxies []string      `yaml:"trusted_proxies"`
	TokenTTL       time.Duration `yaml:"token_ttl"`
	EventRetention time.Duration `yaml:"event_retention"`
	// Secret is the instance secret (base64, >= 32 bytes) used for all
	// pseudonymisation. Env: DOORKEEP_SECRET. Generated if absent.
	Secret string `yaml:"secret"`
	// TokenKeys: first is active, the rest are accepted for verification.
	// Env: DOORKEEP_TOKEN_KEY (active) and DOORKEEP_TOKEN_KEY_OLD.
	TokenKeys []TokenKey `yaml:"token_keys"`
	LogLevel  string     `yaml:"log_level"`
	// IPDataAutoUpdate downloads IP intelligence weekly. Disable for
	// air-gapped installs and run `doorkeep ipdata update` yourself.
	IPDataAutoUpdate bool `yaml:"ipdata_auto_update"`
	// TLS: terminate TLS in doorkeep so JA4 and HTTP/2 fingerprints are
	// available. Either cert/key files or ACME domains (TLS-ALPN-01, port 443).
	TLSCert         string   `yaml:"tls_cert"`
	TLSKey          string   `yaml:"tls_key"`
	AutocertDomains []string `yaml:"autocert_domains"`
	AutocertEmail   string   `yaml:"autocert_email"`

	trusted []netip.Prefix
}

// TokenKey is an identified 32-byte key, base64-encoded.
type TokenKey struct {
	ID  string `yaml:"id"`
	Key string `yaml:"key"`
}

// Defaults returns the default configuration.
func Defaults() Config {
	return Config{
		Listen:           ":8080",
		DataDir:          "./data",
		TokenTTL:         5 * time.Minute,
		EventRetention:   30 * 24 * time.Hour,
		LogLevel:         "info",
		IPDataAutoUpdate: true,
	}
}

// Load reads path (may be empty), applies env overrides, provisions secrets
// in DataDir and validates.
func Load(path string) (*Config, error) {
	c := Defaults()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(b, &c); err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
	}
	env := func(k string, dst *string) {
		if v := os.Getenv(k); v != "" {
			*dst = v
		}
	}
	env("DOORKEEP_LISTEN", &c.Listen)
	env("DOORKEEP_DATA_DIR", &c.DataDir)
	env("DOORKEEP_PUBLIC_URL", &c.PublicURL)
	env("DOORKEEP_SECRET", &c.Secret)
	env("DOORKEEP_LOG_LEVEL", &c.LogLevel)
	env("DOORKEEP_TLS_CERT", &c.TLSCert)
	env("DOORKEEP_TLS_KEY", &c.TLSKey)
	env("DOORKEEP_AUTOCERT_EMAIL", &c.AutocertEmail)
	if v := os.Getenv("DOORKEEP_AUTOCERT_DOMAINS"); v != "" {
		c.AutocertDomains = strings.Split(v, ",")
	}
	if v := os.Getenv("DOORKEEP_IPDATA_AUTO_UPDATE"); v != "" {
		c.IPDataAutoUpdate = v == "1" || strings.EqualFold(v, "true")
	}
	if v := os.Getenv("DOORKEEP_TRUSTED_PROXIES"); v != "" {
		c.TrustedProxies = strings.Split(v, ",")
	}
	if v := os.Getenv("DOORKEEP_TOKEN_KEY"); v != "" {
		keys := []TokenKey{{ID: "env", Key: v}}
		if old := os.Getenv("DOORKEEP_TOKEN_KEY_OLD"); old != "" {
			keys = append(keys, TokenKey{ID: "env-old", Key: old})
		}
		c.TokenKeys = keys
	}
	if err := os.MkdirAll(c.DataDir, 0o700); err != nil {
		return nil, err
	}
	if c.Secret == "" {
		s, err := persisted(filepath.Join(c.DataDir, "instance.secret"))
		if err != nil {
			return nil, err
		}
		c.Secret = s
	}
	if len(c.TokenKeys) == 0 {
		s, err := persisted(filepath.Join(c.DataDir, "token.key"))
		if err != nil {
			return nil, err
		}
		c.TokenKeys = []TokenKey{{ID: "k1", Key: s}}
	}
	return &c, c.validate()
}

func (c *Config) validate() error {
	if b, err := decodeKey(c.Secret); err != nil || len(b) < 32 {
		return errors.New("config: secret must be base64 of at least 32 bytes")
	}
	for _, k := range c.TokenKeys {
		if b, err := decodeKey(k.Key); err != nil || len(b) != 32 || k.ID == "" {
			return fmt.Errorf("config: token key %q must have an id and be base64 of 32 bytes", k.ID)
		}
	}
	for _, p := range c.TrustedProxies {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.Contains(p, "/") {
			if a, err := netip.ParseAddr(p); err == nil {
				c.trusted = append(c.trusted, netip.PrefixFrom(a, a.BitLen()))
				continue
			}
		}
		pf, err := netip.ParsePrefix(p)
		if err != nil {
			return fmt.Errorf("config: trusted proxy %q: %w", p, err)
		}
		c.trusted = append(c.trusted, pf.Masked())
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("config: tls_cert and tls_key must be set together")
	}
	if c.TLSCert != "" && len(c.AutocertDomains) > 0 {
		return errors.New("config: use either tls_cert/tls_key or autocert_domains, not both")
	}
	if c.TokenTTL <= 0 || c.TokenTTL > time.Hour {
		return errors.New("config: token_ttl must be in (0, 1h]")
	}
	return nil
}

// Revalidate re-parses derived fields after the struct was changed in code
// (tests and the admin API).
func (c *Config) Revalidate() error {
	c.trusted = nil
	return c.validate()
}

// TLSEnabled reports whether doorkeep terminates TLS itself.
func (c *Config) TLSEnabled() bool { return c.TLSCert != "" || len(c.AutocertDomains) > 0 }

// IPDataDir is where IP intelligence files live.
func (c *Config) IPDataDir() string { return filepath.Join(c.DataDir, "ipdata") }

// SecretBytes returns the decoded instance secret.
func (c *Config) SecretBytes() []byte { b, _ := decodeKey(c.Secret); return b }

// KeyBytes decodes a token key.
func KeyBytes(k TokenKey) []byte { b, _ := decodeKey(k.Key); return b }

// Trusted reports whether addr is a trusted proxy.
func (c *Config) Trusted(addr netip.Addr) bool {
	for _, p := range c.trusted {
		if p.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}

func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not base64")
}

// persisted reads a key file or creates it with 32 random bytes (0600).
func persisted(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(b)), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	s := base64.StdEncoding.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(s+"\n"), 0o600); err != nil {
		return "", err
	}
	return s, nil
}
