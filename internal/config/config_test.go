package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func load(t *testing.T, yaml string, env map[string]string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DOORKEEP_DATA_DIR", dir)
	for k, v := range env {
		t.Setenv(k, v)
	}
	path := ""
	if yaml != "" {
		path = filepath.Join(dir, "c.yaml")
		os.WriteFile(path, []byte(yaml), 0o600)
	}
	return Load(path)
}

func TestDefaultsAndGeneratedSecrets(t *testing.T) {
	c, err := load(t, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8080" || c.AdminListen != "127.0.0.1:8081" || c.TokenTTL != 5*time.Minute {
		t.Fatalf("defaults: %+v", c)
	}
	if len(c.SecretBytes()) != 32 || len(c.TokenKeys) != 1 {
		t.Fatal("secrets not generated")
	}
	// Generated secrets persist with private permissions and are reused.
	fi, err := os.Stat(filepath.Join(c.DataDir, "instance.secret"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("secret file: %v %v", fi, err)
	}
	c2, _ := Load("")
	if c2.Secret != c.Secret {
		t.Fatal("secret regenerated on second load")
	}
}

func TestAdminListenPublic(t *testing.T) {
	t.Run("public", func(t *testing.T) {
		c, err := load(t, "", map[string]string{"DOORKEEP_ADMIN_LISTEN": "public"})
		if err != nil || c.AdminListen != "" {
			t.Fatalf("public: %q %v", c.AdminListen, err)
		}
	})
	t.Run("same as listen", func(t *testing.T) {
		if _, err := load(t, "listen: \":9\"\nadmin_listen: \":9\"\n", nil); err == nil {
			t.Fatal("admin_listen equal to listen accepted")
		}
	})
}

func TestTrustedProxies(t *testing.T) {
	c, err := load(t, "", map[string]string{"DOORKEEP_TRUSTED_PROXIES": "10.0.0.0/8, 192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]bool{"10.1.2.3": true, "192.0.2.1": true, "192.0.2.2": false, "::ffff:10.0.0.1": true} {
		if got := c.Trusted(mustAddr(ip)); got != want {
			t.Errorf("%s: %v", ip, got)
		}
	}
	if _, err := load(t, "", map[string]string{"DOORKEEP_TRUSTED_PROXIES": "nonsense"}); err == nil {
		t.Fatal("bad proxy accepted")
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]string{
		"cluster without explicit secrets": "database_url: postgres://x\n",
		"redis without postgres":           "redis_url: redis://x\n",
		"cert without key":                 "tls_cert: a.pem\n",
		"cert and autocert":                "tls_cert: a\ntls_key: b\nautocert_domains: [x.example]\n",
		"token ttl too long":               "token_ttl: 2h\n",
		"short secret":                     "secret: c2hvcnQ=\n",
	}
	for name, y := range cases {
		if _, err := load(t, y, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	key := strings.Repeat("A", 43) + "="
	if _, err := load(t, "database_url: postgres://x\n", map[string]string{"DOORKEEP_SECRET": key, "DOORKEEP_TOKEN_KEY": key}); err != nil {
		t.Fatalf("cluster with explicit secrets: %v", err)
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
