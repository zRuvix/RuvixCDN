package config

import (
	"os"
	"testing"
)

func setEnv(t *testing.T, k, v string) {
	t.Helper()
	t.Setenv(k, v)
}

func baseEnv(t *testing.T) {
	t.Helper()
	setEnv(t, "LISTEN_ADDR", "127.0.0.1:8080")
	setEnv(t, "DATA_DIR", t.TempDir())
	setEnv(t, "PUBLIC_URL", "http://localhost:8080")
	setEnv(t, "ADMIN_USER", "admin")
	setEnv(t, "ADMIN_PASS_HASH", "$2a$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaO")
	setEnv(t, "SESSION_SECRET", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	setEnv(t, "SESSION_TTL", "12h")
	setEnv(t, "MAX_UPLOAD_MB", "50")
	setEnv(t, "CACHE_MAX_AGE", "86400")
	setEnv(t, "TRUSTED_PROXIES", "127.0.0.1/32")
	setEnv(t, "LOG_LEVEL", "info")
	os.Unsetenv("COOKIE_INSECURE")
}

func TestLoadOK(t *testing.T) {
	baseEnv(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ListenAddr != "127.0.0.1:8080" || c.MaxUploadMB != 50 || c.CacheMaxAge != 86400 {
		t.Fatalf("unexpected config: %+v", c)
	}
	if len(c.SessionSecret) != 32 {
		t.Fatalf("secret len %d", len(c.SessionSecret))
	}
	if len(c.TrustedProxies) != 1 {
		t.Fatalf("proxies: %+v", c.TrustedProxies)
	}
}

func TestLoadFailClosed(t *testing.T) {
	cases := map[string]map[string]string{
		"missing DATA_DIR":      {"DATA_DIR": ""},
		"missing ADMIN_USER":    {"ADMIN_USER": ""},
		"missing PASS_HASH":     {"ADMIN_PASS_HASH": ""},
		"missing SECRET":        {"SESSION_SECRET": ""},
		"short SECRET":          {"SESSION_SECRET": "AAAA"},
		"bad SECRET":            {"SESSION_SECRET": "!!!"},
		"bad TTL":               {"SESSION_TTL": "banana"},
		"bad upload":            {"MAX_UPLOAD_MB": "0"},
		"bad cache":             {"CACHE_MAX_AGE": "-1"},
		"bad listen":            {"LISTEN_ADDR": "nope"},
		"bad public":            {"PUBLIC_URL": "not-a-url"},
		"bad proxies":           {"TRUSTED_PROXIES": "999.999.0.0/16"},
		"bad log level":         {"LOG_LEVEL": "verbose"},
		"insecure prod refused": {"COOKIE_INSECURE": "true", "PUBLIC_URL": "https://cdn.zruvix.com"},
	}
	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			baseEnv(t)
			for k, v := range override {
				if v == "" {
					os.Unsetenv(k)
				} else {
					setEnv(t, k, v)
				}
			}
			if _, err := Load(); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestCookieInsecureDevAllowed(t *testing.T) {
	baseEnv(t)
	setEnv(t, "COOKIE_INSECURE", "true") // PUBLIC_URL is http here
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.CookieInsecure {
		t.Fatalf("expected insecure cookies in dev")
	}
}
