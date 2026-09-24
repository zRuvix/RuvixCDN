package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all runtime configuration, parsed from environment variables.
// See .env.example and CLAUDE.md §5 for documentation of each variable.
type Config struct {
	ListenAddr     string
	DataDir        string
	PublicURL      string
	AdminUser      string
	AdminPassHash  string
	SessionSecret  []byte
	SessionTTL     time.Duration
	MaxUploadMB    int
	CacheMaxAge    int
	TrustedProxies []*net.IPNet
	LogLevel       string
	// CookieInsecure allows Secure=false cookies in local dev only.
	// It is refused when PublicURL uses https (i.e. production).
	CookieInsecure bool
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// Load reads configuration from the environment. It returns an error
// describing the first problem found; the caller must exit non-zero.
func Load() (*Config, error) {
	c := &Config{}

	c.ListenAddr = getEnv("LISTEN_ADDR", "127.0.0.1:8080")
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return nil, fmt.Errorf("LISTEN_ADDR: invalid address %q: %w", c.ListenAddr, err)
	}

	c.DataDir = os.Getenv("DATA_DIR")
	if c.DataDir == "" {
		return nil, fmt.Errorf("DATA_DIR: required, no default")
	}

	c.PublicURL = strings.TrimRight(os.Getenv("PUBLIC_URL"), "/")
	if c.PublicURL == "" {
		return nil, fmt.Errorf("PUBLIC_URL: required, no default")
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("PUBLIC_URL: must be an absolute http(s) URL, got %q", os.Getenv("PUBLIC_URL"))
	}

	c.AdminUser = os.Getenv("ADMIN_USER")
	if c.AdminUser == "" {
		return nil, fmt.Errorf("ADMIN_USER: required, no default")
	}
	c.AdminPassHash = os.Getenv("ADMIN_PASS_HASH")
	if c.AdminPassHash == "" {
		return nil, fmt.Errorf("ADMIN_PASS_HASH: required, generate with `go run ./cmd/hashpw`")
	}

	secretB64 := os.Getenv("SESSION_SECRET")
	if secretB64 == "" {
		return nil, fmt.Errorf("SESSION_SECRET: required, 32+ random bytes base64-encoded")
	}
	secret, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		if secret, err = base64.URLEncoding.DecodeString(secretB64); err != nil {
			return nil, fmt.Errorf("SESSION_SECRET: must be valid base64: %w", err)
		}
	}
	if len(secret) < 32 {
		return nil, fmt.Errorf("SESSION_SECRET: must decode to at least 32 bytes, got %d", len(secret))
	}
	c.SessionSecret = secret

	ttlStr := getEnv("SESSION_TTL", "12h")
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil || ttl <= 0 {
		return nil, fmt.Errorf("SESSION_TTL: must be a positive duration, got %q", ttlStr)
	}
	c.SessionTTL = ttl

	maxUpStr := getEnv("MAX_UPLOAD_MB", "50")
	maxUp, err := strconv.Atoi(maxUpStr)
	if err != nil || maxUp <= 0 {
		return nil, fmt.Errorf("MAX_UPLOAD_MB: must be a positive integer, got %q", maxUpStr)
	}
	c.MaxUploadMB = maxUp

	cacheStr := getEnv("CACHE_MAX_AGE", "86400")
	cacheAge, err := strconv.Atoi(cacheStr)
	if err != nil || cacheAge < 0 {
		return nil, fmt.Errorf("CACHE_MAX_AGE: must be a non-negative integer (seconds), got %q", cacheStr)
	}
	c.CacheMaxAge = cacheAge

	proxiesStr := getEnv("TRUSTED_PROXIES", "172.16.0.0/12,127.0.0.1/32")
	c.TrustedProxies, err = parseCIDRList(proxiesStr)
	if err != nil {
		return nil, fmt.Errorf("TRUSTED_PROXIES: %w", err)
	}

	c.LogLevel = strings.ToLower(getEnv("LOG_LEVEL", "info"))
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return nil, fmt.Errorf("LOG_LEVEL: must be one of debug, info, warn, error; got %q", c.LogLevel)
	}

	c.CookieInsecure = getEnv("COOKIE_INSECURE", "false") == "true"
	if c.CookieInsecure && u.Scheme == "https" {
		return nil, fmt.Errorf("COOKIE_INSECURE=true is refused when PUBLIC_URL uses https (dev only)")
	}

	return c, nil
}

func parseCIDRList(s string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Allow a bare IP as shorthand for /32 (v4) or /128 (v6).
		if ip := net.ParseIP(part); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, ipnet, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR or IP %q: %w", part, err)
		}
		out = append(out, ipnet)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one CIDR or IP is required")
	}
	return out, nil
}
