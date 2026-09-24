package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"zruvix-cdn/internal/config"
	"zruvix-cdn/internal/storage"
)

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		ListenAddr:     "127.0.0.1:8080",
		DataDir:        t.TempDir(),
		PublicURL:      "http://localhost:8080",
		CacheMaxAge:    86400,
		TrustedProxies: nil,
		LogLevel:       "info",
	}
}

func TestHealthz(t *testing.T) {
	cfg := testConfig(t)
	store, err := storage.New(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	h := New(cfg, store)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("healthz = %d %q", rec.Code, rec.Body.String())
	}
}

func TestDashNeverReachesCDN(t *testing.T) {
	cfg := testConfig(t)
	store, err := storage.New(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	// Even if a CDN-shaped file existed under a dash dir, /dash/manage
	// must be handled by the dash routes, never the CDN handler.
	h := New(cfg, store)
	for _, p := range []string{"/dash/", "/dash/manage", "/dash/api/upload", "/dash/login"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code == http.StatusNotFound && rec.Body.String() == "404 page not found\n" {
			t.Errorf("GET %s fell through to CDN 404 handler", p)
		}
		// None of the dash routes may serve CDN caching headers or file bodies.
		if cc := rec.Header().Get("Cache-Control"); cc == "public, max-age=86400" {
			t.Errorf("GET %s has CDN Cache-Control header", p)
		}
	}
	// /dash/manage specifically redirects to login in v0.1.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/dash/manage", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/dash/login" {
		t.Errorf("/dash/manage = %d loc %q, want 302 to /dash/login", rec.Code, rec.Header().Get("Location"))
	}
}

func TestRootIsMinimal404(t *testing.T) {
	cfg := testConfig(t)
	store, err := storage.New(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	h := New(cfg, store)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("/ = %d, want 404", rec.Code)
	}
}

func TestCDNThroughServer(t *testing.T) {
	cfg := testConfig(t)
	store, err := storage.New(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(store.Root(), "logos", "img.png")
	os.MkdirAll(filepath.Dir(full), 0o755)
	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 600)...)
	os.WriteFile(full, png, 0o644)

	h := New(cfg, store)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/logos/img.png", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("CDN via server = %d", rec.Code)
	}
}
