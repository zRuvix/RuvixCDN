package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"zruvix-cdn/internal/config"
	"zruvix-cdn/internal/storage"
)

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return &config.Config{
		ListenAddr:     "127.0.0.1:8080",
		DataDir:        t.TempDir(),
		PublicURL:      "http://localhost:8080",
		AdminUser:      "admin",
		AdminPassHash:  string(hash),
		SessionSecret:  []byte("0123456789abcdef0123456789abcdef"),
		SessionTTL:     time.Hour,
		MaxUploadMB:    50,
		CacheMaxAge:    86400,
		TrustedProxies: nil,
		LogLevel:       "info",
		CookieInsecure: true,
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
	// /dash/manage unauthenticated redirects to login with ?next=.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/dash/manage", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("/dash/manage = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/dash/login?next=") {
		t.Errorf("/dash/manage Location = %q, want login with next", loc)
	}
}

func TestDashLoginPageAndStatic(t *testing.T) {
	cfg := testConfig(t)
	store, err := storage.New(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	h := New(cfg, store)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/dash/login", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("login page = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("login Content-Type = %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "csrf_token") {
		t.Errorf("login page missing CSRF field")
	}

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest("GET", "/dash/static/css/dash.css", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("dash.css = %d", rec2.Code)
	}
	if ct := rec2.Header().Get("Content-Type"); ct != "text/css; charset=utf-8" {
		t.Errorf("dash.css Content-Type = %q", ct)
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
