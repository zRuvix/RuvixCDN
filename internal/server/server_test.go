package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"zruvix-cdn/internal/config"
	"zruvix-cdn/internal/storage"
)

// loginThroughServer performs the full login flow against the wired router
// and returns the session cookie value.
func loginThroughServer(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/dash/login", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("login page = %d", rec.Code)
	}
	var csrfCookie string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "zruvix_login_csrf" {
			csrfCookie = c.Value
		}
	}
	if csrfCookie == "" {
		t.Fatalf("no login CSRF cookie")
	}
	form := url.Values{
		"username":   {"admin"},
		"password":   {"s3cret"},
		"csrf_token": {csrfCookie},
		"next":       {"/dash/"},
	}
	req := httptest.NewRequest("POST", "/dash/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "zruvix_login_csrf", Value: csrfCookie})
	lrec := httptest.NewRecorder()
	h.ServeHTTP(lrec, req)
	if lrec.Code != http.StatusFound {
		t.Fatalf("login = %d (%q)", lrec.Code, lrec.Body.String())
	}
	for _, c := range lrec.Result().Cookies() {
		if c.Name == "zruvix_session" {
			return c.Value
		}
	}
	t.Fatalf("no session cookie after login")
	return ""
}

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

	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, httptest.NewRequest("GET", "/dash/static/js/manage.js", nil))
	if rec3.Code != http.StatusOK {
		t.Fatalf("manage.js = %d", rec3.Code)
	}
	if ct := rec3.Header().Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
		t.Errorf("manage.js Content-Type = %q", ct)
	}
	if !strings.Contains(rec3.Body.String(), "XMLHttpRequest") {
		t.Errorf("manage.js body looks wrong")
	}

	// Unknown dash paths 404 for logged-in users (never fall through to
	// the CDN handler). Anonymous requests 302 to login first (RequireAuth
	// wraps the dispatcher), so log in before checking.
	session := loginThroughServer(t, h)
	reqNope := httptest.NewRequest("GET", "/dash/nope", nil)
	reqNope.AddCookie(&http.Cookie{Name: "zruvix_session", Value: session})
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, reqNope)
	if rec4.Code != http.StatusNotFound {
		t.Errorf("/dash/nope = %d, want 404", rec4.Code)
	}
	if cc := rec4.Header().Get("Cache-Control"); strings.Contains(cc, "public") {
		t.Errorf("/dash/nope has CDN Cache-Control header %q", cc)
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
