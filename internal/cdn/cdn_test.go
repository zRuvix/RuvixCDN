package cdn

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"zruvix-cdn/internal/storage"
)

func newHandler(t *testing.T) (*Handler, *storage.Store) {
	t.Helper()
	s, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return New(s, 86400), s
}

func seed(t *testing.T, s *storage.Store, rel string, content []byte) {
	t.Helper()
	full := filepath.Join(s.Root(), filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func pngBytes() []byte {
	return append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte("x"), 600)...)
}

func doReq(h http.Handler, method, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestServeOKAndHeaders(t *testing.T) {
	h, s := newHandler(t)
	seed(t, s, "logos/img.png", pngBytes())

	rec := doReq(h, "GET", "/logos/img.png")
	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := res.Header.Get("Cache-Control"); cc != "public, max-age=86400" {
		t.Errorf("Cache-Control = %q", cc)
	}
	if res.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("missing CORS header")
	}
	if res.Header.Get("Cross-Origin-Resource-Policy") != "cross-origin" {
		t.Errorf("missing CORP header")
	}
	if res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("missing nosniff")
	}
	if etag := res.Header.Get("ETag"); !strings.HasPrefix(etag, "W/\"") {
		t.Errorf("ETag = %q, want weak", etag)
	}
	if cookies := res.Cookies(); len(cookies) != 0 {
		t.Errorf("Set-Cookie on CDN response: %v", cookies)
	}
	body, _ := io.ReadAll(res.Body)
	if !bytes.Equal(body, pngBytes()) {
		t.Errorf("body mismatch, len %d", len(body))
	}
}

func TestSvgCSP(t *testing.T) {
	h, s := newHandler(t)
	seed(t, s, "logos/icon.svg", []byte("<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>....padding...."))
	rec := doReq(h, "GET", "/logos/icon.svg")
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "sandbox") {
		t.Errorf("SVG missing sandbox CSP: %q", csp)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	h, _ := newHandler(t)
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		if rec := doReq(h, m, "/logos/img.png"); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s = %d, want 405", m, rec.Code)
		}
	}
}

func TestNotFoundCases(t *testing.T) {
	h, s := newHandler(t)
	seed(t, s, "logos/img.png", pngBytes())
	targets := []string{
		"/logos/missing.png",
		"/",
		"/logos/",
		"/logos",
		"/../cdn.go",
		"/logos/../../etc/passwd",
		"/dash/evil.txt",
		"/healthz",
		"/logos/evil.html",
	}
	for _, tgt := range targets {
		rec := doReq(h, "GET", tgt)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", tgt, rec.Code)
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Errorf("GET %s set cookies", tgt)
		}
	}
	// Encoded slash traversal.
	req := httptest.NewRequest("GET", "/logos/..%2fcdn.go", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("encoded traversal = %d, want 404", rec.Code)
	}
}

func TestHeadAndRange(t *testing.T) {
	h, s := newHandler(t)
	seed(t, s, "logos/img.png", pngBytes())

	rec := doReq(h, "HEAD", "/logos/img.png")
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD = %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD returned %d body bytes", rec.Body.Len())
	}
	if rec.Header().Get("Content-Length") == "" {
		t.Errorf("HEAD missing Content-Length")
	}

	req := httptest.NewRequest("GET", "/logos/img.png", nil)
	req.Header.Set("Range", "bytes=0-9")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusPartialContent {
		t.Fatalf("Range = %d, want 206", rec2.Code)
	}
	if rec2.Body.Len() != 10 {
		t.Errorf("Range body len = %d, want 10", rec2.Body.Len())
	}
}

func TestCacheBusterIgnored(t *testing.T) {
	h, s := newHandler(t)
	seed(t, s, "logos/img.png", pngBytes())
	if rec := doReq(h, "GET", "/logos/img.png?v=abc123"); rec.Code != http.StatusOK {
		t.Errorf("?v= bust = %d, want 200", rec.Code)
	}
}

func TestConditionalGet(t *testing.T) {
	h, s := newHandler(t)
	seed(t, s, "logos/img.png", pngBytes())
	first := doReq(h, "GET", "/logos/img.png")
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatalf("no ETag")
	}
	req := httptest.NewRequest("GET", "/logos/img.png", nil)
	req.Header.Set("If-None-Match", etag)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Errorf("If-None-Match = %d, want 304", rec.Code)
	}
}
