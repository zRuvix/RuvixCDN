package dash

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"zruvix-cdn/internal/auth"
	"zruvix-cdn/internal/config"
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
		LogLevel:       "info",
		CookieInsecure: true,
	}
}

func newHandlers(t *testing.T) *Handlers {
	t.Helper()
	h, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	h.failDelay = 0 // keep tests fast
	return h
}

func loginCSRF(t *testing.T, h *Handlers) (*httptest.ResponseRecorder, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.LoginPage(rec, httptest.NewRequest("GET", "/dash/login", nil))
	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("LoginPage = %d", res.StatusCode)
	}
	var token string
	for _, c := range res.Cookies() {
		if c.Name == auth.LoginCSRFCookie {
			token = c.Value
		}
	}
	if token == "" {
		t.Fatalf("no login CSRF cookie")
	}
	body := rec.Body.String()
	if !strings.Contains(body, `name="csrf_token"`) || !strings.Contains(body, token) {
		t.Fatalf("form missing CSRF token")
	}
	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("login page Cache-Control = %q, want no-store", cc)
	}
	return rec, token
}

func doLogin(h *Handlers, user, pass, token string) *httptest.ResponseRecorder {
	form := url.Values{
		"username":     {user},
		"password":     {pass},
		auth.CSRFField: {token},
		auth.NextField: {"/dash/"},
	}
	req := httptest.NewRequest("POST", "/dash/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.LoginCSRFCookie, Value: token})
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	return rec
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			return c.Value
		}
	}
	t.Fatalf("no session cookie")
	return ""
}

func TestLoginRoundTrip(t *testing.T) {
	h := newHandlers(t)
	_, token := loginCSRF(t, h)
	rec := doLogin(h, "admin", "s3cret", token)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/dash/" {
		t.Fatalf("login = %d loc %q", rec.Code, rec.Header().Get("Location"))
	}
	val := sessionCookie(t, rec)
	req := httptest.NewRequest("GET", "/dash/", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: val})
	if got := h.Session(req); got != "admin" {
		t.Fatalf("Session = %q", got)
	}
}

func TestLoginFailuresGeneric(t *testing.T) {
	h := newHandlers(t)
	_, token := loginCSRF(t, h)
	for name, creds := range map[string][2]string{
		"wrong password": {"admin", "nope"},
		"wrong user":     {"nobody", "s3cret"},
		"both wrong":     {"nobody", "nope"},
	} {
		user, pass := creds[0], creds[1]
		rec := doLogin(h, user, pass, token)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: code = %d, want 401", name, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "invalid credentials") {
			t.Errorf("%s: body leaks detail: %q", name, rec.Body.String())
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == auth.CookieName && c.Value != "" && c.MaxAge >= 0 {
				t.Errorf("%s: session cookie set on failure", name)
			}
		}
	}
}

func TestLoginCSRFEnforced(t *testing.T) {
	h := newHandlers(t)
	_, token := loginCSRF(t, h)
	// Missing cookie.
	form := url.Values{"username": {"admin"}, "password": {"s3cret"}, auth.CSRFField: {token}}
	req := httptest.NewRequest("POST", "/dash/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("missing CSRF cookie = %d, want 401", rec.Code)
	}
	// Mismatched token.
	rec2 := httptest.NewRecorder()
	form.Set(auth.CSRFField, "wrong")
	req2 := httptest.NewRequest("POST", "/dash/login", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(&http.Cookie{Name: auth.LoginCSRFCookie, Value: token})
	h.Login(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("mismatched CSRF = %d, want 401", rec2.Code)
	}
}

func TestLoginRateLimited(t *testing.T) {
	h := newHandlers(t)
	_, token := loginCSRF(t, h)
	var last *httptest.ResponseRecorder
	for i := 0; i < 7; i++ {
		last = doLogin(h, "admin", "wrong", token)
	}
	if last.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d", last.Code)
	}
	if !strings.Contains(last.Body.String(), "too many attempts") {
		t.Fatalf("rate limit not surfaced: %q", last.Body.String())
	}
}

func TestRequireAuth(t *testing.T) {
	h := newHandlers(t)
	inner := h.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret"))
	}))
	// Anonymous → 302 login with ?next=.
	rec := httptest.NewRecorder()
	inner.ServeHTTP(rec, httptest.NewRequest("GET", "/dash/manage", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("anon = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/dash/login?next=") {
		t.Fatalf("Location = %q", loc)
	}

	// Logged in → through.
	_, token := loginCSRF(t, h)
	lrec := doLogin(h, "admin", "s3cret", token)
	req := httptest.NewRequest("GET", "/dash/manage", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: sessionCookie(t, lrec)})
	rec2 := httptest.NewRecorder()
	inner.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK || rec2.Body.String() != "secret" {
		t.Fatalf("authed = %d %q", rec2.Code, rec2.Body.String())
	}

	// Tampered cookie → 302 again.
	req3 := httptest.NewRequest("GET", "/dash/manage", nil)
	req3.AddCookie(&http.Cookie{Name: auth.CookieName, Value: "tampered.sig"})
	rec3 := httptest.NewRecorder()
	inner.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusFound {
		t.Fatalf("tampered = %d, want 302", rec3.Code)
	}
}

func TestLogout(t *testing.T) {
	h := newHandlers(t)
	rec := httptest.NewRecorder()
	h.Logout(rec, httptest.NewRequest("POST", "/dash/logout", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("logout = %d", rec.Code)
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("session cookie not cleared")
	}
	// GET logout is not allowed (POST-only mutations, §2).
	rec2 := httptest.NewRecorder()
	h.Logout(rec2, httptest.NewRequest("GET", "/dash/logout", nil))
	if rec2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET logout = %d, want 405", rec2.Code)
	}
}

func TestNextOpenRedirectRejected(t *testing.T) {
	h := newHandlers(t)
	_, token := loginCSRF(t, h)
	form := url.Values{
		"username":     {"admin"},
		"password":     {"s3cret"},
		auth.CSRFField: {token},
		auth.NextField: {"https://evil.example/"},
	}
	req := httptest.NewRequest("POST", "/dash/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.LoginCSRFCookie, Value: token})
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	if loc := rec.Header().Get("Location"); loc != "/dash/" {
		t.Fatalf("open redirect: Location = %q", loc)
	}
}
