package dash

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"zruvix-cdn/internal/auth"
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
		LogLevel:       "info",
		CookieInsecure: true,
	}
}

func newHandlers(t *testing.T) *Handlers {
	t.Helper()
	return newHandlersWithConfig(t, testConfig(t))
}

func newHandlersWithConfig(t *testing.T, cfg *config.Config) *Handlers {
	t.Helper()
	store, err := storage.New(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	h.failDelay = 0 // keep tests fast
	// Generous login budget: helpers log in fresh for every request.
	// TestLoginRateLimited pins the limiter back to production values.
	h.limiter = auth.NewLimiter(1000, time.Minute)
	return h
}

// sessionFor logs in as admin and returns the session cookie value plus the
// session CSRF token embedded in it.
func sessionFor(t *testing.T, h *Handlers) (session, csrf string) {
	t.Helper()
	_, token := loginCSRF(t, h)
	lrec := doLogin(h, "admin", "s3cret", token)
	for _, c := range lrec.Result().Cookies() {
		if c.Name == auth.CookieName {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatalf("no session from login")
	}
	var ok bool
	_, csrf, ok = auth.Verify(h.cfg.SessionSecret, session, time.Now())
	if !ok {
		t.Fatalf("fresh session does not verify")
	}
	return session, csrf
}

// authed builds a request carrying a valid session cookie for user admin.
// The session CSRF token is NOT attached automatically; mutation tests must
// send it as the csrf_token form field (see postForm / multipartUpload).
func authed(t *testing.T, h *Handlers, method, target string) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	session, _ := sessionFor(t, h)
	req := httptest.NewRequest(method, target, nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: session})
	return httptest.NewRecorder(), req
}

// reqWithCSRF attaches the session cookie (if given) to req. The CSRF token
// itself travels in the form body, not headers — callers must include the
// csrf_token field (postForm injects it automatically).
func reqWithCSRF(req *http.Request, _ string) *http.Request {
	return req
}

func postForm(t *testing.T, h *Handlers, path string, vals url.Values) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	session, csrf := sessionFor(t, h)
	// Carry the session CSRF unless the caller set its own token (e.g. a
	// deliberately wrong one for negative tests).
	if vals.Get(auth.CSRFField) == "" {
		vals.Set(auth.CSRFField, csrf)
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: session})
	return httptest.NewRecorder(), req
}

// multipartUpload builds a multipart POST to path with form fields plus one
// or more files under the "file" field. A session cookie is attached; the
// caller must include the csrf_token field (or leave it out deliberately).
func multipartUpload(t *testing.T, h *Handlers, path string, fields map[string]string, files map[string][]byte, session string, acceptJSON bool) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range files {
		w, err := mw.CreateFormFile("file", name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", path, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if acceptJSON {
		req.Header.Set("Accept", "application/json")
	}
	if session != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: session})
	}
	return httptest.NewRecorder(), req
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON: %v (body %q)", err, rec.Body.String())
	}
	return out
}

func testPNG() []byte {
	return append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte("x"), 600)...)
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
	h.limiter = auth.NewLimiter(5, 10*time.Minute)
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

func TestLogoutRequiresCSRF(t *testing.T) {
	h := newHandlers(t)
	// POST logout without a token is rejected with 403.
	session, _ := sessionFor(t, h)
	bad := httptest.NewRequest("POST", "/dash/logout", strings.NewReader(url.Values{}.Encode()))
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bad.Header.Set("Accept", "application/json")
	bad.AddCookie(&http.Cookie{Name: auth.CookieName, Value: session})
	badRec := httptest.NewRecorder()
	h.Logout(badRec, bad)
	if badRec.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF = %d, want 403", badRec.Code)
	}

	rec, req := postForm(t, h, "/dash/logout", url.Values{})
	h.Logout(rec, req)
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

func TestSanitizeFilename(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"My Photo.PNG", "My-Photo.png"},
		{"a  b\tc.txt", "a-b-c.txt"},
		{"archive.tar.GZ", "archive.tar.gz"},
		{"café.png", "caf.png"},
		{"a/b.png", "ab.png"},
		{"1.png", "1.png"},
	} {
		got, err := sanitizeFilename(tc.in)
		if err != nil {
			t.Errorf("sanitizeFilename(%q) error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "   ", "...", "éè", "...---___..."} {
		if got, err := sanitizeFilename(bad); err == nil {
			t.Errorf("sanitizeFilename(%q) = %q, want error", bad, got)
		}
	}
	long := strings.Repeat("a", 200) + ".png"
	if _, err := sanitizeFilename(long); err == nil {
		t.Errorf("sanitizeFilename(long) succeeded, want error")
	}
}

func seedStoreFile(t *testing.T, h *Handlers, dir, name string, content []byte) {
	t.Helper()
	ctx := context.Background()
	if dir != "" {
		if err := h.store.Mkdir(ctx, dir); err != nil {
			// Parent chain may need building one level at a time.
			parts := strings.Split(dir, "/")
			for i := range parts {
				_ = h.store.Mkdir(ctx, strings.Join(parts[:i+1], "/"))
			}
		}
	}
	if err := h.store.Save(ctx, dir, name, bytes.NewReader(content), true); err != nil {
		t.Fatalf("seed %s/%s: %v", dir, name, err)
	}
}

func TestOverview(t *testing.T) {
	h := newHandlers(t)
	seedStoreFile(t, h, "logos", "a.png", testPNG())
	seedStoreFile(t, h, "logos", "b.txt", []byte("hello world, this is a text file for stats"))

	rec, req := authed(t, h, "GET", "/dash/")
	h.Overview(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("overview = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "logos/a.png") {
		t.Errorf("overview missing recent file path, body:\n%s", body)
	}
	if !strings.Contains(body, `name="csrf_token"`) {
		t.Errorf("overview missing CSRF field")
	}
	if cc := rec.Result().Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("overview Cache-Control = %q, want no-store", cc)
	}

	// Anonymous overview → 401 JSON when asked, redirect-safe via RequireAuth
	// at the router level; direct handler call gives 401.
	anon := httptest.NewRequest("GET", "/dash/", nil)
	anon.Header.Set("Accept", "application/json")
	arec := httptest.NewRecorder()
	h.Overview(arec, anon)
	if arec.Code != http.StatusUnauthorized {
		t.Fatalf("anon overview = %d, want 401", arec.Code)
	}

	// Anonymous through RequireAuth → 302 login.
	wrapped := h.RequireAuth(http.HandlerFunc(h.Overview))
	r302 := httptest.NewRecorder()
	wrapped.ServeHTTP(r302, httptest.NewRequest("GET", "/dash/", nil))
	if r302.Code != http.StatusFound {
		t.Fatalf("anon via RequireAuth = %d, want 302", r302.Code)
	}
}

func TestManage(t *testing.T) {
	h := newHandlers(t)
	seedStoreFile(t, h, "logos", "a.png", testPNG())

	rec, req := authed(t, h, "GET", "/dash/manage?dir=logos")
	h.Manage(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("manage = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"a.png", `name="csrf_token"`, "/dash/manage", "logos"} {
		if !strings.Contains(body, want) {
			t.Errorf("manage missing %q", want)
		}
	}
	if !strings.Contains(body, `name="path" value="logos/a.png"`) {
		t.Errorf("manage missing delete path field")
	}

	// Bad dir redirects back to manage with a flash.
	rec2, req2 := authed(t, h, "GET", "/dash/manage?dir=nosuchdir")
	h.Manage(rec2, req2)
	if rec2.Code != http.StatusFound {
		t.Fatalf("bad dir = %d, want 302", rec2.Code)
	}
	if loc := rec2.Header().Get("Location"); !strings.HasPrefix(loc, "/dash/manage") {
		t.Errorf("bad dir Location = %q", loc)
	}

	// Anonymous → 302 via RequireAuth.
	wrapped := h.RequireAuth(http.HandlerFunc(h.Manage))
	r302 := httptest.NewRecorder()
	wrapped.ServeHTTP(r302, httptest.NewRequest("GET", "/dash/manage", nil))
	if r302.Code != http.StatusFound {
		t.Fatalf("anon manage = %d, want 302", r302.Code)
	}
}

func TestUpload(t *testing.T) {
	newSeeded := func(t *testing.T) *Handlers {
		h := newHandlers(t)
		ctx := context.Background()
		if err := h.store.Mkdir(ctx, "logos"); err != nil {
			t.Fatal(err)
		}
		return h
	}

	// Happy path: multipart upload saves the file, verifiable via store.Open.
	h := newSeeded(t)
	session, csrf := sessionFor(t, h)
	rec, req := multipartUpload(t, h, "/dash/api/upload",
		map[string]string{"dir": "logos", auth.CSRFField: csrf},
		map[string][]byte{"hello.png": testPNG()}, session, true)
	h.Upload(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload = %d %q", rec.Code, rec.Body.String())
	}
	if body := decodeJSON(t, rec); body["ok"] != true {
		t.Fatalf("upload ok = %v (%q)", body["ok"], rec.Body.String())
	}
	f, err := h.store.Open(context.Background(), "logos/hello.png")
	if err != nil {
		t.Fatalf("uploaded file not in store: %v", err)
	}
	f.Close()

	// Sanitised name: spaces become dashes.
	recS, reqS := multipartUpload(t, h, "/dash/api/upload",
		map[string]string{"dir": "logos", auth.CSRFField: csrf},
		map[string][]byte{"My Photo.png": testPNG()}, session, true)
	h.Upload(recS, reqS)
	if recS.Code != http.StatusOK {
		t.Fatalf("spaced upload = %d %q", recS.Code, recS.Body.String())
	}
	if f, err := h.store.Open(context.Background(), "logos/My-Photo.png"); err != nil {
		t.Fatalf("sanitised file not in store: %v", err)
	} else {
		f.Close()
	}

	// Overwrite=false conflict returns 409 JSON when Accept: application/json.
	recC, reqC := multipartUpload(t, h, "/dash/api/upload",
		map[string]string{"dir": "logos", auth.CSRFField: csrf},
		map[string][]byte{"hello.png": testPNG()}, session, true)
	h.Upload(recC, reqC)
	if recC.Code != http.StatusConflict {
		t.Fatalf("overwrite conflict = %d, want 409 (%q)", recC.Code, recC.Body.String())
	}
	if body := decodeJSON(t, recC); body["ok"] != false {
		t.Errorf("conflict ok = %v, want false", body["ok"])
	}

	// Bad CSRF returns 403.
	recB, reqB := multipartUpload(t, h, "/dash/api/upload",
		map[string]string{"dir": "logos", auth.CSRFField: "wrong"},
		map[string][]byte{"other.png": testPNG()}, session, true)
	h.Upload(recB, reqB)
	if recB.Code != http.StatusForbidden {
		t.Fatalf("bad CSRF = %d, want 403", recB.Code)
	}

	// Anonymous returns 401 JSON.
	h2 := newSeeded(t)
	recA, reqA := multipartUpload(t, h2, "/dash/api/upload",
		map[string]string{"dir": "logos", auth.CSRFField: "x"},
		map[string][]byte{"anon.png": testPNG()}, "", true)
	h2.Upload(recA, reqA)
	if recA.Code != http.StatusUnauthorized {
		t.Fatalf("anon upload = %d, want 401", recA.Code)
	}

	// Oversize returns 413. Shrink the cap for this handler only.
	h3 := newSeeded(t)
	h3.maxUploadBytes = 16
	session3, csrf3 := sessionFor(t, h3)
	recO, reqO := multipartUpload(t, h3, "/dash/api/upload",
		map[string]string{"dir": "logos", auth.CSRFField: csrf3},
		map[string][]byte{"big.png": testPNG()}, session3, true)
	h3.Upload(recO, reqO)
	if recO.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize = %d, want 413", recO.Code)
	}
}

func TestDelete(t *testing.T) {
	h := newHandlers(t)
	seedStoreFile(t, h, "logos", "gone.png", testPNG())

	// Delete the file (JSON client): 200 ok:true, then gone from the store.
	rec, req := postForm(t, h, "/dash/api/delete", url.Values{"path": {"logos/gone.png"}})
	req.Header.Set("Accept", "application/json")
	h.Delete(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete = %d %q", rec.Code, rec.Body.String())
	}
	if body := decodeJSON(t, rec); body["ok"] != true {
		t.Fatalf("delete ok = %v", body["ok"])
	}
	if _, err := h.store.Open(context.Background(), "logos/gone.png"); err == nil {
		t.Fatalf("file still present after delete")
	}

	// Non-empty dir is refused with 400.
	seedStoreFile(t, h, "full", "a.txt", []byte("some text content here, padding padding...."))
	rec2, req2 := postForm(t, h, "/dash/api/delete", url.Values{"path": {"full"}})
	req2.Header.Set("Accept", "application/json")
	h.Delete(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("non-empty dir delete = %d, want 400", rec2.Code)
	}

	// Empty dir deletes fine.
	recE, reqE := postForm(t, h, "/dash/api/delete", url.Values{"path": {"logos"}})
	reqE.Header.Set("Accept", "application/json")
	h.Delete(recE, reqE)
	if recE.Code != http.StatusOK {
		t.Fatalf("empty dir delete = %d %q", recE.Code, recE.Body.String())
	}

	// Bad CSRF returns 403.
	seedStoreFile(t, h, "logos2", "x.txt", []byte("some text content here, padding padding...."))
	recB, reqB := postForm(t, h, "/dash/api/delete",
		url.Values{"path": {"logos2/x.txt"}, auth.CSRFField: {"wrong"}})
	reqB.Header.Set("Accept", "application/json")
	h.Delete(recB, reqB)
	if recB.Code != http.StatusForbidden {
		t.Fatalf("bad CSRF delete = %d, want 403", recB.Code)
	}
}

func TestMkdir(t *testing.T) {
	h := newHandlers(t)

	rec, req := postForm(t, h, "/dash/api/mkdir", url.Values{"dir": {""}, "name": {"photos"}})
	req.Header.Set("Accept", "application/json")
	h.Mkdir(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("mkdir = %d %q", rec.Code, rec.Body.String())
	}
	if body := decodeJSON(t, rec); body["created"] != "photos" {
		t.Errorf("mkdir created = %v, want photos", body["created"])
	}
	if _, err := h.store.List(context.Background(), "photos"); err != nil {
		t.Fatalf("created dir not listable: %v", err)
	}

	for _, bad := range []string{"", "UPPER", "has space", "a/b", ".."} {
		brec, breq := postForm(t, h, "/dash/api/mkdir", url.Values{"dir": {""}, "name": {bad}})
		breq.Header.Set("Accept", "application/json")
		h.Mkdir(brec, breq)
		if brec.Code != http.StatusBadRequest {
			t.Errorf("mkdir(%q) = %d, want 400", bad, brec.Code)
		}
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
