package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"zruvix-cdn/internal/config"
)

func testSecret() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

func TestSignVerifyRoundTrip(t *testing.T) {
	secret := testSecret()
	now := time.Now()
	csrf, _ := NewCSRFToken()
	val := Sign(secret, "admin", now.Add(time.Hour), csrf)
	user, gotCSRF, ok := Verify(secret, val, now)
	if !ok || user != "admin" || gotCSRF != csrf {
		t.Fatalf("Verify = %q %q %v", user, gotCSRF, ok)
	}
}

func TestVerifyRejects(t *testing.T) {
	secret := testSecret()
	now := time.Now()
	csrf, _ := NewCSRFToken()
	good := Sign(secret, "admin", now.Add(time.Hour), csrf)

	cases := map[string]string{
		"empty":        "",
		"no separator": "abc",
		"bad sig":      strings.SplitN(good, ".", 2)[0] + ".AAAA",
		"bad body":     "!!!." + strings.SplitN(good, ".", 2)[1],
		"wrong secret": Sign([]byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"), "admin", now.Add(time.Hour), csrf),
		"expired":      Sign(secret, "admin", now.Add(-time.Minute), csrf),
		"tampered": func() string {
			parts := strings.SplitN(good, ".", 2)
			b := parts[0]
			if b[0] == 'A' {
				b = "B" + b[1:]
			} else {
				b = "A" + b[1:]
			}
			return b + "." + parts[1]
		}(),
	}
	for name, val := range cases {
		if _, _, ok := Verify(secret, val, now); ok {
			t.Errorf("%s: verified, want reject", name)
		}
	}
}

func TestCheckPassword(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(string(hash), "admin", "admin", "s3cret") {
		t.Errorf("correct credentials rejected")
	}
	if CheckPassword(string(hash), "admin", "admin", "wrong") {
		t.Errorf("wrong password accepted")
	}
	if CheckPassword(string(hash), "admin", "nobody", "s3cret") {
		t.Errorf("wrong user accepted")
	}
	// Unknown user still runs bcrypt (no panic, no fast path to observe).
	if CheckPassword("not-a-hash", "admin", "nobody", "x") {
		t.Errorf("garbage hash accepted")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(5, 10*time.Minute)
	now := time.Now()
	for i := 0; i < 5; i++ {
		if !l.AllowAt("1.2.3.4", now) {
			t.Fatalf("attempt %d denied, want allow", i+1)
		}
	}
	if l.AllowAt("1.2.3.4", now) {
		t.Fatalf("6th attempt allowed, want deny")
	}
	// Other IPs unaffected.
	if !l.AllowAt("5.6.7.8", now) {
		t.Fatalf("other IP denied")
	}
	// Window expiry restores access.
	if !l.AllowAt("1.2.3.4", now.Add(11*time.Minute)) {
		t.Fatalf("post-window denied")
	}
}

func TestSessionCookieFlags(t *testing.T) {
	cfg := &config.Config{CookieInsecure: true}
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, cfg, "v", time.Now().Add(time.Hour))
	c := rec.Result().Cookies()[0]
	if c.Name != CookieName || c.Path != "/dash" || !c.HttpOnly {
		t.Fatalf("bad cookie: %+v", c)
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite = %v", c.SameSite)
	}
	if c.Secure {
		t.Fatalf("insecure dev cookie must not be Secure")
	}

	prod := &config.Config{}
	rec2 := httptest.NewRecorder()
	SetSessionCookie(rec2, prod, "v", time.Now().Add(time.Hour))
	if !rec2.Result().Cookies()[0].Secure {
		t.Fatalf("prod cookie must be Secure")
	}
	// Never on CDN paths: Path=/dash means browsers withhold it elsewhere.
	if rec2.Result().Cookies()[0].Path != "/dash" {
		t.Fatalf("cookie path must be /dash")
	}

	rec3 := httptest.NewRecorder()
	ClearSessionCookie(rec3, prod)
	if c := rec3.Result().Cookies()[0]; c.MaxAge >= 0 {
		t.Fatalf("clear cookie must expire: %+v", c)
	}
}
