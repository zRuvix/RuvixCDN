// Package auth implements the single-admin session, CSRF protection and
// login rate limiting for the dashboard (CLAUDE.md §8).
//
// The session is stateless: base64url(payload).base64url(HMAC-SHA256) where
// payload is JSON {user, exp, csrf}. Signatures are compared in constant
// time. Rotate SESSION_SECRET to invalidate all sessions (v1 has no
// server-side revocation).
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"zruvix-cdn/internal/config"
)

const (
	// CookieName is the session cookie. Path=/dash keeps it off CDN
	// asset requests (better caching, less exposure).
	CookieName = "zruvix_session"
	// LoginCSRFCookie holds the pre-login double-submit CSRF token.
	LoginCSRFCookie = "zruvix_login_csrf"
	// CSRFField is the form field name carrying a CSRF token.
	CSRFField = "csrf_token"
	// NextField carries the post-login redirect target.
	NextField = "next"
)

type payload struct {
	User string `json:"u"`
	Exp  int64  `json:"e"`
	CSRF string `json:"c"`
}

// Sign creates a session cookie value for user, valid until exp.
func Sign(secret []byte, user string, exp time.Time, csrf string) string {
	raw, _ := json.Marshal(payload{User: user, Exp: exp.Unix(), CSRF: csrf})
	body := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return body + "." + sig
}

// Verify authenticates a cookie value. It returns the user and CSRF token.
// Any failure — bad signature, malformed payload, expiry — returns ok=false
// with no detail, so callers cannot leak why.
func Verify(secret []byte, value string, now time.Time) (user, csrf string, ok bool) {
	body, sig, found := strings.Cut(value, ".")
	if !found || body == "" || sig == "" {
		return "", "", false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return "", "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return "", "", false
	}
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", "", false
	}
	if p.User == "" || p.CSRF == "" || p.Exp <= 0 {
		return "", "", false
	}
	if !now.Before(time.Unix(p.Exp, 0)) {
		return "", "", false
	}
	return p.User, p.CSRF, true
}

// NewCSRFToken returns 32 random bytes as hex.
func NewCSRFToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Equal compares two tokens in constant time.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// CheckPassword verifies credentials. bcrypt always runs — even for unknown
// usernames — so timing reveals nothing about which half was wrong.
func CheckPassword(hash, expectedUser, user, password string) bool {
	pwOK := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(expectedUser)) == 1
	return pwOK && userOK
}

// secureCookies reports whether session cookies must carry the Secure flag:
// always, except local-dev mode (COOKIE_INSECURE=true, http PUBLIC_URL).
func secureCookies(cfg *config.Config) bool { return !cfg.CookieInsecure }

// SetSessionCookie issues the session cookie: HttpOnly, Secure (except dev),
// SameSite=Lax, Path=/dash.
func SetSessionCookie(w http.ResponseWriter, cfg *config.Config, value string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/dash",
		Expires:  exp,
		MaxAge:   int(time.Until(exp).Seconds()),
		HttpOnly: true,
		Secure:   secureCookies(cfg),
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie expires the session cookie.
func ClearSessionCookie(w http.ResponseWriter, cfg *config.Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/dash",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
		HttpOnly: true,
		Secure:   secureCookies(cfg),
		SameSite: http.SameSiteLaxMode,
	})
}

// SetLoginCSRFCookie stores the pre-login double-submit token (short-lived).
func SetLoginCSRFCookie(w http.ResponseWriter, cfg *config.Config, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     LoginCSRFCookie,
		Value:    token,
		Path:     "/dash",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   secureCookies(cfg),
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearLoginCSRFCookie removes the pre-login token after a successful login.
func ClearLoginCSRFCookie(w http.ResponseWriter, cfg *config.Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     LoginCSRFCookie,
		Value:    "",
		Path:     "/dash",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
		HttpOnly: true,
		Secure:   secureCookies(cfg),
		SameSite: http.SameSiteLaxMode,
	})
}

// Limiter is an in-memory per-IP token bucket for login attempts (§8:
// e.g. 5 attempts / 10 min). Zero value is unusable; use NewLimiter.
type Limiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

// NewLimiter allows up to max attempts per window per IP.
func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{hits: make(map[string][]time.Time), max: max, window: window}
}

// Allow reports whether an attempt from ip may proceed, recording it.
func (l *Limiter) Allow(ip string) bool { return l.AllowAt(ip, time.Now()) }

// AllowAt is Allow with an injectable clock (tests).
func (l *Limiter) AllowAt(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.window)
	kept := l.hits[ip][:0]
	for _, t := range l.hits[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.hits[ip] = kept
		return false
	}
	l.hits[ip] = append(kept, now)
	return true
}
