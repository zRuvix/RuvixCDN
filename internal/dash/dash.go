// Package dash implements the password-protected dashboard UI (CLAUDE.md §7).
// v0.2 scope: login/logout only. Overview and manage pages land in v0.3.
package dash

import (
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"zruvix-cdn/internal/auth"
	"zruvix-cdn/internal/config"
	"zruvix-cdn/web"
)

// Handlers serves the dashboard pages and auth endpoints.
type Handlers struct {
	cfg     *config.Config
	tmpl    *template.Template
	limiter *auth.Limiter
	// failDelay slows credential guessing without blocking the server.
	failDelay time.Duration
}

// New builds the dashboard handlers. Templates and static assets come from
// the embedded binary (no runtime file dependencies).
func New(cfg *config.Config) (*Handlers, error) {
	tmpl, err := template.ParseFS(web.Files, "templates/layout.html", "templates/login.html")
	if err != nil {
		return nil, err
	}
	return &Handlers{
		cfg:       cfg,
		tmpl:      tmpl,
		limiter:   auth.NewLimiter(5, 10*time.Minute),
		failDelay: 500 * time.Millisecond,
	}, nil
}

// pageData is passed to every template (§7).
type pageData struct {
	CSRFToken string
	PublicURL string
	Flash     string
}

// Session reports the logged-in user from the request cookie, or "".
func (h *Handlers) Session(r *http.Request) string {
	c, err := r.Cookie(auth.CookieName)
	if err != nil {
		return ""
	}
	user, _, ok := auth.Verify(h.cfg.SessionSecret, c.Value, time.Now())
	if !ok {
		return ""
	}
	return user
}

// RequireAuth redirects unauthenticated requests to /dash/login, preserving
// the original path in ?next= (relative paths only, to avoid open redirects).
func (h *Handlers) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.Session(r) == "" {
			loc := "/dash/login?next=" + url.QueryEscape(r.URL.Path)
			http.Redirect(w, r, loc, http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// LoginPage renders the login form with a fresh double-submit CSRF token.
func (h *Handlers) LoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.Session(r) != "" {
		http.Redirect(w, r, "/dash/", http.StatusFound)
		return
	}
	token, err := auth.NewCSRFToken()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	auth.SetLoginCSRFCookie(w, h.cfg, token)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	h.tmpl.ExecuteTemplate(w, "layout", pageData{
		CSRFToken: token,
		PublicURL: h.cfg.PublicURL,
		Flash:     r.URL.Query().Get("flash"),
	})
}

// Login verifies credentials and issues the session cookie.
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	if !h.limiter.Allow(ip) {
		slog.Warn("login rate-limited", "client_ip", ip)
		h.fail("too many attempts, try again later", w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		h.fail("invalid credentials", w, r)
		return
	}
	// Double-submit CSRF: form token must match the login cookie.
	formToken := r.FormValue(auth.CSRFField)
	cookie, err := r.Cookie(auth.LoginCSRFCookie)
	if err != nil || formToken == "" || !auth.Equal(formToken, cookie.Value) {
		h.fail("invalid credentials", w, r)
		return
	}
	user := r.FormValue("username")
	pass := r.FormValue("password")
	if !auth.CheckPassword(h.cfg.AdminPassHash, h.cfg.AdminUser, user, pass) {
		// Fixed delay + generic message: no user enumeration by timing or text.
		time.Sleep(h.failDelay)
		slog.Warn("login failed", "client_ip", ip)
		h.fail("invalid credentials", w, r)
		return
	}
	csrf, err := auth.NewCSRFToken()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	exp := time.Now().Add(h.cfg.SessionTTL)
	auth.SetSessionCookie(w, h.cfg, auth.Sign(h.cfg.SessionSecret, h.cfg.AdminUser, exp, csrf), exp)
	auth.ClearLoginCSRFCookie(w, h.cfg)
	slog.Info("login", "client_ip", ip)

	next := r.FormValue(auth.NextField)
	if !strings.HasPrefix(next, "/dash/") {
		next = "/dash/"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// fail re-renders the login form with a generic error and a fresh token.
func (h *Handlers) fail(msg string, w http.ResponseWriter, r *http.Request) {
	token, err := auth.NewCSRFToken()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	auth.SetLoginCSRFCookie(w, h.cfg, token)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	h.tmpl.ExecuteTemplate(w, "layout", pageData{
		CSRFToken: token,
		PublicURL: h.cfg.PublicURL,
		Flash:     msg,
	})
}

// Logout clears the session cookie.
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	auth.ClearSessionCookie(w, h.cfg)
	http.Redirect(w, r, "/dash/login", http.StatusFound)
}

// Overview and Manage are v0.3 pages; in v0.2 they serve placeholders
// behind RequireAuth so the routing contract holds now.
func (h *Handlers) Overview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("overview — coming in v0.3"))
}

// Manage is the v0.3 file manager placeholder.
func (h *Handlers) Manage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("manage — coming in v0.3"))
}
