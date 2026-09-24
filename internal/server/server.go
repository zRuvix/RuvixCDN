package server

import (
	"net/http"
	"time"

	"zruvix-cdn/internal/cdn"
	"zruvix-cdn/internal/config"
	"zruvix-cdn/internal/middleware"
	"zruvix-cdn/internal/storage"
)

// New builds the full route tree. More-specific /dash/ wins over the CDN
// catch-all / by ServeMux specificity, not registration order.
func New(cfg *config.Config, store *storage.Store) http.Handler {
	return newWithDash(cfg, store, nil)
}

// newWithDash wires the router; tests inject dash handlers, production
// builds the real ones. A nil dh builds the real dashboard.
func newWithDash(cfg *config.Config, store *storage.Store, dh dashHandlers) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte("ok"))
	})

	dh = resolveDash(cfg, dh)

	// Public (no session): login page + login POST + embedded static.
	mux.HandleFunc("/dash/login", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			dh.LoginPage(w, r)
		case http.MethodPost:
			dh.Login(w, r)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.Handle("/dash/static/", dashStatic())

	// Authenticated: everything else under /dash/.
	authed := dh.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/dash/logout" && r.Method == http.MethodPost:
			dh.Logout(w, r)
		case r.URL.Path == "/dash/" || r.URL.Path == "/dash":
			dh.Overview(w, r)
		default:
			dh.Manage(w, r)
		}
	}))
	mux.Handle("/dash/", authed)

	cdnHandler := cdn.New(store, cfg.CacheMaxAge)
	mux.Handle("/", cdnHandler)

	return middleware.Chain(mux,
		middleware.Recover,
		middleware.RealIP(cfg.TrustedProxies),
		middleware.Log,
		middleware.SecureHeaders,
	)
}

// NewHTTPServer wraps h with the mandatory timeouts (§13).
func NewHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute, // generous for large downloads
		IdleTimeout:       120 * time.Second,
	}
}
