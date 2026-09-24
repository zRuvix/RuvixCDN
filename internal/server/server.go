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

	// v0.1 dash stub: redirect to the future login page so the routing
	// contract (§2: unauthenticated /dash/* → 302 /dash/login) holds now.
	// Real dashboard lands in v0.2/v0.3.
	mux.Handle("/dash/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dash/login", http.StatusFound)
	}))
	mux.Handle("/dash/login", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("login — coming in v0.2"))
	}))

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
