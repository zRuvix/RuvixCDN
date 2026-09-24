package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// Recover converts panics into 500s without killing the server.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic", "path", r.URL.Path, "panic", rec)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// RealIP returns a middleware that trusts X-Forwarded-For only when the
// immediate peer is in one of the trusted networks (§3, §10).
func RealIP(trusted []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			if ip := net.ParseIP(host); ip != nil && trustedContains(trusted, ip) {
				if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
					if first, _, _ := strings.Cut(xff, ","); strings.TrimSpace(first) != "" {
						if ip := net.ParseIP(strings.TrimSpace(first)); ip != nil {
							r.RemoteAddr = ip.String() + ":0"
						}
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func trustedContains(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Log records method, path, status, bytes, duration and client IP.
// It never logs headers (no cookies, no tokens).
func Log(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.EscapedPath(),
			"status", sw.status,
			"bytes", sw.bytes,
			"duration_ms", time.Since(start).Milliseconds(),
			"client_ip", clientIP(r),
		)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// SecureHeaders sets baseline headers. The CDN handler sets its own
// cache/CORS/CORP headers on top; this middleware only adds what is
// safe for every response.
func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// Chain applies middlewares outer-first: Chain(h, recover, log) means
// recover wraps log wraps h.
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}
