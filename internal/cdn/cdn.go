package cdn

import (
	"fmt"
	"net/http"
	"path"
	"strings"

	"zruvix-cdn/internal/storage"
)

// extContentType is the fixed extension map (§6). Anything not listed here
// is rejected by storage, so the zero value is never served.
var extContentType = map[string]string{
	"png":   "image/png",
	"jpg":   "image/jpeg",
	"jpeg":  "image/jpeg",
	"gif":   "image/gif",
	"webp":  "image/webp",
	"avif":  "image/avif",
	"ico":   "image/x-icon",
	"svg":   "image/svg+xml",
	"css":   "text/css; charset=utf-8",
	"woff":  "font/woff",
	"woff2": "font/woff2",
	"ttf":   "font/ttf",
	"mp4":   "video/mp4",
	"webm":  "video/webm",
	"mp3":   "audio/mpeg",
	"pdf":   "application/pdf",
	"json":  "application/json",
	"txt":   "text/plain; charset=utf-8",
}

// Handler serves public CDN files read-only (§6). Hot and boring: no
// sessions, no cookies, no templates. Any resolution failure is a bare 404.
type Handler struct {
	store  *storage.Store
	maxAge int
}

func New(store *storage.Store, cacheMaxAge int) *Handler {
	return &Handler{store: store, maxAge: cacheMaxAge}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// r.URL.Path is already %-decoded by net/http; EscapedPath retains the
	// raw form. Reject anything where the two disagree on slashes so that
	// "..%2f" can never become a path separator downstream.
	raw := r.URL.EscapedPath()
	rel := strings.TrimPrefix(path.Clean("/"+raw), "/")
	if strings.Contains(raw, "%2f") || strings.Contains(raw, "%2F") ||
		strings.Contains(raw, "%5c") || strings.Contains(raw, "%5C") ||
		strings.Contains(raw, "%00") {
		http.NotFound(w, r)
		return
	}
	if rel == "" || strings.HasSuffix(raw, "/") {
		// "/" and directory URLs: minimal 404, never list.
		http.NotFound(w, r)
		return
	}

	f, err := h.store.Open(r.Context(), rel)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}

	ext := strings.ToLower(strings.TrimPrefix(path.Ext(rel), "."))
	ct, ok := extContentType[ext]
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", h.maxAge))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	if ext == "svg" {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	}
	// Weak ETag from modtime-size; no hashing on the hot path.
	etag := fmt.Sprintf("W/\"%x-%x\"", fi.ModTime().Unix(), fi.Size())
	w.Header().Set("ETag", etag)
	// Never Set-Cookie here.

	http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
}
