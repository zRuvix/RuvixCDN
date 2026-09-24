package server

import (
	"net/http"
	"path"
	"strings"

	"zruvix-cdn/web"
)

// dashStatic serves embedded dashboard CSS/JS (§2: /dash/static/*, no auth,
// embedded in the binary). Only the two known files are served; anything
// else is a 404. Long immutable caching is safe: v0.2 has no JS and the CSS
// changes only with new binary releases.
func dashStatic() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rel := strings.TrimPrefix(path.Clean(r.URL.Path), "/dash/static/")
		switch rel {
		case "css/dash.css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		case "js/manage.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		http.ServeFileFS(w, r, web.Files, path.Join("static", rel))
	})
}
