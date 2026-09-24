package server

import (
	"net/http"

	"zruvix-cdn/internal/config"
	"zruvix-cdn/internal/dash"
)

// dashHandlers is the dashboard surface the router needs. *dash.Handlers
// implements it; tests substitute a stub to avoid template setup.
type dashHandlers interface {
	Session(r *http.Request) string
	RequireAuth(next http.Handler) http.Handler
	LoginPage(w http.ResponseWriter, r *http.Request)
	Login(w http.ResponseWriter, r *http.Request)
	Logout(w http.ResponseWriter, r *http.Request)
	// Overview/Manage are v0.3 pages; in v0.2 they serve placeholders.
	Overview(w http.ResponseWriter, r *http.Request)
	Manage(w http.ResponseWriter, r *http.Request)
}

func resolveDash(cfg *config.Config, dh dashHandlers) dashHandlers {
	if dh != nil {
		return dh
	}
	h, err := dash.New(cfg)
	if err != nil {
		// Templates are embedded; failure means a broken build. Fail
		// closed at startup rather than serving a half-wired dashboard.
		panic("dash: " + err.Error())
	}
	return h
}
