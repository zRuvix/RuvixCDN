package server

import (
	"net/http"

	"zruvix-cdn/internal/config"
	"zruvix-cdn/internal/dash"
	"zruvix-cdn/internal/storage"
)

// dashHandlers is the dashboard surface the router needs. *dash.Handlers
// implements it; tests substitute a stub to avoid template setup.
type dashHandlers interface {
	Session(r *http.Request) string
	RequireAuth(next http.Handler) http.Handler
	LoginPage(w http.ResponseWriter, r *http.Request)
	Login(w http.ResponseWriter, r *http.Request)
	Logout(w http.ResponseWriter, r *http.Request)
	Overview(w http.ResponseWriter, r *http.Request)
	Manage(w http.ResponseWriter, r *http.Request)
	Upload(w http.ResponseWriter, r *http.Request)
	Delete(w http.ResponseWriter, r *http.Request)
	Mkdir(w http.ResponseWriter, r *http.Request)
}

func resolveDash(cfg *config.Config, store *storage.Store, dh dashHandlers) dashHandlers {
	if dh != nil {
		return dh
	}
	h, err := dash.New(cfg, store)
	if err != nil {
		// Templates are embedded; failure means a broken build. Fail
		// closed at startup rather than serving a half-wired dashboard.
		panic("dash: " + err.Error())
	}
	return h
}
