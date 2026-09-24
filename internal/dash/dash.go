// Package dash implements the password-protected dashboard UI (CLAUDE.md §7).
package dash

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"zruvix-cdn/internal/auth"
	"zruvix-cdn/internal/config"
	"zruvix-cdn/internal/storage"
	"zruvix-cdn/web"
)

// maxUploadFiles caps files per upload request (bulk upload UI is later).
const maxUploadFiles = 20

// Handlers serves the dashboard pages and API endpoints.
type Handlers struct {
	cfg            *config.Config
	store          *storage.Store
	loginTmpl      *template.Template
	overviewTmpl   *template.Template
	manageTmpl     *template.Template
	limiter        *auth.Limiter
	failDelay      time.Duration
	maxUploadBytes int64
}

// New builds the dashboard handlers. Templates and static assets come from
// the embedded binary (no runtime file dependencies).
//
// Each page gets its own template set (shared layout + nav plus one page).
// A single shared set would be wrong: layout's {{ block }} directives would
// resolve "title"/"content" to the login page's definitions on every page,
// rendering a stray login form on the overview and manage pages.
func New(cfg *config.Config, store *storage.Store) (*Handlers, error) {
	funcs := template.FuncMap{
		"humanSize":  humanSize,
		"formatTime": formatTime,
	}
	parse := func(page string) (*template.Template, error) {
		return template.New("").Funcs(funcs).ParseFS(web.Files,
			"templates/layout.html",
			"templates/nav.html",
			"templates/"+page,
		)
	}
	loginTmpl, err := parse("login.html")
	if err != nil {
		return nil, err
	}
	overviewTmpl, err := parse("overview.html")
	if err != nil {
		return nil, err
	}
	manageTmpl, err := parse("manage.html")
	if err != nil {
		return nil, err
	}
	return &Handlers{
		cfg:            cfg,
		store:          store,
		loginTmpl:      loginTmpl,
		overviewTmpl:   overviewTmpl,
		manageTmpl:     manageTmpl,
		limiter:        auth.NewLimiter(5, 10*time.Minute),
		failDelay:      500 * time.Millisecond,
		maxUploadBytes: int64(cfg.MaxUploadMB) << 20,
	}, nil
}

// pageData is passed to every template (§7). Active selects the pill-nav
// highlight ("overview"/"manage"); login pages leave it empty (no nav).
type pageData struct {
	CSRFToken string
	PublicURL string
	Flash     string
	LoggedIn  bool
	Active    string
}

// fileEntry is a storage entry plus its public URL and image flag for
// thumbnails. Storage.Entry fields (Name, Path, IsDir, Size, ModTime)
// promote through embedding.
type fileEntry struct {
	storage.Entry
	URL     string
	IsImage bool
}

type crumb struct {
	Name string
	Dir  string
}

type overviewData struct {
	pageData
	FileCount int
	DirCount  int
	TotalSize int64
	Recent    []fileEntry
}

type manageData struct {
	pageData
	Dir     string
	Crumbs  []crumb
	TopDirs []storage.Entry
	Entries []fileEntry
}

func humanSize(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	case n < 1024*1024*1024:
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	default:
		return fmt.Sprintf("%.1f GB", float64(n)/(1024*1024*1024))
	}
}

func formatTime(unix int64) string {
	return time.Unix(unix, 0).Local().Format("2006-01-02 15:04")
}

func isImage(name string) bool {
	i := strings.LastIndex(name, ".")
	if i < 0 {
		return false
	}
	switch strings.ToLower(name[i+1:]) {
	case "png", "jpg", "jpeg", "gif", "webp", "avif", "ico", "svg":
		return true
	}
	return false
}

// sanitizeFilename normalises a user-supplied upload name (§9): whitespace
// runs become "-", non-ASCII and punctuation are stripped, the extension is
// lowercased. The result must fit storage's file-name shape; the extension
// allowlist itself is enforced by storage.Save.
func sanitizeFilename(name string) (string, error) {
	s := strings.Join(strings.Fields(name), "-")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		}
	}
	s = strings.TrimLeft(b.String(), ".-_")
	if s == "" {
		return "", errors.New("empty filename after sanitising")
	}
	if len(s) > 128 {
		return "", errors.New("filename too long")
	}
	if i := strings.LastIndex(s, "."); i >= 0 {
		s = s[:i] + strings.ToLower(s[i:])
	}
	return s, nil
}

// sessionCSRF returns the logged-in user and their session CSRF token.
func (h *Handlers) sessionCSRF(r *http.Request) (user, csrf string) {
	c, err := r.Cookie(auth.CookieName)
	if err != nil {
		return "", ""
	}
	u, c2, ok := auth.Verify(h.cfg.SessionSecret, c.Value, time.Now())
	if !ok {
		return "", ""
	}
	return u, c2
}

// Session reports the logged-in user from the request cookie, or "".
func (h *Handlers) Session(r *http.Request) string {
	u, _ := h.sessionCSRF(r)
	return u
}

// RequireAuth redirects unauthenticated requests to /dash/login, preserving
// the original path in ?next= (dash paths only, no open redirects).
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

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

func manageURL(dir string) string {
	if dir == "" {
		return "/dash/manage"
	}
	return "/dash/manage?dir=" + url.QueryEscape(dir)
}

// apiOK answers a successful mutation: JSON for fetch clients, redirect
// back to the file manager for plain form posts.
func (h *Handlers) apiOK(w http.ResponseWriter, r *http.Request, dir string, payload map[string]any) {
	if wantsJSON(r) {
		payload["ok"] = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(payload)
		return
	}
	http.Redirect(w, r, manageURL(dir), http.StatusSeeOther)
}

// apiFail answers a failed mutation: JSON with status for fetch clients,
// redirect with ?flash= for plain form posts. msg is user-facing and must
// not contain paths or internals; details go to the log.
func (h *Handlers) apiFail(w http.ResponseWriter, r *http.Request, dir string, status int, msg string) {
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": msg})
		return
	}
	loc := manageURL(dir)
	sep := "?"
	if strings.Contains(loc, "?") {
		sep = "&"
	}
	http.Redirect(w, r, loc+sep+"flash="+url.QueryEscape(msg), http.StatusSeeOther)
}

// requireSession rejects unauthenticated mutation calls.
func (h *Handlers) requireSession(w http.ResponseWriter, r *http.Request) (user, csrf string, ok bool) {
	user, csrf = h.sessionCSRF(r)
	if user == "" {
		h.apiFail(w, r, "", http.StatusUnauthorized, "not logged in")
		return "", "", false
	}
	return user, csrf, true
}

// checkCSRF compares the submitted token against the session token.
func (h *Handlers) checkCSRF(w http.ResponseWriter, r *http.Request, dir, sessionCSRF, formToken string) bool {
	if formToken == "" || !auth.Equal(formToken, sessionCSRF) {
		h.apiFail(w, r, dir, http.StatusForbidden, "bad csrf token")
		return false
	}
	return true
}

// storageStatus maps storage errors to HTTP status + generic message.
func storageStatus(err error) (int, string) {
	switch {
	case errors.Is(err, storage.ErrExists):
		return http.StatusConflict, "already exists"
	case errors.Is(err, storage.ErrNotFound):
		return http.StatusNotFound, "not found"
	case errors.Is(err, storage.ErrDirNotEmpty):
		return http.StatusBadRequest, "directory not empty"
	case errors.Is(err, storage.ErrInvalidPath),
		errors.Is(err, storage.ErrReserved),
		errors.Is(err, storage.ErrDisallowedExt),
		errors.Is(err, storage.ErrContentSniff):
		return http.StatusBadRequest, "invalid file or path"
	default:
		return http.StatusInternalServerError, "internal error"
	}
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
	h.loginTmpl.ExecuteTemplate(w, "layout", pageData{
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
	h.loginTmpl.ExecuteTemplate(w, "layout", pageData{
		CSRFToken: token,
		PublicURL: h.cfg.PublicURL,
		Flash:     msg,
	})
}

// Logout clears the session cookie. The session CSRF token is verified
// like any other mutation (§8).
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, sessionCSRF, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		h.apiFail(w, r, "", http.StatusBadRequest, "bad request")
		return
	}
	if !h.checkCSRF(w, r, "", sessionCSRF, r.FormValue(auth.CSRFField)) {
		return
	}
	auth.ClearSessionCookie(w, h.cfg)
	slog.Info("logout", "client_ip", clientIP(r))
	http.Redirect(w, r, "/dash/login", http.StatusFound)
}

// Overview renders file count, total size, dir count and recent uploads.
func (h *Handlers) Overview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, sessionCSRF, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	st, err := h.store.Stats(r.Context())
	if err != nil {
		slog.Error("overview stats", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	recent := make([]fileEntry, 0, len(st.Recent))
	for _, e := range st.Recent {
		recent = append(recent, h.entry(e))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	h.overviewTmpl.ExecuteTemplate(w, "overview", overviewData{
		pageData: pageData{
			CSRFToken: sessionCSRF,
			PublicURL: h.cfg.PublicURL,
			Flash:     r.URL.Query().Get("flash"),
			LoggedIn:  true,
			Active:    "overview",
		},
		FileCount: st.FileCount,
		DirCount:  st.DirCount,
		TotalSize: st.TotalSize,
		Recent:    recent,
	})
}

func (h *Handlers) entry(e storage.Entry) fileEntry {
	return fileEntry{
		Entry:   e,
		URL:     h.cfg.PublicURL + "/" + e.Path,
		IsImage: !e.IsDir && isImage(e.Name),
	}
}

func crumbs(dir string) []crumb {
	out := []crumb{{Name: "/", Dir: ""}}
	if dir == "" {
		return out
	}
	parts := strings.Split(dir, "/")
	for i, p := range parts {
		out = append(out, crumb{Name: p, Dir: strings.Join(parts[:i+1], "/")})
	}
	return out
}

// Manage renders the file manager for ?dir= (root by default).
func (h *Handlers) Manage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, sessionCSRF, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	dir := r.URL.Query().Get("dir")
	entries, err := h.store.List(r.Context(), dir)
	if err != nil {
		// Unknown/garbage dir: back to root rather than a dead page.
		slog.Warn("manage bad dir", "dir", dir, "client_ip", clientIP(r))
		http.Redirect(w, r, "/dash/manage?flash="+url.QueryEscape("invalid directory"), http.StatusFound)
		return
	}
	root, err := h.store.List(r.Context(), "")
	if err != nil {
		slog.Error("manage root list", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	var topDirs []storage.Entry
	for _, e := range root {
		if e.IsDir {
			topDirs = append(topDirs, e)
		}
	}
	files := make([]fileEntry, 0, len(entries))
	for _, e := range entries {
		files = append(files, h.entry(e))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	h.manageTmpl.ExecuteTemplate(w, "manage", manageData{
		pageData: pageData{
			CSRFToken: sessionCSRF,
			PublicURL: h.cfg.PublicURL,
			Flash:     r.URL.Query().Get("flash"),
			LoggedIn:  true,
			Active:    "manage",
		},
		Dir:     dir,
		Crumbs:  crumbs(dir),
		TopDirs: topDirs,
		Entries: files,
	})
}

// Upload stores multipart files into a directory (§2: POST /dash/api/upload).
// Size is capped by MAX_UPLOAD_MB via MaxBytesReader.
func (h *Handlers) Upload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, sessionCSRF, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.maxUploadBytes)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			h.apiFail(w, r, r.FormValue("dir"), http.StatusRequestEntityTooLarge, "upload too large")
		} else {
			h.apiFail(w, r, "", http.StatusBadRequest, "bad upload")
		}
		return
	}
	dir := r.FormValue("dir")
	if !h.checkCSRF(w, r, dir, sessionCSRF, r.FormValue(auth.CSRFField)) {
		return
	}
	overwrite := r.FormValue("overwrite") == "1" ||
		r.FormValue("overwrite") == "true" ||
		r.FormValue("overwrite") == "on"
	fhs := r.MultipartForm.File["file"]
	if len(fhs) == 0 {
		h.apiFail(w, r, dir, http.StatusBadRequest, "no files selected")
		return
	}
	if len(fhs) > maxUploadFiles {
		h.apiFail(w, r, dir, http.StatusBadRequest, "too many files at once")
		return
	}
	var saved []string
	for _, fh := range fhs {
		name, err := sanitizeFilename(fh.Filename)
		if err != nil {
			slog.Warn("upload bad filename", "dir", dir, "client_ip", clientIP(r))
			h.apiFail(w, r, dir, http.StatusBadRequest, "bad filename")
			return
		}
		src, err := fh.Open()
		if err != nil {
			slog.Error("upload open", "err", err)
			h.apiFail(w, r, dir, http.StatusInternalServerError, "internal error")
			return
		}
		err = h.store.Save(r.Context(), dir, name, src, overwrite)
		src.Close()
		if err != nil {
			status, msg := storageStatus(err)
			slog.Warn("upload save", "dir", dir, "file", name, "err", err, "client_ip", clientIP(r))
			h.apiFail(w, r, dir, status, msg)
			return
		}
		saved = append(saved, name)
	}
	slog.Info("upload", "dir", dir, "files", len(saved), "client_ip", clientIP(r))
	h.apiOK(w, r, dir, map[string]any{"saved": saved})
}

// Delete removes a file or an empty directory (§2: POST /dash/api/delete).
func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, sessionCSRF, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		h.apiFail(w, r, "", http.StatusBadRequest, "bad request")
		return
	}
	p := r.FormValue("path")
	dir := ""
	if i := strings.LastIndex(p, "/"); i >= 0 {
		dir = p[:i]
	}
	if !h.checkCSRF(w, r, dir, sessionCSRF, r.FormValue(auth.CSRFField)) {
		return
	}
	if err := h.store.Delete(r.Context(), p); err != nil {
		status, msg := storageStatus(err)
		slog.Warn("delete", "path", p, "err", err, "client_ip", clientIP(r))
		h.apiFail(w, r, dir, status, msg)
		return
	}
	slog.Info("delete", "path", p, "client_ip", clientIP(r))
	h.apiOK(w, r, dir, map[string]any{"deleted": p})
}

// Mkdir creates one directory level (§2: POST /dash/api/mkdir).
func (h *Handlers) Mkdir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, sessionCSRF, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		h.apiFail(w, r, "", http.StatusBadRequest, "bad request")
		return
	}
	parent := r.FormValue("dir")
	name := r.FormValue("name")
	if !h.checkCSRF(w, r, parent, sessionCSRF, r.FormValue(auth.CSRFField)) {
		return
	}
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		h.apiFail(w, r, parent, http.StatusBadRequest, "bad folder name")
		return
	}
	full := name
	if parent != "" {
		full = parent + "/" + name
	}
	if err := h.store.Mkdir(r.Context(), full); err != nil {
		status, msg := storageStatus(err)
		slog.Warn("mkdir", "dir", full, "err", err, "client_ip", clientIP(r))
		h.apiFail(w, r, parent, status, msg)
		return
	}
	slog.Info("mkdir", "dir", full, "client_ip", clientIP(r))
	h.apiOK(w, r, parent, map[string]any{"created": full})
}
