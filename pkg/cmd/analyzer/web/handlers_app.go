package web

import (
	"bytes"
	"net/http"
	"time"
)

// Tool slugs are served the same SPA so a reload of /sandbox or /mitm is not a 404.
var toolSlugs = map[string]bool{
	"/minecraft": true,
	"/full":      true, "/decode": true, "/build": true, "/machine-code": true, "/firmware": true,
	"/diff": true, "/js": true, "/js-patch": true,
	"/sandbox": true, "/scan": true, "/mitm": true,
}

// serveApp serves the single-page app from the embedded assets.
func (s *Server) serveApp(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	if r.URL.Path != "/" && !toolSlugs[r.URL.Path] {
		httpError(w, r, http.StatusNotFound, "No page is served at this address.")
		return
	}
	// Landing with ?t=<token> stores the token so the SPA's own fetch/EventSource
	// calls keep working unchanged in network-bound mode.
	if s.token != "" && eq(r.URL.Query().Get("t"), s.token) {
		http.SetCookie(w, &http.Cookie{
			Name: tokenCookie, Value: s.token, Path: "/",
			HttpOnly: true, SameSite: http.SameSiteStrictMode,
		})
	}
	a := staticAssets["index.html"]
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("ETag", a.etag)
	w.Header().Set("Cache-Control", "no-cache")
	if r.Method == http.MethodHead {
		return
	}
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(a.body))
}
