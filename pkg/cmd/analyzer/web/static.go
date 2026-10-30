package web

import (
	"bytes"
	"net/http"
	"path"
	"strings"
	"time"
)

// staticHandler serves assets/ from the binary. ServeContent gives us ETag
// revalidation, HEAD and Range for free -- the old code wrote a fresh 200 KB
// copy of the whole app on every navigation.
func (s *Server) staticHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		name := path.Base(path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/static/")))
		a, ok := staticAssets[name]
		if !ok || name == "index.html" {
			httpError(w, r, http.StatusNotFound, "No asset is served at this address.")
			return
		}
		w.Header().Set("Content-Type", a.mime)
		w.Header().Set("ETag", a.etag)
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(a.body))
	})
}
