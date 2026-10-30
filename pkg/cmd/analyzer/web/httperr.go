// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
)

// errorPage renders assets/error.html. html/template escapes Detail and Path
// automatically, so a future field cannot be forgotten the way a manual
// html.EscapeString call can.
var errorPage = template.Must(template.New("error").Parse(mustAsset("assets/error.html")))

type errorPageData struct {
	Code   int
	Status string
	Detail string
	Path   string
}

// httpError renders a themed page for browser navigation and JSON for API and
// XHR callers, so the front-end can still parse a failure.
func httpError(w http.ResponseWriter, r *http.Request, code int, detail string) {
	status := http.StatusText(code)
	if detail == "" {
		detail = status
	}
	wantsJSON := strings.HasPrefix(r.URL.Path, "/api/") ||
		strings.Contains(r.Header.Get("Accept"), "application/json") ||
		r.Header.Get("X-Requested-With") == "XMLHttpRequest"
	if wantsJSON {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":  status,
			"status": code,
			"detail": detail,
			"path":   r.URL.Path,
		})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = errorPage.Execute(w, errorPageData{
		Code:   code,
		Status: status,
		Detail: detail,
		Path:   r.URL.Path,
	})
}

// requireMethod rejects a request whose method is not allowed and reports
// whether the caller may continue. State-changing endpoints must not be
// reachable by a plain GET, which any prefetch, crawler or <img> tag can issue.
func requireMethod(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for _, m := range allowed {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	httpError(w, r, http.StatusMethodNotAllowed,
		"This endpoint only accepts "+strings.Join(allowed, " or ")+".")
	return false
}
