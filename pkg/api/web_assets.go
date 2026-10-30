package api

import (
	"embed"
	"encoding/json"
	"mega-analyzer/pkg/buildinfo"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// WEB ASSETS — HTML/Swagger served from embedded files (production) with
// optional live directory override for UI iteration without recompiling:
//   MEGA_ANALYZER_WEB_DIR=/path/to/pkg/api/web go run ...
// Files live in pkg/api/web/ so UI changes show up as normal HTML/JSON diffs.
// ═══════════════════════════════════════════════════════════════════════════════

//go:embed web/dashboard.html
var embeddedDashboardHTML string

//go:embed web/swagger.json
var embeddedSwaggerJSON string

//go:embed web/swagger-ui.html
var embeddedSwaggerUIHTML string

//go:embed web/openapi.js web/openapi.css
var docsAssets embed.FS

func (s *APIServer) handleDocsAsset(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/docs/assets/")
	if name != "openapi.js" && name != "openapi.css" {
		http.NotFound(w, r)
		return
	}
	data, err := docsAssets.ReadFile("web/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if strings.HasSuffix(name, ".js") {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	}
	w.Write(data)
}

// Backward-compatible exported aliases (previously string constants).
// New code should prefer the getters below which honor MEGA_ANALYZER_WEB_DIR.
var (
	DashboardHTML = embeddedDashboardHTML
	SwaggerJSON   = embeddedSwaggerJSON
	SwaggerUIHTML = embeddedSwaggerUIHTML
)

func readWebOverride(name string) (string, bool) {
	dir := strings.TrimSpace(os.Getenv("MEGA_ANALYZER_WEB_DIR"))
	if dir == "" {
		return "", false
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return "", false
	}
	return string(b), true
}

func dashboardHTML() string {
	if s, ok := readWebOverride("dashboard.html"); ok {
		return strings.ReplaceAll(s, "__VERSION__", buildinfo.Version)
	}
	return strings.ReplaceAll(embeddedDashboardHTML, "__VERSION__", buildinfo.Version)
}

func swaggerJSON() string {
	data := embeddedSwaggerJSON
	if s, ok := readWebOverride("swagger.json"); ok {
		data = s
	}
	var spec map[string]any
	if json.Unmarshal([]byte(data), &spec) != nil {
		return data
	}
	if info, ok := spec["info"].(map[string]any); ok {
		info["version"] = buildinfo.Version
	}
	spec["servers"] = []map[string]string{{"url": "/", "description": "This local analyzer"}}
	b, err := json.Marshal(spec)
	if err != nil {
		return data
	}
	return string(b)
}

func swaggerUIHTML() string {
	if s, ok := readWebOverride("swagger-ui.html"); ok {
		return s
	}
	return embeddedSwaggerUIHTML
}
