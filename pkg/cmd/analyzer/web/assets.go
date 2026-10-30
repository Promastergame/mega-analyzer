// The single-page app used to be a 204 KB Go string constant (76%% of the old
// web_ui.go). It now lives in assets/ as real .html/.css/.js files: editors
// lint and highlight them, and the "no backtick may appear anywhere in this
// file" trap is gone.

package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
)

//go:embed assets/index.html assets/app.css assets/app.js assets/error.html assets/workspace.css assets/workspace.js assets/workspace-preview.js assets/novnc.js assets/novnc-LICENSE.txt
var assetFS embed.FS

type staticAsset struct {
	body []byte
	mime string
	etag string
}

var staticAssets = map[string]*staticAsset{}

func init() {
	for name, mime := range map[string]string{
		"index.html":           "text/html; charset=utf-8",
		"app.css":              "text/css; charset=utf-8",
		"app.js":               "text/javascript; charset=utf-8",
		"workspace.js":         "text/javascript; charset=utf-8",
		"workspace-preview.js": "text/javascript; charset=utf-8",
		"workspace.css":        "text/css; charset=utf-8",
		"novnc.js":             "text/javascript; charset=utf-8",
		"novnc-LICENSE.txt":    "text/plain; charset=utf-8",
	} {
		body := []byte(mustAsset("assets/" + name))
		sum := sha256.Sum256(body)
		staticAssets[name] = &staticAsset{
			body: body,
			mime: mime,
			etag: `"` + hex.EncodeToString(sum[:8]) + `"`,
		}
	}
}

func mustAsset(name string) string {
	b, err := assetFS.ReadFile(name)
	if err != nil {
		panic("webui: embedded asset missing: " + name)
	}
	return string(b)
}
