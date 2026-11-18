package report

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestSVGHTMLRemainsInImageContext(t *testing.T) {
	payload := `<svg xmlns="http://www.w3.org/2000/svg" onload="window.__svgExecuted=true"><script>window.__svgExecuted=true</script></svg>`
	view := &ArtifactsView{Summary: ArtifactsSummary{Total: 1, ByType: map[string]int{"image": 1}}, Items: []ArtifactItem{{ID: "svg_test", Path: "assets/test.svg", Type: "image", Mime: "image/svg+xml", EmbeddedDataURI: "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(payload)), SVG: &SVGInspection{Active: true, Complete: true}}}}
	page := NewHTMLReporter(makeResultWithData()).WithArtifacts(view).BuildHTML()
	if strings.Contains(page, payload) || !strings.Contains(page, "SVG Script Alert") || !strings.Contains(page, `src="data:image/svg+xml;base64,`) {
		t.Fatal("SVG was inserted as markup or not flagged")
	}
	if strings.Contains(page, "lowerSvg.indexOf") || strings.Contains(page, "Secure. No active") {
		t.Fatal("browser maintained a separate SVG verdict")
	}
}

func TestSVGExternalAndIncompleteBadges(t *testing.T) {
	for _, scan := range []*SVGInspection{nil, {Complete: false}, {Complete: true}, {Complete: true, Active: true}} {
		var out strings.Builder
		item := ArtifactItem{ID: "svg_test", Path: "external.svg", Type: "image", Mime: "image/svg+xml", ExternalPath: "artifacts/external.svg", SVG: scan}
		writeArtifactCard(&out, item, false, false)
		page := out.String()
		if strings.Contains(page, "SVG Secure") {
			t.Fatal("unconditional safety claim")
		}
		if scan == nil || !scan.Complete {
			if !strings.Contains(page, "SVG inspection incomplete") {
				t.Fatal("missing incomplete badge")
			}
		}
		if scan != nil && scan.Active && !strings.Contains(page, "SVG Script Alert") {
			t.Fatal("external SVG lost active-content result")
		}
	}
}
