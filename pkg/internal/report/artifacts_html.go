package report

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ARTIFACTS HTML RENDERER
//
// Plan В§1: section sits between Recommendations and footer. Sub-tabs for
// All / Images / 3D / Native / Other. Cards link to a vanilla-JS lightbox
// for image viewing; native cards expand into a deep-view block.
// ═══════════════════════════════════════════════════════════════════════════════

func (r *HTMLReporter) buildArtifactsSection(sb htmlWriter) {
	if r.artifacts == nil || r.artifacts.Summary.Total == 0 {
		return
	}
	view := r.artifacts

	sb.WriteString(`<section class="section artifacts" id="artifacts" data-allow-export="`)
	if view.AllowExport {
		sb.WriteString("1")
	} else {
		sb.WriteString("0")
	}
	sb.WriteString(`" data-no-image-blur="`)
	if view.NoImageBlur {
		sb.WriteString("1")
	} else {
		sb.WriteString("0")
	}
	sb.WriteString(`">`)

	// Header
	sb.WriteString(`<header class="section-header">`)
	sb.WriteString(fmt.Sprintf(`<span class="section-icon">%s</span>`, icon("package")))
	sb.WriteString(`<h2>Artifacts</h2>`)
	sb.WriteString(fmt.Sprintf(`<span class="section-meta">%d items, %d flagged</span>`, view.Summary.Total, view.Summary.Flagged))
	sb.WriteString(`</header>`)

	// Hero banner — emphasises that this panel surfaces every non-Smali / non-XML
	// payload extracted from the target (images, 3D models, native libraries,
	// audio, video, fonts, archives). v11.1.1 introduced the explicit ARTIFACTS
	// action button in the TUI; the banner gives the same visual cue here.
	sb.WriteString(`<div class="artifacts-banner" role="note" aria-label="Artifacts overview">`)
	sb.WriteString(fmt.Sprintf(`<div class="artifacts-banner-icon">%s</div>`, icon("package")))
	sb.WriteString(`<div class="artifacts-banner-text">`)
	sb.WriteString(`<strong>Artifacts panel armed.</strong> `)
	sb.WriteString(`Everything that is <em>not</em> Smali and <em>not</em> XML is collected here — `)
	sb.WriteString(`images, 3D models, native libraries, audio, video, fonts and archives. `)
	sb.WriteString(`Use the type tabs below to filter, click a card to open the in-browser viewer.`)
	sb.WriteString(`</div></div>`)

	// Summary bar
	sb.WriteString(`<div class="artifacts-summary">`)
	for _, t := range []string{"image", "model3d", "native", "code", "audio", "video", "font", "archive", "other"} {
		count := view.Summary.ByType[t]
		if count == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf(`<span class="art-stat" data-type="%s"><strong>%d</strong> %s</span>`,
			html.EscapeString(t), count, html.EscapeString(artifactTypeLabel(t))))
	}
	sb.WriteString(`</div>`)

	// Sub-tabs
	sb.WriteString(`<div class="artifacts-tabs" role="tablist">`)
	tabs := []struct{ key, label string }{
		{"all", "All"},
		{"image", "Images"},
		{"model3d", "3D"},
		{"native", "Native"},
		{"code", "Code"},
		{"audio", "Audio"},
		{"video", "Video"},
		{"font", "Fonts"},
		{"archive", "Archives"},
		{"other", "Other"},
	}
	for i, t := range tabs {
		active := ""
		if i == 0 {
			active = " is-active"
		}
		// Hide tabs with zero entries to avoid clutter.
		count := view.Summary.ByType[t.key]
		if t.key != "all" && count == 0 {
			continue
		}
		badge := ""
		if t.key != "all" && count > 0 {
			badge = fmt.Sprintf(`<span class="art-tab-badge">%d</span>`, count)
		} else if t.key == "all" {
			badge = fmt.Sprintf(`<span class="art-tab-badge">%d</span>`, view.Summary.Total)
		}
		sb.WriteString(fmt.Sprintf(
			`<button type="button" class="art-tab%s" data-art-tab="%s" role="tab" aria-label="Filter: %s">%s%s</button>`,
			active, html.EscapeString(t.key), html.EscapeString(t.label),
			html.EscapeString(t.label), badge))
	}
	sb.WriteString(`</div>`)

	// Search + tools bar — live filter across name/type/path/mime/findings,
	// plus an "Easter-egg scan" that sweeps every embedded payload for hidden
	// strings (URLs, emails, flags, base64 blobs, credits, debug toggles).
	sb.WriteString(`<div class="artifacts-toolbar">`)
	sb.WriteString(`<div class="art-search">`)
	sb.WriteString(fmt.Sprintf(`<span class="art-search-icon">%s</span>`, icon("search")))
	sb.WriteString(`<input type="search" id="art-search-input" placeholder="Filter artifacts — name, type, path, mime, finding…" aria-label="Filter artifacts" autocomplete="off">`)
	sb.WriteString(`<button type="button" class="art-search-clear" id="art-search-clear" aria-label="Clear filter" hidden>&times;</button>`)
	sb.WriteString(`</div>`)
	sb.WriteString(`<button type="button" class="art-egg-btn" id="art-egg-btn" title="Sweep every embedded artifact for hidden strings, URLs, flags and base64 blobs">`)
	sb.WriteString(fmt.Sprintf(`<span class="art-egg-emoji">%s</span> Easter-egg scan`, icon("egg")))
	sb.WriteString(`</button>`)
	sb.WriteString(`<span class="art-search-count" id="art-search-count"></span>`)
	sb.WriteString(`</div>`)

	// Easter-egg results panel (filled on demand by JS).
	sb.WriteString(`<div class="art-egg-results" id="art-egg-results" hidden></div>`)

	// Card grid
	sb.WriteString(`<div class="artifacts-grid" id="artifacts-grid">`)
	for _, item := range view.Items {
		writeArtifactCard(sb, item, view.AllowExport, view.NoImageBlur)
	}
	sb.WriteString(`</div>`)

	// Empty-state for when a filter matches nothing.
	sb.WriteString(`<div class="art-noresults" id="art-noresults" hidden>No artifacts match your filter.</div>`)

	// Embedded JSON for the viewer JS
	sb.WriteString(`<script type="application/json" id="artifacts-data">`)
	if data, err := json.Marshal(view); err == nil {
		// json escaping for </script>
		sb.WriteString(strings.ReplaceAll(string(data), "</", "<\\/"))
	} else {
		sb.WriteString(`{"items":[]}`)
	}
	sb.WriteString(`</script>`)

	sb.WriteString(`<dialog id="artifact-viewer" class="art-dialog" aria-label="Artifact viewer"></dialog>`)
	sb.WriteString(`<div id="art-warning-modal" class="art-warning-modal" hidden></div>`)

	// Embedded CSS + JS
	sb.WriteString(`<style>`)
	sb.WriteString(artifactsCSS)
	sb.WriteString(`</style>`)
	sb.WriteString(`<script>`)
	sb.WriteString(artifactsJS)
	sb.WriteString(`</script>`)

	sb.WriteString(`</section>`)
}

func artifactTypeLabel(t string) string {
	switch t {
	case "image":
		return "images"
	case "model3d":
		return "3D"
	case "native":
		return "native"
	case "font":
		return "fonts"
	case "audio":
		return "audio"
	case "video":
		return "video"
	case "archive":
		return "archives"
	case "code":
		return "code"
	}
	return "other"
}

func writeArtifactCard(sb htmlWriter, item ArtifactItem, allowExport, noBlur bool) {
	sb.WriteString(fmt.Sprintf(`<article class="art-card" data-id="%s" data-type="%s">`,
		html.EscapeString(item.ID), html.EscapeString(item.Type)))

	// Thumbnail
	sb.WriteString(`<div class="art-thumb">`)
	if item.Type == "image" && (item.EmbeddedDataURI != "" || item.ExternalPath != "") {
		imgSrc := item.EmbeddedDataURI
		if imgSrc == "" {
			imgSrc = item.ExternalPath
		}
		sensitive := item.Image != nil && item.Image.SensitiveLabel != ""
		blur := sensitive && !noBlur
		class := "art-img"
		if blur {
			class += " is-blurred"
		}
		sb.WriteString(fmt.Sprintf(`<img loading="lazy" decoding="async" class="%s" src="%s" alt="%s">`,
			class, html.EscapeString(imgSrc), html.EscapeString(item.Path)))
		if blur {
			sb.WriteString(`<button type="button" class="art-reveal">Reveal</button>`)
		}
	} else if item.Type == "audio" {
		sb.WriteString(fmt.Sprintf(`<span class="art-icon art-icon-audio">%s</span>`, icon("audio")))
	} else if item.Type == "video" {
		sb.WriteString(fmt.Sprintf(`<span class="art-icon art-icon-video">%s</span>`, icon("video")))
	} else if item.Type == "font" {
		sb.WriteString(`<div class="art-font-thumb">`)
		sb.WriteString(fmt.Sprintf(`<span class="art-font-label">%s</span>`, html.EscapeString(strings.ToUpper(fontExt(item.Path)))))
		sb.WriteString(`<span class="art-font-sample">Aa</span>`)
		sb.WriteString(`</div>`)
	} else if item.Type == "code" && item.Code != nil {
		// Code thumbnail = language badge + first findings.
		lang := item.Code.Language
		if lang == "" {
			lang = "text"
		}
		sb.WriteString(`<div class="art-code-thumb">`)
		sb.WriteString(fmt.Sprintf(`<span class="art-code-lang">%s</span>`, html.EscapeString(strings.ToUpper(lang))))
		if len(item.Code.Findings) > 0 {
			sb.WriteString(fmt.Sprintf(`<span class="art-code-flag">%s %d</span>`, icon("alert-triangle"), len(item.Code.Findings)))
		}
		sb.WriteString(`</div>`)
	} else {
		sb.WriteString(fmt.Sprintf(`<span class="art-icon">%s</span>`, icon(artifactTypeIcon(item.Type))))
	}
	sb.WriteString(`</div>`)

	// Body
	sb.WriteString(`<div class="art-body">`)
	sb.WriteString(fmt.Sprintf(`<h3 class="art-name" title="%s">%s</h3>`,
		html.EscapeString(item.Path), html.EscapeString(shortBaseName(item.Path))))
	sb.WriteString(`<div class="art-pills">`)
	sb.WriteString(fmt.Sprintf(`<span class="art-pill">%s</span>`, html.EscapeString(item.Type)))

	// Sniff precise asset extension formats
	ext := ""
	if idx := strings.LastIndex(item.Path, "."); idx >= 0 {
		ext = strings.ToLower(item.Path[idx+1:])
	}
	if ext != "" {
		sb.WriteString(fmt.Sprintf(`<span class="art-pill" style="color:#7eb6ff; border-color:rgba(126,182,255,0.25); font-weight:600;">%s</span>`, html.EscapeString(strings.ToUpper(ext))))
	}

	sb.WriteString(fmt.Sprintf(`<span class="art-pill">%s</span>`, html.EscapeString(humanSize(item.Size))))
	if item.Entropy > 0 {
		sb.WriteString(fmt.Sprintf(`<span class="art-pill">H=%.2f</span>`, item.Entropy))
	}
	if item.Code != nil && item.Code.Language != "" {
		sb.WriteString(fmt.Sprintf(`<span class="art-pill">%s</span>`, html.EscapeString(item.Code.Language)))
		if len(item.Code.Findings) > 0 {
			sb.WriteString(fmt.Sprintf(`<span class="art-pill art-pill-warn" title="static-analysis findings">%s %d</span>`, icon("alert-triangle"), len(item.Code.Findings)))
		}
		if item.Code.IsMinified {
			sb.WriteString(`<span class="art-pill" title="single huge line / no whitespace">min</span>`)
		}
		if item.Code.IsObfuscated {
			sb.WriteString(`<span class="art-pill art-pill-warn" title="hex/unicode literal soup">obf</span>`)
		}
	}
	sb.WriteString(fmt.Sprintf(`<span class="art-pill art-verdict art-verdict-%s">%s</span>`,
		verdictKey(item.Forensic.Verdict), html.EscapeString(item.Forensic.Verdict)))
	sb.WriteString(`</div>`)

	// SVG security badge notice
	if ext == "svg" || item.Mime == "image/svg+xml" {
		hasScript := false
		if item.EmbeddedDataURI != "" {
			if commaIdx := strings.Index(item.EmbeddedDataURI, ","); commaIdx >= 0 {
				if decoded, err := base64.StdEncoding.DecodeString(item.EmbeddedDataURI[commaIdx+1:]); err == nil {
					// D1: единый канонический список паттернов; см. SVGActivePatterns.
					hasScript = SVGHasActiveContent(decoded)
				}
			}
		}
		if hasScript {
			sb.WriteString(`<div class="art-svg-badge svg-badge-danger" title="Active scripting elements detected! Potential XSS Vector.">`)
			sb.WriteString(`<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline-block; vertical-align:middle; margin-right:4px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`)
			sb.WriteString(`<span>SVG Script Alert</span>`)
			sb.WriteString(`</div>`)
		} else {
			sb.WriteString(`<div class="art-svg-badge svg-badge-secure" title="SVG analyzed. No active scripting elements.">`)
			sb.WriteString(`<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline-block; vertical-align:middle; margin-right:4px;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`)
			sb.WriteString(`<span>SVG Secure</span>`)
			sb.WriteString(`</div>`)
		}
	}
	if len(item.Forensic.Reasons) > 0 {
		sb.WriteString(`<ul class="art-reasons">`)
		for _, r := range item.Forensic.Reasons {
			sb.WriteString(fmt.Sprintf(`<li>%s</li>`, html.EscapeString(r)))
		}
		sb.WriteString(`</ul>`)
	}
	if item.Image != nil && item.Image.SensitiveLabel != "" {
		sb.WriteString(fmt.Sprintf(`<p class="art-warn">%s</p>`, html.EscapeString(item.Image.SensitiveLabel)))
	}
	sb.WriteString(`<div class="art-actions">`)
	sb.WriteString(fmt.Sprintf(`<button type="button" class="btn btn-sm" data-art-open="%s">Open</button>`, html.EscapeString(item.ID)))
	sb.WriteString(fmt.Sprintf(`<button type="button" class="btn btn-sm" data-art-details="%s">Details</button>`, html.EscapeString(item.ID)))
	if allowExport {
		sb.WriteString(fmt.Sprintf(`<button type="button" class="btn btn-sm" data-art-export="%s">Export</button>`, html.EscapeString(item.ID)))
	}
	sb.WriteString(`</div>`)
	sb.WriteString(`</div>`)

	// Native deep-view (collapsed by default)
	if item.Native != nil {
		writeNativeDeepView(sb, item)
	}

	sb.WriteString(`</article>`)
}

func writeNativeDeepView(sb htmlWriter, item ArtifactItem) {
	n := item.Native
	if n == nil || (n.Arch == "" && n.Verdict == "" && len(n.JNIBindings) == 0 && len(n.CrackPoints) == 0 && len(n.SuspiciousStrings) == 0 && len(n.AntiSignals) == 0) {
		return
	}
	sb.WriteString(`<details class="art-native">`)
	sb.WriteString(`<summary>Native analysis</summary>`)
	sb.WriteString(`<div class="art-native-body">`)
	if n.Arch != "" {
		sb.WriteString(fmt.Sprintf(`<p><strong>Arch:</strong> %s</p>`, html.EscapeString(n.Arch)))
	}
	if n.Verdict != "" {
		sb.WriteString(fmt.Sprintf(`<p><strong>Verdict:</strong> %s (score %d)</p>`, html.EscapeString(n.Verdict), n.Score))
	}
	if len(n.JNIBindings) > 0 {
		sb.WriteString(`<h4>JNI bindings</h4><ul class="art-jni">`)
		for _, b := range n.JNIBindings {
			if b.SmaliTarget != "" {
				sb.WriteString(fmt.Sprintf(
					`<li><a href="?focus=%s">%s</a> → %s</li>`,
					html.EscapeString(b.SmaliTarget),
					html.EscapeString(b.Symbol),
					html.EscapeString(b.SmaliTarget)))
			} else {
				sb.WriteString(fmt.Sprintf(`<li>%s</li>`, html.EscapeString(b.Symbol)))
			}
		}
		sb.WriteString(`</ul>`)
	}
	if len(n.CrackPoints) > 0 {
		sb.WriteString(`<h4>Crack points</h4><ul>`)
		for _, cp := range n.CrackPoints {
			sb.WriteString(fmt.Sprintf(`<li>%s</li>`, html.EscapeString(cp)))
		}
		sb.WriteString(`</ul>`)
	}
	if len(n.SuspiciousStrings) > 0 {
		sb.WriteString(`<h4>Suspicious strings</h4><pre>`)
		sb.WriteString(html.EscapeString(strings.Join(n.SuspiciousStrings, "\n")))
		sb.WriteString(`</pre>`)
	}
	if len(n.AntiSignals) > 0 {
		sb.WriteString(fmt.Sprintf(`<p><strong>Anti-* signals:</strong> %s</p>`,
			html.EscapeString(strings.Join(n.AntiSignals, ", "))))
	}
	sb.WriteString(`</div>`)
	sb.WriteString(`</details>`)
}

func artifactTypeIcon(t string) string {
	switch t {
	case "image":
		return "image"
	case "model3d":
		return "cube"
	case "native":
		return "puzzle"
	case "font":
		return "type"
	case "audio":
		return "audio"
	case "video":
		return "video"
	case "archive":
		return "package"
	case "code":
		return "file-code"
	}
	return "file"
}

func verdictKey(v string) string {
	v = strings.ReplaceAll(v, " ", "-")
	if v == "" {
		return "ok"
	}
	return strings.ToLower(v)
}

func shortBaseName(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

func fontExt(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return "font"
}

func humanSize(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%dB", n)
	}
	if n < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(n)/1024)
	}
	if n < 1024*1024*1024 {
		return fmt.Sprintf("%.1fMB", float64(n)/(1024*1024))
	}
	return fmt.Sprintf("%.2fGB", float64(n)/(1024*1024*1024))
}
