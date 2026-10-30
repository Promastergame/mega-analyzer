package report

import _ "embed"

// ═══════════════════════════════════════════════════════════════════════════════
// STATIC WEB ASSETS
//
// The HTML report front-end (SVG icon sprite, CSS themes and the interactive
// JavaScript) lives under web/ as regular standalone files and is embedded
// into the binary at compile time. Edit the files in web/ directly — no Go
// string constants to maintain.
//
// NOTE: web/report.js contains the __ENABLE_FILTERS__ / __ENABLE_HIGHLIGHT__
// tokens which buildJS() substitutes with per-report configuration.
// ═══════════════════════════════════════════════════════════════════════════════

//go:embed web/icons.svg
var iconSprite string

//go:embed web/styles.css
var htmlStyles string

//go:embed web/report.js
var htmlJS string

//go:embed web/artifacts.css
var artifactsCSS string

//go:embed web/artifacts/00_init.js
var artifactsJSInit string

//go:embed web/artifacts/01_tabs_search.js
var artifactsJSTabsSearch string

//go:embed web/artifacts/02_easter_egg.js
var artifactsJSEasterEgg string

//go:embed web/artifacts/03_dialog.js
var artifactsJSDialog string

//go:embed web/artifacts/04_viewer_registry.js
var artifactsJSViewerRegistry string

//go:embed web/artifacts/05_shell.js
var artifactsJSShell string

//go:embed web/artifacts/06_image_viewer.js
var artifactsJSImageViewer string

//go:embed web/artifacts/07_media_player.js
var artifactsJSMediaPlayer string

//go:embed web/artifacts/08_code_viewer.js
var artifactsJSCodeViewer string

//go:embed web/artifacts/09_font_viewer.js
var artifactsJSFontViewer string

//go:embed web/artifacts/10_export_modal.js
var artifactsJSExportModal string

//go:embed web/artifacts/11_helpers.js
var artifactsJSHelpers string

// artifactsJS is assembled from the ordered per-section files in
// web/artifacts/. The sections share one closure scope, so the IIFE
// wrapper is added here and every part must stay in load order.
var artifactsJS = "\n(function(){\n" +
	artifactsJSInit +
	artifactsJSTabsSearch +
	artifactsJSEasterEgg +
	artifactsJSDialog +
	artifactsJSViewerRegistry +
	artifactsJSShell +
	artifactsJSImageViewer +
	artifactsJSMediaPlayer +
	artifactsJSCodeViewer +
	artifactsJSFontViewer +
	artifactsJSExportModal +
	artifactsJSHelpers +
	"})();\n"
