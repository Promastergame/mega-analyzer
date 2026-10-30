// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"path/filepath"
)

// validModes is the whitelist of modes the web UI can launch.
var validModes = map[string]bool{
	"minecraft": true,
	"full":      true, "decode": true, "build": true, "machine-code": true,
	"firmware": true, "version-diff": true, "js-deobf": true, "js-patch": true,
	"sandbox": true, "web-scan": true, "intercept": true,
}

// filelessModes do not take an uploaded file (they operate on a URL or a port).
var filelessModes = map[string]bool{"web-scan": true, "intercept": true}

// BuildModeArgs is the exported bridge for package main's CLI-parser tests:
// every flag the web UI hands to the spawned analyzer must exist there.
func BuildModeArgs(mode string, targets []string, outDir, url, port, upstream string, extra []string) []string {
	return buildModeArgs(mode, targets, outDir, url, port, upstream, extra)
}

// buildModeArgs constructs the analyzer argument list for a given mode. targets
// holds the saved upload path(s): one for most modes, two (old, new) for diff.
// url/port/upstream are used by the fileless modes (web-scan, intercept).
func buildModeArgs(mode string, targets []string, outDir, url, port, upstream string, extra []string) []string {
	base := []string{"-no-tui", "-no-color"}
	switch mode {
	case "minecraft":
		return append([]string{"-minecraft", "-t", targets[0], "-output", outDir}, base...)
	case "decode":
		a := append([]string{"-decode", "-t", targets[0], "-o", outDir}, base...)
		a = append(a, extra...)
		return append(a, "-standalone")
	case "build":
		a := append([]string{"-build", "-t", targets[0], "-o", filepath.Join(outDir, "app.apk")}, base...)
		a = append(a, extra...)
		return append(a, "-standalone", "-use-aapt2=false")
	case "machine-code":
		a := append([]string{"-scan-native", "-t", targets[0], "-output", outDir}, base...)
		return append(a, extra...)
	case "firmware":
		a := append([]string{"-firmware", "-t", targets[0], "-output", outDir}, base...)
		return append(a, extra...)
	case "js-deobf":
		return append([]string{"-js-deobf", "-t", targets[0], "-output", outDir, "-js-deobf-out", filepath.Join(outDir, "deobfuscated.js")}, base...)
	case "js-patch":
		return append([]string{"-js-patch", "-t", targets[0], "-output", outDir}, base...)
	case "version-diff":
		return append([]string{"-version-diff", "--diff-old", targets[0], "--diff-new", targets[1], "-output", outDir}, base...)
	case "sandbox":
		a := append([]string{"-sandbox", "-sandbox-stream", "-t", targets[0], "-output", outDir}, base...)
		return append(a, extra...)
	case "web-scan":
		a := []string{"-web-scan", "-web-scan-target", url, "-output", outDir}
		a = append(a, base...)
		return append(a, extra...)
	case "intercept":
		// Proxy LISTENS on -port and forwards to -upstream (the real server).
		// Capture is recorded to the output dir so the session is saved.
		a := []string{"-intercept", "-intercept-stop-on-eof"}
		if port != "" {
			a = append(a, "-port", port)
		}
		if upstream != "" {
			a = append(a, "-upstream", upstream)
		}
		a = append(a, "-record", filepath.Join(outDir, "capture.jsonl"))
		return append(a, "-no-color")
	default: // full
		a := append([]string{"-t", targets[0], "-output", outDir}, base...)
		return append(a, extra...)
	}
}
