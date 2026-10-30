// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"strings"
)

// isSafeArg allows option flags like -callgraph, -report, full, -workers, 8, -1
func isSafeArg(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		// Allow '/' for IANA timezone values (e.g. Europe/Moscow). Args are passed
		// to exec.Command without a shell, so there is no injection risk.
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '/') {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	if s == "" || len(s) > 5 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isSafeHostPort allows host:port like 127.0.0.1:9339 (no shell metachars).
func isSafeHostPort(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == ':' || c == '-') {
			return false
		}
	}
	return true
}

// isSafeURL accepts an http(s) URL with no whitespace or control characters.
func isSafeURL(s string) bool {
	if len(s) < 8 || len(s) > 2048 {
		return false
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		return false
	}
	for _, c := range s {
		if c <= ' ' || c == 0x7f {
			return false
		}
	}
	return true
}

// isSafeOutputPath rejects empty paths, overlong paths, and control characters.
// Absolute paths are allowed: this is a local tool writing to the user's own
// machine (exec.Command is used without a shell, so there is no shell injection).
func isSafeOutputPath(s string) bool {
	if s == "" || len(s) > 4096 {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}
