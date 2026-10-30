// Package appconfig resolves runtime configuration locations.
//
// Historically every config consumer built paths like
// "configs/dynamic_rules/rules.json" relative to the process working
// directory, so analysis behaved differently depending on where the binary
// was launched from and anyone who could write into the CWD could swap the
// rule set. This resolver pins the lookup to an explicit, operator-chosen
// root with a sane fallback chain.
package appconfig

import (
	"os"
	"path/filepath"
	"strings"
)

// EnvDir names the environment variable that overrides the configuration
// root. It must point at the directory that CONTAINS the "configs" tree.
const EnvDir = "MEGA_ANALYZER_CONFIG_DIR"

// BaseDir returns the deployment root holding the runtime "configs/" tree.
//
// Resolution order:
//  1. MEGA_ANALYZER_CONFIG_DIR, when set;
//  2. the directory of the running executable, when it ships a configs/
//     subtree (installed/portable deployments);
//  3. "." — the legacy CWD behavior, kept only as a last resort so source
//     layouts and tests keep working.
func BaseDir() string {
	if v := strings.TrimSpace(os.Getenv(EnvDir)); v != "" {
		return v
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		if _, statErr := os.Stat(filepath.Join(dir, "configs")); statErr == nil {
			return dir
		}
	}
	return "."
}

// Path resolves a slash-relative config path against BaseDir. Absolute
// inputs are returned unchanged.
func Path(rel string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	return filepath.Join(BaseDir(), filepath.FromSlash(rel))
}
