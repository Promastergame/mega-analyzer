package apkloader

import (
	"os"
	"strings"
	"sync/atomic"
)

// StandaloneMode forces the pipeline to use only embedded Go
// implementations: no Java, aapt2, apksigner or zipalign
// processes are discovered, unpacked or executed in any stage.
//
// It is enabled by --standalone (CLI), MEGA_STANDALONE=1, or
// SetStandalone(true) for in-process callers. External backends remain
// available as explicit compatibility options when the mode is off.
var standaloneFlag atomic.Bool

// SetStandalone enables or disables standalone policy for this process.
func SetStandalone(on bool) { standaloneFlag.Store(on) }

// Standalone reports whether external-tool execution is forbidden.
func Standalone() bool {
	if standaloneFlag.Load() {
		return true
	}
	v := strings.TrimSpace(os.Getenv("MEGA_STANDALONE"))
	if v == "" {
		return false
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// StandaloneReason is a short human-readable policy explanation for errors
// returned when an external tool would otherwise be launched.
func StandaloneReason(tool string) string {
	return "standalone mode: external tool " + tool + " is disabled (use native output or rerun without --standalone for compatibility backends)"
}
