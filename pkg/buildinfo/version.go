// Package buildinfo supplies the same build identity to every runtime surface.
package buildinfo

import (
	"runtime/debug"
	"strings"
)

var (
	Version    = "1.0.0-beta.2"
	BuildDate  = "dev"
	CommitHash = "dev"
)

// Configure accepts the legacy main.* linker flags and normalizes tag prefixes.
func Configure(version, date, commit string) {
	if version != "" {
		Version = strings.TrimPrefix(version, "v")
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				CommitHash = s.Value
			case "vcs.time":
				BuildDate = s.Value
			}
		}
	}
	if date != "" {
		BuildDate = date
	}
	if commit != "" {
		CommitHash = commit
	}
}
