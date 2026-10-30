// Package arscsigs holds the data-driven fingerprint database for Android
// resource containers: resources.arsc (ResTable chunk tree), binary
// AndroidManifest.xml (AXML) and zip-level container artifacts. It is the
// resource-layer companion to pkg/internal/nativesigs (ELF / .so payloads):
// the resource layer says what the build claims to be, the native layer says
// what it actually loads, and contradictions between the two are the
// highest-value findings.
//
// The database follows the repo convention (sastrules, trackers, niap): a
// JSON blob next to a tiny embed.go, so rules stay reviewable in a diff and
// can be extended without touching Go code.
package arscsigs

import (
	_ "embed"
)

//go:embed android_resource_rules.json
var AndroidResourceRulesJSON []byte
