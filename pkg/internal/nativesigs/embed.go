// Package nativesigs holds the vendor-agnostic fingerprint database for
// native Android and Linux libraries (ELF shared objects): ecosystem
// signatures (engine, audio, crypto, crash SDK, packer, hooking framework)
// plus structural heuristics that work without any name allowlist. It is the
// native-layer companion to pkg/internal/arscsigs (resources.arsc / AXML /
// container artifacts): contradictions between what the build claims and what
// it loads are the highest-value findings.
//
// The database follows the repo convention (sastrules, trackers, niap): a
// JSON blob next to a tiny embed.go, so rules stay reviewable in a diff and
// can be extended without touching Go code.
package nativesigs

import (
	_ "embed"
)

//go:embed native_lib_signatures.json
var NativeLibSignaturesJSON []byte
