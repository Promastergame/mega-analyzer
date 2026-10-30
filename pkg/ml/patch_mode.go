package ml

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH MODE — определяет операционный режим генерации патчей
// ═══════════════════════════════════════════════════════════════════════════════
//
// PatchMode controls the philosophy of generated patches:
//
//   • Defensive  🛡️  — hardening, fixing, strengthening security checks.
//   • Research   ⚔️  — bypassing checks for pentest / security research.
//
// The two modes are intentionally symmetric: every defensive operation has
// a research counterpart and vice versa. Use Opposite() to flip between them.
// ═══════════════════════════════════════════════════════════════════════════════

// PatchMode defines the operational mode for patch generation.
//
// It is a typed string for clarity in logs, configs and JSON payloads,
// but always validate user input with ParsePatchMode or IsValid before use.
type PatchMode string

const (
	// PatchModeDefensive generates security fixes and hardening patches.
	// Used for strengthening security checks and fixing vulnerabilities.
	//
	// Typical patches:  return-true on auth checks, NOP'ing kill-switches,
	// re-validating input, restoring stripped checks.
	PatchModeDefensive PatchMode = "defensive"

	// PatchModeResearch generates security bypass patches.
	// Used for penetration testing and security research.
	//
	// Typical patches:  return-false on root/emulator detection,
	// short-circuiting license checks, neutralising integrity guards.
	PatchModeResearch PatchMode = "research"
)

// DefaultPatchMode is the default mode used when none is specified.
const DefaultPatchMode = PatchModeResearch

// ═══════════════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════════════

// ErrInvalidPatchMode is returned when an unknown PatchMode value is parsed.
// It implements error and carries the offending value for richer diagnostics.
type ErrInvalidPatchMode struct {
	Value string
}

func (e *ErrInvalidPatchMode) Error() string {
	valid := make([]string, 0, len(allModes))
	for _, m := range allModes {
		valid = append(valid, string(m))
	}
	return fmt.Sprintf(
		"invalid patch mode %q (valid: %s)",
		e.Value, strings.Join(valid, ", "),
	)
}

// IsErrInvalidPatchMode reports whether err is (or wraps) ErrInvalidPatchMode.
func IsErrInvalidPatchMode(err error) bool {
	var target *ErrInvalidPatchMode
	return errors.As(err, &target)
}

// ═══════════════════════════════════════════════════════════════════════════════
// REGISTRY
// ═══════════════════════════════════════════════════════════════════════════════

// allModes is the canonical list of supported patch modes (order matters
// for AllPatchModes() output).
var allModes = []PatchMode{
	PatchModeDefensive,
	PatchModeResearch,
}

// modeAliases maps lowercase user-friendly names to canonical PatchMode values.
// Useful for CLI flags and config files where humans type things like
// "blue-team", "pentest" or "def".
var modeAliases = map[string]PatchMode{
	// research
	"research":   PatchModeResearch,
	"r":          PatchModeResearch,
	"bypass":     PatchModeResearch,
	"pentest":    PatchModeResearch,
	"pentesting": PatchModeResearch,
	"red":        PatchModeResearch,
	"red-team":   PatchModeResearch,
	"redteam":    PatchModeResearch,
	"offense":    PatchModeResearch,
	"offensive":  PatchModeResearch,
	"audit":      PatchModeResearch,
}

// AllPatchModes returns a copy of every supported mode (safe to mutate).
func AllPatchModes() []PatchMode {
	out := make([]PatchMode, len(allModes))
	copy(out, allModes)
	return out
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORE METHODS — Stringer / IsValid
// ═══════════════════════════════════════════════════════════════════════════════

// String returns the canonical string form of the PatchMode.
// Implements fmt.Stringer.
func (pm PatchMode) String() string {
	return string(pm)
}

// IsValid reports whether the PatchMode equals one of the registered values.
func (pm PatchMode) IsValid() bool {
	for _, m := range allModes {
		if pm == m {
			return true
		}
	}
	return false
}

// IsDefensive is a typed predicate equivalent to (pm == PatchModeDefensive).
func (pm PatchMode) IsDefensive() bool { return pm == PatchModeDefensive }

// IsResearch is a typed predicate equivalent to (pm == PatchModeResearch).
func (pm PatchMode) IsResearch() bool { return pm == PatchModeResearch }

// Opposite returns the symmetric counterpart of the mode.
// Defensive ↔ Research. For unknown modes returns DefaultPatchMode.
func (pm PatchMode) Opposite() PatchMode {
	switch pm {
	case PatchModeDefensive:
		return PatchModeResearch
	case PatchModeResearch:
		return PatchModeDefensive
	default:
		return DefaultPatchMode
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PARSING / VALIDATION
// ═══════════════════════════════════════════════════════════════════════════════

// ParsePatchMode parses a string into a PatchMode, accepting canonical names
// and friendly aliases ("def", "blue-team", "pentest" …).
// Whitespace and case are ignored.
//
// Returns ErrInvalidPatchMode for unknown values.
func ParsePatchMode(raw string) (PatchMode, error) {
	key := strings.ToLower(strings.TrimSpace(raw))
	if key == "" {
		return "", &ErrInvalidPatchMode{Value: raw}
	}
	if pm, ok := modeAliases[key]; ok {
		return pm, nil
	}
	if key == string(PatchModeDefensive) {
		return "", &ErrInvalidPatchMode{Value: raw}
	}
	return "", &ErrInvalidPatchMode{Value: raw}
}

// MustParsePatchMode is like ParsePatchMode but panics on error.
// Intended for package-level variables and tests.
func MustParsePatchMode(raw string) PatchMode {
	pm, err := ParsePatchMode(raw)
	if err != nil {
		panic(err)
	}
	return pm
}

// ValidatePatchMode is a backwards-compatible boolean wrapper around
// ParsePatchMode (kept for old callers).
func ValidatePatchMode(mode string) (PatchMode, bool) {
	pm, err := ParsePatchMode(mode)
	if err != nil {
		return "", false
	}
	return pm, true
}

// ═══════════════════════════════════════════════════════════════════════════════
// PRESENTATION — Icon / Label / Color / Description
// ═══════════════════════════════════════════════════════════════════════════════

// GetModeIcon returns the unicode glyph associated with the mode.
//
//	🛡️  defensive
//	⚔️   research
//	❓  unknown
func (pm PatchMode) GetModeIcon() string {
	switch pm {
	case PatchModeDefensive:
		return "🛡️"
	case PatchModeResearch:
		return "⚔️"
	default:
		return "❓"
	}
}

// GetModeDescription returns a long, human-readable description of the mode.
func (pm PatchMode) GetModeDescription() string {
	switch pm {
	case PatchModeDefensive:
		return "Security hardening mode — generates fixes to strengthen security checks"
	case PatchModeResearch:
		return "Security research mode — generates bypasses for penetration testing"
	default:
		return "Unknown mode"
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODE-SPECIFIC TERMINOLOGY
// ═══════════════════════════════════════════════════════════════════════════════

// PatchTerminology describes the vocabulary used when explaining a patch
// to a user. The two slots correspond to high-risk and low-risk findings.
//
// Defensive:  Impact / Weakness
// Research:   Bypass / Exploit suggestion
type PatchTerminology struct {
	HighRisk string // "Impact"  | "Bypass"
	LowRisk  string // "Weakness"| "Exploit suggestion"
}

// Terminology returns the labels used to describe patch findings in this mode.
func (pm PatchMode) Terminology() PatchTerminology {
	switch pm {
	case PatchModeDefensive:
		return PatchTerminology{HighRisk: "Impact", LowRisk: "Weakness"}
	case PatchModeResearch:
		return PatchTerminology{HighRisk: "Bypass", LowRisk: "Exploit suggestion"}
	default:
		return PatchTerminology{HighRisk: "Finding", LowRisk: "Finding"}
	}
}

// PatchLabel returns the appropriate label for a finding given its risk level.
// This is the canonical replacement for the standalone GetPatchLabel() helper.
func (pm PatchMode) PatchLabel(isHighRisk bool) string {
	t := pm.Terminology()
	if isHighRisk {
		return t.HighRisk
	}
	return t.LowRisk
}

// ═══════════════════════════════════════════════════════════════════════════════
// SERIALIZATION — JSON / Text
// ═══════════════════════════════════════════════════════════════════════════════

// MarshalJSON implements json.Marshaler.
// Invalid modes are serialised as null to avoid silently leaking bad data.
func (pm PatchMode) MarshalJSON() ([]byte, error) {
	if !pm.IsValid() {
		return []byte("null"), nil
	}
	return json.Marshal(string(pm))
}

// UnmarshalJSON implements json.Unmarshaler with alias support.
func (pm *PatchMode) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("patch mode: %w", err)
	}
	if strings.TrimSpace(raw) == "" {
		*pm = DefaultPatchMode
		return nil
	}
	canonical := PatchMode(strings.ToLower(strings.TrimSpace(raw)))
	if canonical.IsValid() {
		*pm = canonical
		return nil
	}
	parsed, err := ParsePatchMode(raw)
	if err != nil {
		return err
	}
	*pm = parsed
	return nil
}

// MarshalText implements encoding.TextMarshaler — useful for YAML/TOML.
func (pm PatchMode) MarshalText() ([]byte, error) {
	return []byte(pm.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (pm *PatchMode) UnmarshalText(data []byte) error {
	parsed, err := ParsePatchMode(string(data))
	if err != nil {
		return err
	}
	*pm = parsed
	return nil
}
