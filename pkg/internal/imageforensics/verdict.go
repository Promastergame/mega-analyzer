package imageforensics

// ═══════════════════════════════════════════════════════════════════════════════
// VERDICT WHITELIST
//
// The forensic engine NEVER emits the word "virus" or anything that resembles
// a definitive malware verdict. Only the labels in the whitelist below are
// allowed. The choice is enforced through the constants exposed here and a
// property test that exercises every analyser path.
// ═══════════════════════════════════════════════════════════════════════════════

const (
	VerdictOK                = "ok"
	VerdictSuspicious        = "suspicious"
	VerdictPotentiallyUnsafe = "potentially unsafe"
	VerdictUnusualStructure  = "unusual structure"
	VerdictPossibleEmbedded  = "possible embedded payload"
)

// allowedVerdicts is the source of truth for valid verdict labels.
var allowedVerdicts = map[string]struct{}{
	VerdictOK:                {},
	VerdictSuspicious:        {},
	VerdictPotentiallyUnsafe: {},
	VerdictUnusualStructure:  {},
	VerdictPossibleEmbedded:  {},
}

// IsAllowedVerdict returns true if v is in the whitelist.
func IsAllowedVerdict(v string) bool {
	_, ok := allowedVerdicts[v]
	return ok
}

// SanitizeVerdict normalises any unexpected value to VerdictSuspicious,
// guaranteeing that callers never receive the word "virus" or similar.
func SanitizeVerdict(v string) string {
	if IsAllowedVerdict(v) {
		return v
	}
	return VerdictSuspicious
}

// AllowedVerdicts returns a copy of the whitelist for tests.
func AllowedVerdicts() []string {
	out := make([]string, 0, len(allowedVerdicts))
	for k := range allowedVerdicts {
		out = append(out, k)
	}
	return out
}
