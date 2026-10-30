package ensemble

import "strings"

// ═══════════════════════════════════════════════════════════════════════════════
// STRUCTURAL FEATURES
// ═══════════════════════════════════════════════════════════════════════════════

// cyclomatic computes McCabe-style cyclomatic complexity for a smali body.
//
// Each branch instruction (if-*, packed-switch, sparse-switch, throw, catch)
// contributes one edge; we start at 1.
//
// ifChecks is deliberately NOT added. It is derived from this same body by
// counting "if-" prefixed lines, which the loop below counts again — so every
// conditional was scored twice. The feature is then squashed through
// log1p(c)/log1p(50), so the doubling saturated it about twice as early and
// biased both the heuristic ensemble score and anything trained on it. The
// parameter is kept for call-site compatibility.
func cyclomatic(body []string, ifChecks int) float64 {
	_ = ifChecks
	c := 1
	for _, line := range body {
		l := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(l, "if-"):
			c++
		case strings.HasPrefix(l, "packed-switch"), strings.HasPrefix(l, "sparse-switch"):
			c += 2
		case strings.HasPrefix(l, "throw"):
			c++
		case strings.HasPrefix(l, ":catch"), strings.HasPrefix(l, ".catch"):
			c++
		}
	}
	if c < 1 {
		c = 1
	}
	return float64(c)
}

// nestingDepth approximates the maximum control-flow nesting depth in a smali
// body by tracking goto labels. It is a heuristic: smali doesn't have block
// braces, but consecutive labels typically signal nested branches.
func nestingDepth(body []string) float64 {
	depth, max := 0, 0
	for _, line := range body {
		l := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(l, ":try_start"):
			depth++
		case strings.HasPrefix(l, ":try_end"):
			depth--
		case strings.HasPrefix(l, "if-") && strings.Contains(l, ":"):
			depth++
		case strings.HasPrefix(l, ":cond_"), strings.HasPrefix(l, ":goto_"):
			if depth > 0 {
				depth--
			}
		}
		if depth > max {
			max = depth
		}
	}
	if max < 0 {
		max = 0
	}
	if max > 16 {
		max = 16
	}
	return float64(max)
}

// opcodeStats returns (uniqueOpcodes, branchCount, returnCount).
func opcodeStats(body []string, knownReturns int) (int, int, int) {
	seen := make(map[string]struct{}, 64)
	branches, returns := 0, knownReturns
	for _, line := range body {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ".") || strings.HasPrefix(l, ":") {
			continue
		}
		// Opcode is the first whitespace-separated token.
		opc := l
		if idx := strings.IndexByte(l, ' '); idx > 0 {
			opc = l[:idx]
		}
		seen[opc] = struct{}{}

		switch {
		case strings.HasPrefix(opc, "if-"),
			strings.HasPrefix(opc, "packed-switch"),
			strings.HasPrefix(opc, "sparse-switch"),
			strings.HasPrefix(opc, "goto"):
			branches++
		case strings.HasPrefix(opc, "return"):
			if knownReturns == 0 {
				returns++
			}
		}
	}
	return len(seen), branches, returns
}

// ═══════════════════════════════════════════════════════════════════════════════
// CALL RATIOS
// ═══════════════════════════════════════════════════════════════════════════════

// securityHints / netHints / cryptoHints / dynHints are case-insensitive
// substrings used to bucket invoke targets.
var (
	securityHints = []string{
		"trustmanager", "x509", "certificate", "signature", "checksignatures",
		"verifyinstaller", "iscertvalid", "rootbeer", "supersu", "frida",
		"safetynet", "playintegrity",
	}
	netHints = []string{
		"httpurlconnection", "okhttp", "retrofit", "/url;->", "/socket;->",
		"websocket", "/datagram",
	}
	cryptoHints = []string{
		"javax/crypto/", "ljavax/crypto/", "/cipher;->", "/messagedigest;->",
		"/mac;->", "/keygen", "spongycastle", "bouncycastle",
	}
	dynHints = []string{
		"dexclassloader", "pathclassloader", "inmemorydexclassloader",
		"reflect/method;->invoke", "reflect/constructor;->newinstance",
		"system;->loadlibrary", "runtime;->load",
	}
)

func callRatios(calls []string) (sec, net, cry, dyn float64) {
	if len(calls) == 0 {
		return
	}
	for _, c := range calls {
		lower := strings.ToLower(c)
		if anySubstring(lower, securityHints) {
			sec++
		}
		if anySubstring(lower, netHints) {
			net++
		}
		if anySubstring(lower, cryptoHints) {
			cry++
		}
		if anySubstring(lower, dynHints) {
			dyn++
		}
	}
	total := float64(len(calls))
	return sec / total, net / total, cry / total, dyn / total
}

func anySubstring(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}
