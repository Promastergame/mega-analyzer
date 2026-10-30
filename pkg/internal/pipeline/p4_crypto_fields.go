// p4_crypto_fields.go — weak-crypto transformations declared as field
// initializers (Phase 4 / P18a, eval known_gap "weak-ecb-cipher").
//
// STATUS: reconstructed source. The verified build closed the corpus gap
// (Crypto.smali: .field ... MODE:Ljava/lang/String; = "AES/ECB/PKCS5Padding").
// Field accessor names on types.SmaliClass/SmaliField must be confirmed against
// the tree at compile time — adjust the loop below if they differ.
//
// Destination: pkg/internal/pipeline/p4_crypto_fields.go
//
// Why: detectCryptoFromAST (vuln_crypto_smali.go:61) only evaluates
// Cipher.getInstance / SecretKeySpec call sites inside method bodies. A
// transformation stored in a class field constant never appears as an operand
// there, so ECB/DES/RC4 declared at class level was invisible — a baseline
// false negative since corpus v1.

package pipeline

import (
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// weakTransformationReason returns a human-readable reason when the constant
// names a broken cipher configuration, or "" when it is acceptable.
func weakTransformationReason(value string) string {
	v := strings.ToUpper(strings.TrimSpace(value))
	if v == "" || !strings.Contains(v, "/") && !strings.Contains(v, "DES") && !strings.Contains(v, "RC") {
		return ""
	}
	switch {
	case strings.Contains(v, "/ECB"):
		return "ECB mode leaks plaintext structure (identical blocks encrypt identically)"
	case strings.HasPrefix(v, "DES/") || v == "DES":
		return "DES has a 56-bit effective key and is brute-forceable"
	case strings.HasPrefix(v, "DESEDE") :
		return "3DES is deprecated (64-bit block, Sweet32)"
	case strings.HasPrefix(v, "RC4") || strings.HasPrefix(v, "ARCFOUR"):
		return "RC4 keystream is biased and practically broken"
	case strings.HasPrefix(v, "RC2"):
		return "RC2 is obsolete"
	case strings.Contains(v, "AES") && strings.Contains(v, "NOPADDING") && strings.Contains(v, "/CBC"):
		return "CBC without padding oracle protection"
	}
	return ""
}

// detectWeakCryptoFieldInits scans class-level constants for cipher
// transformations the AST detector cannot see.
func detectWeakCryptoFieldInits(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx == nil || analysis == nil || ctx.Class == nil {
		return
	}
	for i := range ctx.Class.Fields {
		field := &ctx.Class.Fields[i]
		value := strings.Trim(field.Value, "\"")
		if value == "" {
			continue
		}
		reason := weakTransformationReason(value)
		if reason == "" {
			continue
		}
		m := newMatch(
			types.CategoryWeakCrypto,
			analysis.Path,
			field.Line,
			value,
			value,
			false,
		)
		m.EvidenceType = "smali_field_constant"
		m.ClassName = ctx.Class.Name
		m.IsCritical = false
		m.ReasonForSeverity = reason
		analysis.Matches = append(analysis.Matches, m)
	}
}
