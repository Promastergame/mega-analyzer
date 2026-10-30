// pkg/internal/pipeline/vuln_crypto_smali.go
//
// AST-based weak-crypto detection (audit item P0-2 / B5).
//
// The original byte-pattern detector matched decompiled-Java syntax such as
// `cipher.getinstance("aes")`, which never occurs in smali: the algorithm
// string lives in a `const-string` instruction and the API call is a separate
// `invoke-static {...}, Ljavax/crypto/Cipher;->getInstance(...)`. Those
// patterns could therefore never fire on the primary input format.
//
// This detector walks each method body with a lightweight register tracker
// (const-string / new-array / fill-array-data / String.getBytes provenance)
// and evaluates the actual crypto API call sites:
//
//   - Cipher.getInstance transformations: ECB (incl. default "AES"/"DES"),
//     DES/3DES, RC2/RC4/Blowfish, textbook RSA (NoPadding)
//   - MessageDigest.getInstance: MD5 / SHA-1 (escalated in password context)
//   - SecretKeyFactory.getInstance: DES / DESede key factories
//   - SecretKeySpec / DESKeySpec / IvParameterSpec constructed from literal
//     byte-array payloads or const-string bytes → hardcoded key / static IV
//   - SecureRandom.setSeed → deterministic RNG

package pipeline

import (
	"strconv"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// ── register provenance tracking ────────────────────────────────────────────

type cryptoRegKind uint8

const (
	cryptoRegNone cryptoRegKind = iota
	cryptoRegString
	cryptoRegBytesFromString // String.getBytes() result
	cryptoRegNewArray        // new-array, contents unknown
	cryptoRegLiteralArray    // fill-array-data literal payload
)

type cryptoRegValue struct {
	kind  cryptoRegKind
	str   string // cryptoRegString: literal value
	label string // cryptoRegLiteralArray: payload label (without ':')
}

type cryptoInvoke struct {
	opcode    string
	registers []string
	classDesc string // e.g. "Ljavax/crypto/Cipher;"
	method    string // e.g. "getInstance"
	raw       string // full method reference, e.g. "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;"
	line      int    // smali source line (filled by caller)
}

// detectCryptoFromAST runs structured weak-crypto detection over every method
// of the parsed class. Findings are deduplicated per (kind, line).
func detectCryptoFromAST(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	class := ctx.Class
	if class == nil {
		return
	}
	seen := make(map[string]bool, 8)
	for i := range class.Methods {
		detectCryptoInMethod(&class.Methods[i], class, analysis, ctx, seen)
	}
}

func detectCryptoInMethod(m *types.SmaliMethod, class *types.SmaliClass, analysis *types.FileAnalysis, ctx *FileDetectContext, seen map[string]bool) {
	if len(m.Body) == 0 {
		return
	}

	regs := make(map[string]cryptoRegValue, 16)
	var pending cryptoRegValue
	hasPending := false
	hasPasswordCtx := false

	emit := func(kind string, line int, desc, evidence string, critical bool) {
		key := kind + "\x00" + strconv.Itoa(line)
		if seen[key] {
			return
		}
		seen[key] = true
		match := newMatch(
			types.CategoryWeakCrypto, analysis.Path, line,
			desc, evidence, critical,
		)
		match.MethodName = m.Name
		match.ClassName = class.Name
		match.Confidence = "high"
		match.EvidenceType = "smali_ast_dataflow"
		if !critical {
			match.Severity = types.SeverityMedium
		}
		analysis.Matches = append(analysis.Matches, match)
	}

	for bodyIdx, raw := range m.Body {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" || strings.HasPrefix(line, ".") || strings.HasPrefix(line, ":") {
			continue
		}
		lineNumber := m.LineStart + bodyIdx

		switch {
		case strings.HasPrefix(line, "const-string"):
			if reg, val, ok := parseConstStringLine(line); ok {
				regs[reg] = cryptoRegValue{kind: cryptoRegString, str: val}
				if !hasPasswordCtx && looksLikePasswordContext(val) {
					hasPasswordCtx = true
				}
			}
			hasPending = false

		case strings.HasPrefix(line, "new-array"):
			if reg := parseDestRegister(line); reg != "" {
				regs[reg] = cryptoRegValue{kind: cryptoRegNewArray}
			}
			hasPending = false

		case strings.HasPrefix(line, "fill-array-data"):
			if reg, label := parseFillArrayData(line); reg != "" {
				regs[reg] = cryptoRegValue{kind: cryptoRegLiteralArray, label: label}
			}
			hasPending = false

		case strings.HasPrefix(line, "move-result"):
			if reg := parseDestRegister(line); reg != "" {
				if hasPending {
					regs[reg] = pending
				} else {
					delete(regs, reg)
				}
			}
			hasPending = false

		case strings.HasPrefix(line, "invoke-"):
			call, ok := parseCryptoInvoke(line)
			if !ok {
				hasPending = false
				continue
			}
			call.line = lineNumber
			hasPending = false
			pending = cryptoRegValue{}

			// String.getBytes() turns a literal string into key/IV bytes.
			if call.classDesc == "Ljava/lang/String;" && call.method == "getBytes" {
				if len(call.registers) > 0 {
					if src, ok := regs[call.registers[len(call.registers)-1]]; ok && src.kind == cryptoRegString {
						pending = cryptoRegValue{kind: cryptoRegBytesFromString, str: src.str}
						hasPending = true
					}
				}
				continue
			}

			analyzeCryptoCall(call, regs, m, analysis, ctx, emit, &hasPasswordCtx)
		}
	}
}

// analyzeCryptoCall evaluates one invoke against the crypto weakness catalog.
func analyzeCryptoCall(
	call cryptoInvoke,
	regs map[string]cryptoRegValue,
	m *types.SmaliMethod,
	analysis *types.FileAnalysis,
	ctx *FileDetectContext,
	emit func(kind string, line int, desc, evidence string, critical bool),
	hasPasswordCtx *bool,
) {
	args := call.registers
	if !strings.HasPrefix(call.opcode, "invoke-static") && len(args) > 0 {
		args = args[1:] // drop the receiver for instance calls
	}
	strArg := func(idx int) (string, bool) {
		if idx >= len(args) {
			return "", false
		}
		if v, ok := regs[args[idx]]; ok && v.kind == cryptoRegString {
			return v.str, true
		}
		return "", false
	}
	line := call.line

	switch {
	// ── Cipher.getInstance(transformation) ──
	case call.classDesc == "Ljavax/crypto/Cipher;" && call.method == "getInstance":
		transformation, ok := strArg(0)
		if !ok {
			return
		}
		t := strings.ToLower(transformation)
		switch {
		case t == "aes" || t == "des":
			emit("ecb_default", line,
				`Cipher.getInstance("`+transformation+`") without mode/padding — Android's default provider resolves this to ECB, which leaks plaintext structure (CWE-327)`,
				"Cipher.getInstance default ECB", true)
		case strings.Contains(t, "/ecb/"):
			emit("ecb", line,
				`Cipher transformation "`+transformation+`" uses ECB mode — identical plaintext blocks produce identical ciphertext (CWE-327)`,
				"Cipher ECB mode", true)
		case strings.HasPrefix(t, "desede"):
			emit("3des", line,
				`Cipher transformation "`+transformation+`" — Triple-DES is deprecated (sweet32, 64-bit block); prefer AES-GCM (CWE-327)`,
				"Cipher 3DES", false)
		case strings.HasPrefix(t, "des/"), strings.HasPrefix(t, "des "):
			emit("des", line,
				`Cipher transformation "`+transformation+`" — DES has a 56-bit key and is brute-forceable (CWE-327)`,
				"Cipher DES", true)
		case strings.HasPrefix(t, "rc4"), strings.HasPrefix(t, "rc2"), strings.HasPrefix(t, "blowfish"):
			emit("weak_stream", line,
				`Cipher transformation "`+transformation+`" — broken/legacy cipher (CWE-327)`,
				"Cipher weak algorithm", true)
		case strings.HasPrefix(t, "rsa") && strings.Contains(t, "nopadding"):
			emit("rsa_nopad", line,
				`Cipher transformation "`+transformation+`" — textbook RSA without padding is malleable and vulnerable to chosen-ciphertext attacks (CWE-327)`,
				"RSA NoPadding", true)
		}

	// ── MessageDigest.getInstance(algorithm) ──
	case call.classDesc == "Ljava/security/MessageDigest;" && call.method == "getInstance":
		alg, ok := strArg(0)
		if !ok {
			return
		}
		a := strings.ToLower(alg)
		switch {
		case a == "md5" || a == "md4":
			desc := `MessageDigest.getInstance("` + alg + `") — MD5 is collision-broken and must not be used for security purposes (CWE-328)`
			critical := false
			if *hasPasswordCtx || looksLikePasswordContext(strings.ToLower(m.Name)) {
				desc = `MessageDigest.getInstance("` + alg + `") in a password/credential context — password hashing with MD5 is trivially crackable; use bcrypt/PBKDF2/Argon2 (CWE-328/916)`
				critical = true
			}
			emit("md5", line, desc, "MessageDigest MD5", critical)
		case a == "sha-1" || a == "sha1":
			emit("sha1", line,
				`MessageDigest.getInstance("`+alg+`") — SHA-1 is deprecated for security use (collision attacks, CWE-328)`,
				"MessageDigest SHA-1", false)
		}

	// ── SecretKeyFactory.getInstance(algorithm) ──
	case call.classDesc == "Ljavax/crypto/SecretKeyFactory;" && call.method == "getInstance":
		alg, ok := strArg(0)
		if !ok {
			return
		}
		a := strings.ToLower(alg)
		if a == "des" || a == "desede" || strings.HasPrefix(a, "pbe withmd5") {
			emit("weak_keyfactory", line,
				`SecretKeyFactory.getInstance("`+alg+`") — weak key derivation algorithm (CWE-327)`,
				"SecretKeyFactory weak algorithm", a == "des")
		}

	// ── SecretKeySpec / DESKeySpec: weak algorithm + hardcoded key material ──
	case call.classDesc == "Ljavax/crypto/spec/SecretKeySpec;" && call.method == "<init>":
		if alg, ok := strArg(len(args) - 1); ok {
			a := strings.ToLower(alg)
			if a == "des" || a == "desede" || a == "rc4" || a == "rc2" || a == "blowfish" {
				emit("weak_keyspec", line,
					`SecretKeySpec for weak algorithm "`+alg+`" (CWE-327)`,
					"SecretKeySpec weak algorithm", a == "des" || a == "rc4")
			}
		}
		if len(args) > 0 {
			if v, ok := regs[args[0]]; ok && (v.kind == cryptoRegLiteralArray || v.kind == cryptoRegBytesFromString) {
				emit("hardcoded_key", line,
					"SecretKeySpec constructed from hardcoded key material embedded in the APK — extractable by any attacker with the package (CWE-321)",
					"SecretKeySpec hardcoded key bytes", true)
			}
		}

	case call.classDesc == "Ljavax/crypto/spec/DESKeySpec;" && call.method == "<init>":
		emit("des_keyspec", line,
			"DESKeySpec — DES key material (56-bit, brute-forceable, CWE-327)",
			"DESKeySpec", true)
		if len(args) > 0 {
			if v, ok := regs[args[0]]; ok && (v.kind == cryptoRegLiteralArray || v.kind == cryptoRegBytesFromString) {
				emit("des_hardcoded_key", line,
					"DESKeySpec constructed from hardcoded key material embedded in the APK (CWE-321)",
					"DESKeySpec hardcoded key bytes", true)
			}
		}

	// ── IvParameterSpec: static/hardcoded IV ──
	case call.classDesc == "Ljavax/crypto/spec/IvParameterSpec;" && call.method == "<init>":
		if len(args) == 0 {
			return
		}
		v, ok := regs[args[0]]
		if !ok {
			return
		}
		switch v.kind {
		case cryptoRegLiteralArray:
			desc := "IvParameterSpec built from a literal byte-array payload compiled into the DEX — static IV breaks CBC semantic security (CWE-329)"
			if arrayPayloadAllZero(m.Body, v.label) {
				desc = "IvParameterSpec built from an all-zero literal byte array — zero IV breaks CBC semantic security (CWE-329)"
			}
			emit("static_iv", line, desc, "IvParameterSpec literal payload", true)
		case cryptoRegBytesFromString:
			emit("static_iv", line,
				`IvParameterSpec built from the bytes of a hardcoded string literal — static IV breaks CBC semantic security (CWE-329)`,
				"IvParameterSpec const-string IV", true)
		}

	// ── SecureRandom.setSeed: deterministic output ──
	case call.classDesc == "Ljava/security/SecureRandom;" && call.method == "setSeed":
		emit("seeded_rng", line,
			"SecureRandom.setSeed() — seeding the CSPRNG can make its output predictable (CWE-336)",
			"SecureRandom.setSeed", true)
	}
}

// ── smali line helpers ──────────────────────────────────────────────────────

// parseConstStringLine extracts the destination register and the quoted value
// from `const-string[/jumbo] vX, "value"`.
func parseConstStringLine(line string) (reg, value string, ok bool) {
	comma := strings.IndexByte(line, ',')
	if comma < 0 {
		return "", "", false
	}
	head := strings.Fields(line[:comma])
	if len(head) < 2 {
		return "", "", false
	}
	reg = head[1]
	rest := line[comma+1:]
	first := strings.IndexByte(rest, '"')
	last := strings.LastIndexByte(rest, '"')
	if first < 0 || last <= first {
		return "", "", false
	}
	return reg, rest[first+1 : last], true
}

// parseDestRegister returns the first register operand of instructions shaped
// like `opcode vX, ...` (new-array, fill-array-data, move-result*).
func parseDestRegister(line string) string {
	comma := strings.IndexByte(line, ',')
	head := line
	if comma >= 0 {
		head = line[:comma]
	}
	fields := strings.Fields(head)
	if len(fields) < 2 {
		return ""
	}
	return fields[1]
}

// parseFillArrayData parses `fill-array-data vX, :label`.
func parseFillArrayData(line string) (reg, label string) {
	comma := strings.IndexByte(line, ',')
	if comma < 0 {
		return "", ""
	}
	fields := strings.Fields(line[:comma])
	if len(fields) < 2 {
		return "", ""
	}
	label = strings.TrimSpace(line[comma+1:])
	label = strings.TrimPrefix(label, ":")
	return fields[1], label
}

// parseCryptoInvoke parses an invoke line into registers and target reference.
func parseCryptoInvoke(line string) (cryptoInvoke, bool) {
	open := strings.IndexByte(line, '{')
	closeBr := strings.IndexByte(line, '}')
	arrow := strings.Index(line, "->")
	if open < 0 || closeBr <= open || arrow < closeBr {
		return cryptoInvoke{}, false
	}
	// Opcode is the first whitespace-delimited token (invoke-kind may be
	// followed immediately by `{regs}` with a comma before the reference).
	opcode := strings.Fields(line[:open])
	if len(opcode) == 0 {
		return cryptoInvoke{}, false
	}
	target := strings.TrimSpace(line[closeBr+1:])
	target = strings.TrimPrefix(target, ",") // `{regs}, Lclass;->method` form
	target = strings.TrimSpace(target)
	classEnd := strings.IndexByte(target, ';')
	if classEnd < 0 || !strings.HasPrefix(target, "L") {
		return cryptoInvoke{}, false
	}
	methodPart := target[classEnd+1:]
	methodPart = strings.TrimPrefix(methodPart, "->")
	if paren := strings.IndexByte(methodPart, '('); paren >= 0 {
		methodPart = methodPart[:paren]
	}
	return cryptoInvoke{
		opcode:    opcode[0],
		registers: expandRegisterRange(line[open+1 : closeBr]),
		classDesc: target[:classEnd+1],
		method:    methodPart,
		raw:       target,
		line:      0, // caller fills from method body position
	}, true
}

// expandRegisterRange splits "v0, v1, v2" or "v0 .. v3" into register names.
func expandRegisterRange(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if parts := strings.Split(value, ".."); len(parts) == 2 {
		start := strings.TrimSpace(parts[0])
		end := strings.TrimSpace(parts[1])
		if len(start) >= 2 && len(end) >= 2 && start[0] == end[0] {
			first, err1 := strconv.Atoi(start[1:])
			last, err2 := strconv.Atoi(end[1:])
			if err1 == nil && err2 == nil && last >= first && last-first <= 64 {
				out := make([]string, 0, last-first+1)
				for i := first; i <= last; i++ {
					out = append(out, string(start[0])+strconv.Itoa(i))
				}
				return out
			}
		}
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if r := strings.TrimSpace(p); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// arrayPayloadAllZero reports whether the `.array-data` block under `label`
// contains only zero words. Returns false when the payload cannot be located
// (never asserts without evidence).
func arrayPayloadAllZero(body []string, label string) bool {
	if label == "" {
		return false
	}
	target := ":" + label
	inPayload := false
	sawValue := false
	for _, raw := range body {
		line := strings.TrimSpace(raw)
		if !inPayload {
			if line == target {
				inPayload = true
			}
			continue
		}
		if strings.HasPrefix(line, ".end array-data") {
			return sawValue
		}
		if strings.HasPrefix(line, ".array-data") {
			continue
		}
		for _, tok := range strings.Fields(line) {
			tok = strings.TrimPrefix(tok, "0x")
			tok = strings.TrimPrefix(tok, "0X")
			tok = strings.TrimSuffix(tok, "t")
			if tok == "" {
				continue
			}
			sawValue = true
			for i := 0; i < len(tok); i++ {
				if tok[i] != '0' {
					return false
				}
			}
		}
	}
	return false
}

func looksLikePasswordContext(s string) bool {
	return strings.Contains(s, "password") || strings.Contains(s, "passwd") ||
		strings.Contains(s, "credential") || strings.Contains(s, "pin_code") ||
		strings.Contains(s, "secret_key") || strings.Contains(s, "auth_token")
}
