package pipeline

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/types"
)

// StringFog XOR constant evaluator.
//
// StringFog (com.github.megatronking.stringfog) is the most widespread
// Android string-obfuscation library, and its XOR variant is fully static:
// every call site carries the payload and the key as `fill-array-data` byte
// arrays, and StringFogImpl.decrypt is `out[i] = data[i] ^ key[i % len(key)]`.
// Without evaluation the analyzer sees only byte arrays, so every decrypted
// marker — C2 URLs, second-stage payload names, injection tooling ids — is
// invisible to rules and combos.
//
// This pass evaluates those constants offline (no code execution) and feeds
// the plaintext into RecoveredStrings, which the rule engine already consumes
// as string evidence. It also registers the raw byte arrays (the same
// constants double as decryption keys of packed asset containers) for the
// payload-recovery pass.

const (
	stringFogDecryptCall = "Lcom/github/megatronking/stringfog/xor/StringFogImpl;->decrypt([B[B)Ljava/lang/String;"
	stringFogPrefilter   = "([b[b)ljava/lang/string;"

	maxStringFogStringsPerFile  = 512
	maxStringFogArraysPerFile   = 96
	maxFogKeyCandidatesGlobal   = 4096
	minDecodedStringLen         = 4
	minFogKeyCandidateLen       = 8
	maxFogKeyCandidateLen       = 64
	maxStringFogArrayLineLength = 512
)

type stringFogEvaluator struct {
	p *Pipeline
}

func (e *stringFogEvaluator) Name() string { return "stringfog_evaluator" }

var stringFogArrayLabelRe = regexp.MustCompile(`^(:[\w$]+)\s*$`)

type stringFogMethodState struct {
	// arrays holds the most recent fill-array-data contents per register.
	arrays map[int][]byte
	// decoded registers that already produced a string (a register can be
	// reused for a second constant after a new new-array/fill).
	decodedAt map[int]int
}

func (e *stringFogEvaluator) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx == nil || analysis == nil || ctx.FileType != types.FileTypeSmali {
		return
	}
	// Two independent gates: decrypt-shape evaluation, and plain clinit
	// byte-array field registration (the packed-container keys live in
	// classes that never call a decrypt wrapper).
	hasDecryptCalls := bytes.Contains(ctx.ContentLower, []byte(stringFogPrefilter))
	hasByteArrayFields := bytes.Contains(ctx.Content, []byte(".array-data 1")) &&
		bytes.Contains(ctx.ContentLower, []byte("sput-object")) &&
		bytes.Contains(ctx.ContentLower, []byte(":[b"))
	if !hasDecryptCalls && !hasByteArrayFields {
		return
	}
	if e.p == nil {
		return
	}

	content := ctx.Content
	classDesc := smaliClassDescriptor(content)
	lines := strings.Split(string(content), "\n")

	// Class-wide byte-array fields: <clinit> fills and sputs them; later
	// methods sget them as decrypt keys or payloads.
	fieldArrays := make(map[string][]byte, 8)

	decoded := make([]string, 0, 16)
	seenDecoded := make(map[string]struct{}, 16)
	inClinit := false

	flushMethod := func(lines []string) {
		st := &stringFogMethodState{arrays: make(map[int][]byte, 8), decodedAt: make(map[int]int, 8)}
		arraysByLabel := make(map[string][]byte, 8)
		currentLabel := ""
		// Pass 1: collect .array-data blocks. In smali they sit at the END of
		// the method while the fill-array-data instructions referencing them
		// appear earlier, so collection must complete before evaluation.
		for i := 0; i < len(lines); i++ {
			trimmed := strings.TrimSpace(strings.TrimRight(lines[i], "\r"))
			if label := stringFogArrayLabelRe.FindStringSubmatch(trimmed); label != nil {
				currentLabel = label[1]
				continue
			}
			if strings.HasPrefix(trimmed, ".array-data 1") {
				vals := parseSmaliByteArray(lines[i+1:])
				if currentLabel != "" && len(vals) > 0 {
					arraysByLabel[currentLabel] = vals
				}
				currentLabel = ""
			}
		}
		// Pass 2: instructions.
		for i := 0; i < len(lines); i++ {
			line := strings.TrimRight(lines[i], "\r")
			trimmed := strings.TrimSpace(line)

			if strings.HasPrefix(trimmed, ".array-data") || stringFogArrayLabelRe.MatchString(trimmed) {
				continue // handled in pass 1
			}

			if strings.HasPrefix(trimmed, ".method ") {
				inClinit = strings.Contains(trimmed, "<clinit>")
			}

			if m := smaliFillArrayRe.FindStringSubmatch(trimmed); m != nil {
				reg := smaliRegNum(m[1])
				if arr, ok := arraysByLabel[m[2]]; ok {
					if st.decodedAt[reg] > 0 {
						delete(st.decodedAt, reg)
					}
					st.arrays[reg] = arr
				}
				continue
			}
			if m := smaliSgetByteArrayRe.FindStringSubmatch(trimmed); m != nil {
				// sget-object vN, Lcls;->field:[B — resolvable when the field
				// belongs to this class and <clinit> filled it.
				if arr, ok := fieldArrays[m[2]]; ok {
					st.arrays[smaliRegNum(m[1])] = arr
				}
				continue
			}
			if inClinit {
				if m := smaliSputByteArrayRe.FindStringSubmatch(trimmed); m != nil && classDesc != "" {
					if arr, ok := st.arrays[smaliRegNum(m[1])]; ok {
						fieldArrays[m[2]] = arr
						// Plain (undecoded) clinit byte arrays are the keys
						// of packed asset containers in this family; hand
						// them to the payload-recovery pass.
						if len(arr) >= minFogKeyCandidateLen && len(arr) <= maxFogKeyCandidateLen {
							e.p.registerFogKeyCandidate(arr)
						}
					}
				}
			}

			if m := decryptCallRe.FindStringSubmatch(trimmed); m != nil {
				payReg, keyReg := smaliRegNum(m[2]), smaliRegNum(m[3])
				payload, okP := st.arrays[payReg]
				key, okK := st.arrays[keyReg]
				if !okP || !okK || len(key) == 0 || len(payload) == 0 {
					continue
				}
				plain := stringFogXor(payload, key)
				if !isPlausibleDecodedString(plain) {
					continue
				}
				value := string(plain)
				if _, dup := seenDecoded[value]; !dup {
					seenDecoded[value] = struct{}{}
					decoded = append(decoded, value)
				}
				st.decodedAt[payReg] = i
				continue
			}

			// Stale-array invalidation: any instruction that writes its
			// destination register (const*, move*, aget, invoke results via
			// move-result*, …) voids a previously filled byte array in that
			// register. Without this a register reused for another value
			// would decode from leftover bytes.
			if dest := parseDestRegister(trimmed); dest != "" {
				if reg := smaliRegNum(dest); reg >= 0 {
					if _, ok := st.arrays[reg]; ok {
						delete(st.arrays, reg)
					}
				}
			}
		}
	}

	// Split into methods and evaluate each. <clinit> runs first regardless
	// of its position in the file: it fills the class byte-array fields that
	// later methods sget as decrypt keys or payloads.
	var clinitRange []string
	var otherRanges [][]string
	start := -1
	for i := 0; i <= len(lines); i++ {
		var line string
		if i < len(lines) {
			line = strings.TrimRight(lines[i], "\r")
		}
		if strings.HasPrefix(strings.TrimSpace(line), ".method ") {
			start = i
			continue
		}
		if strings.TrimSpace(line) == ".end method" && start >= 0 {
			if strings.Contains(lines[start], "<clinit>") {
				clinitRange = lines[start : i+1]
			} else {
				otherRanges = append(otherRanges, lines[start:i+1])
			}
			start = -1
		}
	}
	if clinitRange != nil {
		flushMethod(clinitRange)
	}
	for _, rng := range otherRanges {
		flushMethod(rng)
	}

	if len(decoded) == 0 {
		return
	}
	if len(decoded) > maxStringFogStringsPerFile {
		decoded = decoded[:maxStringFogStringsPerFile]
	}
	analysis.RecoveredStrings = dedupeStrings(append(analysis.RecoveredStrings, decoded...))

	// One inventory match per file keeps the recovery visible without noise.
	match := newMatch(
		types.CategoryObfuscatedString, analysis.Path, 0,
		"StringFog XOR constants decoded: "+firstNonEmpty(classDesc, filepath.Base(analysis.Path)),
		"decrypt([B[B) evaluated offline; sample: "+truncateForMatch(decoded, 2),
		false,
	)
	match.Metadata = map[string]string{
		"detector":      e.Name(),
		"decoded_count": itoa(len(decoded)),
		"finding_kind":  "inventory",
		"evidence_type": "stringfog_eval",
	}
	analysis.Matches = append(analysis.Matches, match)

	// The same constants double as decryption keys of packed asset
	// containers; register mid-size arrays for the recovery pass.
	registered := 0
	for _, arr := range collectFogArrays(fieldArrays) {
		if registered >= maxStringFogArraysPerFile {
			break
		}
		if len(arr) < minFogKeyCandidateLen || len(arr) > maxFogKeyCandidateLen {
			continue
		}
		if e.p.registerFogKeyCandidate(arr) {
			registered++
		}
	}
}

func truncateForMatch(values []string, n int) string {
	parts := make([]string, 0, n)
	for i := 0; i < len(values) && i < n; i++ {
		v := values[i]
		if len(v) > 48 {
			v = v[:45] + "..."
		}
		parts = append(parts, v)
	}
	return strings.Join(parts, "; ")
}

// stringFogXor implements StringFogImpl.decrypt: out[i] = data[i] ^ key[i % len(key)].
func stringFogXor(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

// isPlausibleDecodedString accepts printable ASCII/UTF-8-ish text: decodes of
// binary payloads (images, nested blobs) fail the printable ratio.
func isPlausibleDecodedString(plain []byte) bool {
	if len(plain) < minDecodedStringLen {
		return false
	}
	printable := 0
	for _, b := range plain {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 0x20 && b != 0x7f) {
			printable++
		}
	}
	return printable*100 >= len(plain)*92
}

// collectFogArrays gathers the distinct byte arrays seen in this file:
// class-field arrays (clinit-filled keys) dominate, inline call-site arrays
// are usually payload+key pairs worth registering too.
func collectFogArrays(fieldArrays map[string][]byte) [][]byte {
	out := make([][]byte, 0, len(fieldArrays))
	for _, arr := range fieldArrays {
		out = append(out, arr)
	}
	return out
}

var (
	smaliFillArrayRe     = regexp.MustCompile(`^fill-array-data (v\d+),\s*(:[\w$]+)$`)
	smaliSgetByteArrayRe = regexp.MustCompile(`^sget-object (v\d+),\s*(L[^;]+;->[^\s:]+:\[B)$`)
	smaliSputByteArrayRe = regexp.MustCompile(`^sput-object (v\d+),\s*(L[^;]+;->[^\s:]+:\[B)$`)
	// decryptCallRe matches both shapes of the decrypt call:
	//   invoke-virtual {vI, vP, vK}, Lcom/...StringFogImpl;->decrypt([B[B)Ljava/lang/String;
	//   invoke-static  {vP, vK},     Lz/...;->wrapper([B[B)Ljava/lang/String;
	// Obfuscators wrap the library call in their own class; matching the
	// signature SHAPE is what makes renamed builds visible.
	decryptCallRe = regexp.MustCompile(`^invoke-(?:virtual|static) \{(?:(v\d+), )?(v\d+), (v\d+)\}, L[^;]+;->[^\s(]+\(\[B\[B\)Ljava/lang/String;`)
)

func smaliRegNum(reg string) int {
	if len(reg) < 2 {
		return -1
	}
	n := 0
	for _, c := range reg[1:] {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func parseSmaliByteArray(lines []string) []byte {
	vals := make([]byte, 0, 64)
	for _, raw := range lines {
		s := strings.TrimSpace(raw)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if strings.HasPrefix(s, ".end array-data") {
			break
		}
		if len(s) > maxStringFogArrayLineLength {
			continue
		}
		token := strings.TrimRight(s, "tTsSlL")
		if token == "" {
			continue
		}
		v, ok := parseSmaliInt(token)
		if !ok {
			continue
		}
		vals = append(vals, byte(v))
		if len(vals) >= 65536 {
			break
		}
	}
	return vals
}

func parseSmaliInt(token string) (int, bool) {
	if token == "" {
		return 0, false
	}
	neg := false
	if strings.HasPrefix(token, "-") {
		neg = true
		token = token[1:]
	}
	var n int64
	switch {
	case strings.HasPrefix(token, "0x"), strings.HasPrefix(token, "0X"):
		for _, c := range token[2:] {
			var d int64
			switch {
			case c >= '0' && c <= '9':
				d = int64(c - '0')
			case c >= 'a' && c <= 'f':
				d = int64(c-'a') + 10
			case c >= 'A' && c <= 'F':
				d = int64(c-'A') + 10
			default:
				return 0, false
			}
			n = n*16 + d
		}
	default:
		for _, c := range token {
			if c < '0' || c > '9' {
				return 0, false
			}
			n = n*10 + int64(c-'0')
		}
	}
	if neg {
		n = -n
	}
	return int(n), true
}

func smaliClassDescriptor(content []byte) string {
	idx := bytes.Index(content, []byte(".class "))
	if idx < 0 {
		return ""
	}
	line := content[idx:]
	if end := bytes.IndexByte(line, '\n'); end >= 0 {
		line = line[:end]
	}
	for _, field := range strings.Fields(string(line)) {
		if strings.HasPrefix(field, "L") && strings.HasSuffix(field, ";") {
			return field
		}
	}
	return ""
}

// fogKeyRegistry is the pipeline-wide collector of mid-size byte arrays that
// may serve as decryption keys of packed asset containers.
type fogKeyRegistry struct {
	mu    sync.Mutex
	seen  map[uint64]struct{}
	keys  [][]byte
	total int
}

func newFogKeyRegistry() *fogKeyRegistry {
	return &fogKeyRegistry{seen: make(map[uint64]struct{}, 64)}
}

func (r *fogKeyRegistry) register(arr []byte) bool {
	if r == nil || len(arr) == 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.total >= maxFogKeyCandidatesGlobal {
		return false
	}
	h := fnv64(arr)
	if _, dup := r.seen[h]; dup {
		return false
	}
	r.seen[h] = struct{}{}
	cp := make([]byte, len(arr))
	copy(cp, arr)
	r.keys = append(r.keys, cp)
	r.total++
	return true
}

func (r *fogKeyRegistry) snapshot() [][]byte {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(r.keys))
	copy(out, r.keys)
	return out
}

func fnv64(data []byte) uint64 {
	var h uint64 = 14695981039346656037
	for _, b := range data {
		h ^= uint64(b)
		h *= 1099511628211
	}
	return h
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// registerFogKeyCandidate records a byte-array constant as a potential
// container-decryption key for the payload-recovery pass.
func (p *Pipeline) registerFogKeyCandidate(arr []byte) bool {
	return p.fogKeys.register(arr)
}
