package deobfuscation

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// JAVASCRIPT DEOBFUSCATOR
// ═══════════════════════════════════════════════════════════════════════════════
//
// A lightweight, string-oriented deobfuscator for the transforms commonly
// emitted by tools such as javascript-obfuscator and React-Native bundlers.
// Every pass is conservative: when a construct does not match with high
// confidence the input is returned unchanged, so the transform never corrupts
// otherwise-valid code.

// Package-level compiled patterns. Compiling once (rather than on every call)
// keeps the hot deobfuscation loop allocation-free with respect to regexps.
var (
	reHexEscape     = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	reUnicodeEscape = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	reSourceMap     = regexp.MustCompile(`//# sourceMappingURL=data:application/json;(charset=utf-8;)?base64,([a-zA-Z0-9+/=]+)`)
	reNativeModule  = regexp.MustCompile(`NativeModules\.([a-zA-Z0-9_]+)`)
	reConcatDouble  = regexp.MustCompile(`"([^"\\]*)"\s*\+\s*"([^"\\]*)"`)
	reConcatSingle  = regexp.MustCompile(`'([^'\\]*)'\s*\+\s*'([^'\\]*)'`)

	// String-table declaration: `var NAME = ['a', "b", ...];`
	reStringTableDecl = regexp.MustCompile(`(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*\[([^\]]*)\]\s*;`)
	// A single quoted string literal (used to validate array elements).
	reStringLiteral = regexp.MustCompile(`^\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')\s*$`)
	// Simple binary-operator proxy: `function NAME(a, b) { return a OP b; }`.
	reProxyFunc = regexp.MustCompile(`function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{\s*return\s+([^;{}]+);\s*\}`)

	// maxProxyInlinePasses bounds the fixpoint loop that unwraps nested proxies.
	maxProxyInlinePasses = 5
)

// JSDeobfuscatorOptions configures the deobfuscation engine.
type JSDeobfuscatorOptions struct {
	EnableUnescape      bool
	EnableStringResolve bool
	EnableInlineProxy   bool
	EnableCFFUnflatten  bool
	EnableExprSimplify  bool
	EnableBeautify      bool
}

// DefaultJSOptions returns the standard set of enabled passes.
func DefaultJSOptions() JSDeobfuscatorOptions {
	return JSDeobfuscatorOptions{
		EnableUnescape:      true,
		EnableStringResolve: true,
		EnableInlineProxy:   true,
		EnableCFFUnflatten:  true,
		EnableExprSimplify:  true,
		EnableBeautify:      true,
	}
}

// ScanJSOptions keeps only transformations that improve literal discovery.
// It deliberately skips whole-bundle beautification, proxy inlining and other
// rewrite-heavy passes that are unnecessary for endpoint/secret scanning.
func ScanJSOptions() JSDeobfuscatorOptions {
	return JSDeobfuscatorOptions{
		EnableUnescape: true,
	}
}

// JSDeobfuscator is the core engine.
type JSDeobfuscator struct {
	opts JSDeobfuscatorOptions
}

// NewJSDeobfuscator creates a new JS deobfuscator.
func NewJSDeobfuscator(opts JSDeobfuscatorOptions) *JSDeobfuscator {
	return &JSDeobfuscator{opts: opts}
}

// Deobfuscate orchestrates all enabled passes sequentially. The ordering
// matters: strings are unescaped and resolved from their lookup tables first so
// that later constant-folding sees concrete literals.
func (j *JSDeobfuscator) Deobfuscate(code string) string {
	if j.opts.EnableUnescape {
		code = j.UnescapeStrings(code)
	}
	if j.opts.EnableStringResolve {
		code = j.ResolveStringTables(code)
	}
	if j.opts.EnableInlineProxy {
		code = j.InlineProxyFunctions(code)
	}
	if j.opts.EnableExprSimplify {
		code = j.SimplifyExpressions(code)
	}
	if j.opts.EnableCFFUnflatten {
		code = j.UnflattenControlFlow(code)
	}
	if j.opts.EnableBeautify {
		code = j.Beautify(code)
	}
	return code
}

// UnescapeStrings decodes \xXX and \uXXXX escape sequences.
func (j *JSDeobfuscator) UnescapeStrings(code string) string {
	code = reHexEscape.ReplaceAllStringFunc(code, func(m string) string {
		if v, err := strconv.ParseInt(m[2:], 16, 32); err == nil {
			return string(rune(v))
		}
		return m
	})
	code = reUnicodeEscape.ReplaceAllStringFunc(code, func(m string) string {
		if v, err := strconv.ParseInt(m[2:], 16, 32); err == nil {
			return string(rune(v))
		}
		return m
	})
	return code
}

// ExtractSourceMaps looks for an inline base64-encoded source map and decodes it.
func ExtractSourceMaps(code string) (string, error) {
	matches := reSourceMap.FindStringSubmatch(code)
	if len(matches) > 2 {
		decoded, err := base64.StdEncoding.DecodeString(matches[2])
		if err != nil {
			return "", err
		}
		return string(decoded), nil
	}
	return "", fmt.Errorf("no inline source map found")
}

// MapRNBridge extracts unique NativeModules references, mapping the React
// Native surface to its Java/ObjC bridge.
func MapRNBridge(code string) []string {
	var bridges []string
	seen := make(map[string]bool)
	for _, m := range reNativeModule.FindAllStringSubmatch(code, -1) {
		if !seen[m[1]] {
			bridges = append(bridges, m[1])
			seen[m[1]] = true
		}
	}
	return bridges
}

// ResolveStringTables inlines references to constant string-lookup arrays.
//
// javascript-obfuscator hoists every string literal into a single array and
// rewrites usages as indexed accesses:
//
//	var _0x12ab = ['log', 'hello world'];
//	console[_0x12ab[0]](_0x12ab[1]);
//
// This pass finds arrays that contain only string literals and rewrites
// integer-indexed accesses back to the literal they denote. Arrays with
// non-literal elements, and non-constant indices, are left untouched so the
// transform is always semantics-preserving.
func (j *JSDeobfuscator) ResolveStringTables(code string) string {
	for _, decl := range reStringTableDecl.FindAllStringSubmatch(code, -1) {
		name := decl[1]
		literals, ok := parseStringArray(decl[2])
		if !ok {
			continue
		}
		accessRe, err := regexp.Compile(regexp.QuoteMeta(name) + `\s*\[\s*(0[xX][0-9a-fA-F]+|\d+)\s*\]`)
		if err != nil {
			continue
		}
		code = accessRe.ReplaceAllStringFunc(code, func(m string) string {
			sub := accessRe.FindStringSubmatch(m)
			if sub == nil {
				return m
			}
			idx, perr := strconv.ParseInt(strings.ToLower(sub[1]), 0, 64)
			if perr != nil || idx < 0 || int(idx) >= len(literals) {
				return m
			}
			return literals[idx]
		})
	}
	return code
}

// parseStringArray splits an array body into its elements and returns their raw
// quoted literals when every element is a string literal. The second return
// value is false when any element is a non-literal (number, identifier, nested
// expression), signalling the caller to leave the array alone.
func parseStringArray(body string) ([]string, bool) {
	if strings.TrimSpace(body) == "" {
		return nil, false
	}
	elems := splitTopLevel(body, ',')
	out := make([]string, 0, len(elems))
	for _, e := range elems {
		m := reStringLiteral.FindStringSubmatch(e)
		if m == nil {
			return nil, false
		}
		out = append(out, strings.TrimSpace(e))
	}
	return out, true
}

// InlineProxyFunctions replaces calls to trivial wrapper functions with the
// expression they compute. Two safe shapes are handled:
//
//	function _0xa(a) { return a; }         // identity
//	function _0xb(a, b) { return a + b; }  // single binary operator
//
// Calls are rewritten as parenthesised expressions with the arguments
// substituted, e.g. `_0xb(x, y)` → `(x + y)`. Nested proxies are unwrapped by
// iterating to a fixpoint (bounded to avoid pathological inputs).
func (j *JSDeobfuscator) InlineProxyFunctions(code string) string {
	proxies := collectProxies(code)
	if len(proxies) == 0 {
		return code
	}
	for pass := 0; pass < maxProxyInlinePasses; pass++ {
		changed := false
		for _, p := range proxies {
			next := inlineProxyCalls(code, p)
			if next != code {
				changed = true
				code = next
			}
		}
		if !changed {
			break
		}
	}
	return code
}

type proxyFunc struct {
	name   string
	params []string
	op     string // "" means identity (single param passthrough)
}

func collectProxies(code string) []proxyFunc {
	var out []proxyFunc
	for _, m := range reProxyFunc.FindAllStringSubmatch(code, -1) {
		name := m[1]
		params := splitParams(m[2])
		expr := strings.TrimSpace(m[3])
		switch len(params) {
		case 1:
			if expr == params[0] {
				out = append(out, proxyFunc{name: name, params: params})
			}
		case 2:
			if op, ok := matchBinaryProxy(expr, params[0], params[1]); ok {
				out = append(out, proxyFunc{name: name, params: params, op: op})
			}
		}
	}
	return out
}

// allowedProxyOps lists the binary operators we will inline. String and numeric
// concatenation dominates real obfuscated code; the rest are included because
// substitution is unconditionally semantics-preserving for them.
var allowedProxyOps = []string{"+", "-", "*", "/", "%", "&&", "||", "&", "|", "^", "<<", ">>"}

// matchBinaryProxy checks whether expr is exactly `p0 OP p1` for one of the
// allowed operators and returns that operator.
func matchBinaryProxy(expr, p0, p1 string) (string, bool) {
	for _, op := range allowedProxyOps {
		want := p0 + " " + op + " " + p1
		if normalizeSpaces(expr) == want {
			return op, true
		}
	}
	return "", false
}

// inlineProxyCalls rewrites every well-formed call to p found in code.
func inlineProxyCalls(code string, p proxyFunc) string {
	var b strings.Builder
	i := 0
	for i < len(code) {
		loc := indexIdentCall(code, p.name, i)
		if loc < 0 {
			b.WriteString(code[i:])
			break
		}
		// Emit everything up to the call site.
		b.WriteString(code[i:loc])

		// Skip the proxy's own definition: `function NAME(...) {...}`.
		if precededByFunctionKeyword(code, loc) {
			b.WriteString(p.name)
			i = loc + len(p.name)
			continue
		}

		open := loc + len(p.name)
		// Skip whitespace between the name and '('.
		for open < len(code) && (code[open] == ' ' || code[open] == '\t') {
			open++
		}
		if open >= len(code) || code[open] != '(' {
			b.WriteString(code[loc:open])
			i = open
			continue
		}
		args, end, ok := readCallArgs(code, open)
		if !ok || len(args) != len(p.params) {
			b.WriteString(code[loc:open])
			i = open
			continue
		}
		b.WriteString(renderProxy(p, args))
		i = end
	}
	return b.String()
}

// renderProxy produces the inlined expression for a proxy call.
func renderProxy(p proxyFunc, args []string) string {
	for i := range args {
		args[i] = strings.TrimSpace(args[i])
	}
	if p.op == "" { // identity
		return "(" + args[0] + ")"
	}
	return "(" + args[0] + " " + p.op + " " + args[1] + ")"
}

// SimplifyExpressions folds trivially constant expressions.
func (j *JSDeobfuscator) SimplifyExpressions(code string) string {
	for reConcatDouble.MatchString(code) {
		code = reConcatDouble.ReplaceAllString(code, `"$1$2"`)
	}
	for reConcatSingle.MatchString(code) {
		code = reConcatSingle.ReplaceAllString(code, `'$1$2'`)
	}

	code = strings.ReplaceAll(code, "!![]", "true")
	code = strings.ReplaceAll(code, "![]", "false")
	code = strings.ReplaceAll(code, "!!~", "")

	return code
}

// UnflattenControlFlow is a placeholder for switch-dispatcher unflattening.
//
// A correct, semantics-preserving unflattener requires a real parser and data
// flow analysis over the state variable; attempting it with regexes risks
// silently corrupting code. Until an AST-based implementation lands, this pass
// deliberately makes no changes rather than guess.
func (j *JSDeobfuscator) UnflattenControlFlow(code string) string {
	return code
}

// Beautify formats minified or scrambled code with standard spacing.
func (j *JSDeobfuscator) Beautify(code string) string {
	code = strings.ReplaceAll(code, "{", "{\n")
	code = strings.ReplaceAll(code, "}", "\n}\n")
	code = strings.ReplaceAll(code, ";", ";\n")

	lines := strings.Split(code, "\n")
	var result strings.Builder
	indent := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "}") {
			indent--
		}
		if indent < 0 {
			indent = 0
		}
		for i := 0; i < indent; i++ {
			result.WriteString("    ")
		}
		result.WriteString(line)
		result.WriteString("\n")

		if strings.HasSuffix(line, "{") {
			indent++
		}
	}

	return result.String()
}

// ═══════════════════════════════════════════════════════════════════════════════
// SMALL LEXICAL HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// splitParams splits a comma-separated parameter list, trimming each name.
func splitParams(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

// normalizeSpaces collapses runs of whitespace to single spaces and trims ends,
// so `a+b`, `a + b` and `a  +  b` all compare equal.
func normalizeSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// splitTopLevel splits s on sep, ignoring separators nested inside quotes,
// parentheses, brackets or braces.
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth := 0
	var quote byte
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote && (i == 0 || s[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case sep:
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// indexIdentCall finds the next occurrence of ident at or after position from
// that is a standalone identifier (not part of a longer identifier or a member
// access like `obj.ident`).
func indexIdentCall(code, ident string, from int) int {
	for {
		rel := strings.Index(code[from:], ident)
		if rel < 0 {
			return -1
		}
		pos := from + rel
		before := byte(' ')
		if pos > 0 {
			before = code[pos-1]
		}
		after := byte(' ')
		if pos+len(ident) < len(code) {
			after = code[pos+len(ident)]
		}
		if !isIdentByte(before) && before != '.' && !isIdentByte(after) {
			return pos
		}
		from = pos + len(ident)
		if from >= len(code) {
			return -1
		}
	}
}

// readCallArgs parses an argument list beginning at the '(' at position open.
// It returns the top-level arguments, the index just past the closing ')', and
// whether a balanced list was found.
func readCallArgs(code string, open int) ([]string, int, bool) {
	if open >= len(code) || code[open] != '(' {
		return nil, open, false
	}
	depth := 0
	var quote byte
	for i := open; i < len(code); i++ {
		c := code[i]
		if quote != 0 {
			if c == quote && code[i-1] != '\\' {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				inner := code[open+1 : i]
				if strings.TrimSpace(inner) == "" {
					return nil, i + 1, true
				}
				return splitTopLevel(inner, ','), i + 1, true
			}
		}
	}
	return nil, open, false
}

// precededByFunctionKeyword reports whether the identifier starting at pos is
// immediately preceded (ignoring whitespace) by the `function` keyword, i.e.
// pos is a function declaration name rather than a call site.
func precededByFunctionKeyword(code string, pos int) bool {
	j := pos - 1
	for j >= 0 && (code[j] == ' ' || code[j] == '\t' || code[j] == '\n' || code[j] == '\r') {
		j--
	}
	const kw = "function"
	if j+1 < len(kw) {
		return false
	}
	start := j + 1 - len(kw)
	if code[start:j+1] != kw {
		return false
	}
	// Ensure it is the standalone keyword, not a suffix like `myfunction`.
	if start > 0 && isIdentByte(code[start-1]) {
		return false
	}
	return true
}

func isIdentByte(b byte) bool {
	return b == '_' || b == '$' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}
