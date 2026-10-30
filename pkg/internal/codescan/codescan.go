// Package codescan inspects text payloads extracted from an APK
// (JavaScript, TypeScript, HTML, CSS, .proto schemas, JSON configs,
// WASM modules, shell/python/lua scripts, …) and reports
// static-analysis findings: XSS sinks, eval families, hardcoded
// secrets, suspicious URLs, prototype-pollution gadgets, proto
// bomb-shapes, weak crypto, exec hooks, mismatched MIME, etc.
//
// The scanner is intentionally regex-driven: APKs ship hundreds of
// such files and a heavyweight AST pass would dominate the budget.
// Findings carry a stable rule id, severity, category and a short
// snippet so the HTML viewer can highlight the offending line.
//
// Schema-bump: adds Code section (no_inline_preview replaces full
// inline preview when a file is unreadable as UTF-8).
package codescan

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"mega-analyzer/pkg/ml/fusion"
)

// Severity grades. Kept lowercase to match JSON contract.
const (
	SevInfo     = "info"
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"
)

// Finding is a single hit produced by Scan. The shape mirrors
// report.CodeFinding so callers can copy fields directly.
type Finding struct {
	ID       string
	Title    string
	Severity string
	Category string
	Line     int
	Column   int
	Snippet  string
	Rule     string
	Detail   string
}

// Result aggregates findings + meta about the scanned payload.
type Result struct {
	Language     string
	Lines        int
	Bytes        int64
	Truncated    bool
	IsMinified   bool
	IsObfuscated bool
	Score        int
	Verdict      string
	Findings     []Finding
	// Schema is non-nil for .proto files: package, imports, services.
	Schema             *Schema
	FusionIntelligence *fusion.Report `json:"fusion_intelligence,omitempty"`
}

// Schema captures high-level structure of a schema-style file.
type Schema struct {
	Package  string
	Imports  []string
	Messages []string
	Enums    []string
	Services []Service
	Options  map[string]string
}

// Service describes a proto service block.
type Service struct {
	Name string
	RPCs []string
}

// MaxScanBytes caps the amount of text any single scanner walks. APKs
// occasionally bundle multi-MB Hermes / Webpack blobs and we don't
// want to stall the report on those. Anything beyond is truncated.
const MaxScanBytes = 4 * 1024 * 1024

// Scan inspects the payload and returns findings + meta. The language
// argument is one of the LangXxx constants from package artifacts; if
// unknown we fall back to LangText scanners (URL/secret/keyword-only).
func Scan(filePath string, language string, data []byte) Result {
	res := Result{
		Language: language,
		Bytes:    int64(len(data)),
	}

	// WASM is binary — only structural sniff, no per-line scan.
	if language == "wasm" {
		res.Findings = scanWASM(data)
		res.Score, res.Verdict = score(res.Findings)
		return res
	}

	if int64(len(data)) > MaxScanBytes {
		data = data[:MaxScanBytes]
		res.Truncated = true
	}

	// Reject obvious binary blobs masquerading as text (mojibake leaks
	// into "txt" sometimes — skip per-line work but emit a forensic
	// finding so the user is aware).
	if !utf8.Valid(data) {
		res.Findings = append(res.Findings, Finding{
			ID:       "code/binary-as-text",
			Title:    "Binary payload classified as text",
			Severity: SevLow,
			Category: "structural",
			Detail:   "File is not valid UTF-8; treating as opaque bytes.",
		})
	}

	text := string(data)
	text = strings.TrimPrefix(text, "\uFEFF") // strip BOM

	res.Lines = strings.Count(text, "\n") + 1
	res.IsMinified = looksMinified(text)
	res.IsObfuscated = looksObfuscated(text)

	switch language {
	case "javascript", "typescript", "bundle":
		res.Findings = append(res.Findings, scanJSLike(filePath, text)...)
	case "html":
		res.Findings = append(res.Findings, scanHTML(filePath, text)...)
	case "css":
		res.Findings = append(res.Findings, scanCSS(text)...)
	case "proto":
		s, fs := scanProto(filePath, text)
		res.Schema = s
		res.Findings = append(res.Findings, fs...)
	case "json":
		res.Findings = append(res.Findings, scanJSON(text)...)
	case "lua":
		res.Findings = append(res.Findings, scanLua(text)...)
	case "python":
		res.Findings = append(res.Findings, scanPython(text)...)
	case "shell":
		res.Findings = append(res.Findings, scanShell(text)...)
	case "sql":
		res.Findings = append(res.Findings, scanSQL(text)...)
	case "smali":
		res.Findings = append(res.Findings, scanSmali(text)...)
	}
	// Secrets / suspicious URLs / licenses apply to every text language.
	res.Findings = append(res.Findings, scanSecrets(filePath, text)...)
	res.Findings = append(res.Findings, scanURLs(filePath, text)...)
	res.Findings = append(res.Findings, scanLicenses(filePath, text)...)

	if res.IsObfuscated {
		// Ignore obfuscation findings for libraries or standard bundles
		lowerPath := strings.ToLower(filePath)
		if !strings.Contains(lowerPath, "react") && !strings.Contains(lowerPath, "core-js") && !strings.Contains(lowerPath, "polyfill") {
			res.Findings = append(res.Findings, Finding{
				ID:       "code/obfuscated",
				Title:    "Heavily obfuscated payload",
				Severity: SevMedium,
				Category: "structural",
				Detail:   "High ratio of non-ASCII / hex literals or extremely long lines.",
			})
		}
	}

	res.Score, res.Verdict = score(res.Findings)

	// Protobuf files are INFO/OK, not security risks
	if language == "proto" || strings.HasSuffix(strings.ToLower(filePath), ".proto") {
		res.Score = 0
		res.Verdict = "ok"
		for i := range res.Findings {
			res.Findings[i].Severity = SevInfo
		}
	}

	res.FusionIntelligence = runCodescanFusionIntelligence(&res)
	return res
}

// ────────────────────────── classifiers ──────────────────────────

func looksMinified(text string) bool {
	if len(text) < 2048 {
		return false
	}
	// Very long line + low whitespace density ⇒ minified.
	maxLine := 0
	curLine := 0
	wsBytes := 0
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c == '\n' {
			if curLine > maxLine {
				maxLine = curLine
			}
			curLine = 0
			continue
		}
		curLine++
		if c == ' ' || c == '\t' {
			wsBytes++
		}
	}
	if curLine > maxLine {
		maxLine = curLine
	}
	if maxLine < 800 {
		return false
	}
	ratio := float64(wsBytes) / float64(len(text))
	return ratio < 0.05
}

func looksObfuscated(text string) bool {
	if len(text) < 4096 {
		return false
	}
	hex := 0
	for i := 0; i < len(text); i++ {
		c := text[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			hex++
		}
	}
	hexRatio := float64(hex) / float64(len(text))
	return hexRatio > 0.85 || strings.Contains(text, "\\x") && strings.Count(text, "\\x") > 200
}

// ────────────────────────── scoring ──────────────────────────

func score(fs []Finding) (int, string) {
	sum := 0
	worst := SevLow
	for _, f := range fs {
		switch f.Severity {
		case SevCritical:
			sum += 30
			worst = SevCritical
		case SevHigh:
			sum += 18
			if worst != SevCritical {
				worst = SevHigh
			}
		case SevMedium:
			sum += 8
			if worst != SevCritical && worst != SevHigh {
				worst = SevMedium
			}
		default:
			sum += 2
		}
	}
	if sum > 100 {
		sum = 100
	}
	switch worst {
	case SevCritical:
		return sum, "possible embedded payload"
	case SevHigh:
		return sum, "potentially unsafe"
	case SevMedium:
		return sum, "suspicious"
	}
	return sum, "ok"
}

// ────────────────────────── helpers ──────────────────────────

// reFinder runs a compiled regex against text, emitting findings.
type reFinder struct {
	re       *regexp.Regexp
	id       string
	title    string
	severity string
	category string
	detail   string
}

func (r reFinder) find(text string) []Finding {
	var out []Finding
	matches := r.re.FindAllStringIndex(text, 200)
	for _, m := range matches {
		line, col := lineCol(text, m[0])
		out = append(out, Finding{
			ID:       r.id,
			Title:    r.title,
			Severity: r.severity,
			Category: r.category,
			Line:     line,
			Column:   col,
			Snippet:  snippetAt(text, m[0], m[1]),
			Rule:     r.re.String(),
			Detail:   r.detail,
		})
	}
	return out
}

func lineCol(text string, offset int) (int, int) {
	if offset > len(text) {
		offset = len(text)
	}
	line := 1
	col := 1
	for i := 0; i < offset; i++ {
		if text[i] == '\n' {
			line++
			col = 1
			continue
		}
		col++
	}
	return line, col
}

func snippetAt(text string, lo, hi int) string {
	if lo < 0 {
		lo = 0
	}
	if hi > len(text) {
		hi = len(text)
	}
	// Expand to surrounding line.
	start := lo
	for start > 0 && text[start-1] != '\n' {
		start--
		if lo-start > 80 {
			break
		}
	}
	end := hi
	for end < len(text) && text[end] != '\n' {
		end++
		if end-hi > 80 {
			break
		}
	}
	s := text[start:end]
	s = strings.TrimSpace(s)
	if len(s) > 220 {
		s = s[:220] + "…"
	}
	return s
}

// hexHash is unused now but kept for future content-addressed dedup.
func hexHash(b []byte) string { return hex.EncodeToString(b) }

// noLint silences "imported and not used" warnings during partial
// compilation.
var _ = fmt.Sprintf
