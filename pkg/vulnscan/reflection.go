package vulnscan

import (
	"fmt"
	"regexp"
	"strings"
)

// ReflectionContext describes where a canary value landed in a response. It
// drives context-aware payload selection: there is no point spraying HTML
// breakout payloads at a value that is only reflected inside a JSON body.
type ReflectionContext string

const (
	CtxNotReflected  ReflectionContext = "NotReflected"
	CtxHTMLText      ReflectionContext = "HTMLText"
	CtxHTMLAttribute ReflectionContext = "HTMLAttribute"
	CtxScriptBlock   ReflectionContext = "ScriptBlock"
	CtxHTMLComment   ReflectionContext = "HTMLComment"
	CtxCSSBlock      ReflectionContext = "CSSBlock"
	CtxJSONBody      ReflectionContext = "JSONBody"
	CtxURLContext    ReflectionContext = "URLContext"
)

// NewCanary returns a unique, easy-to-locate marker for reflection probing.
func NewCanary(seed string) string {
	return fmt.Sprintf("mzc%sqz", sanitizeCanarySeed(seed))
}

func sanitizeCanarySeed(seed string) string {
	var b strings.Builder
	for _, r := range seed {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
		if b.Len() >= 8 {
			break
		}
	}
	if b.Len() == 0 {
		return "canary"
	}
	return b.String()
}

var (
	reScriptBlock = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)
	reStyleBlock  = regexp.MustCompile(`(?is)<style\b[^>]*>(.*?)</style>`)
	reComment     = regexp.MustCompile(`(?s)<!--(.*?)-->`)
)

// DetectReflectionContext locates a canary in a response body and classifies
// the surrounding syntactic context. contentType helps distinguish JSON APIs
// from HTML pages.
func DetectReflectionContext(body, canary, contentType string) ReflectionContext {
	if canary == "" || !strings.Contains(body, canary) {
		return CtxNotReflected
	}
	if strings.Contains(strings.ToLower(contentType), "application/json") {
		return CtxJSONBody
	}

	// Executable / comment / style contexts take precedence over plain text.
	for _, m := range reScriptBlock.FindAllStringSubmatch(body, -1) {
		if strings.Contains(m[1], canary) {
			return CtxScriptBlock
		}
	}
	for _, m := range reStyleBlock.FindAllStringSubmatch(body, -1) {
		if strings.Contains(m[1], canary) {
			return CtxCSSBlock
		}
	}
	for _, m := range reComment.FindAllStringSubmatch(body, -1) {
		if strings.Contains(m[1], canary) {
			return CtxHTMLComment
		}
	}

	// Attribute context: canary appears inside a tag, within quotes.
	if inAttributeContext(body, canary) {
		return CtxHTMLAttribute
	}
	return CtxHTMLText
}

// inAttributeContext heuristically decides if the canary sits inside a tag's
// attribute value by checking whether the nearest preceding unclosed '<' has
// no matching '>' before the canary.
func inAttributeContext(body, canary string) bool {
	idx := strings.Index(body, canary)
	if idx < 0 {
		return false
	}
	lt := strings.LastIndex(body[:idx], "<")
	if lt < 0 {
		return false
	}
	gt := strings.Index(body[lt:idx], ">")
	return gt < 0 // still inside the opening tag
}

// Context-aware payload banks.
var (
	payloadsHTMLText = []string{
		"<script>alert('XSS-PROBE')</script>",
		"<svg onload=alert(1)>",
		"<img src=x onerror=alert(1)>",
	}
	payloadsAttribute = []string{
		`"><img src=x onerror=alert(1)>`,
		`'><svg onload=alert(1)>`,
		`" autofocus onfocus=alert(1) x="`,
	}
	payloadsScript = []string{
		"';alert(1);//",
		"\";alert(1);//",
		"</script><script>alert(1)</script>",
	}
	payloadsJSON = []string{
		`","injected":"mzc-json-probe`,
		`"}]}<script>alert(1)</script>`,
	}
	payloadsNumericSQLi = []string{
		"1 OR 1=1",
		"1) OR (1=1",
		"1 AND SLEEP(0)",
	}
	payloadsStringSQLi = []string{
		"1' OR '1'='1",
		"'",
		"\"'",
		"')) OR 1=1--",
	}
)

// SelectPayloads chooses a payload set tailored to an injection point's
// inferred data type and the reflection context observed for its canary. This
// replaces the "every payload at every input" spray, cutting request volume
// while improving accuracy.
func SelectPayloads(point InjectionPoint, ctx ReflectionContext) []string {
	// Never send injection payloads to fields that clearly expect an opaque
	// identifier - it only generates noise and requests.
	if point.DataType == TypeUUID || point.DataType == TypeToken {
		return nil
	}

	switch ctx {
	case CtxScriptBlock:
		return payloadsScript
	case CtxHTMLAttribute:
		return payloadsAttribute
	case CtxJSONBody:
		return payloadsJSON
	case CtxHTMLText, CtxHTMLComment:
		return payloadsHTMLText
	}

	// No reflection observed (or CSS/URL context): fall back on data type.
	if point.DataType == TypeNumeric {
		return payloadsNumericSQLi
	}
	return payloadsStringSQLi
}

// SelectSQLiPayloads picks SQLi payloads appropriate to the field's data type.
func SelectSQLiPayloads(point InjectionPoint) []string {
	if point.DataType == TypeUUID || point.DataType == TypeToken {
		return nil
	}
	if point.DataType == TypeNumeric {
		return payloadsNumericSQLi
	}
	return payloadsStringSQLi
}
