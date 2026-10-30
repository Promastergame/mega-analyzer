package report

import "strings"

// SVGActivePatterns is the canonical list of substrings that mark an SVG as
// containing active content (scripting, event handlers, animation vectors).
// It is shared by the artifacts pipeline verdict, the Go-side security badge
// and mirrored in the JS-side notice in artifacts_html.go, so the checks
// cannot drift apart (deferred finding D1: the old badge tested only four
// patterns and could show "SVG Secure" for an SVG the pipeline flagged).
var SVGActivePatterns = []string{
	"<script", "javascript:", "<foreignobject", "<set", "<animate",
	"onload=", "onclick=", "onerror=", "onmouseover=", "onfocusin=", "onbegin=",
}

// SVGHasActiveContent reports whether the SVG bytes contain active content
// per SVGActivePatterns. Matching is case-insensitive.
func SVGHasActiveContent(data []byte) bool {
	low := strings.ToLower(string(data))
	for _, p := range SVGActivePatterns {
		if strings.Contains(low, p) {
			return true
		}
	}
	return false
}
