package report

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// D2: truncation must never split a multibyte rune.
func TestTruncateString_UTF8Safe(t *testing.T) {
	in := "\u043f\u0440\u0438\u0432\u0435\u0442 \u043c\u0438\u0440 \u043a\u0430\u043a \u0434\u0435\u043b\u0430 \u0441\u0435\u0433\u043e\u0434\u043d\u044f"
	for _, max := range []int{1, 2, 3, 5, 10, 15, 21} {
		got := TruncateString(in, max)
		if len(got) > max {
			t.Errorf("max=%d: byte len %d exceeds cap (%q)", max, len(got), got)
		}
		if !utf8.ValidString(got) {
			t.Errorf("max=%d: broken UTF-8: %q", max, got)
		}
	}
	if got := TruncateString("hello world this is long", 10); !strings.HasPrefix(got, "...") {
		t.Errorf("ellipsis prefix lost: %q", got)
	}
	if got := TruncateString("short", 100); got != "short" {
		t.Errorf("short string must pass through: %q", got)
	}
}

// D2: leading and interior traversal segments are collapsed, not just one "../".
func TestNormalizePath_Traversal(t *testing.T) {
	cases := map[string]string{
		"../../etc/passwd":      "etc/passwd",
		"..\\..\\etc\\passwd":   "etc/passwd",
		"./x/y":                 "x/y",
		"a/../../b":             "b",
		"a/b/../c":              "a/c",
		"smali/com/app/T.smali": "smali/com/app/T.smali",
		"C:\\path\\to\\file":    "C:/path/to/file",
		"":                      "",
	}
	for in, want := range cases {
		if got := NormalizePath(in); got != want {
			t.Errorf("NormalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// D1: canonical SVG active-content check catches what the old 4-pattern
// badge missed.
func TestSVGHasActiveContent_Canonical(t *testing.T) {
	active := []string{
		`<svg><script>x()</script></svg>`,
		`<svg onload="x()"/>`,
		`<svg onerror="x()"/>`,
		`<svg onclick="x()"/>`,
		`<svg onfocusin="x()"/>`,
		`<svg><set attributeName="href" onbegin="x()"/></svg>`,
		`<svg><foreignObject><body/></foreignObject></svg>`,
		`<svg><animate attributeName="href"/></svg>`,
		`<svg><a href="javascript:x()">go</a></svg>`,
	}
	for _, s := range active {
		if !SVGHasActiveContent([]byte(s)) {
			t.Errorf("active content missed: %s", s)
		}
	}
	if SVGHasActiveContent([]byte(`<svg><rect width="1"/></svg>`)) {
		t.Error("plain svg falsely flagged")
	}
}
