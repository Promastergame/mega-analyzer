package piracy

import (
	"context"
	"regexp"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

var (
	benchCtx       = context.Background()
	benchSmaliType = types.FileTypeSmali
)

// wordIndex must reproduce Go's `(?i)\b<literal>\b` semantics exactly, because
// that is what word-mode patterns used to compile to.
func TestWordIndexMatchesRegexSemantics(t *testing.T) {
	patterns := []string{"mod", "lp", "modded", "no_ads", "4pda", ".ru", "pro"}
	corpus := []string{
		"",
		"mod",
		"a mod b",
		"remodded",
		"mod_ded",
		"lp_abcd and lp",
		"no_ads=true",
		"see 4pda.ru now",
		"x4pda",
		"pro-version pro",
		"...mod...",
		"\u043c\u043e\u0434 mod \u043c\u043e\u0434",
	}

	for _, pat := range patterns {
		re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(pat) + `\b`)
		for _, text := range corpus {
			want := -1
			if loc := re.FindIndex([]byte(text)); loc != nil {
				want = loc[0]
			}
			if got := wordIndex([]byte(text), []byte(pat)); got != want {
				t.Errorf("wordIndex(%q, %q) = %d, regexp says %d", text, pat, got, want)
			}
		}
	}
}

func TestRequiredLiteralsAnchors(t *testing.T) {
	cases := []struct {
		expr string
		want []string
	}{
		{`(?i)luckypatcher`, []string{"luckypatcher"}},
		{`(?i)lp_\w+`, []string{"lp_"}},
		{`(?i)mod\s+by\s+chelpus`, []string{"chelpus"}},
		{`(?i)(4pda|trashbox)\.ru`, []string{"4pda", "trashbox"}},
		{`(?i)\d+`, nil},
		{`(?i)(a|cracked)`, nil}, // one branch is un-anchorable => no gating
	}

	for _, tc := range cases {
		got := regexAnchors(regexp.MustCompile(tc.expr))
		if len(got) != len(tc.want) {
			t.Errorf("regexAnchors(%q) = %v, want %v", tc.expr, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("regexAnchors(%q)[%d] = %q, want %q", tc.expr, i, got[i], tc.want[i])
			}
		}
	}
}

// The prefilter must never hide a finding: gating off must produce exactly the
// same findings as gating on.
func TestPrefilterDoesNotChangeFindings(t *testing.T) {
	d := NewDetector()

	samples := []string{
		"const-string v0, \"https://4pda.to/forum\"",
		"// modded by chelpus, lucky patcher",
		"nothing interesting here at all",
		"cracked apk from trashbox.ru mirror",
		"no_ads unlocked premium",
	}

	for _, text := range samples {
		content := []byte(text)
		lower := []byte(lowerASCII(text))

		hits := d.prefilter.hits(lower)
		if hits == nil {
			t.Fatalf("prefilter produced no hit vector for %q", text)
		}

		for i := range d.config.Sites {
			site := &d.config.Sites[i]
			anchors := d.prefilter.patternAnchors(i)
			for j, cp := range site.CompiledPatterns {
				matched := d.findPatternIndex(cp, lower) >= 0
				if matched && anchorMiss(hits, anchorAt(anchors, j)) {
					t.Fatalf("prefilter suppressed matching pattern %q in %q", cp.Original, text)
				}
			}
			reAnchors := d.prefilter.regexAnchorIDs(i)
			for j, re := range site.CompiledRegex {
				if re.Match(content) && anchorsMiss(hits, anchorListAt(reAnchors, j)) {
					t.Fatalf("prefilter suppressed matching regex %q in %q", re.String(), text)
				}
			}
		}
	}
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func BenchmarkAnalyzeSmaliFile(b *testing.B) {
	d := NewDetector()
	body := make([]byte, 0, 64*1024)
	for len(body) < 64*1024 {
		body = append(body, ".method public final a(Ljava/lang/String;)V\n    invoke-virtual {p0}, Lcom/example/App;->run()V\n"...)
	}
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := d.Analyze(benchCtx, "smali/com/example/App.smali", body, benchSmaliType); err != nil {
			b.Fatal(err)
		}
	}
}
