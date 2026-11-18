package piracy

import (
	"bytes"
	"math/rand"
	"mega-analyzer/pkg/internal/configs"
	"reflect"
	"regexp/syntax"
	"testing"
)

func TestRegexCandidateSearchPreservesOffsets(t *testing.T) {
	d, err := NewDetectorFromBytes(configs.PiracySites())
	if err != nil {
		t.Fatal(err)
	}
	texts := []string{"", "AndroEed", "andro_eed", "андроид andro-eed", "İKſ ANDRO.EED", "exposed XPOSED", "xposed\nxposed", "lucky patcher", "luCKy-patcher", "ЧЕТЫРЕ-ПДА"}
	rng := rand.New(rand.NewSource(22))
	alphabet := []rune("androexposedLUCKYПДАчетыре Kſİ._-\n")
	for i := 0; i < 200; i++ {
		runes := make([]rune, i)
		for j := range runes {
			runes[j] = alphabet[rng.Intn(len(alphabet))]
		}
		texts = append(texts, string(runes))
	}
	for i, site := range d.config.Sites {
		for j, re := range site.CompiledRegex {
			for _, text := range texts {
				raw := []byte(text)
				want := re.FindIndex(raw)
				got := d.prefilter.findRegexIndex(i, j, re, raw)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%q on %q: got %v want %v", re, text, got, want)
				}
				if want != nil && d.prefilter.regexClauseMiss(d.prefilter.hits(bytes.ToLower(raw)), i, j) {
					t.Fatalf("clause hid %q on %q", re, text)
				}
			}
		}
	}
	// Leading assertions must use the original whole-input search.
	for _, expr := range []string{`\bandroeed`, `^androeed`, `(?i)ſite`, `(?i)лспатч`} {
		parsed, _ := syntax.Parse(expr, syntax.Perl)
		if regexStartPrefix(parsed.Simplify()) != nil {
			t.Fatalf("unsafe prefix: %s", expr)
		}
	}
}
