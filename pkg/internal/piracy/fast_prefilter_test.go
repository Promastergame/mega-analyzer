package piracy

import (
	"bytes"
	"context"
	"encoding/base64"
	"math/rand"
	"reflect"
	"regexp"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestRegexRequiresNonASCII(t *testing.T) {
	for _, tc := range []struct {
		expr string
		want bool
	}{
		{`(?i)четыре[._-]?пда`, true},
		{`(?i)(четыре|пять)`, true},
		{`(?i)(четыре|four)`, false},
		{`(?:пда)?four`, false},
		{`пда+`, true},
		{`[А-Я]+`, true},
		{`[А-Яa-z]+`, false},
		{`(?i)K`, false},
		{`(?i)ſ`, false},
		{`K`, true},
	} {
		if got := regexRequiresNonASCII(regexp.MustCompile(tc.expr)); got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.expr, got, tc.want)
		}
	}
}

func TestASCIIRegexPrefilterPreservesFindings(t *testing.T) {
	d, err := NewDetectorFromBytes([]byte(`{"schema_version":2,"sites":[
		{"name":"4PDA","domains":["4pda.to"],"patterns_regex":["(?i)четыре[._-]?пда","4[._-]?pda"],"confidence":0.95},
		{"name":"Kelvin","domains":["example.com"],"patterns_regex":["(?i)Ksite"],"confidence":0.95}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	d.cache = nil
	pf := d.prefilter
	for _, text := range []string{"ordinary ASCII smali", "ЧЕТЫРЕ_ПДА", "Ksite", "4_pda", "Ksite", "Kſite", "четыре-пда"} {
		d.prefilter = pf
		got, err := d.Analyze(context.Background(), "smali/App.smali", []byte(text), types.FileTypeSmali)
		if err != nil {
			t.Fatal(err)
		}
		d.prefilter = nil
		want, err := d.Analyze(context.Background(), "smali/App.smali", []byte(text), types.FileTypeSmali)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("prefilter changed findings for %q: got %+v, want %+v", text, got, want)
		}
	}
}

func TestXOR2ByteDomainPrefilterMatchesExhaustiveDecode(t *testing.T) {
	engine := newTestEngine("4pda.to", "example.com", "a", "я.рф")
	rng := rand.New(rand.NewSource(17))
	samples := [][]byte{nil, []byte("ordinary text without a domain"), []byte("A")}
	for _, text := range []string{"4PDA.TO", "x4Pda.To", "HTTPS://EXAMPLE.COM/", "я.рф"} {
		for _, key := range []byte{0, 0x20, 0x7f, 0xff} {
			samples = append(samples, xorDecode([]byte(text), []byte{0, key}))
		}
	}
	for i := 0; i < 40; i++ {
		data := make([]byte, 32+i)
		rng.Read(data)
		samples = append(samples, data)
	}
	for _, sample := range samples {
		for _, key1 := range []byte{0, 0x20, 0xff} {
			keys := engine.xor2ByteDomainKeys(sample, key1)
			for key2 := 0; key2 < 256; key2++ {
				decoded := xorDecode(sample, []byte{key1, byte(key2)})
				want := engine.extractURLFromBytesLowered(decoded, lowerASCIIInto(make([]byte, len(decoded)), decoded)) != nil
				if keys[key2] != want {
					t.Fatalf("sample %x, keys %02x/%02x: got %v, want %v", sample, key1, key2, keys[key2], want)
				}
			}
		}
	}
}

func TestBase64MultiLineCandidateLimitPreservesPrefix(t *testing.T) {
	engine := newTestEngine("4pda.to")
	encoded := []byte(base64.StdEncoding.EncodeToString([]byte("https://4pda.to/forum")))
	content := bytes.Repeat(append(encoded, '!'), 80)
	got := engine.detectBase64MultiLine(content)
	if len(got) != 50 {
		t.Fatalf("got %d decoded URLs, want the first 50 candidates", len(got))
	}
	for _, finding := range got {
		if finding.Domain != "4pda.to" || finding.Decoded != "https://4pda.to/forum" {
			t.Fatalf("unexpected finding: %+v", finding)
		}
	}
}
