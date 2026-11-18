package semai

import (
	"math"
	"os"
	"reflect"
	"testing"
)

func TestTokenizerShareDifferentWeights(t *testing.T) {
	t.Setenv("DAI_NO_NIM", "1")
	b := wordShareFixture(t)
	base, err := parseDTE(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	base.word[0] ^= 1 // Simulate different fine-tuned embeddings.
	e, err := parseDTE(b, base)
	if err != nil {
		t.Fatal(err)
	}
	if &e.pieces[0] != &base.pieces[0] {
		t.Fatal("tokenizer not shared")
	}
	// Only this test mutates the fixture map; inference treats it as immutable.
	base.vocab["__sharing_probe__"] = 123
	if e.vocab["__sharing_probe__"] != 123 {
		t.Fatal("vocabulary map not shared")
	}
	delete(base.vocab, "__sharing_probe__")
	if &e.word[0] == &base.word[0] {
		t.Fatal("different embeddings shared")
	}
}

func TestTokenizerShareGuards(t *testing.T) {
	for _, tc := range []struct {
		name, vocab string
		size        int
		lower, want bool
	}{
		{"same", "[UNK]\n[CLS]\n[SEP]\nx", 4, false, true},
		{"different", "[UNK]\n[CLS]\n[SEP]\ny", 4, false, false},
		{"prefix", "[UNK]\n[CLS]\n[SEP]\nxy", 4, false, false},
		{"truncated", "[UNK]\n[CLS]\n[SEP]", 4, false, false},
		{"trailing newline", "[UNK]\n[CLS]\n[SEP]\nx\n", 4, false, false},
		{"size", "[UNK]\n[CLS]\n[SEP]\nx", 5, false, false},
		{"lower", "[UNK]\n[CLS]\n[SEP]\nx", 4, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := &Encoder{pieces: []string{"[UNK]", "[CLS]", "[SEP]", "x"}}
			m := dteMeta{Vocab: tc.vocab, VocabSz: tc.size, Lower: tc.lower}
			if got := identicalTokenizer(m, base); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			if identicalTokenizer(m, nil) {
				t.Fatal("nil base accepted")
			}
		})
	}
}

func TestTokenizerShareRealModelParity(t *testing.T) {
	t.Setenv("DAI_NO_NIM", "1")
	for _, p := range []string{"../models/encoder-tiny.dte", "../models/s1-distilled.dte"} {
		if _, err := os.Stat(p); err != nil {
			t.Skip("real weights unavailable")
		}
	}
	base, err := LoadEncoder("../models/encoder-tiny.dte")
	if err != nil {
		t.Fatal(err)
	}
	shared, err := LoadCrossEncoderAny("../models/s1-distilled.dte", base)
	if err != nil {
		t.Fatal(err)
	}
	alone, err := LoadEncoder("../models/s1-distilled.dte")
	if err != nil {
		t.Fatal(err)
	}
	if &base.pieces[0] != &shared.pieces[0] {
		t.Fatal("real tokenizer not shared")
	}
	if &base.word[0] == &shared.word[0] {
		t.Fatal("different real embeddings shared")
	}
	for _, text := range []string{"Проверка модели.", "Choose the safer action."} {
		a, b := shared.Encode(text), alone.Encode(text)
		if !reflect.DeepEqual(a.Pieces, b.Pieces) {
			t.Fatal("tokenization changed")
		}
		for i := range a.Mean {
			if math.Float32bits(a.Mean[i]) != math.Float32bits(b.Mean[i]) {
				t.Fatalf("mean differs at %d", i)
			}
		}
		for i := range a.Tokens {
			for j := range a.Tokens[i] {
				if math.Float32bits(a.Tokens[i][j]) != math.Float32bits(b.Tokens[i][j]) {
					t.Fatalf("token output differs at %d,%d", i, j)
				}
			}
		}
	}
}
