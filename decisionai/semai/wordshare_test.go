package semai

import (
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"testing"
)

func wordShareFixture(t *testing.T) []byte {
	t.Helper()
	m := dteMeta{Format: "DTE1", Source: "fixture", Hidden: 8, Layers: 1,
		Heads: 2, Inter: 8, VocabSz: 4, MaxPos: 8, Eps: 1e-12,
		Vocab: "[UNK]\n[CLS]\n[SEP]\nx"}
	var raw []byte
	add := func(name, dtype string, shape []int, values []byte) {
		m.Tensors = append(m.Tensors, dteTensor{name, dtype, shape, len(raw), len(values)})
		raw = append(raw, values...)
	}
	f32 := func(name string, shape []int, val float32) {
		n := 1
		for _, d := range shape {
			n *= d
		}
		b := make([]byte, 4*n)
		for i := 0; i < n; i++ {
			binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(val))
		}
		add(name, "f32", shape, b)
	}
	f32("word.scale", []int{4}, 0.01)
	w := make([]byte, 32)
	for i := range w {
		w[i] = byte(i)
	}
	add("word", "i8r", []int{4, 8}, w)
	f32("pos", []int{8, 8}, 0)
	f32("type", []int{2, 8}, 0)
	f32("emb_ln.w", []int{8}, 1)
	f32("emb_ln.b", []int{8}, 0)
	for _, n := range []string{"q", "k", "v", "o", "f1", "f2"} {
		f32("l0."+n+".w", []int{8, 8}, 0.1)
		f32("l0."+n+".b", []int{8}, 0)
	}
	for _, n := range []string{"ln1", "ln2"} {
		f32("l0."+n+".w", []int{8}, 1)
		f32("l0."+n+".b", []int{8}, 0)
	}
	h, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	b := append([]byte("DTE1"), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(h)))
	return append(append(b, h...), raw...)
}

func TestWordShareIdentical(t *testing.T) {
	t.Setenv("DAI_NO_NIM", "1")
	b := wordShareFixture(t)
	base, err := parseDTE(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := parseDTE(b, base)
	if err != nil {
		t.Fatal(err)
	}
	if &base.word[0] != &shared.word[0] || &base.wordScale[0] != &shared.wordScale[0] {
		t.Fatal("identical tables were copied")
	}
	if &base.layers[0].q.w[0] == &shared.layers[0].q.w[0] {
		t.Fatal("transformer weights must stay independent")
	}
}

func TestWordShareDifferentDoesNotShare(t *testing.T) {
	t.Setenv("DAI_NO_NIM", "1")
	b := wordShareFixture(t)
	for _, change := range []string{"word", "scale", "vocab", "lower", "hidden"} {
		t.Run(change, func(t *testing.T) {
			base, err := parseDTE(b, nil)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "word":
				base.word[0] ^= 1
			case "scale":
				base.wordScale[0] = math.Float32frombits(math.Float32bits(base.wordScale[0]) + 1)
			case "vocab":
				base.pieces[3] = "y"
			case "lower":
				base.lower = true
			case "hidden":
				base.hidden = 16
			}
			e, err := parseDTE(b, base)
			if err != nil {
				t.Fatal(err)
			}
			if &base.word[0] == &e.word[0] {
				t.Fatal("different tables shared")
			}
		})
	}
}

func TestWordShareRealModelParity(t *testing.T) {
	t.Setenv("DAI_NO_NIM", "1")
	paths := []string{"../models/s1-distilled.dte", "../models/s1-distilled-b.dte"}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Skip("real weights unavailable")
		}
	}
	base, err := LoadEncoder(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	shared, err := LoadCrossEncoderAny(paths[1], base)
	if err != nil {
		t.Fatal(err)
	}
	standalone, err := LoadEncoder(paths[1])
	if err != nil {
		t.Fatal(err)
	}
	if &base.word[0] != &shared.word[0] {
		t.Fatal("real tables not shared")
	}
	for _, text := range []string{"Проверка модели.", "Choose the safer action."} {
		a, b := shared.Encode(text), standalone.Encode(text)
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
