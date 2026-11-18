package semai

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func sharedTableFixture(t *testing.T) []byte {
	t.Helper()
	b := wordShareFixture(t)
	n := int(binary.LittleEndian.Uint32(b[4:8]))
	var m dteMeta
	if err := json.Unmarshal(b[8:8+n], &m); err != nil {
		t.Fatal(err)
	}
	m.Vocab, m.VocabSz, m.Source = "", 0, "test/base + fine-tuned"
	var tensors []dteTensor
	for _, tensor := range m.Tensors {
		if tensor.Name != "word" && tensor.Name != "word.scale" {
			tensors = append(tensors, tensor)
		}
	}
	m.Tensors = tensors
	h, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	out := append([]byte("DTE1"), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(h)))
	return append(append(out, h...), b[8+n:]...)
}

func TestLoadCrossEncoderWithoutBase(t *testing.T) {
	t.Setenv("DAI_NO_NIM", "1")
	path := filepath.Join(t.TempDir(), "standalone.dte")
	if err := os.WriteFile(path, wordShareFixture(t), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, bases := range [][]*Encoder{nil, {nil}, {nil, nil}} {
		if _, err := LoadCrossEncoderAny(path, bases...); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadSharedEncoderRequiresCompatibleBase(t *testing.T) {
	t.Setenv("DAI_NO_NIM", "1")
	path := filepath.Join(t.TempDir(), "shared.dte")
	data := sharedTableFixture(t)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEncoder(data); !errors.Is(err, ErrBaseRequired) {
		t.Fatalf("missing base: %v", err)
	}
	wrong, err := ParseEncoder(wordShareFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	wrong.Source = "test/different"
	if _, err := LoadCrossEncoderAny(path, nil, wrong); !errors.Is(err, ErrBaseRequired) {
		t.Fatalf("wrong base: %v", err)
	}
	base, err := ParseEncoder(wordShareFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	base.Source = "test/base"
	shared, err := LoadCrossEncoderAny(path, wrong, nil, base)
	if err != nil {
		t.Fatal(err)
	}
	if &shared.word[0] != &base.word[0] {
		t.Fatal("legacy word table was copied or selected incorrectly")
	}
}

func TestLoadMalformedEncoderIsNotMissingBase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.dte")
	for _, data := range [][]byte{[]byte("invalid data"), []byte("DTE1\xff\xff\xff\xff"), []byte("DTE1\x02\x00\x00\x00{}")} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCrossEncoderAny(path); err == nil || errors.Is(err, ErrBaseRequired) {
			t.Fatalf("malformed DTE accepted as needing a base: %v", err)
		}
	}
}
