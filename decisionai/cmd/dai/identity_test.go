package main

import (
	"decisionai/s1"
	"os"
	"path/filepath"
	"testing"
)

func TestAuxiliaryFingerprintTracksFileBytes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "model.json")
	os.WriteFile(p, []byte("first"), 0600)
	e := s1.NewEngine(s1.LexicalBackend{}, s1.DefaultCalibration())
	e.Experts = []s1.Expert{testIdentityExpert{}}
	a, err := auxiliaryFingerprint(e, "", p, p)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p, []byte("second"), 0600)
	b, err := auxiliaryFingerprint(e, "", p, p)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("auxiliary model bytes ignored")
	}
}

type testIdentityExpert struct{}

func (testIdentityExpert) Name() string { return "test" }
func (testIdentityExpert) Answer(any, string, s1.ExpertQuestion) (s1.ExpertAnswer, bool) {
	return s1.ExpertAnswer{}, false
}
