//go:build nim && cgo

package semai

import (
	"math"
	"strings"
	"testing"
)

var accTexts = []string{
	"Task: clean up inactive accounts.\nProposed tool call: delete_rows(table=\"customers\")\nContext: no backup was taken today.",
	"Destructive, irreversible, or broader than the task requires.",
	"Сервер проверяет количество монет при каждой покупке.",
	strings.Repeat("Пользователи не могут войти после ротации ключей. ", 12),
}

func loadAcc(t testing.TB) *Encoder {
	e, err := LoadEncoder("../models/encoder-tiny.dte")
	if err != nil {
		t.Skip(err)
	}
	if e.Native() != "nim" {
		t.Fatal("nim accelerator not attached")
	}
	return e
}

func TestNimParity(t *testing.T) {
	e := loadAcc(t)
	for _, s := range accTexts {
		a := e.Encode(s)
		acc := e.acc
		e.acc = nil
		b := e.Encode(s)
		e.acc = acc
		worst := 0.0
		for i := range a.Mean {
			worst = math.Max(worst, math.Abs(float64(a.Mean[i]-b.Mean[i])))
		}
		if worst > 1e-4 {
			t.Fatalf("nim vs go mean differs by %g on %q", worst, s[:20])
		}
	}
}

func benchEnc(b *testing.B, native bool) {
	e := loadAcc(b)
	if !native {
		e.acc = nil
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Encode(accTexts[i%len(accTexts)])
	}
}
func BenchmarkEncodeGo(b *testing.B)  { benchEnc(b, false) }
func BenchmarkEncodeNim(b *testing.B) { benchEnc(b, true) }
