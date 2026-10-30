package apkloader

import (
	"encoding/binary"
	"testing"
)

func reviewPENativeSample(machine uint16, flags uint16) []byte {
	b := make([]byte, 1024)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[0x84:], machine)
	binary.LittleEndian.PutUint16(b[0x94:], 240)
	binary.LittleEndian.PutUint16(b[0x98:], 0x20b)
	binary.LittleEndian.PutUint16(b[0x98+70:], flags)
	binary.LittleEndian.PutUint32(b[0x98+108:], 16)
	return b
}

func TestReviewPENativeCFGIsNotCanary(t *testing.T) {
	r, ok := AnalyzeNativeGo(reviewPENativeSample(0x8664, 0x4000))
	if !ok || r.Verdict == "parse-error" {
		t.Fatal("fixture not parsed")
	}
	if r.Hardening.StackCanary != nil && *r.Hardening.StackCanary {
		t.Error("CFG bit alone reports StackCanary=true")
	}
}

func TestReviewPENativeARM64(t *testing.T) {
	r, ok := AnalyzeNativeGo(reviewPENativeSample(0xaa64, 0))
	if !ok || r.Verdict == "parse-error" {
		t.Fatal("fixture not parsed")
	}
	if r.TargetArch != "arm64" {
		t.Errorf("ARM64 machine reported as %s", r.TargetArch)
	}
}
