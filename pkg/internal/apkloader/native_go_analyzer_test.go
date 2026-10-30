package apkloader

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAnalyzeNativeGo_FormatDetection(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"elf", []byte{0x7f, 'E', 'L', 'F', 1, 1, 1, 0}, true},
		{"pe", []byte{'M', 'Z', 0x90, 0x00}, true},
		{"macho64", []byte{0xCF, 0xFA, 0xED, 0xFE}, true},
		{"text", []byte("hello world not a binary"), false},
		{"tiny", []byte{0x7f}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, ok := AnalyzeNativeGo(c.data)
			if ok != c.want {
				t.Errorf("AnalyzeNativeGo(%s) format-recognized=%v, want %v", c.name, ok, c.want)
			}
		})
	}
}

func TestExtractStrings(t *testing.T) {
	data := []byte("ab\x00/system/bin/su\x00\x01\x02frida-server")
	got := extractStrings(data, 5)
	joined := strings.Join(got, "|")
	if !strings.Contains(joined, "/system/bin/su") || !strings.Contains(joined, "frida-server") {
		t.Errorf("extractStrings missed expected runs, got %q", joined)
	}
	for _, s := range got {
		if s == "ab" {
			t.Errorf("extractStrings kept short run %q", s)
		}
	}
}

func TestScanNativeStrings_FlagsRootAndFrida(t *testing.T) {
	rep := &NativeScanReport{}
	scanNativeStrings(rep, []string{"this app checks /system/bin/su path", "frida gadget loaded"})
	finalizeNativeReport(rep)
	if len(rep.Findings) < 2 {
		t.Fatalf("expected >=2 findings for root+frida strings, got %d", len(rep.Findings))
	}
	if rep.Verdict == "clean" {
		t.Errorf("expected non-clean verdict, got %q", rep.Verdict)
	}
}

// TestAnalyzeNativeGo_RealBinary builds a tiny binary with the current toolchain
// and verifies the analyzer parses it and reports a sane arch + verdict.
func TestAnalyzeNativeGo_RealBinary(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "tiny.go")
	if err := os.WriteFile(src, []byte("package main\nfunc main(){}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(tmp, "tiny.bin")
	cmd := exec.Command("go", "build", "-o", out, src)
	cmd.Env = os.Environ()
	if outBytes, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not build test binary: %v (%s)", err, outBytes)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	rep, ok := AnalyzeNativeGo(data)
	if !ok {
		t.Fatalf("native binary not recognized on %s", runtime.GOOS)
	}
	if rep.TargetArch == "" {
		t.Errorf("expected a non-empty arch, got empty")
	}
	if rep.Verdict == "" {
		t.Errorf("expected a verdict, got empty")
	}
	if rep.Hardening.PIE == nil {
		t.Errorf("expected PIE hardening flag to be populated")
	}
	t.Logf("format=%s arch=%s verdict=%s score=%d findings=%d",
		rep.TargetFormat, rep.TargetArch, rep.Verdict, rep.Score, len(rep.Findings))
}
