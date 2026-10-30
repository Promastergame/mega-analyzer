package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/profile"
)

func fixedNow() func() time.Time {
	base := time.Date(2026, 7, 16, 23, 5, 0, 0, time.UTC)
	return func() time.Time { return base }
}

func TestNewSession_CreatesLayout(t *testing.T) {
	p, _ := profile.Generate(profile.GenSpec{Mode: profile.ModeSeeded, Model: "Pixel 7", API: 34, Seed: 1})
	root := t.TempDir()

	s, err := NewSession(root, p, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != "2026-07-16T230500-panther-api-34" {
		t.Errorf("unexpected session id: %q", s.ID)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "profile.json")); err != nil {
		t.Errorf("profile.json not written: %v", err)
	}
}

func TestSession_Artifacts(t *testing.T) {
	p, _ := profile.Generate(profile.GenSpec{Mode: profile.ModeSeeded, Model: "Pixel 8", API: 35, Seed: 2})
	s, err := NewSession(t.TempDir(), p, fixedNow())
	if err != nil {
		t.Fatal(err)
	}

	st := adapter.NewDeviceState()
	st.Props["ro.product.model"] = "Pixel 8"
	if err := s.SaveBefore(st); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAfter(st); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendCommand("setprop ro.product.model 'Pixel 8'"); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendCommand("dumpsys battery set level 71"); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteReport("html", []byte("<html></html>")); err != nil {
		t.Fatal(err)
	}

	for _, f := range []string{"before.json", "after.json", "commands.log", "report.html"} {
		if _, err := os.Stat(filepath.Join(s.Dir, f)); err != nil {
			t.Errorf("artifact %s missing: %v", f, err)
		}
	}
	data, _ := os.ReadFile(filepath.Join(s.Dir, "commands.log"))
	if lines := len(splitNonEmpty(string(data))); lines != 2 {
		t.Errorf("commands.log has %d lines, want 2", lines)
	}
}

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"Pixel 7": "Pixel-7",
		"a/b\\c":  "abc",
		"":        "session",
		"api.34":  "api-34",
	}
	for in, want := range cases {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, line := range filepathSplitLines(s) {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func filepathSplitLines(s string) []string {
	var lines []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			lines = append(lines, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	lines = append(lines, cur)
	return lines
}
