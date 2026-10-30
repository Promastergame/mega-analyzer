package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func h(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }

func TestBuildAndCheck(t *testing.T) {
	pool := fmt.Sprintf(`{"sha256":"%s","label":"good"}
{"purl":"pkg:maven/org.x/lib@1.0","label":"good"}
{"sha256":"%s","purl":"pkg:pypi/Evil_Pkg@6.6.6","label":"bad"}
`, h("clean-app"), h("evil-app"))
	path := filepath.Join(t.TempDir(), "known.mks")
	var out, errb bytes.Buffer
	if code := run([]string{"-in", "-", "-out", path, "-fpr", "1e-6"}, strings.NewReader(pool), &out, &errb); code != 0 {
		t.Fatalf("build: %d %s", code, errb.String())
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-check", path, "-sha256", h("clean-app")}, "known-good"},
		{[]string{"-check", path, "-sha256", strings.ToUpper(h("evil-app"))}, "known-bad"},
		{[]string{"-check", path, "-sha256", h("stranger")}, "unknown"},
		{[]string{"-check", path, "-purl", "pkg:pypi/evil-pkg@6.6.6"}, "known-bad"},
		{[]string{"-check", path, "-purl", "pkg:maven/org.x/lib@1.0"}, "known-good"},
	} {
		out.Reset()
		errb.Reset()
		if code := run(c.args, nil, &out, &errb); code != 0 || strings.TrimSpace(out.String()) != c.want {
			t.Errorf("%v => %q (code %d, %s), want %q", c.args, out.String(), code, errb.String(), c.want)
		}
	}
}

func TestMalformedPoolFailsAndWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known.mks")
	pool := fmt.Sprintf(`{"sha256":"%s","label":"good"}`+"\nnot json\n", h("a"))
	var out, errb bytes.Buffer
	if code := run([]string{"-in", "-", "-out", path}, strings.NewReader(pool), &out, &errb); code != 3 || !strings.Contains(errb.String(), "malformed") {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	out.Reset()
	if code := run([]string{"-check", path}, nil, &out, &errb); code != 3 {
		t.Fatal("no bundle may exist after a failed build")
	}
}

func TestUnknownLabelIsRejected(t *testing.T) {
	var out, errb bytes.Buffer
	pool := fmt.Sprintf(`{"sha256":"%s","label":"maybe"}`+"\n", h("a"))
	if code := run([]string{"-in", "-", "-out", filepath.Join(t.TempDir(), "k")}, strings.NewReader(pool), &out, &errb); code != 3 {
		t.Fatalf("code=%d", code)
	}
}

func TestConflictAndUnusableWarn(t *testing.T) {
	pool := fmt.Sprintf(`{"sha256":"%s","label":"good"}
{"sha256":"%s","label":"bad"}
{"sha256":"zzz","label":"good"}
`, h("x"), h("x"))
	var out, errb bytes.Buffer
	code := run([]string{"-in", "-", "-out", filepath.Join(t.TempDir(), "k")}, strings.NewReader(pool), &out, &errb)
	if code != 0 || !strings.Contains(errb.String(), "both good and bad") || !strings.Contains(errb.String(), "no usable key") {
		t.Fatalf("code=%d stderr=%s", code, errb.String())
	}
}

func TestUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if run(nil, nil, &out, &errb) != 2 {
		t.Fatal("usage error expected")
	}
	if run([]string{"-check", "/nonexistent/file"}, nil, &out, &errb) != 3 {
		t.Fatal("missing bundle must fail")
	}
}
