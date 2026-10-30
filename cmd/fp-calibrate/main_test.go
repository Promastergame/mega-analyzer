package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func corpus(t *testing.T, nBenign int) string {
	t.Helper()
	var b strings.Builder
	r := rand.New(rand.NewSource(1))
	for i := 0; i < nBenign; i++ {
		fmt.Fprintf(&b, `{"route":"dex","label":"benign","score":%.5f}`+"\n", r.Float64()*0.8)
	}
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&b, `{"route":"dex","label":"malicious","score":%.5f}`+"\n", 0.5+r.Float64()*0.5)
	}
	return b.String()
}

func TestBuildThenQuery(t *testing.T) {
	dir := t.TempDir()
	grid := filepath.Join(dir, "grid.json")
	var out, errb bytes.Buffer
	code := run([]string{"-in", "-", "-out", grid, "-budgets", "0,100,1000", "-corpus-id", "unit"}, strings.NewReader(corpus(t, 2000)), &out, &errb)
	if code != 0 {
		t.Fatalf("build failed: %d %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "route dex") || !strings.Contains(out.String(), "route general") {
		t.Fatalf("routes not reported:\n%s", out.String())
	}

	out.Reset()
	errb.Reset()
	if code := run([]string{"-grid", grid, "-route", "dex", "-budget", "100"}, nil, &out, &errb); code != 0 {
		t.Fatalf("query failed: %d %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "route=dex budget=100") {
		t.Fatalf("unexpected query output: %s", out.String())
	}

	out.Reset()
	errb.Reset()
	run([]string{"-grid", grid, "-route", "elf", "-budget", "100"}, nil, &out, &errb)
	if !strings.Contains(errb.String(), "no calibration for route") || !strings.Contains(out.String(), "route=general") {
		t.Fatalf("missing route must fall back with a warning: %q %q", out.String(), errb.String())
	}
}

func TestMalformedInputFailsLoudly(t *testing.T) {
	dir := t.TempDir()
	in := corpus(t, 500) + "not json\n"
	var out, errb bytes.Buffer
	code := run([]string{"-in", "-", "-out", filepath.Join(dir, "g.json")}, strings.NewReader(in), &out, &errb)
	if code != 3 || !strings.Contains(errb.String(), "malformed") {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "g.json")); err == nil {
		t.Fatal("no grid may be written from a partially unreadable corpus")
	}
}

func TestUnknownLabelAndMissingScoreAreRejected(t *testing.T) {
	for _, line := range []string{
		`{"route":"dex","label":"maybe","score":0.1}`,
		`{"route":"dex","label":"benign"}`,
		`{"label":"benign","score":0.1}`,
	} {
		var out, errb bytes.Buffer
		code := run([]string{"-in", "-", "-out", filepath.Join(t.TempDir(), "g.json")}, strings.NewReader(line+"\n"), &out, &errb)
		if code != 3 {
			t.Errorf("%s: code=%d", line, code)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	var out, errb bytes.Buffer
	if run(nil, nil, &out, &errb) != 2 {
		t.Fatal("no args must be a usage error")
	}
	if run([]string{"-in", "-", "-out", "x", "-budgets", "a,b"}, strings.NewReader(""), &out, &errb) != 2 {
		t.Fatal("bad budgets must be a usage error")
	}
}
