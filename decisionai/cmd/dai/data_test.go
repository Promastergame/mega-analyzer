package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"decisionai/s1"
)

func TestDataCommandsWithoutModels(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "data.jsonl")
	valid := `{"group":"project","request":{"state":"ready","questions":{"q":{"type":"noul","instructions":"Ready?"}}},"labels":{"q":true}}`
	if err := os.WriteFile(input, []byte(valid+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"data-check", "distill-export"} {
		output := filepath.Join(dir, command+".json")
		if err := run([]string{command, "-input", input, "-output", output, "-encoder", filepath.Join(dir, "missing.dte")}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(input, []byte(strings.Replace(valid, `"q":true`, `"q":null`, 1)), 0600); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(output)
		if err := run([]string{command, "-input", input, "-output", output}); err == nil {
			t.Fatal("invalid labels must fail before output is opened")
		}
		after, _ := os.ReadFile(output)
		if string(before) != string(after) {
			t.Fatal("invalid input destroyed existing output")
		}
		os.WriteFile(input, []byte(valid), 0600)
	}
}

func TestEvalRejectsInvalidOrEmptyReportWithoutThresholds(t *testing.T) {
	for _, rep := range []s1.EvalReport{{}, {Questions: 1, Errors: []string{"bad label"}}} {
		if err := checkQuality(rep, nil); err == nil {
			t.Fatal("invalid evaluation reported success")
		}
	}
}
