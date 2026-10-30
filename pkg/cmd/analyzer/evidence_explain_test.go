package main

import "testing"

func TestEvidenceExplainCLIFlags(t *testing.T) {
	opts, err := NewCLIParser().Parse([]string{"--explain-result", "analysis.json", "--explain-file", "a.smali", "--explain-format", "json"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.ExplainResult != "analysis.json" || opts.ExplainFile != "a.smali" || opts.ExplainFormat != "json" {
		t.Fatalf("unexpected options: %#v", opts)
	}
}
