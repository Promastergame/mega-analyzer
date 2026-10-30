package main

import (
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/decisionai"
)

func TestDecisionAIFlagsAndEnvironment(t *testing.T) {
	t.Setenv("MEGA_DECISION_AI_URL", "http://localhost:17480")
	opts, err := NewCLIParser().Parse([]string{"-t", "demo/vulnerable-app"})
	if err != nil || opts.DecisionAIURL != "http://127.0.0.1:17480" || opts.DecisionAIMaxFindings != 64 || opts.DecisionAIBudget != 30 {
		t.Fatalf("environment/defaults: %+v, %v", opts, err)
	}
	opts, err = NewCLIParser().Parse([]string{"-decision-ai-url=", "-t", "demo/vulnerable-app"})
	if err != nil || opts.DecisionAIURL != "" {
		t.Fatal("explicit opt-out did not override environment")
	}
	t.Setenv("MEGA_DECISION_AI_URL", "")
	opts, err = NewCLIParser().Parse([]string{"-decision-ai-input", "request.json"})
	if err != nil || opts.DecisionAIURL != decisionai.DefaultURL {
		t.Fatalf("standalone defaults not resolved before dispatch: %+v %v", opts, err)
	}
	if err := opts.Validate(); err != nil {
		t.Fatalf("standalone request should not require a scan target: %v", err)
	}
}

func TestDecisionAIRejectsInvalidOptionsBeforeDispatch(t *testing.T) {
	t.Setenv("MEGA_DECISION_AI_URL", "")
	for _, args := range [][]string{
		{"-decision-ai-url", "https://example.com"},
		{"-decision-ai-input", "request.json", "-decision-ai-budget", "0"},
		{"-decision-ai-input", "request.json", "-decision-ai-max-findings", "513"},
		{"-decision-ai-input", "request.json", "-web"},
		{"-decision-ai-input", "request.json", "-t", "app.apk"},
	} {
		if _, err := NewCLIParser().Parse(args); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}

func TestDecisionAIReportArtifacts(t *testing.T) {
	dir := t.TempDir()
	if err := writeDecisionAIReports(dir, decisionai.Report{SchemaVersion: 1, AdvisoryOnly: true, Status: "unavailable", Total: 3, Skipped: 3, Error: "service offline"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"decision_ai.json", "DECISION_AI.txt"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || len(b) == 0 {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
}
