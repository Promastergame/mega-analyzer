package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"decisionai/s1"
)

func TestBuildEngineDefersSkillWeights(t *testing.T) {
	model, err := filepath.Abs("../../models/s1-distilled.dte")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(model); os.IsNotExist(err) {
		t.Skip("real weights unavailable")
	}
	previous := distilledPath
	distilledPath = model
	t.Cleanup(func() { distilledPath = previous })
	calib, err := filepath.Abs("../../models/s1-distilled-calibration.json")
	if err != nil {
		t.Fatal(err)
	}
	missingBase := filepath.Join(t.TempDir(), "absent-encoder.dte")
	e, err := buildEngine("s1", missingBase, "", calib, 1)
	if err != nil {
		t.Fatalf("ordinary model required skill weights at startup: %v", err)
	}
	if e.SkillBackend != nil || e.SkillBackendLoader == nil {
		t.Fatal("skill backend was not deferred")
	}
	var general, skill s1.Request
	if err := json.Unmarshal([]byte(`{"state":"The door is open.","questions":{"door":{"type":"noul","instructions":"Is the door open?"}}}`), &general); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"state":"merge PDF files","questions":{"skill":{"type":"choice","task":"skill_routing","instructions":"Choose a skill","criteria":{"pdf":"Read and merge PDF files","xlsx":"Create spreadsheets and charts"}}}}`), &skill); err != nil {
		t.Fatal(err)
	}
	first, err := e.Decide(general)
	if err != nil {
		t.Fatal(err)
	}
	warm, err := e.Decide(general)
	if err != nil {
		t.Fatal(err)
	}
	if first.Usage.ModelCalls == 0 || warm.Usage.ModelCalls != 0 || warm.Usage.CacheHits == 0 {
		t.Fatalf("production engine did not reuse judgements: first=%+v warm=%+v", first.Usage, warm.Usage)
	}
	if _, err := e.Decide(skill); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing skill weights did not surface on first skill request: %v", err)
	}
	if _, err := e.Decide(general); err != nil {
		t.Fatalf("skill failure broke general decisions: %v", err)
	}
}

func TestBuildEngineLoadsLegacySharedTable(t *testing.T) {
	// The bundled NLI DTE omits its word table, like older custom distilled
	// exports. The S1 builder must load its base before wrapping this encoder.
	paths := make([]string, 3)
	for i, name := range []string{"nli-tiny.dte", "encoder-tiny.dte", "s1-distilled-calibration.json"} {
		p, err := filepath.Abs(filepath.Join("../../models", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(p); os.IsNotExist(err) {
			t.Skip("real weights unavailable")
		}
		paths[i] = p
	}
	previous := distilledPath
	distilledPath = paths[0]
	t.Cleanup(func() { distilledPath = previous })
	e, err := buildEngine("s1", paths[1], "", paths[2], 1)
	if err != nil {
		t.Fatalf("legacy shared-table model failed: %v", err)
	}
	if e.Backend == nil || e.SkillBackendLoader == nil {
		t.Fatal("incomplete engine")
	}
}
