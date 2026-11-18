package main

import (
	"slices"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestReputationInputsIncludeDecodedAndBareNetworkAddresses(t *testing.T) {
	r := types.NewAnalysisResult("sample.apk")
	r.Files["Loader.smali"] = &types.FileAnalysis{
		Matches: []types.Match{
			{Categorized: types.Categorized{Category: types.CategoryHardcodedIP}, Pattern: "198.51.100.42:8080"},
			{Categorized: types.Categorized{Category: types.CategoryNetworkEndpoint}, Pattern: "https://controller.example.org/gate"},
		},
		RecoveredArtifacts: []types.RecoveredArtifact{
			{Kind: "domain", Preview: "backup.example.cfd"},
			{Kind: "url", Preview: "https://controller.example.org/gate"},
			{Kind: "domain", Preview: "com.buttonvpn.hjexqm"},
		},
	}
	want := []string{"198.51.100.42:8080", "backup.example.cfd", "https://controller.example.org/gate"}
	if got := extractURLs(r); !slices.Equal(got, want) {
		t.Fatalf("local reputation inputs = %#v, want %#v", got, want)
	}
}
