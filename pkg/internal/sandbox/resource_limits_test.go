package sandbox

import (
	"strings"
	"testing"
)

func TestAnalyzeResourcePressureLevels(t *testing.T) {
	tests := []struct {
		name  string
		usage ResourceUsage
		level string
		score int
	}{
		{name: "idle", usage: ResourceUsage{}, level: "idle", score: 0},
		{name: "medium", usage: ResourceUsage{KernelEventCount: MaxKernelEvents / 2}, level: "medium", score: 50},
		{name: "high", usage: ResourceUsage{DNSQueryCount: MaxDNSQueries * 9 / 10}, level: "high", score: 90},
		{name: "exhausted", usage: ResourceUsage{PCAPSize: MaxPCAPSize + 1}, level: "exhausted", score: 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AnalyzeResourcePressure(tt.usage)
			if got.Level != tt.level {
				t.Fatalf("level = %q, want %q", got.Level, tt.level)
			}
			if got.Score != tt.score {
				t.Fatalf("score = %d, want %d", got.Score, tt.score)
			}
		})
	}
}

func TestAnalyzeResourcePressureNamesResources(t *testing.T) {
	pressure := AnalyzeResourcePressure(ResourceUsage{
		APICallCount:  MaxAPICalls * 85 / 100,
		MemoryUsageMB: TotalMemoryBudget / (1024 * 1024),
	})

	if pressure.Level != "exhausted" {
		t.Fatalf("level = %q, want exhausted", pressure.Level)
	}
	if !containsString(pressure.HighPressureResources, "api_calls") {
		t.Fatalf("expected api_calls high pressure, got %v", pressure.HighPressureResources)
	}
	if !containsString(pressure.ExhaustedResources, "memory") {
		t.Fatalf("expected memory exhaustion, got %v", pressure.ExhaustedResources)
	}
	if pressure.RecommendedAction == "" {
		t.Fatal("expected an operator recommendation")
	}
}

func TestCheckResourceLimitsIncludesMemoryAndHighPressureWarnings(t *testing.T) {
	warnings := CheckResourceLimits(ResourceUsage{
		NetworkConnectionCount: MaxNetworkConnections * 81 / 100,
		MemoryUsageMB:          TotalMemoryBudget / (1024 * 1024),
	})

	if !containsSubstring(warnings, "Sandbox memory budget reached") {
		t.Fatalf("expected memory limit warning, got %v", warnings)
	}
	if !containsSubstring(warnings, "network_connections is above 80%") {
		t.Fatalf("expected high pressure warning, got %v", warnings)
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func containsSubstring(items []string, want string) bool {
	for _, item := range items {
		if strings.Contains(item, want) {
			return true
		}
	}
	return false
}
