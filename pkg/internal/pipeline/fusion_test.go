package pipeline

import (
	"testing"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/types"
)

func TestPipelineFusionIntegration(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.EnableCorrelations = true

	p, err := NewPipeline(cfg)
	if err != nil {
		t.Fatalf("failed to create pipeline: %v", err)
	}

	res := &types.AnalysisResult{
		AppPackage:  "com.test.vulnerable",
		Files:       make(map[string]*types.FileAnalysis),
		RuleMatches: []types.Match{},
		MatchesByCategory: map[types.Category]int{
			types.CategoryHardcodedSecret: 2,
			types.CategoryWeakCrypto:      1,
		},
	}
	p.result = res

	// Simulate a file with signals and rule matches
	fa := &types.FileAnalysis{
		Path: "classes.dex",
		Matches: []types.Match{
			{
				Pattern:    "secret/hardcoded-key",
				Severity:   types.SeverityCritical,
				IsCritical: true,
			},
		},
	}
	res.Files["classes.dex"] = fa

	// Get threat detector and simulate signals
	var threatDet *ThreatIndicatorsDetector
	for _, det := range p.allDetectors() {
		if td, ok := det.(*ThreatIndicatorsDetector); ok {
			threatDet = td
			break
		}
	}
	if threatDet == nil {
		t.Fatal("expected ThreatIndicatorsDetector in pipeline")
	}

	agg := threatDet.GetAggregator()
	signals := agg.GetSignals()
	signals.mu.Lock()
	if signals.SignalCounts == nil {
		signals.SignalCounts = make(map[SignalType]int)
	}
	signals.SignalCounts[SignalDexClassLoader] = 2
	signals.SignalCounts[SignalNetworkHTTP] = 3
	signals.SignalCounts[SignalDexSuffix] = 1
	signals.TotalScore = 65
	signals.mu.Unlock()

	// Run post process (or runFusionReports directly to test)
	p.runFusionReports()

	if res.VulnFusionReport == nil {
		t.Error("expected non-nil VulnFusionReport attached to result")
	} else if res.VulnFusionReport.SampleID == "" {
		t.Error("expected SampleID in VulnFusionReport")
	}

	if res.BehaviorFusionReport == nil {
		t.Error("expected non-nil BehaviorFusionReport attached to result")
	} else if res.BehaviorFusionReport.SampleID == "" {
		t.Error("expected SampleID in BehaviorFusionReport")
	}
}

func TestBehaviorAndVulnFusionStandalone(t *testing.T) {
	signals := &ApkSignals{
		SignalCounts: map[SignalType]int{
			SignalBase64Decode: 5,
			SignalNetworkHTTPS: 2,
		},
		TotalScore: 40,
	}
	rep := runBehaviorFusionIntelligence(signals)
	if rep == nil {
		t.Fatal("expected non-nil report from runBehaviorFusionIntelligence")
	}

	res := &types.AnalysisResult{
		AppPackage: "com.test.standalone",
		Hotspots: []types.Hotspot{
			{Path: "classes.dex", Score: 80},
		},
	}
	vulnRep := runVulnDetectorsFusionIntelligence(res)
	if vulnRep == nil {
		t.Fatal("expected non-nil report from runVulnDetectorsFusionIntelligence")
	}
}
