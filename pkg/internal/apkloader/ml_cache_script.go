package apkloader

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ML-APLI-CACHE SCRIPT v1.0
// Predictive cache vulnerability exploitation analyzer.
// Defensive tool: maps attack surface and generates remediation chains.
// ═══════════════════════════════════════════════════════════════════════════════

// MLCacheScriptResult is the output of the predictive cache analysis.
type MLCacheScriptResult struct {
	Package       string              `json:"package"`
	CacheDir      string              `json:"cacheDir"`
	TotalFindings int                 `json:"totalFindings"`
	RiskScore     float64             `json:"riskScore"`    // 0.0 — 1.0
	ExploitChain  []ExploitStep       `json:"exploitChain"` // ordered attack steps
	Predictions   []MLCachePrediction `json:"predictions"`
	Remediation   []RemediationAction `json:"remediation"`
	Conclusion    string              `json:"conclusion"`
}

// MLCachePrediction wraps a raw cache finding with ML-derived scores.
type MLCachePrediction struct {
	Finding       CacheFinding `json:"finding"`
	ExploitProb   float64      `json:"exploitProb"`   // 0.0 — 1.0
	ImpactScore   float64      `json:"impactScore"`   // severity of potential damage (0..1)
	Difficulty    string       `json:"difficulty"`    // trivial | easy | moderate | hard
	AttackVector  string       `json:"attackVector"`  // description
	Prerequisites []string     `json:"prerequisites"` // what attacker needs
}

// ExploitStep is one link in the attack chain.
type ExploitStep struct {
	Step        int    `json:"step"`
	Title       string `json:"title"`
	Description string `json:"description"`
	FindingRef  string `json:"findingRef"` // path or type reference
}

// RemediationAction is a fix recommendation.
type RemediationAction struct {
	Priority   int    `json:"priority"`
	Action     string `json:"action"`
	Target     string `json:"target"`     // file or pattern
	Difficulty string `json:"difficulty"` // trivial | moderate | complex
	EstTime    string `json:"estTime"`    // e.g. "1h", "1d"
}

// RunMLCacheScript executes the full ML-Apli-Cache pipeline.
// It wraps CacheAnalyzer and applies predictive scoring + chain generation.
func RunMLCacheScript(pkg, cacheDir, outputDir string) (*MLCacheScriptResult, error) {
	ca := NewCacheAnalyzer(pkg, cacheDir)
	if err := ca.Scan(); err != nil {
		return nil, fmt.Errorf("cache scan failed: %w", err)
	}

	res := &MLCacheScriptResult{
		Package:  pkg,
		CacheDir: cacheDir,
	}

	// Phase 1: ML scoring per finding
	for _, f := range ca.Findings {
		pred := scoreFinding(f)
		res.Predictions = append(res.Predictions, pred)
	}

	res.TotalFindings = len(res.Predictions)

	// Phase 2: aggregate risk
	res.RiskScore = aggregateRisk(res.Predictions)

	// Phase 3: build exploit chain (ordered by exploitProb desc)
	res.ExploitChain = buildExploitChain(res.Predictions)

	// Phase 4: remediation mapping
	res.Remediation = buildRemediation(res.Predictions)

	// Phase 5: conclusion
	res.Conclusion = generateConclusion(res.RiskScore, res.TotalFindings)

	// Write report
	if outputDir != "" {
		_ = writeMLCacheReport(outputDir, res)
	}

	return res, nil
}

// ─────────────────────────────────────────────────────────────────
// ML SCORING ENGINE
// ─────────────────────────────────────────────────────────────────

func scoreFinding(f CacheFinding) MLCachePrediction {
	pred := MLCachePrediction{Finding: f}

	// Base exploit probability from severity
	baseProb := 0.3
	switch f.Severity {
	case "critical":
		baseProb = 0.95
	case "high":
		baseProb = 0.75
	case "medium":
		baseProb = 0.45
	case "info":
		baseProb = 0.1
	}

	// Type-specific adjustments (simulating an ML model)
	switch f.Type {
	case "api_key":
		pred.ExploitProb = min(baseProb+0.3, 1.0)
		pred.ImpactScore = 0.9
		pred.Difficulty = "trivial"
		pred.AttackVector = "Direct reuse of leaked credential in API calls"
		pred.Prerequisites = []string{"network access to API endpoint"}

	case "token":
		pred.ExploitProb = min(baseProb+0.2, 1.0)
		pred.ImpactScore = 0.85
		pred.Difficulty = "trivial"
		pred.AttackVector = "Session hijacking or unauthorized API access"
		pred.Prerequisites = []string{"token not expired", "same IP or no IP binding"}

	case "unencrypted_save":
		pred.ExploitProb = min(baseProb+0.15, 1.0)
		pred.ImpactScore = 0.6
		pred.Difficulty = "easy"
		pred.AttackVector = "Save file tampering (currency, level, unlocks)"
		pred.Prerequisites = []string{"write access to cache dir", "app trusts local save"}

	case "weak_crypto":
		pred.ExploitProb = min(baseProb+0.1, 1.0)
		pred.ImpactScore = 0.7
		pred.Difficulty = "moderate"
		pred.AttackVector = "Decrypt sensitive data offline or tamper encrypted saves"
		pred.Prerequisites = []string{"reverse engineer crypto routine", "key in binary"}

	case "tracker_config":
		pred.ExploitProb = baseProb * 0.5
		pred.ImpactScore = 0.3
		pred.Difficulty = "hard"
		pred.AttackVector = "Privacy profiling or ad fraud via injected events"
		pred.Prerequisites = []string{"MITM or root to inject events"}

	default:
		pred.ExploitProb = baseProb
		pred.ImpactScore = 0.5
		pred.Difficulty = "moderate"
		pred.AttackVector = "Context-dependent exploitation"
		pred.Prerequisites = []string{"further reconnaissance required"}
	}

	return pred
}

func aggregateRisk(preds []MLCachePrediction) float64 {
	if len(preds) == 0 {
		return 0.0
	}
	// Weighted average with emphasis on highest-probability findings
	var weightedSum float64
	var totalWeight float64
	for _, p := range preds {
		w := 1.0 + p.ExploitProb*2.0 // high-prob findings count more
		weightedSum += p.ExploitProb * p.ImpactScore * w
		totalWeight += w
	}
	score := weightedSum / totalWeight
	if score > 1.0 {
		score = 1.0
	}
	return score
}

func buildExploitChain(preds []MLCachePrediction) []ExploitStep {
	// Sort by exploit probability descending
	sorted := make([]MLCachePrediction, len(preds))
	copy(sorted, preds)
	// simple bubble sort for small slices
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].ExploitProb > sorted[i].ExploitProb {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	var chain []ExploitStep
	for i, p := range sorted {
		if p.ExploitProb < 0.3 {
			continue // skip low-prob
		}
		chain = append(chain, ExploitStep{
			Step:        i + 1,
			Title:       fmt.Sprintf("Exploit %s (%s)", p.Finding.Type, p.Difficulty),
			Description: p.AttackVector,
			FindingRef:  p.Finding.Path,
		})
	}
	return chain
}

func buildRemediation(preds []MLCachePrediction) []RemediationAction {
	var actions []RemediationAction
	seen := make(map[string]bool)

	for _, p := range preds {
		if p.ExploitProb < 0.3 {
			continue
		}
		var action RemediationAction
		switch p.Finding.Type {
		case "api_key", "token":
			action = RemediationAction{
				Priority:   1,
				Action:     "Move credential to Keystore / server-side proxy; rotate immediately",
				Target:     p.Finding.Path,
				Difficulty: "moderate",
				EstTime:    "1d",
			}
		case "unencrypted_save":
			action = RemediationAction{
				Priority:   2,
				Action:     "Encrypt save files with AES-256-GCM or use Android EncryptedSharedPreferences",
				Target:     "*.json / *.xml save files",
				Difficulty: "moderate",
				EstTime:    "2d",
			}
		case "weak_crypto":
			action = RemediationAction{
				Priority:   2,
				Action:     "Replace custom crypto with libsodium or Android Keystore-backed encryption",
				Target:     p.Finding.Path,
				Difficulty: "complex",
				EstTime:    "3d",
			}
		default:
			action = RemediationAction{
				Priority:   3,
				Action:     "Review and harden storage for this file type",
				Target:     p.Finding.Path,
				Difficulty: "moderate",
				EstTime:    "1d",
			}
		}

		key := action.Action + action.Target
		if !seen[key] {
			seen[key] = true
			actions = append(actions, action)
		}
	}

	return actions
}

func generateConclusion(risk float64, count int) string {
	if count == 0 {
		return "No cache vulnerabilities detected. Storage posture is clean."
	}
	if risk >= 0.8 {
		return fmt.Sprintf("CRITICAL: Cache is highly exploitable (risk %.0f%%). Immediate hardening required.", risk*100)
	}
	if risk >= 0.5 {
		return fmt.Sprintf("HIGH: Significant attack surface in cache (risk %.0f%%). Prioritize credential and save encryption.", risk*100)
	}
	return fmt.Sprintf("MODERATE: Some cache findings present (risk %.0f%%). Address unencrypted saves and review configs.", risk*100)
}

func writeMLCacheReport(outputDir string, res *MLCacheScriptResult) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}
	path := filepath.Join(outputDir, "ML_APLI_CACHE_REPORT.json")
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
