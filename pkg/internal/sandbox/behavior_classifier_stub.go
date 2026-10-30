//go:build !windows

package sandbox

import "fmt"

// stubBehaviorClassifier is a no-op implementation for non-Windows platforms.
type stubBehaviorClassifier struct {
	rules []ClassificationRule
}

func newBehaviorClassifier() BehaviorClassifier {
	return &stubBehaviorClassifier{
		rules: DefaultRules(),
	}
}

func (bc *stubBehaviorClassifier) Analyze(events []Event) *BehaviorAnalysis {
	return &BehaviorAnalysis{
		RiskScore:      0,
		Techniques:     []MITRETechnique{},
		Indicators:     []BehaviorIndicator{},
		Classification: "Unknown",
		Confidence:     0.0,
	}
}

func (bc *stubBehaviorClassifier) AddRule(rule ClassificationRule) error {
	return fmt.Errorf("behavior classification is only supported on Windows")
}

func (bc *stubBehaviorClassifier) GetRules() []ClassificationRule {
	return bc.rules
}
