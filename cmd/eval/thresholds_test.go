package main

import (
	"math"
	"strings"
	"testing"
)

func TestCategoryGateCatchesFailureHiddenByMicro(t *testing.T) {
	gates := map[string]ruleThreshold{"rare": {Precision: 1, Recall: 1}}
	metrics := map[string]counts{"rare": calculate(counts{FalseNegative: 1}), "common": calculate(counts{TruePositive: 100})}
	if calculate(counts{TruePositive: 100, FalseNegative: 1}).Recall < .95 {
		t.Fatal("invalid test setup")
	}
	if err := checkRuleThresholds(metrics, gates); err == nil || !strings.Contains(err.Error(), "rare") {
		t.Fatalf("gate error = %v", err)
	}
	if err := checkRuleThresholds(map[string]counts{}, gates); err == nil {
		t.Fatal("missing category passed")
	}
	metrics["rare"] = calculate(counts{TruePositive: 1})
	if err := checkRuleThresholds(metrics, gates); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidThresholds(t *testing.T) {
	for _, v := range []float64{-1, 1.01, math.NaN(), math.Inf(1)} {
		if validateThreshold(ruleThreshold{Precision: v}) == nil {
			t.Fatalf("accepted %v", v)
		}
	}
}
