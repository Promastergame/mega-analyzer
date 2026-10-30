package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
)

type ruleThreshold struct {
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
}

func validateThreshold(t ruleThreshold) error {
	for _, v := range []float64{t.Precision, t.Recall} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1 {
			return fmt.Errorf("threshold must be finite and between 0 and 1")
		}
	}
	return nil
}

func loadRuleThresholds(paths []string) (map[string]ruleThreshold, error) {
	if len(paths) == 0 || paths[0] == "" {
		return nil, nil
	}
	data, err := os.ReadFile(paths[0])
	if err != nil {
		return nil, err
	}
	var gates map[string]ruleThreshold
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if err := d.Decode(&gates); err != nil {
		return nil, err
	}
	if len(gates) == 0 {
		return nil, fmt.Errorf("empty rule thresholds")
	}
	for category, gate := range gates {
		if category == "" {
			return nil, fmt.Errorf("empty threshold category")
		}
		if err := validateThreshold(gate); err != nil {
			return nil, fmt.Errorf("%s: %w", category, err)
		}
	}
	return gates, nil
}

func checkRuleThresholds(metrics map[string]counts, gates map[string]ruleThreshold) error {
	var failures []string
	for category, gate := range gates {
		m, ok := metrics[category]
		if !ok || m.TruePositive+m.FalseNegative == 0 {
			failures = append(failures, category+": no scored positive cases")
		} else if m.Precision < gate.Precision || m.Recall < gate.Recall {
			failures = append(failures, fmt.Sprintf("%s: precision %.3f/%.3f, recall %.3f/%.3f", category, m.Precision, gate.Precision, m.Recall, gate.Recall))
		}
	}
	sort.Strings(failures)
	if len(failures) != 0 {
		return fmt.Errorf("category gates failed: %s", strings.Join(failures, "; "))
	}
	return nil
}
