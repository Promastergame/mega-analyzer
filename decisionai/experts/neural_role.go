package experts

import (
	"encoding/json"
	"fmt"

	"decisionai/s1"
	"decisionai/smalirole"
)

// NeuralRole is deliberately separate from Role, which retains its legacy
// LR/GNN ensemble and explicit rule contributions.
type NeuralRole struct{ Model *smalirole.Model }

func (NeuralRole) Name() string { return "smalirole-neural" }

func (r NeuralRole) Answer(state any, _ string, q s1.ExpertQuestion) (s1.ExpertAnswer, bool) {
	if q.Task != s1.TaskLiteralRoleNeural {
		return s1.ExpertAnswer{}, false
	}
	options := map[string]int{}
	for i, option := range q.Options {
		options[option.Key] = i
	}
	ea := s1.ExpertAnswer{Source: r.Name(), Abstained: true, Neural: &s1.NeuralInference{
		SchemaVersion: 1, Task: smalirole.NeuralTask, Status: "unavailable", Architecture: "relational_gcn",
		Scope: smalirole.NeuralScope, FeatureSchema: smalirole.NeuralFeatureSchema, Threshold: smalirole.NeuralThreshold}}
	if q.Type != s1.TypeChoice || len(options) != len(smalirole.Labels) {
		ea.Reason, ea.Neural.Reason = "literal_role_option_schema_mismatch", "literal_role_option_schema_mismatch"
		return ea, true
	}
	for _, label := range smalirole.Labels {
		if _, ok := options[label]; !ok {
			ea.Reason, ea.Neural.Reason = "literal_role_option_schema_mismatch", "literal_role_option_schema_mismatch"
			return ea, true
		}
	}
	var request smalirole.Request
	data, err := json.Marshal(state)
	if err != nil || json.Unmarshal(data, &request) != nil {
		ea.Reason, ea.Neural.Reason = "invalid_numeric_role_input", "invalid_numeric_role_input"
		return ea, true
	}
	result := smalirole.AnalyzeNeural(request, r.Model)
	ea.Reason, ea.Abstained = result.Reason, result.Abstained
	n := ea.Neural
	n.Status, n.Reason, n.ModelSHA256, n.InputSHA256 = result.Status, result.Reason, result.ModelSHA256, result.InputSHA256
	n.TargetLine, n.GraphNodes, n.GraphEdges, n.ForwardPasses, n.Threshold = result.Line, result.GraphNodes, result.GraphEdges, result.ForwardPasses, result.Threshold
	if result.Status == "predicted" {
		p := make([]float64, len(q.Options))
		for i, label := range smalirole.Labels {
			p[options[label]] = result.Probabilities[i]
		}
		ea.Probs = p
		for _, evidence := range result.Evidence[:min(len(result.Evidence), 8)] {
			ea.Evidence = append(ea.Evidence, fmt.Sprintf("строка %d: %s", evidence.Line, evidence.Text))
		}
	}
	// The new task always remains advisory, including high-scoring outputs.
	ea.Calibrated = false
	return ea, true
}
