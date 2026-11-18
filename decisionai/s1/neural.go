package s1

// NeuralInference records an actual specialised forward pass and its input
// scope. A skipped/unavailable result carries no neural prediction.
type NeuralInference struct {
	SchemaVersion  int     `json:"schema_version"`
	Task           string  `json:"task"`
	Status         string  `json:"status"`
	Reason         string  `json:"reason,omitempty"`
	Architecture   string  `json:"architecture"`
	Scope          string  `json:"scope"`
	ModelSHA256    string  `json:"model_sha256,omitempty"`
	InputSHA256    string  `json:"input_sha256,omitempty"`
	FeatureSchema  string  `json:"feature_schema"`
	TargetLine     int     `json:"target_line"`
	GraphNodes     int     `json:"graph_nodes"`
	GraphEdges     int     `json:"graph_edges"`
	ForwardPasses  int     `json:"forward_passes"`
	Threshold      float64 `json:"threshold"`
	RuleVotesAdded bool    `json:"rule_votes_added"`
}

func unavailableNeuralAnswer(q compiled) Answer {
	a, _ := expertAnswer(q, ExpertAnswer{Source: "smalirole-neural", Abstained: true,
		Reason: "literal_role_neural_expert_unavailable", Neural: &NeuralInference{SchemaVersion: 1,
			Task: TaskLiteralRoleNeural, Status: "unavailable", Reason: "literal_role_neural_expert_unavailable",
			Architecture: "relational_gcn", Scope: "single_method_normal_cfg_def_use", FeatureSchema: "smalirole-def-use-v1", Threshold: .8}})
	return a
}
