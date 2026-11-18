package decisionai

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"mega-analyzer/pkg/internal/sourceevidence"
)

const NeuralRoleTask = "smali_literal_role_neural"
const NeuralRoleScope = "single_method_normal_cfg_def_use"
const MaxNeuralRoles = 128

var neuralRoleLabels = []string{"bitmask", "flag_bit", "sentinel", "color_argb", "layout_param", "boolean",
	"limit_threshold", "counter_step", "duration_ms", "resource_id", "index_or_size", "api_constant", "unknown"}

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

type CodeReviewEntry struct {
	File         string   `json:"file"`
	Method       string   `json:"method"`
	Line         int      `json:"line"`
	LocalLine    int      `json:"local_line"`
	Literal      string   `json:"literal"`
	SourceSHA256 string   `json:"source_sha256"`
	Status       string   `json:"status"`
	Reason       string   `json:"reason,omitempty"`
	ReviewRoute  string   `json:"review_route"`
	Response     Response `json:"response"`
}

type CodeReviewReport struct {
	SchemaVersion int               `json:"schema_version"`
	AdvisoryOnly  bool              `json:"advisory_only"`
	StaticOnly    bool              `json:"static_only"`
	Task          string            `json:"task"`
	Scope         string            `json:"scope"`
	Status        string            `json:"status"`
	InputSHA256   string            `json:"input_sha256"`
	Candidates    int               `json:"numeric_candidates"`
	Selected      int               `json:"selected_candidates"`
	Processed     int               `json:"processed_candidates"`
	Inferred      int               `json:"neural_predictions"`
	Uncertain     int               `json:"uncertain_predictions"`
	Skipped       int               `json:"skipped_candidates"`
	Failed        int               `json:"failed_candidates"`
	NotProcessed  int               `json:"not_processed_candidates"`
	Error         string            `json:"error,omitempty"`
	Entries       []CodeReviewEntry `json:"entries"`
}

// ReviewCodeRoles supplies only retained method code and the numeric definition
// to the explicitly named GNN task. No scanner finding or authored conclusion
// is sent as an input. Responses are freshly queried so changed weights cannot
// reuse predictions from an earlier model under the same source hash.
func ReviewCodeRoles(ctx context.Context, client *Client, source sourceevidence.Report, limit int) CodeReviewReport {
	r := CodeReviewReport{SchemaVersion: 1, AdvisoryOnly: true, StaticOnly: true, Task: NeuralRoleTask,
		Scope: NeuralRoleScope, Status: "complete", InputSHA256: source.SHA256(), Entries: []CodeReviewEntry{}}
	limit = max(0, min(limit, MaxNeuralRoles))
	type candidate struct {
		source    sourceevidence.Source
		localLine int
		literal   string
	}
	var candidates []candidate
	for _, snapshot := range source.Sources {
		if snapshot.Representation != "retained_smali_method" || snapshot.Method == "" {
			continue
		}
		for i, text := range strings.Split(snapshot.Code, "\n") {
			parts := strings.Fields(strings.TrimSpace(text))
			if len(parts) < 3 || !strings.HasPrefix(parts[0], "const") || strings.Contains(parts[0], "string") ||
				strings.Contains(parts[0], "class") || strings.Contains(parts[0], "method") {
				continue
			}
			r.Candidates++
			if len(candidates) < limit {
				candidates = append(candidates, candidate{snapshot, i + 1, parts[2]})
			}
		}
	}
	r.Selected = len(candidates)
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			r.Error = ctx.Err().Error()
			break
		}
		snapshot := candidate.source
		entry := CodeReviewEntry{File: snapshot.File, Method: snapshot.Method, LocalLine: candidate.localLine,
			Literal: candidate.literal, SourceSHA256: snapshot.SHA256, Status: "skipped", ReviewRoute: "human"}
		if snapshot.Line > 0 {
			entry.Line = snapshot.Line + candidate.localLine - 1
		}
		if len(snapshot.Code) > 64<<10 || snapshot.SHA256 != sourceevidence.Digest(snapshot.Code) {
			entry.Reason = "whole_method_input_unavailable"
			r.Skipped++
			r.Processed++
			r.Entries = append(r.Entries, entry)
			continue
		}
		state, _ := json.Marshal(map[string]any{"code": snapshot.Code, "line": candidate.localLine,
			"class": strings.SplitN(snapshot.Method, "->", 2)[0]})
		criteria := map[string]any{}
		for _, label := range neuralRoleLabels {
			criteria[label] = nil
		}
		encoded, _ := json.Marshal(criteria)
		request := Request{State: state, Questions: map[string]Question{"literal_role": {
			Type: "choice", Task: NeuralRoleTask, AbstainKey: "unknown", Criteria: encoded,
			Instructions: json.RawMessage(`"Predict the role of the selected numeric constant using only the literal-role GNN and retained method code."`),
		}}}
		response, err := client.Decide(ctx, request)
		if err != nil {
			r.Error = err.Error()
			break
		}
		entry.Response = response
		answer := response.Answers["literal_role"]
		if err := validateNeuralRole(answer, snapshot, candidate.localLine); err != nil {
			entry.Status, entry.Reason = "failed", err.Error()
			r.Failed++
		} else {
			n := answer.Neural
			entry.Status, entry.Reason = n.Status, n.Reason
			switch n.Status {
			case "predicted":
				r.Inferred++
				if answer.Abstained {
					r.Uncertain++
				} else {
					entry.ReviewRoute = "review"
				}
			case "skipped":
				r.Skipped++
			case "unavailable":
				r.Failed++
			}
		}
		r.Processed++
		r.Entries = append(r.Entries, entry)
	}
	r.NotProcessed = r.Candidates - r.Processed
	if r.Error != "" && r.Processed == 0 || r.Failed > 0 && r.Inferred == 0 {
		r.Status = "unavailable"
	} else if r.NotProcessed > 0 || r.Failed > 0 || r.Skipped > 0 || source.LimitReached || source.Cancelled {
		r.Status = "partial"
	}
	return r
}

func validateNeuralRole(answer Answer, source sourceevidence.Source, localLine int) error {
	n := answer.Neural
	if n == nil || answer.Source != "smalirole-neural" || n.SchemaVersion != 1 || n.Task != NeuralRoleTask ||
		n.Architecture != "relational_gcn" || n.Scope != NeuralRoleScope || n.FeatureSchema != "smalirole-def-use-v1" ||
		n.RuleVotesAdded || !probability(n.Threshold) || math.Abs(n.Threshold-.8) > 1e-6 {
		return fmt.Errorf("neural_role_provenance_mismatch")
	}
	if (n.Status == "skipped" || n.Status == "unavailable") && (answer.Choice != "" || len(answer.Probabilities) != 0 || answer.Confidence != nil) {
		return fmt.Errorf("neural_role_prediction_without_inference")
	}
	if n.Status == "unavailable" && n.ForwardPasses == 0 && answer.Abstained {
		return nil
	}
	if n.InputSHA256 != source.SHA256 || n.TargetLine != localLine || n.Reason != answer.Reason {
		return fmt.Errorf("neural_role_input_mismatch")
	}
	if n.Status == "skipped" && n.ForwardPasses == 0 && answer.Abstained {
		return nil
	}
	weights, err := hex.DecodeString(n.ModelSHA256)
	if n.Status != "predicted" || n.ForwardPasses != 1 || err != nil || len(weights) != 32 ||
		n.GraphNodes <= 0 || n.GraphNodes > 1024 || n.GraphEdges < 0 || n.GraphEdges > 8192 {
		return fmt.Errorf("neural_role_inference_missing")
	}
	if answer.Probabilities[answer.Choice] < .8-.000051 && !answer.Abstained {
		return fmt.Errorf("neural_role_uncertainty_missing")
	}
	for _, p := range answer.Probabilities {
		if p > answer.Probabilities[answer.Choice]+.000051 {
			return fmt.Errorf("neural_role_choice_mismatch")
		}
	}
	return nil
}

func (r CodeReviewReport) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Нейронная оценка ролей числовых констант: %s. Прогнозов: %d; неуверенных: %d; пропущено: %d; ошибок: %d; не обработано: %d.\n",
		r.Status, r.Inferred, r.Uncertain, r.Skipped, r.Failed, r.NotProcessed)
	b.WriteString("R-GCN читает граф использования значения в одном сохранённом методе. Голоса правил не добавлены. Объяснения интерфейса — шаблоны; прогноз сети — распределение классов. Выполнение и вредоносное поведение не устанавливаются.\n")
	if r.Error != "" {
		fmt.Fprintf(&b, "Ошибка нейронного анализа: %s\n", r.Error)
	}
	for _, entry := range r.Entries {
		a := entry.Response.Answers["literal_role"]
		fmt.Fprintf(&b, "  %s · %s:%d · %s = %s (%.4f); %s\n", entry.Method, entry.File, entry.Line, entry.Literal, a.Choice, a.Probabilities[a.Choice], entry.Status)
		if entry.Reason != "" {
			fmt.Fprintf(&b, "    %s\n", entry.Reason)
		}
	}
	b.WriteByte('\n')
	return b.String()
}
