package smalirole

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strings"
)

const NeuralTask = "smali_literal_role_neural"
const NeuralScope = "single_method_normal_cfg_def_use"
const NeuralFeatureSchema = "smalirole-def-use-v1"
const NeuralThreshold = 0.8

// NeuralResult contains the R-GCN output before any LR ensemble or rule votes.
// Input preparation and coverage gates are deterministic; they are not predictions.
type NeuralResult struct {
	Status         string
	Reason         string
	InputSHA256    string
	ModelSHA256    string
	Line           int
	Literal        string
	GraphNodes     int
	GraphEdges     int
	ForwardPasses  int
	Threshold      float64
	PredictedClass string
	Probabilities  []float64
	Evidence       []Evidence
	Abstained      bool
}

func AnalyzeNeural(r Request, model *Model) NeuralResult {
	digest := sha256.Sum256([]byte(r.Code))
	out := NeuralResult{Status: "skipped", InputSHA256: hex.EncodeToString(digest[:]), Line: r.Line,
		Threshold: NeuralThreshold, Abstained: true}
	if model == nil || model.Graph == nil || model.Graph.SHA256() == "" {
		out.Status, out.Reason = "unavailable", "literal_role_gnn_weights_unavailable"
		if model != nil && model.GraphError != "" {
			out.Reason = model.GraphError
		}
		return out
	}
	g := model.Graph
	out.ModelSHA256 = g.SHA256()
	if len(g.Classes) != len(Labels) || g.Relations != SiteRelations || g.Validate() != nil {
		out.Status, out.Reason = "unavailable", "literal_role_gnn_schema_invalid"
		return out
	}
	for i, label := range Labels {
		if g.Classes[i] != label {
			out.Status, out.Reason = "unavailable", "literal_role_gnn_class_order_mismatch"
			return out
		}
	}
	if r.Threshold != nil {
		if math.IsNaN(*r.Threshold) || math.IsInf(*r.Threshold, 0) || *r.Threshold < 0 || *r.Threshold > 1 {
			out.Reason = "invalid_neural_threshold"
			return out
		}
		out.Threshold = *r.Threshold
	}
	if len(r.Code) == 0 || len(r.Code) > 64<<10 || r.Line < 1 || !singleMethod(r.Code) {
		out.Reason = "complete_single_method_required"
		return out
	}
	m := ParseMethod(r.Class, r.Code)
	if len(m.Insns) > 4096 {
		out.Reason = "method_instruction_limit"
		return out
	}
	idx := -1
	for i, in := range m.Insns {
		if in.Line == r.Line {
			idx = i
		}
		if strings.HasPrefix(in.Op, "if-") || strings.HasPrefix(in.Op, "goto") {
			parts := strings.Fields(in.Raw)
			if _, ok := m.Labels[parts[len(parts)-1]]; !ok {
				out.Reason = "branch_target_missing"
				return out
			}
		}
	}
	if idx < 0 {
		out.Reason = "target_is_not_instruction"
		return out
	}
	seen := make([]bool, len(m.Insns))
	work := []int{0}
	for len(work) > 0 {
		i := work[len(work)-1]
		work = work[:len(work)-1]
		if i < 0 || i >= len(seen) || seen[i] {
			continue
		}
		seen[i] = true
		work = append(work, m.succ(i)...)
	}
	if !seen[idx] {
		out.Reason = "unreachable_in_retained_normal_cfg"
		return out
	}
	site, ok := NewSite(m, idx, nil)
	if !ok {
		out.Reason = "numeric_constant_required"
		return out
	}
	out.Literal = site.Literal
	if site.TraceLimited {
		out.Reason = "def_use_trace_limit"
		return out
	}
	if len(site.Uses) == 0 {
		out.Reason = "no_retained_value_use"
		return out
	}
	if len(site.Uses) > 256 {
		out.Reason = "graph_use_limit"
		return out
	}
	if IsFloatUse(site.Sigs) {
		out.Reason = "float_role_outside_taxonomy"
		return out
	}
	if neuralReferenceUse(site) {
		out.Reason = "reference_role_outside_taxonomy"
		return out
	}
	graph := site.Graph(-1)
	out.GraphNodes, out.GraphEdges = len(graph.Feats), len(graph.Edges)
	out.ForwardPasses = 1
	predictions := g.Predict(graph)
	if len(predictions) != 1 || len(predictions[0]) != len(Labels) {
		out.Status, out.Reason = "unavailable", "invalid_neural_output"
		return out
	}
	p := predictions[0]
	sum, best := 0.0, 0
	for i, v := range p {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1 {
			out.Status, out.Reason = "unavailable", "non_finite_neural_output"
			return out
		}
		sum += v
		if v > p[best] {
			best = i
		}
	}
	if math.Abs(sum-1) > 1e-6 {
		out.Status, out.Reason = "unavailable", "unnormalized_neural_output"
		return out
	}
	out.Status, out.PredictedClass, out.Probabilities = "predicted", Labels[best], p
	out.Abstained = p[best] < out.Threshold || Labels[best] == "unknown"
	if out.Abstained {
		out.Reason = "neural_role_uncertain"
	}
	for i, use := range site.Uses {
		out.Evidence = append(out.Evidence, Evidence{Line: use.Insn.Line, Text: use.Insn.Raw, Via: use.Via,
			Tags: site.Sigs[i], Signal: describe(site.Sigs[i])})
	}
	return out
}

// A zero constant can be null in Dalvik. The trained class schema has no
// reference role, so typed reference consumers are a coverage limit, not a
// numeric prediction. Operand positions matter: an object-array index is an int.
func neuralReferenceUse(site *Site) bool {
	for i, use := range site.Uses {
		op := use.Insn.Op
		switch {
		case strings.HasPrefix(op, "invoke-"):
			for _, tag := range site.Sigs[i] {
				if tag == "arg:receiver" || strings.HasPrefix(tag, "arg:type:L") || strings.HasPrefix(tag, "arg:type:[") {
					return true
				}
			}
		case op == "return-object", op == "throw", strings.HasPrefix(op, "monitor-"), op == "check-cast", strings.HasPrefix(op, "move-object"), op == "fill-array-data":
			return true
		case strings.HasPrefix(op, "aget"), op == "array-length", strings.HasPrefix(op, "iget"):
			if use.Pos == 1 {
				return true
			}
		case strings.HasPrefix(op, "aput"), strings.HasPrefix(op, "iput"):
			if use.Pos == 1 || use.Pos == 0 && strings.HasSuffix(op, "-object") {
				return true
			}
		case op == "sput-object":
			return true
		case strings.HasPrefix(op, "filled-new-array"):
			parts := strings.SplitN(use.Insn.Raw, "}", 2)
			if len(parts) == 2 {
				typ := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(parts[1]), ","))
				if strings.HasPrefix(typ, "[L") || strings.HasPrefix(typ, "[[") {
					return true
				}
			}
		}
	}
	return false
}

// Validate the signature before using the legacy parser on arbitrary code.
func singleMethod(code string) bool {
	started, ended := false, false
	for _, raw := range strings.Split(code, "\n") {
		line := stripComment(raw)
		if strings.HasPrefix(line, ".method") {
			if started || ended {
				return false
			}
			parts := strings.Fields(line)
			if len(parts) < 2 || parts[0] != ".method" {
				return false
			}
			sig := parts[len(parts)-1]
			a, b := strings.IndexByte(sig, '('), strings.IndexByte(sig, ')')
			if a <= 0 || b < a || strings.Count(sig, "(") != 1 || strings.Count(sig, ")") != 1 ||
				!validDescriptors(sig[a+1:b], false, false) || !validDescriptors(sig[b+1:], true, true) {
				return false
			}
			started = true
		} else if line == ".end method" {
			if !started || ended {
				return false
			}
			ended = true
		} else if line != "" && (!started || ended) {
			return false
		}
	}
	return started && ended
}

func validDescriptors(text string, single, allowVoid bool) bool {
	count := 0
	for i := 0; i < len(text); {
		array := false
		for i < len(text) && text[i] == '[' {
			array = true
			i++
		}
		if i == len(text) {
			return false
		}
		if text[i] == 'L' {
			end := strings.IndexByte(text[i:], ';')
			if end < 2 {
				return false
			}
			i += end + 1
		} else {
			if !strings.ContainsRune("ZBSCIJFD", rune(text[i])) && !(allowVoid && !array && text[i] == 'V') {
				return false
			}
			i++
		}
		count++
	}
	return !single || count == 1
}
