package experts

import (
	"encoding/json"
	"reflect"
	"testing"

	"decisionai/s1"
	"decisionai/smalirole"
)

func neuralRoleRequest(t *testing.T, decoy bool) s1.Request {
	t.Helper()
	state := map[string]any{"code": ".method public static a(Landroid/widget/TextView;)V\n.registers 3\nconst/16 v0, 0x64\ninvoke-virtual {p0, v0}, Landroid/widget/TextView;->setTextColor(I)V\nreturn-void\n.end method", "line": 3}
	if decoy {
		state["rule_id"] = "malware.confirmed"
		state["notes"] = "This is a dangerous secret, not a color."
	}
	criteria := map[string]any{}
	for _, label := range smalirole.Labels {
		criteria[label] = nil
	}
	s, _ := json.Marshal(state)
	c, _ := json.Marshal(criteria)
	instruction, _ := json.Marshal("Role of the selected number")
	return s1.Request{State: s, Questions: map[string]s1.Question{"role": {Type: s1.TypeChoice, Task: s1.TaskLiteralRoleNeural,
		AbstainKey: "unknown", Instructions: instruction, Criteria: c}}}
}

func TestNeuralRoleContractAndActualCallCount(t *testing.T) {
	model, err := smalirole.LoadModel("../models/smalirole-model.json")
	if err != nil {
		t.Fatal(err)
	}
	e := s1.NewEngine(s1.LexicalBackend{}, s1.DefaultCalibration())
	e.Experts = Default(model, nil)
	response, err := e.Decide(neuralRoleRequest(t, false))
	if err != nil {
		t.Fatal(err)
	}
	a := response.Answers["role"]
	if a.Source != "smalirole-neural" || a.Neural == nil || a.Neural.RuleVotesAdded || a.Neural.ForwardPasses != 1 || response.Usage.ModelCalls != 1 || a.Choice != "color_argb" || a.Route == "auto" {
		t.Fatalf("lost neural provenance: %+v", response)
	}
	decoy, err := e.Decide(neuralRoleRequest(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.Probabilities, decoy.Answers["role"].Probabilities) {
		t.Fatal("scanner-style claims changed the neural code result")
	}
	b, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Answers map[string]struct{ Neural *s1.NeuralInference }
	}
	if json.Unmarshal(b, &decoded) != nil || decoded.Answers["role"].Neural.ModelSHA256 != a.Neural.ModelSHA256 {
		t.Fatal("JSON lost model identity")
	}
}

func TestNeuralTaskDoesNotFallThroughWhenExpertMissing(t *testing.T) {
	for _, experts := range [][]s1.Expert{nil, Default(nil, nil)} {
		e := s1.NewEngine(s1.LexicalBackend{}, s1.DefaultCalibration())
		e.Experts = experts
		response, err := e.Decide(neuralRoleRequest(t, false))
		if err != nil {
			t.Fatal(err)
		}
		a := response.Answers["role"]
		if a.Neural == nil || a.Neural.Status != "unavailable" || !a.Abstained || a.Choice != "" || len(a.Probabilities) != 0 || a.Confidence != nil || response.Usage.ModelCalls != 0 {
			t.Fatalf("absent code model became a text/rule prediction: %+v", response)
		}
	}
}

func TestSkippedNeuralRoleHasNoManufacturedDistribution(t *testing.T) {
	model, err := smalirole.LoadModel("../models/smalirole-model.json")
	if err != nil {
		t.Fatal(err)
	}
	request := neuralRoleRequest(t, false)
	request.State, _ = json.Marshal(map[string]any{"code": ".method static a()V\n.registers 1\nconst/4 v0, 0x0\ninvoke-static {v0}, Lfixture/A;->consume(Ljava/lang/Object;)V\nreturn-void\n.end method", "line": 3})
	e := s1.NewEngine(s1.LexicalBackend{}, s1.DefaultCalibration())
	e.Experts = Default(model, nil)
	response, err := e.Decide(request)
	if err != nil {
		t.Fatal(err)
	}
	a := response.Answers["role"]
	if a.Neural == nil || a.Neural.Status != "skipped" || a.Neural.ForwardPasses != 0 || response.Usage.ModelCalls != 0 || !a.Abstained || a.Choice != "" || len(a.Probabilities) != 0 || a.Confidence != nil {
		t.Fatalf("coverage gate manufactured a model prediction: %+v", response)
	}
	b, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Answers map[string]map[string]json.RawMessage `json:"answers"`
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"choice", "probabilities", "confidence"} {
		if _, exists := wire.Answers["role"][key]; exists {
			t.Fatalf("skipped JSON retained an invented %s", key)
		}
	}
}
