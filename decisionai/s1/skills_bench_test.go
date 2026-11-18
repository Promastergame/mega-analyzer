package s1

import (
	"os"
	"strings"
	"testing"

	"decisionai/semai"
)

// Real-model skill routing regression: 35 realistic skills, three case sets.
// Thresholds sit a little below current numbers so regressions fail loudly.
func realSkillEngine(t *testing.T) *Engine {
	if testing.Short() {
		t.Skip("real-model skill eval skipped in -short")
	}
	enc, err := semai.LoadEncoder("../models/encoder-tiny.dte")
	if err != nil {
		t.Skip("encoder weights not available")
	}
	cal, err := LoadCalibration("../models/s1-calibration.json")
	if err != nil {
		cal = DefaultCalibration()
	}
	e := NewEngine(NewEmbedBackend(enc), cal)
	reg, err := LoadSkillRegistry([]string{"../evals/skills"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.LoadSkillExamples("../evals/skill-examples.jsonl"); err != nil {
		t.Fatal(err)
	}
	e.Skills = reg
	return e
}

func TestSkillRoutingRealModel(t *testing.T) {
	e := realSkillEngine(t)
	for _, tc := range []struct {
		file             string
		minTop1, minTop3 float64
	}{
		{"skill-routing.jsonl", 0.95, 0.97},
		{"skill-routing-holdout.jsonl", 0.93, 0.97},
		{"skill-routing-stress.jsonl", 0.80, 0.90},
		{"skill-routing-blind2.jsonl", 0.88, 0.95},
	} {
		f, err := os.Open("../evals/" + tc.file)
		if err != nil {
			t.Fatal(err)
		}
		cases, err := ReadSkillCases(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		rep, err := e.EvaluateSkills(cases)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: top1=%.3f top3=%.3f other=%.2f false-abstain=%.3f plan=%.2f auto=%.2f@%.2f p50=%.0fms\n%s", tc.file, rep.Top1, rep.Top3,
			rep.OtherRecall, rep.FalseAbstain, rep.PlanExact, rep.AutoRate, rep.AutoAccuracy, rep.LatencyP50, strings.Join(rep.Failures, "\n"))
		if rep.AutoRate > 0 && rep.AutoAccuracy < 0.98 {
			t.Errorf("%s: auto answers must be right: %.3f", tc.file, rep.AutoAccuracy)
		}
		if rep.Top1 < tc.minTop1 || rep.Top3 < tc.minTop3 {
			t.Errorf("%s regressed: top1 %.3f (min %.2f) top3 %.3f (min %.2f)", tc.file, rep.Top1, tc.minTop1, rep.Top3, tc.minTop3)
		}
	}
}

// The request that started it all.
func TestSkillRoutingDesignRequest(t *testing.T) {
	e := realSkillEngine(t)
	resp, err := e.Decide(req(t, `{"state":"найди скилл для ИИ который делает дизайн лучше","questions":{"skill":{"type":"choice","task":"skill_routing","instructions":"Какой скил нужен?"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	a := resp.Answers["skill"]
	if a.Abstained || (a.Choice != "frontend-design" && a.Choice != "artifact-design") {
		t.Fatalf("design request routed to %q: %+v", a.Choice, a)
	}
	if len(a.References) != 1 || !strings.HasSuffix(a.References[0].File, "SKILL.md") {
		t.Fatalf("winner must carry its SKILL.md: %+v", a.References)
	}
	if len(a.Evidence) == 0 || !strings.Contains(a.Evidence[0], "дизайн") {
		t.Fatalf("evidence must name the matched words: %v", a.Evidence)
	}
}
