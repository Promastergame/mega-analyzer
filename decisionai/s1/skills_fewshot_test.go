package s1

import (
	"os"
	"strconv"
	"testing"
)

// 2-fold cross-validation on the dev set: route each half with only the
// other half loaded as examples. Run: DAI_FEWSHOT_CV=1 go test ./s1 -run FewShotCV -v
func TestFewShotCV(t *testing.T) {
	if os.Getenv("DAI_FEWSHOT_CV") == "" {
		t.Skip()
	}
	if v := os.Getenv("DAI_EXMIN"); v != "" {
		ExampleMinSupport, _ = strconv.ParseFloat(v, 64)
	}
	f, _ := os.Open("../evals/skill-routing.jsonl")
	cases, _ := ReadSkillCases(f)
	f.Close()
	var top1, other, n, on float64
	for fold := 0; fold < 2; fold++ {
		e := realSkillEngine(t)
		var test []SkillCase
		for i, c := range cases {
			if i%2 == fold {
				test = append(test, c)
			} else if os.Getenv("DAI_NOEX") == "" && len(c.Accept) == 1 && c.Accept[0] != SkillOtherKey {
				e.Skills.addExampleNoIndex(c.Accept[0], c.State)
			}
		}
		e.Skills.reindex()
		rep, _ := e.EvaluateSkills(test)
		top1 += rep.Top1 * float64(len(test))
		n += float64(len(test))
		k := 0.0
		for _, c := range test {
			if c.Accept[0] == SkillOtherKey {
				k++
			}
		}
		other += rep.OtherRecall * k
		on += k
	}
	t.Logf("cv top1=%.3f other=%.3f", top1/n, other/on)
}
