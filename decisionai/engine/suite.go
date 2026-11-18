package engine

import "fmt"

type Expected struct {
	Answers    []string `json:"answers"`
	Decision   string   `json:"decision"`
	Validation string   `json:"validation"`
	HasPlan    bool     `json:"has_plan"`
}
type TestCase struct {
	Name     string   `json:"name"`
	Note     string   `json:"note,omitempty"`
	Input    Request  `json:"input"`
	Expected Expected `json:"expected"`
}
type TestSuite struct {
	Cases []TestCase `json:"cases"`
}
type CaseResult struct {
	Name   string   `json:"name"`
	Passed bool     `json:"passed"`
	Errors []string `json:"errors"`
}
type SuiteResult struct {
	Passed int          `json:"passed"`
	Failed int          `json:"failed"`
	Cases  []CaseResult `json:"cases"`
}

func RunSuite(s TestSuite, finding, patch *Model) (SuiteResult, error) {
	out := SuiteResult{Cases: []CaseResult{}}
	if len(s.Cases) == 0 || len(s.Cases) > 1000 {
		return out, fmt.Errorf("suite needs 1..1000 cases")
	}
	for _, c := range s.Cases {
		res := CaseResult{Name: c.Name, Passed: true, Errors: []string{}}
		rep, e := Analyze(c.Input, finding, patch)
		if e != nil {
			res.Errors = append(res.Errors, e.Error())
		} else {
			if len(rep.Answers) != len(c.Expected.Answers) {
				res.Errors = append(res.Errors, "answer count mismatch")
			} else {
				for i, a := range rep.Answers {
					if a.State != c.Expected.Answers[i] {
						res.Errors = append(res.Errors, fmt.Sprintf("answer %d: got %s, want %s", i, a.State, c.Expected.Answers[i]))
					}
				}
			}
			if rep.Decision != c.Expected.Decision {
				res.Errors = append(res.Errors, "decision: got "+rep.Decision+", want "+c.Expected.Decision)
			}
			if rep.Validation.Status != c.Expected.Validation {
				res.Errors = append(res.Errors, "validation: got "+rep.Validation.Status+", want "+c.Expected.Validation)
			}
			if (rep.Plan != nil) != c.Expected.HasPlan {
				res.Errors = append(res.Errors, "has_plan mismatch")
			}
		}
		res.Passed = len(res.Errors) == 0
		if res.Passed {
			out.Passed++
		} else {
			out.Failed++
		}
		out.Cases = append(out.Cases, res)
	}
	return out, nil
}
