package s1

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitClauses(t *testing.T) {
	for in, want := range map[string]int{
		"проанализируй продажи и построй график":                       2,
		"переведи статью на английский, а потом убери следы нейросети": 2,
		"найди баг, потом напиши коммит с фиксом":                      2,
		"сделай презентацию про продажи":                               1,
		"find fresh news and then make a deck":                         2,
	} {
		if got := splitClauses(in); len(got) != want {
			t.Errorf("%q -> %q", in, got)
		}
	}
}

func TestMoneyIsNotTranslation(t *testing.T) {
	if k := tokKeys("переведи 500 рублей маме", true); strings.Contains(k, "#translate") {
		t.Fatalf("payment read as translation: %q", k)
	}
	if k := tokKeys("переведи письмо на английский", true); !strings.Contains(k, "#translate") {
		t.Fatalf("translation lost: %q", k)
	}
}

func TestSkillExamplesLearnAndLoad(t *testing.T) {
	r := testRegistry(t)
	if r.AddExample("nope", "x") {
		t.Fatal("unknown skill must be rejected")
	}
	keys := []string{"agent-browser", "humanizer"}
	before, _ := r.LexScores("залогинься в кабинет банка", keys)
	if !r.AddExample("agent-browser", "залогинься в кабинет и скачай выписку") || r.AddExample("agent-browser", "залогинься в кабинет и скачай выписку") {
		t.Fatal("add once, ignore duplicates")
	}
	after, _ := r.LexScores("залогинься в кабинет банка", keys)
	if after[0] <= before[0] || after[0] <= after[1] {
		t.Fatalf("example must pull the request to its skill: %v -> %v", before, after)
	}
	p := filepath.Join(t.TempDir(), "ex.jsonl")
	os.WriteFile(p, []byte(`{"state":"убери канцелярит","skill":"humanizer"}`+"\n"+`{"state":"x","skill":"missing"}`+"\n"), 0o644)
	r2 := testRegistry(t)
	n, err := r2.LoadSkillExamples(p)
	if err != nil || n != 1 || len(r2.ExamplesOf("humanizer")) != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestFitSkillTemperature(t *testing.T) {
	// confidently right -> sharpen (T<1); confidently wrong half the time -> soften (T>1)
	zs := [][]float64{{3, 0}, {3, 0}, {3, 0}, {3, 0}}
	right := [][]bool{{true, false}, {true, false}, {true, false}, {true, false}}
	mixed := [][]bool{{true, false}, {false, true}, {true, false}, {false, true}}
	if FitSkillTemperature(zs, right) >= 1 || FitSkillTemperature(zs, mixed) <= 1 {
		t.Fatal("temperature direction")
	}
}

func TestSkillAutoNeedsTwoChannels(t *testing.T) {
	r := testRegistry(t)
	cal := DefaultCalibration()
	cal.Temps[TaskSkillRouting], cal.Fitted = 0.3, map[string]int{TaskSkillRouting: 100}
	e := NewEngine(&siteBackend{}, cal)
	e.Skills = r
	// one matched word ("сайты") is never enough for auto
	resp, err := e.Decide(req(t, `{"state":"сайты","questions":{"skill":{"type":"choice","task":"skill_routing","instructions":"Какой скил нужен?"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if a := resp.Answers["skill"]; a.Choice != "agent-browser" || a.Route == "auto" {
		t.Fatalf("%+v", a)
	}
}
