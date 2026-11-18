package s1

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestSkill(t *testing.T, dir, name, desc string) {
	t.Helper()
	d := filepath.Join(dir, name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "---\nname: " + name + "\ndescription: " + desc + "\n---\n\n# " + name + "\n"
	if err := os.WriteFile(filepath.Join(d, "SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func testRegistry(t *testing.T) *SkillRegistry {
	t.Helper()
	dir := t.TempDir()
	writeTestSkill(t, dir, "agent-browser", "Браузер открывает сайты и нажимает кнопки везде.")
	writeTestSkill(t, dir, "humanizer", "Убирает следы машинного письма из длинных текстов.")
	r, err := LoadSkillRegistry([]string{dir}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Skills) != 2 {
		t.Fatalf("%+v", r.Skills)
	}
	return r
}

func TestSkillRegistryLoad(t *testing.T) {
	r := testRegistry(t)
	if r.Skills[0].Name != "agent-browser" || r.Skills[1].Name != "humanizer" {
		t.Fatalf("sorted by name: %+v", r.Skills)
	}
	p, ok := r.PathOf("humanizer")
	if !ok || !strings.HasSuffix(p, "SKILL.md") || !filepath.IsAbs(p) {
		t.Fatalf("%q %v", p, ok)
	}
	if _, ok := r.PathOf("nope"); ok {
		t.Fatal("unknown skill must miss")
	}
	opts, err := r.Expand()
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) != 3 || opts[2].Key != SkillOtherKey {
		t.Fatalf("%+v", opts)
	}
}

func TestSkillRegistryGloss(t *testing.T) {
	dir := t.TempDir()
	writeTestSkill(t, dir, "agent-browser", "Browser opens websites.")
	gp := filepath.Join(dir, "gloss.json")
	if err := os.WriteFile(gp, []byte(`{"agent-browser":"браузер открывает сайты"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := LoadSkillRegistry([]string{dir}, gp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Skills[0].Desc, "браузер открывает сайты") {
		t.Fatalf("%+v", r.Skills[0])
	}
	if _, err := LoadSkillRegistry([]string{dir}, filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing gloss must fail")
	}
}

func TestSkillPrefilterKeepsMatch(t *testing.T) {
	dir := t.TempDir()
	writeTestSkill(t, dir, "agent-browser", "Браузер открывает сайты.")
	for i := 0; i < prefilterLimit+5; i++ {
		writeTestSkill(t, dir, fmt.Sprintf("filler-%02d", i), "Совершенно постороннее описание без пересечений.")
	}
	r, err := LoadSkillRegistry([]string{dir}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Skills) <= prefilterLimit {
		t.Fatalf("want a big registry, got %d", len(r.Skills))
	}
	opts, err := r.ExpandFor("открой сайты в браузере")
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) > prefilterKeep+1 {
		t.Fatalf("too many options: %d", len(opts))
	}
	found, other := false, false
	for _, o := range opts {
		if o.Key == "agent-browser" {
			found = true
		}
		if o.Key == SkillOtherKey {
			other = true
		}
	}
	if !found || !other {
		t.Fatalf("match=%v other=%v in %+v", found, other, opts)
	}
}

func TestSkillRegistryEmpty(t *testing.T) {
	r, err := LoadSkillRegistry([]string{t.TempDir()}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Expand(); err == nil {
		t.Fatal("empty registry must not expand")
	}
}

type siteBackend struct{}

func (*siteBackend) Name() string        { return "site" }
func (*siteBackend) Tokens(s string) int { return len(strings.Fields(s)) }
func (*siteBackend) JudgeBatch(p []Pair) []Judgement {
	out := make([]Judgement, len(p))
	for i := range out {
		out[i] = Judgement{Entail: 0.02, Neutral: 0.03, Contra: 0.95}
		if strings.Contains(p[i].Hypothesis, "сайты") {
			out[i] = Judgement{Entail: 0.9, Neutral: 0.05, Contra: 0.05}
		}
	}
	return out
}

func TestSkillRoutingEndToEnd(t *testing.T) {
	r := testRegistry(t)
	e := NewEngine(&siteBackend{}, DefaultCalibration())
	e.NoLex = true
	e.Skills = r
	resp, err := e.Decide(req(t, `{"state":"открой сайты","questions":{"skill":{"type":"choice","task":"skill_routing","instructions":"Какой скил нужен?"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	a := resp.Answers["skill"]
	if a.Choice != "agent-browser" {
		t.Fatalf("%+v", a)
	}
	if len(a.References) != 1 || !strings.HasSuffix(a.References[0].File, "SKILL.md") {
		t.Fatalf("%+v", a.References)
	}
}

func TestSkillRoutingRejected(t *testing.T) {
	r := testRegistry(t)
	e := NewEngine(&rejecting{}, DefaultCalibration())
	e.NoLex = true
	e.Skills = r
	resp, err := e.Decide(req(t, `{"state":"открой сайты","questions":{"skill":{"type":"choice","task":"skill_routing","instructions":"Какой скил нужен?"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	a := resp.Answers["skill"]
	if a.Choice != SkillOtherKey || !a.Abstained {
		t.Fatalf("%+v", a)
	}
	if len(a.References) != 0 {
		t.Fatalf("other must carry no path: %+v", a.References)
	}
}

func TestSkillRoutingNeedsRegistry(t *testing.T) {
	e := NewEngine(&siteBackend{}, DefaultCalibration())
	_, err := e.Decide(req(t, `{"state":"x","questions":{"skill":{"type":"choice","task":"skill_routing","instructions":"Какой скил нужен?"}}}`))
	if err == nil {
		t.Fatal("registry-less routing must fail loudly, not guess")
	}
}

func TestSkillRoutingWrongType(t *testing.T) {
	e := NewEngine(&siteBackend{}, DefaultCalibration())
	_, err := e.Decide(req(t, `{"state":"x","questions":{"skill":{"type":"noul","task":"skill_routing","instructions":"Какой скил нужен?"}}}`))
	if err == nil {
		t.Fatal("skill_routing requires choice")
	}
}
