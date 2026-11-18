package s1

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"strings"
)

// Skill routing: the server reads SKILL.md files itself, so clients only send
// {state, questions: {skill: {type: choice, task: skill_routing}}} with no
// criteria. The engine expands the registry into options, answers, and
// attaches the winner's file path as a source reference.

// SkillOtherKey is the escape option appended to every expanded registry.
// Choosing it means "no skill fits" and is reported as unknown.
const SkillOtherKey = "other"

// SkillOtherText is deliberately Russian: the backbone matches Russian best.
const SkillOtherText = "Никакой скил не подходит"

// SkillEntry is one discovered skill.
type SkillEntry struct {
	Name string
	Desc string
	Path string // absolute path to SKILL.md
	Body string // SKILL.md body (first 2000 runes), indexed with a low weight
	// Examples are real requests that were routed to this skill (few-shot
	// memory). They feed both the lexical index and the bi-encoder.
	Examples []string
}

// SkillRegistry is a server-side skill index built from skill directories.
type SkillRegistry struct {
	Skills []SkillEntry
	byName map[string]SkillEntry
	index  *skillIndex
	pos    map[string]int
	mu     sync.RWMutex // AddExample may run while requests are routed
	// NoGloss disables the automatic Russian gloss appended to option texts.
	NoGloss bool
}

// LoadSkillRegistry scans roots (up to 4 levels deep) for SKILL.md files.
// glossPath is an optional JSON object {skill name: Russian gloss} merged in
// front of each description, because the backbone matches Russian best.
func LoadSkillRegistry(roots []string, glossPath string) (*SkillRegistry, error) {
	gloss := map[string]string{}
	if strings.TrimSpace(glossPath) != "" {
		data, err := os.ReadFile(glossPath)
		if err != nil {
			return nil, fmt.Errorf("skills gloss: %v", err)
		}
		if err := json.Unmarshal(data, &gloss); err != nil {
			return nil, fmt.Errorf("skills gloss: %v", err)
		}
	}
	r := &SkillRegistry{byName: map[string]SkillEntry{}}
	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		if err := r.scan(root, 0); err != nil {
			return nil, err
		}
	}
	sort.Slice(r.Skills, func(i, j int) bool { return r.Skills[i].Name < r.Skills[j].Name })
	for i := range r.Skills {
		sk := &r.Skills[i]
		if g, ok := gloss[sk.Name]; ok && strings.TrimSpace(g) != "" {
			sk.Desc = strings.TrimSpace(g) + ". " + sk.Desc
		}
		if len([]rune(sk.Desc)) > 300 {
			sk.Desc = string([]rune(sk.Desc)[:300])
		}
		r.byName[sk.Name] = *sk
	}
	r.reindex()
	return r, nil
}

func (r *SkillRegistry) scan(dir string, depth int) error {
	entries, err := os.ReadDir(dir)
	if err != nil || depth > 4 {
		return err
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if e.IsDir() {
			if err := r.scan(p, depth+1); err != nil {
				return err
			}
			continue
		}
		if !strings.EqualFold(e.Name(), "SKILL.md") {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return err
		}
		name, desc, body, ok := parseSkillFile(p)
		if !ok {
			continue
		}
		if _, dup := r.byName[name]; dup {
			continue // first root wins: an override dir shadows a shared one
		}
		r.byName[name] = SkillEntry{}
		r.Skills = append(r.Skills, SkillEntry{Name: name, Desc: desc, Path: abs, Body: body})
	}
	return nil
}

// parseSkillFile reads name and description from SKILL.md frontmatter,
// falling back to the directory name and the first paragraph.
func parseSkillFile(path string) (name, desc, body string, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", "", false
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	body = text
	if strings.HasPrefix(text, "---") {
		if end := strings.Index(text[3:], "---"); end >= 0 {
			body = text[3+end+3:]
			for _, line := range strings.Split(text[3:3+end], "\n") {
				line = strings.TrimSpace(line)
				low := strings.ToLower(line)
				if strings.HasPrefix(low, "name:") && name == "" {
					name = strings.TrimSpace(line[len("name:"):])
				}
				if strings.HasPrefix(low, "description:") && desc == "" {
					desc = strings.Trim(strings.TrimSpace(line[len("description:"):]), `"'`)
				}
			}
		}
	}
	if name == "" {
		name = filepath.Base(filepath.Dir(path))
	}
	if desc == "" {
		desc = firstBlock(body)
	}
	if name == "" {
		return "", "", "", false
	}
	if r := []rune(body); len(r) > 2000 {
		body = string(r[:2000])
	}
	return name, desc, body, true
}

func firstBlock(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	for _, b := range strings.Split(text, "\n\n") {
		b = strings.TrimSpace(strings.TrimLeft(b, "#* \t"))
		if b != "" {
			return b
		}
	}
	return ""
}

// Expand builds choice options from the registry plus the escape option.
// Small registries pass through untouched; see ExpandFor.
func (r *SkillRegistry) Expand() ([]Option, error) {
	return r.ExpandFor("")
}

// prefilterLimit bounds one expanded question: bigger registries are
// prefiltered by the hybrid lexical ranker (coarse-to-fine), keeping the
// escape option. The bi-encoder caches every option text, so a few dozen
// options per question stay cheap.
const prefilterLimit = 40
const prefilterKeep = 24

func (r *SkillRegistry) reindex() {
	r.index = buildSkillIndex(r.Skills)
	r.pos = map[string]int{}
	for i, sk := range r.Skills {
		r.pos[sk.Name] = i
	}
}

// ExpandFor builds options. Large registries keep the prefilterKeep skills
// with the best lexical score; zero-hit skills only fill remaining slots.
func (r *SkillRegistry) ExpandFor(state string) ([]Option, error) {
	if r == nil || len(r.Skills) == 0 {
		return nil, fmt.Errorf("skill registry is empty")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	idx := make([]int, len(r.Skills))
	for i := range idx {
		idx[i] = i
	}
	if len(r.Skills)+1 > prefilterLimit {
		hits := r.index.score(state)
		sort.SliceStable(idx, func(a, b int) bool { return hits[idx[a]].score > hits[idx[b]].score })
		idx = idx[:prefilterKeep]
		sort.Ints(idx)
	}
	opts := make([]Option, 0, len(idx)+1)
	for _, i := range idx {
		sk := r.Skills[i]
		text := sk.Name + ": " + sk.Desc
		if g := r.index.gloss[i]; g != "" && !r.NoGloss {
			text += " (" + g + ")"
		}
		opts = append(opts, Option{Key: sk.Name, Text: text})
	}
	opts = append(opts, Option{Key: SkillOtherKey, Text: SkillOtherText})
	return opts, nil
}

// LexScores returns the hybrid lexical score and matched query words for
// each option key (0 for unknown keys and the escape option).
func (r *SkillRegistry) LexScores(state string, keys []string) ([]float64, [][]string) {
	sc := make([]float64, len(keys))
	ws := make([][]string, len(keys))
	if r == nil || len(r.Skills) == 0 {
		return sc, ws
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	hits := r.index.score(state)
	for i, k := range keys {
		if p, ok := r.pos[k]; ok {
			sc[i], ws[i] = hits[p].score, hits[p].words
		}
	}
	return sc, ws
}

// MaxExamplesPerSkill bounds the bi-encoder hypotheses per option; the
// lexical index uses every example.
const MaxExamplesPerSkill = 8

// AddExample stores a routed request as a few-shot example. Unknown skills
// and exact duplicates are ignored (returns false).
func (r *SkillRegistry) AddExample(skill, state string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.addExampleNoIndex(skill, state) {
		return false
	}
	r.reindex()
	return true
}

// Has reports whether a skill is in the registry.
func (r *SkillRegistry) Has(skill string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.pos[skill]
	return ok
}

// LoadSkillExamples reads JSONL {"state": "...", "skill": "name"} lines,
// as written by `dai skills-learn` or POST /v1/skills/feedback.
func (r *SkillRegistry) LoadSkillExamples(path string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	n := 0
	for ln, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ex struct {
			State string `json:"state"`
			Skill string `json:"skill"`
		}
		if err := json.Unmarshal([]byte(line), &ex); err != nil {
			return n, fmt.Errorf("%s:%d: %v", path, ln+1, err)
		}
		if r.addExampleNoIndex(ex.Skill, ex.State) {
			n++
		}
	}
	r.reindex()
	return n, nil
}

func (r *SkillRegistry) addExampleNoIndex(skill, state string) bool {
	state = strings.TrimSpace(state)
	i, ok := r.pos[skill]
	if !ok || state == "" {
		return false
	}
	for _, ex := range r.Skills[i].Examples {
		if ex == state {
			return false
		}
	}
	r.Skills[i].Examples = append(r.Skills[i].Examples, state)
	return true
}

// ExamplesOf returns the newest examples of a skill for the bi-encoder.
func (r *SkillRegistry) ExamplesOf(skill string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	i, ok := r.pos[skill]
	if !ok {
		return nil
	}
	ex := r.Skills[i].Examples
	if len(ex) > MaxExamplesPerSkill {
		ex = ex[len(ex)-MaxExamplesPerSkill:]
	}
	return ex
}

// PathOf returns the SKILL.md path for a chosen skill name.
func (r *SkillRegistry) PathOf(name string) (string, bool) {
	sk, ok := r.byName[name]
	if !ok {
		return "", false
	}
	return sk.Path, true
}

// skillStop are filler words ignored by the ranker.
var skillStop = map[string]bool{
	"и": true, "в": true, "на": true, "не": true, "что": true, "это": true,
	"как": true, "для": true, "или": true, "есть": true, "было": true,
	"меня": true, "мне": true, "the": true, "and": true, "for": true,
	"that": true, "this": true, "with": true, "you": true, "your": true,
	"какой": true, "какая": true, "где": true, "нужен": true, "нужно": true,
	"нужна": true, "найди": true, "найти": true, "пожалуйста": true,
	"use": true, "when": true, "using": true, "any": true, "into": true,
	"сделай": true, "сделать": true, "make": true, "help": true, "помоги": true,
	"хочу": true, "чтобы": true, "который": true, "которая": true, "дай": true,
}
