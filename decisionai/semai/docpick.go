package semai

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// Document picker: "which of these files answers my question?" — e.g. which skill.md is for React.
// Scoring = BM25 over words (+ camelCase parts) + a small tech concept lexicon (ru/en aliases and code
// markers such as `useState`, `func main`) + file-name match, then a softmax over files plus a
// "none of them" option. Temperature and the none-score were fitted on a synthetic benchmark
// (docpick_bench_test.go); probabilities are honest only for that kind of task.

type Doc struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type DocScore struct {
	Name     string   `json:"name"`
	Prob     float64  `json:"probability"`
	Score    float64  `json:"score"`
	Matched  []string `json:"matched"`
	Concepts []string `json:"concepts,omitempty"`
}

type DocPick struct {
	Answer     string     `json:"answer"` // file name or "none"
	Confidence float64    `json:"confidence"`
	Ranking    []DocScore `json:"ranking"`
	NoneProb   float64    `json:"none_probability"`
	Query      []string   `json:"query_concepts,omitempty"`
	Reasoning  []string   `json:"reasoning"`
}

// fitted on the synthetic benchmark (see docpick_bench_test.go)
var (
	DocTemp      = 0.30
	DocNoneScore = 1.10
)

type concept struct {
	name    string
	aliases []string // lowercase words or stems; "~" prefix = substring marker in raw text
}

var concepts = []concept{
	{"react", []string{"react", "реакт", "реакта", "реакте", "реактом", "jsx", "tsx", "usestate", "useeffect", "usememo", "usecallback", "useref", "props", "hooks", "хуки", "хук", "nextjs", "next.js", "~import react", "~from 'react'", "~from \"react\"", "redux", "компонент", "компоненты", "component", "components"}},
	{"vue", []string{"vue", "вью", "nuxt", "pinia", "vuex", "~<template>"}},
	{"angular", []string{"angular", "ангуляр", "ngmodule", "rxjs"}},
	{"svelte", []string{"svelte", "свелт", "sveltekit"}},
	{"javascript", []string{"javascript", "js", "джаваскрипт", "жс", "node", "nodejs", "npm", "~console.log", "~const ", "es6"}},
	{"typescript", []string{"typescript", "ts", "тайпскрипт", "~interface ", "tsconfig"}},
	{"css", []string{"css", "tailwind", "scss", "sass", "стили", "верстка", "вёрстка", "flexbox"}},
	{"go", []string{"go", "golang", "гоу", "голанг", "го", "goroutine", "горутины", "горутина", "~func main()", "~package main", "go.mod", "gofmt", "~:= "}},
	{"python", []string{"python", "питон", "пайтон", "py", "pip", "django", "flask", "fastapi", "pandas", "numpy", "~def ", "~import numpy"}},
	{"java", []string{"java", "джава", "ява", "spring", "maven", "gradle", "jvm", "~public static void main"}},
	{"kotlin", []string{"kotlin", "котлин", "coroutines", "корутины", "~fun ", "compose"}},
	{"android", []string{"android", "андроид", "apk", "смали", "smali", "apktool", "activity", "manifest", "dalvik", "dex"}},
	{"swift", []string{"swift", "свифт", "ios", "swiftui", "xcode", "айос"}},
	{"rust", []string{"rust", "раст", "cargo", "~fn main()", "borrow", "крейт", "crate"}},
	{"cpp", []string{"c++", "cpp", "плюсы", "~#include", "cmake"}},
	{"csharp", []string{"c#", "csharp", "шарп", ".net", "dotnet", "unity", "юнити"}},
	{"php", []string{"php", "пхп", "laravel", "~<?php"}},
	{"ruby", []string{"ruby", "руби", "rails"}},
	{"sql", []string{"sql", "скуль", "postgres", "postgresql", "mysql", "sqlite", "запрос", "запросы", "~select ", "база", "бд", "database"}},
	{"docker", []string{"docker", "докер", "dockerfile", "контейнер", "контейнеры", "compose", "kubernetes", "k8s", "кубер", "кубернетес", "helm"}},
	{"git", []string{"git", "гит", "github", "коммит", "commit", "merge", "rebase", "ветка"}},
	{"testing", []string{"test", "tests", "тест", "тесты", "тестирование", "jest", "pytest", "unittest", "vitest", "coverage"}},
	{"security", []string{"security", "безопасность", "уязвимость", "уязвимости", "xss", "csrf", "owasp", "pentest"}},
	{"ml", []string{"ml", "нейросеть", "нейросети", "pytorch", "tensorflow", "обучение", "модель", "llm", "transformer", "трансформер"}},
	{"design", []string{"дизайн", "design", "figma", "фигма", "ui", "ux", "интерфейс"}},
	{"writing", []string{"текст", "статья", "статьи", "copywriting", "копирайтинг", "пост", "пиши", "write", "writing", "essay"}},
}

var conceptIdx = func() map[string][]int {
	m := map[string][]int{}
	for i, c := range concepts {
		for _, a := range c.aliases {
			if !strings.HasPrefix(a, "~") {
				m[a] = append(m[a], i)
			}
		}
	}
	return m
}()

var camelRE = regexp.MustCompile(`[A-Z]?[a-z]+|[A-Z]+(?:[a-z]+)?|\d+`)
var wordRE = regexp.MustCompile(`[\p{L}\d][\p{L}\d+#.]*`)

// docTokens returns lowercased words (+ camelCase parts), trimming trailing dots.
func docTokens(s string) []string {
	var out []string
	for _, w := range wordRE.FindAllString(s, -1) {
		w = strings.TrimRight(w, ".")
		if w == "" {
			continue
		}
		lw := strings.ToLower(strings.ReplaceAll(w, "ё", "е"))
		out = append(out, lw)
		if parts := camelRE.FindAllString(w, -1); len(parts) > 1 {
			for _, p := range parts {
				out = append(out, strings.ToLower(p))
			}
		}
	}
	return out
}

func conceptsOf(raw string, toks []string, short bool) map[int]float64 {
	got := map[int]float64{}
	low := strings.ToLower(raw)
	for _, t := range toks {
		for _, i := range conceptIdx[t] {
			// 1–2 letter aliases ("go", "js", "го") only count in short texts (queries/names), not prose
			if len([]rune(t)) <= 2 && !short {
				continue
			}
			got[i]++
		}
		if t != stem(t) {
			for _, i := range conceptIdx[stem(t)] {
				got[i] += 0.5
			}
		}
	}
	for i, c := range concepts {
		for _, a := range c.aliases {
			if strings.HasPrefix(a, "~") && strings.Contains(low, a[1:]) {
				got[i] += 2
			}
		}
	}
	return got
}

// ruEn is a small ru→en glossary so Russian questions match English skill files.
var ruEn = map[string][]string{
	"кнопк": {"button"}, "счетчик": {"counter"}, "счётчик": {"counter"}, "фронт": {"frontend"}, "фронтенд": {"frontend"}, "бэкенд": {"backend"}, "бекенд": {"backend"},
	"сервис": {"service", "services"}, "сервер": {"server", "backend"}, "ошибк": {"error", "errors"}, "таблиц": {"table", "tables"}, "прочита": {"read"}, "чита": {"read"},
	"секрет": {"secrets"}, "парол": {"secrets", "auth"}, "репозитор": {"git", "repository"}, "безопасн": {"security"}, "абзац": {"paragraph"}, "мысл": {"idea"},
	"залог": {"voice"}, "вод": {"filler"}, "пост": {"posts"}, "стать": {"articles"}, "образ": {"image", "images"}, "запрос": {"query", "queries"}, "индекс": {"indexes"},
	"медлен": {"slow"}, "компонент": {"components", "component"}, "состоян": {"state"}, "тест": {"test", "tests"}, "сборк": {"build"}, "подпис": {"sign"},
	"пересобра": {"rebuild"}, "ветк": {"branches", "branch"}, "коммит": {"commits"}, "слиян": {"merge"}, "данн": {"data"}, "скрипт": {"scripts"}, "числ": {"numbers"},
	"ввод": {"input"}, "вывод": {"output"}, "проверк": {"check", "review"}, "развернут": {"deploy"}, "деплой": {"deploy"}, "задеплои": {"deploy"}, "контейнер": {"containers"},
	"интерфейс": {"interface", "ui"}, "рендеринг": {"rendering", "ssr"}, "серверн": {"server", "ssr"}, "патч": {"patch"}, "пропатчи": {"patch"}, "распакова": {"decode"},
}

func glossary(t string) []string {
	if v, ok := ruEn[t]; ok {
		return v
	}
	if v, ok := ruEn[stem(t)]; ok {
		return v
	}
	r := []rune(t)
	for n := len(r) - 1; n >= 3; n-- {
		if v, ok := ruEn[string(r[:n])]; ok {
			return v
		}
	}
	return nil
}

var docStop = map[string]bool{"md": true, "txt": true, "skill": false, "file": true, "файл": true, "нужен": true, "нужна": true, "нужно": true, "какой": true, "какая": true, "какие": true, "для": true, "ии": true, "ai": true, "кода": true, "код": true, "code": true}

// PickDoc ranks docs for the question.
func PickDoc(question string, docs []Doc, enc *Encoder) DocPick {
	qt := docTokens(question)
	var qs []string
	for _, t := range qt {
		if !stopWords[t] && !docStop[t] {
			qs = append(qs, stem(t))
			for _, g := range glossary(t) {
				qs = append(qs, stem(g))
			}
		}
	}
	qc := conceptsOf(question, qt, true)
	out := DocPick{Answer: "none", Reasoning: []string{}}
	for i := range qc {
		out.Query = append(out.Query, concepts[i].name)
	}
	sort.Strings(out.Query)
	if len(docs) == 0 {
		out.Reasoning = append(out.Reasoning, "файлов нет")
		return out
	}
	// BM25 statistics
	type dstat struct {
		tf   map[string]float64
		len  float64
		conc map[int]float64
		name map[string]bool
	}
	st := make([]dstat, len(docs))
	df := map[string]float64{}
	var avg float64
	for i, d := range docs {
		toks := docTokens(d.Content)
		nameToks := docTokens(strings.NewReplacer("/", " ", "\\", " ", "_", " ", "-", " ").Replace(d.Name))
		s := dstat{tf: map[string]float64{}, name: map[string]bool{}}
		for _, t := range toks {
			s.tf[stem(t)]++
		}
		for _, t := range nameToks {
			s.name[stem(t)] = true
			s.tf[stem(t)] += 2
		}
		s.len = float64(len(toks) + 2*len(nameToks))
		s.conc = conceptsOf(d.Content, toks, false)
		for i, v := range conceptsOf(d.Name, nameToks, true) {
			s.conc[i] += 2 * v
		}
		for t := range s.tf {
			df[t]++
		}
		avg += s.len
		st[i] = s
	}
	avg /= float64(len(docs))
	n := float64(len(docs))
	var qconc float64
	for _, v := range qc {
		qconc += math.Min(v, 1)
	}
	scores := make([]float64, len(docs))
	for i, d := range docs {
		s := st[i]
		var matched []string
		bm := 0.0
		seen := map[string]bool{}
		for _, q := range qs {
			if seen[q] {
				continue
			}
			seen[q] = true
			tf := s.tf[q]
			if tf == 0 {
				continue
			}
			idf := math.Log(1 + (n-df[q]+0.5)/(df[q]+0.5))
			bm += idf * tf * 2.2 / (tf + 1.2*(0.25+0.75*s.len/math.Max(avg, 1)))
			matched = append(matched, q)
		}
		// concept agreement: query concepts present in the doc, penalise docs about other concepts only
		cs, other := 0.0, 0.0
		var dcs []string
		var tot float64
		for _, v := range s.conc {
			tot += v
		}
		for ci, v := range s.conc {
			share := v / math.Max(tot, 1)
			if qc[ci] > 0 {
				cs += math.Min(1, math.Log1p(v)/math.Log(4)) * (0.5 + share)
				dcs = append(dcs, concepts[ci].name)
			} else if share > 0.3 {
				other += share
			}
		}
		if qconc > 0 {
			cs /= qconc
		}
		score := 0.35*bm + 2.2*cs
		if qconc > 0 && cs == 0 {
			score -= 0.8 * other
		}
		// semantic similarity (Transformer) when weights are present
		if enc != nil && strings.TrimSpace(d.Content) != "" {
			a := enc.Encode(question)
			b := enc.Encode(firstChars(d.Name+". "+d.Content, 600))
			score += 1.0 * math.Max(0, Cosine(a.Mean, b.Mean)-0.3)
		}
		sort.Strings(dcs)
		scores[i] = score
		out.Ranking = append(out.Ranking, DocScore{Name: d.Name, Score: round3(score), Matched: matched, Concepts: dcs})
	}
	// softmax over docs + "none"
	mx := DocNoneScore
	for _, s := range scores {
		mx = math.Max(mx, s)
	}
	z := math.Exp((DocNoneScore - mx) / DocTemp)
	ex := make([]float64, len(scores))
	for i, s := range scores {
		ex[i] = math.Exp((s - mx) / DocTemp)
		z += ex[i]
	}
	for i := range out.Ranking {
		out.Ranking[i].Prob = round3(ex[i] / z)
	}
	out.NoneProb = round3(math.Exp((DocNoneScore-mx)/DocTemp) / z)
	sort.SliceStable(out.Ranking, func(a, b int) bool { return out.Ranking[a].Prob > out.Ranking[b].Prob })
	top := out.Ranking[0]
	if top.Prob > out.NoneProb {
		out.Answer, out.Confidence = top.Name, top.Prob
		why := []string{}
		if len(top.Concepts) > 0 {
			why = append(why, "тема: "+strings.Join(top.Concepts, ", "))
		}
		if len(top.Matched) > 0 {
			why = append(why, "совпали слова: "+strings.Join(top.Matched, ", "))
		}
		out.Reasoning = append(out.Reasoning, fmt.Sprintf("%s — %s", top.Name, strings.Join(why, "; ")))
		if len(out.Ranking) > 1 {
			out.Reasoning = append(out.Reasoning, fmt.Sprintf("следующий: %s (%.0f%%)", out.Ranking[1].Name, 100*out.Ranking[1].Prob))
		}
	} else {
		out.Confidence = out.NoneProb
		out.Reasoning = append(out.Reasoning, "ни один файл явно не подходит к вопросу")
	}
	return out
}

func firstChars(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func round3(v float64) float64 { return math.Round(v*1000) / 1000 }
