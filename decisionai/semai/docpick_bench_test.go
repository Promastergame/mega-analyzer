package semai

import (
	"fmt"
	"math"
	"os"
	"testing"
)

// Synthetic benchmark for PickDoc. Skills are written as typical SKILL.md files; queries are written
// separately (ru/en, slang, no file names). Folder names are deliberately uninformative (IMBA/NOTIMBA…).
var benchSkills = map[string]string{
	"react":    "# Frontend components\nUse function components and hooks (useState, useEffect, useMemo). Keep props typed with TypeScript, colocate styles, prefer composition. Example:\n```tsx\nimport React, { useState } from 'react'\nexport function Counter(){ const [n,setN]=useState(0); return <button onClick={()=>setN(n+1)}>{n}</button> }\n```\nTest components with React Testing Library.",
	"go":       "# Backend services\nWrite idiomatic code: small interfaces, errors as values, context.Context first arg, goroutines with errgroup. Run gofmt and go vet. Keep go.mod tidy.\n```go\npackage main\nfunc main() { if err := run(); err != nil { log.Fatal(err) } }\n```",
	"python":   "# Data scripts\nUse virtualenv and pip, type hints, pathlib. For tables use pandas, for numbers numpy. Format with black, test with pytest.\n```python\ndef load(path: str) -> pd.DataFrame:\n    return pd.read_csv(path)\n```",
	"android":  "# APK reverse engineering\nDecode with apktool, read smali, find const literals, patch and rebuild, sign with apksigner. Dalvik registers v0..vN, p0 = this. Check AndroidManifest.xml activities.",
	"sql":      "# Database queries\nWrite SELECT with explicit columns, use indexes, avoid N+1, parameterize queries. Postgres EXPLAIN ANALYZE for slow queries. Migrations are versioned.",
	"docker":   "# Containers\nWrite small Dockerfile images (multi-stage), pin base image tags, use docker compose for local stacks, healthchecks. Deploy to Kubernetes with helm charts.",
	"rust":     "# Systems code\nUse cargo, clippy, rustfmt. Ownership and borrow checker: prefer &str over String in args. Errors with thiserror/anyhow.\n```rust\nfn main() { println!(\"hi\"); }\n```",
	"security": "# Security review\nCheck OWASP top 10: XSS, CSRF, SQL injection, auth. Validate input, escape output, least privilege, secrets out of git.",
	"writing":  "# Copywriting\nWrite short clear posts and articles: hook in the first line, one idea per paragraph, active voice, no filler.",
	"vue":      "# Vue apps\nUse the Composition API with <script setup>, Pinia for state, single file components with <template>. Nuxt for SSR.",
	"kotlin":   "# Kotlin/Android apps\nUse Kotlin coroutines and Flow, Jetpack Compose UI, ViewModel, Hilt. fun main() samples, Gradle Kotlin DSL.",
	"git":      "# Git workflow\nSmall commits with clear messages, rebase feature branches, never force-push main, use pull requests and code review on GitHub.",
}

var benchJunk = []Doc{
	{"skibidi.md", "skibidi toilet lore and memes, episode list, favorite characters"},
	{"poop.md", "shopping list: milk, bread, eggs. call grandma on sunday"},
	{"README.md", "This folder contains my notes. Nothing important here."},
}

type benchQ struct {
	q, want string // want = skill key or "none"
}

var benchQueries = []benchQ{
	{"какой скилл для ИИ нужен для реакт кода", "react"},
	{"нужен скилл чтобы писать компоненты на реакте с хуками", "react"},
	{"how do I make a React counter with useState", "react"},
	{"фронтенд на jsx, какой файл дать нейронке", "react"},
	{"скилл для бэкенда на го", "go"},
	{"пишу сервис на golang, горутины, какой скилл", "go"},
	{"which skill for a Go microservice", "go"},
	{"скрипт на питоне для таблиц pandas", "python"},
	{"python data processing skill", "python"},
	{"как распаковать apk и пропатчить smali", "android"},
	{"реверс андроид приложения апктул", "android"},
	{"медленный запрос в postgres, что почитать", "sql"},
	{"написать sql select с индексами", "sql"},
	{"как собрать докер образ", "docker"},
	{"задеплоить в кубер через helm", "docker"},
	{"скилл для раст кода с cargo", "rust"},
	{"borrow checker ругается, какой скилл", "rust"},
	{"проверить сайт на xss и csrf", "security"},
	{"аудит безопасности по owasp", "security"},
	{"написать пост для телеграма", "writing"},
	{"помоги со статьёй, копирайтинг", "writing"},
	{"vue компонент с pinia", "vue"},
	{"composition api script setup", "vue"},
	{"jetpack compose и корутины на котлин", "kotlin"},
	{"как сделать rebase ветки в гит", "git"},
	{"коммиты и pull request на github", "git"},
	{"сделать кнопку-счётчик на фронте", "react"},
	{"сервис падает, где обработать err и context", "go"},
	{"прочитать csv в dataframe", "python"},
	{"подписать пересобранный apk", "android"},
	{"контейнер не проходит healthcheck", "docker"},
	{"интерфейс на compose с viewmodel", "kotlin"},
	{"серверный рендеринг nuxt", "vue"},
	{"секреты попали в репозиторий, что делать по безопасности", "security"},
	{"тесты компонентов testing library", "react"},
	{"N+1 запросов к базе", "sql"},
	{"clippy и rustfmt ругаются", "rust"},
	{"активный залог, без воды, один абзац — одна мысль", "writing"},
	{"рецепт борща", "none"},
	{"какая погода завтра", "none"},
	{"скилл для unity c# игр", "none"},
	{"how to train a cat", "none"},
	{"скилл для swift ios приложения", "none"},
	{"скилл для php laravel", "none"},
}

func benchDocs(skip string) ([]Doc, map[string]string) {
	docs := append([]Doc{}, benchJunk...)
	names := map[string]string{}
	i := 0
	for k, v := range benchSkills {
		if k == skip {
			continue
		}
		dir := []string{"IMBA", "NOTIMBA", "stuff", "x", "misc", "old", "new", "tmp", "a", "b", "c", "d"}[i%12]
		n := fmt.Sprintf("%s%d/skill.md", dir, i)
		names[n] = k
		docs = append(docs, Doc{n, v})
		i++
	}
	return docs, names
}

type benchRow struct {
	scores []float64
	names  []string
	gold   int // index into names, -1 = none
}

func benchRows() []benchRow {
	var rows []benchRow
	for _, bq := range benchQueries {
		docs, names := benchDocs("")
		r := PickDoc(bq.q, docs, nil)
		row := benchRow{gold: -1}
		for i, d := range r.Ranking {
			row.scores = append(row.scores, d.Score)
			row.names = append(row.names, d.Name)
			if names[d.Name] == bq.want {
				row.gold = i
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func evalRows(rows []benchRow, T, s0 float64) (acc, nll, ece float64) {
	type bin struct{ n, conf, ok float64 }
	bins := make([]bin, 10)
	for _, r := range rows {
		mx := s0
		for _, s := range r.scores {
			mx = math.Max(mx, s)
		}
		z := math.Exp((s0 - mx) / T)
		for _, s := range r.scores {
			z += math.Exp((s - mx) / T)
		}
		pn := math.Exp((s0-mx)/T) / z
		best, bp := -1, pn
		for i, s := range r.scores {
			if p := math.Exp((s-mx)/T) / z; p > bp {
				best, bp = i, p
			}
		}
		pg := pn
		if r.gold >= 0 {
			pg = math.Exp((r.scores[r.gold]-mx)/T) / z
		}
		nll -= math.Log(math.Max(pg, 1e-9))
		ok := 0.0
		if best == r.gold {
			ok = 1
			acc++
		}
		b := int(math.Min(9, bp*10))
		bins[b].n++
		bins[b].conf += bp
		bins[b].ok += ok
	}
	n := float64(len(rows))
	for _, b := range bins {
		if b.n > 0 {
			ece += b.n / n * math.Abs(b.conf/b.n-b.ok/b.n)
		}
	}
	return acc / n, nll / n, ece
}

// go test ./semai -run TestDocPickFit -v   (prints the fitted temperature / none score; DOCPICK_FIT=1 to fit)
func TestDocPickFit(t *testing.T) {
	rows := benchRows()
	var train, test []benchRow
	for i, r := range rows {
		if i%2 == 0 {
			train = append(train, r)
		} else {
			test = append(test, r)
		}
	}
	if os.Getenv("DOCPICK_FIT") != "" {
		bT, bS, best := 0.0, 0.0, math.Inf(1)
		for T := 0.3; T <= 3; T += 0.05 { // T >= 0.3: a tiny separable benchmark would otherwise push T→0
			for s0 := 0.0; s0 <= 4; s0 += 0.1 {
				if _, nll, _ := evalRows(train, T, s0); nll < best {
					bT, bS, best = T, s0, nll
				}
			}
		}
		t.Logf("fitted on even queries: T=%.2f none=%.2f train NLL=%.3f", bT, bS, best)
	}
	acc, nll, ece := evalRows(test, DocTemp, DocNoneScore)
	accAll, _, _ := evalRows(rows, DocTemp, DocNoneScore)
	t.Logf("held-out (odd) queries n=%d: acc=%.3f NLL=%.3f ECE=%.3f; all n=%d acc=%.3f", len(test), acc, nll, ece, len(rows), accAll)
	for _, bq := range benchQueries {
		docs, names := benchDocs("")
		r := PickDoc(bq.q, docs, nil)
		got := names[r.Answer]
		if r.Answer == "none" {
			got = "none"
		}
		if got != bq.want {
			t.Logf("miss: %q want %s got %s (%.2f)", bq.q, bq.want, r.Answer, r.Confidence)
		}
	}
	if acc < 0.8 {
		t.Errorf("docpick held-out accuracy %.2f < 0.8", acc)
	}
}

func TestDocPickExample(t *testing.T) {
	docs := []Doc{
		{"skibidi.md", "skibidi"},
		{"poop.md", "poop"},
		{"IMBA/skill.md", benchSkills["react"]},
		{"NOTIMBA/skill.md", benchSkills["go"]},
	}
	r := PickDoc("какой скилл для ИИ нужен для реакт кода", docs, nil)
	if r.Answer != "IMBA/skill.md" || r.Confidence < 0.6 {
		t.Fatalf("%+v", r)
	}
	t.Logf("%s %.2f %v", r.Answer, r.Confidence, r.Reasoning)
	r = PickDoc("рецепт борща", docs, nil)
	if r.Answer != "none" {
		t.Fatalf("%+v", r)
	}
}
