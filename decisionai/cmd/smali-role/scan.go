package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"decisionai/smalirole"
)

type finding struct {
	Method     string   `json:"method"`
	Line       int      `json:"line"`
	Literal    string   `json:"literal"`
	Value      int64    `json:"value"`
	Role       string   `json:"role"`
	Confidence float64  `json:"confidence"`
	Human      string   `json:"human,omitempty"`
	Stored     []string `json:"stored_fields,omitempty"`
	Sink       string   `json:"sink,omitempty"`
}

// scan analyzes every const literal in app-owned code of an apktool dir and summarizes roles.
func scan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	appDir := fs.String("app", "", "apktool output dir")
	pkg := fs.String("pkg", "", "comma-separated class prefixes to keep, e.g. Lcom/supercell/,Lcom/defract/")
	modelPath := fs.String("model", "", "trained model JSON (optional)")
	thr := fs.Float64("threshold", 0.6, "abstain below this confidence")
	top := fs.Int("top", 25, "findings to print per role")
	roles := fs.String("roles", "duration_ms,limit_threshold,counter_step", "roles to list in detail")
	jsonOut := fs.String("json", "", "write all findings as JSONL here")
	fs.Parse(args)
	if *appDir == "" {
		die(fmt.Errorf("-app is required"))
	}
	var m *smalirole.Model
	var err error
	if *modelPath != "" {
		if m, err = smalirole.LoadModel(*modelPath); err != nil {
			die(err)
		}
	}
	app, err := smalirole.LoadApp(*appDir, false)
	if err != nil {
		die(err)
	}
	var prefixes []string
	for _, p := range strings.Split(*pkg, ",") {
		if p = strings.TrimSpace(p); p != "" {
			prefixes = append(prefixes, p)
		}
	}
	keep := func(cls string) bool {
		if len(prefixes) == 0 {
			return true
		}
		for _, p := range prefixes {
			if strings.HasPrefix(cls, p) {
				return true
			}
		}
		return false
	}
	ctx := app.Ctx()
	keys := make([]string, 0, len(app.Methods))
	for k := range app.Methods {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	counts := map[string]int{}
	byRole := map[string][]finding{}
	total, methods := 0, 0
	var jw *json.Encoder
	if *jsonOut != "" {
		f, err := os.Create(*jsonOut)
		if err != nil {
			die(err)
		}
		defer f.Close()
		jw = json.NewEncoder(f)
		jw.SetEscapeHTML(false)
	}
	for _, k := range keys {
		mt := app.Methods[k]
		if !keep(mt.Class) {
			continue
		}
		methods++
		for i := range mt.Insns {
			s, ok := smalirole.NewSiteCtx(mt, i, ctx)
			if !ok {
				continue
			}
			p, _ := smalirole.Score(s, m)
			best := 0
			for j := range p {
				if p[j] > p[best] {
					best = j
				}
			}
			role, conf := smalirole.Labels[best], p[best]
			if smalirole.IsFloatUse(s.Sigs) {
				role, conf = "float", 0
			} else if conf < *thr {
				role = "unknown"
			}
			total++
			counts[role]++
			f := finding{Method: k, Line: mt.Insns[i].Line, Literal: s.Literal, Value: s.V, Role: role, Confidence: round3(conf), Stored: s.StoredFields()}
			if role == "duration_ms" {
				f.Human = smalirole.HumanMillis(s.V)
			}
			for _, sg := range s.Sigs {
				for _, t := range sg {
					if strings.HasPrefix(t, "sink:") && f.Sink == "" {
						f.Sink = t
					}
				}
			}
			byRole[role] = append(byRole[role], f)
			if jw != nil {
				jw.Encode(f)
			}
		}
	}
	fmt.Printf("files %d, methods %d, consts %d\n", app.Files, methods, total)
	type kv struct {
		k string
		v int
	}
	var cs []kv
	for k, v := range counts {
		cs = append(cs, kv{k, v})
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].v > cs[j].v })
	for _, c := range cs {
		fmt.Printf("  %-16s %6d  %5.1f%%\n", c.k, c.v, 100*float64(c.v)/float64(max(total, 1)))
	}
	for _, r := range strings.Split(*roles, ",") {
		fs := byRole[r]
		if len(fs) == 0 {
			continue
		}
		sort.SliceStable(fs, func(i, j int) bool { return fs[i].Confidence > fs[j].Confidence })
		fmt.Printf("\n== %s (%d) ==\n", r, len(fs))
		for i, f := range fs {
			if i >= *top {
				break
			}
			extra := f.Human
			if len(f.Stored) > 0 {
				extra += " -> " + strings.Join(f.Stored, ",")
			}
			fmt.Printf("  %3.0f%%  %-12s %s  %s:%d\n", 100*f.Confidence, f.Literal, extra, f.Method, f.Line)
		}
	}
}

func round3(x float64) float64 { return float64(int(x*1000+0.5)) / 1000 }
