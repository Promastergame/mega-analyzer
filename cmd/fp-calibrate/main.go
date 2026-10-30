// Command fp-calibrate строит сетку порогов под бюджет ложных срабатываний
// (см. pkg/internal/fplevel) из размеченных оценок модели.
//
// Вход — NDJSON, по строке на образец:
//
//	{"route":"dex","label":"benign","score":0.12}
//	{"route":"dex","label":"malicious","score":0.93}
//
// Маршрут "general" собирается автоматически из всех образцов.
//
// Построить сетку:
//
//	fp-calibrate -in scores.ndjson -out grid.json -budgets 0,10,100,1000
//
// Показать порог для маршрута и бюджета:
//
//	fp-calibrate -grid grid.json -route dex -budget 100
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"mega-analyzer/pkg/fplevel"
)

type record struct {
	Route string   `json:"route"`
	Label string   `json:"label"`
	Score *float64 `json:"score"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fp-calibrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "NDJSON with labelled scores ('-' = stdin)")
	out := fs.String("out", "", "grid file to write")
	budgets := fs.String("budgets", "0,10,25,100,250,1000", "comma-separated false-positive budgets per -scale benign samples")
	scale := fs.Int("scale", fplevel.DefaultScale, "benign samples the budget is expressed over")
	minBenign := fs.Int("min-benign", fplevel.DefaultMinBenign, "smallest benign corpus a route needs to stand on its own")
	corpusID := fs.String("corpus-id", "", "free-form corpus identifier stored in the grid")
	gridPath := fs.String("grid", "", "existing grid to query")
	route := fs.String("route", "general", "route to resolve (with -grid)")
	budget := fs.Int("budget", 100, "budget to resolve (with -grid)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *gridPath != "" {
		g, err := fplevel.Load(*gridPath)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 3
		}
		r, err := g.Resolve(*route, *budget)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 3
		}
		fmt.Fprintf(stdout, "route=%s budget=%d threshold=%.6f false_positives=%d recall=%.4f fp_rate_upper_95=%.6f\n",
			r.Route, r.Level.Budget, r.Threshold, r.Level.FalsePositives, r.Level.Recall, r.Level.UpperBound95)
		if r.Warning != "" {
			fmt.Fprintln(stderr, "warning:", r.Warning)
		}
		return 0
	}

	if *in == "" || *out == "" {
		fmt.Fprintln(stderr, "usage: fp-calibrate -in scores.ndjson -out grid.json  |  fp-calibrate -grid grid.json -route R -budget N")
		return 2
	}
	bl, err := parseBudgets(*budgets)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}

	var r io.Reader = stdin
	if *in != "-" {
		f, err := os.Open(*in)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 3
		}
		defer f.Close()
		r = f
	}

	type bucket struct{ benign, pos []float64 }
	routes := map[string]*bucket{}
	get := func(name string) *bucket {
		b := routes[name]
		if b == nil {
			b = &bucket{}
			routes[name] = b
		}
		return b
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	line, bad := 0, 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var rec record
		if err := json.Unmarshal([]byte(text), &rec); err != nil || rec.Score == nil || rec.Route == "" {
			bad++
			continue
		}
		var benign bool
		switch strings.ToLower(rec.Label) {
		case "benign", "good", "clean":
			benign = true
		case "malicious", "bad", "hostile":
		default:
			bad++
			continue
		}
		for _, name := range []string{rec.Route, "general"} {
			b := get(name)
			if benign {
				b.benign = append(b.benign, *rec.Score)
			} else {
				b.pos = append(b.pos, *rec.Score)
			}
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 3
	}
	if bad > 0 {
		// Битая строка — не повод молча получить порог по урезанному корпусу.
		fmt.Fprintf(stderr, "error: %d of %d lines are malformed (need route, label benign|malicious, finite score)\n", bad, line)
		return 3
	}

	g := fplevel.NewGrid(*corpusID)
	g.Scale, g.MinBenign = *scale, *minBenign
	names := make([]string, 0, len(routes))
	for name := range routes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b := routes[name]
		if len(b.benign) == 0 {
			fmt.Fprintf(stderr, "warning: route %q has no benign samples; skipped\n", name)
			continue
		}
		rt, err := fplevel.BuildRoute(b.benign, b.pos, bl, *scale)
		if err != nil {
			fmt.Fprintf(stderr, "error: route %q: %v\n", name, err)
			return 3
		}
		g.Routes[name] = rt
		fmt.Fprintf(stdout, "route %-10s benign=%-7d malicious=%-7d\n", name, rt.Benign, rt.Positives)
	}
	if err := g.Save(*out); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 3
	}
	fmt.Fprintf(stdout, "wrote %s (%d routes)\n", *out, len(g.Routes))
	return 0
}

func parseBudgets(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid budget %q", part)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no budgets given")
	}
	return out, nil
}
