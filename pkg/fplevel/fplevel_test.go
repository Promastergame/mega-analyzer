package fplevel

import (
	"math"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"
)

func uniformBenign(n int, seed int64) []float64 {
	r := rand.New(rand.NewSource(seed))
	out := make([]float64, n)
	for i := range out {
		out[i] = r.Float64() * 0.8 // чистые в основном ниже 0.8
	}
	return out
}

func TestFalsePositivesNeverExceedBudget(t *testing.T) {
	benign := uniformBenign(5000, 1)
	route, err := BuildRoute(benign, []float64{0.9, 0.95, 0.5}, []int{0, 10, 100, 1000}, 10000)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range route.Levels {
		allowed := l.Budget * 5000 / 10000
		if l.FalsePositives > allowed {
			t.Errorf("budget %d: %d false positives > allowed %d", l.Budget, l.FalsePositives, allowed)
		}
	}
	if route.Levels[0].FalsePositives != 0 {
		t.Errorf("budget 0 must give zero false positives, got %d", route.Levels[0].FalsePositives)
	}
}

func TestLoosenBudgetLowersThresholdAndRaisesRecall(t *testing.T) {
	benign := uniformBenign(4000, 2)
	var pos []float64
	r := rand.New(rand.NewSource(3))
	for i := 0; i < 500; i++ {
		pos = append(pos, 0.4+r.Float64()*0.6)
	}
	route, _ := BuildRoute(benign, pos, []int{0, 25, 250, 2500}, 10000)
	for i := 1; i < len(route.Levels); i++ {
		if route.Levels[i].Threshold > route.Levels[i-1].Threshold {
			t.Fatalf("threshold rose with budget: %+v", route.Levels)
		}
		if route.Levels[i].Recall < route.Levels[i-1].Recall {
			t.Fatalf("recall fell with budget: %+v", route.Levels)
		}
	}
}

func TestTiesDoNotBreakBudget(t *testing.T) {
	// 100 одинаковых оценок: разрезать их пополам нельзя.
	benign := make([]float64, 100)
	for i := range benign {
		benign[i] = 0.5
	}
	route, _ := BuildRoute(benign, nil, []int{0, 5000}, 10000) // допустимо 50 из 100
	if route.Levels[0].FalsePositives != 0 {
		t.Fatalf("budget 0: %+v", route.Levels[0])
	}
	if route.Levels[1].FalsePositives > 50 {
		t.Fatalf("tie group must not exceed budget: %+v", route.Levels[1])
	}
}

func TestSmallCorpusIsNotResolvable(t *testing.T) {
	route, _ := BuildRoute(uniformBenign(50, 4), nil, []int{25, 5000}, 10000)
	if route.Levels[0].Resolvable {
		t.Fatal("25/10000 over 50 samples cannot be resolved")
	}
	if !route.Levels[1].Resolvable {
		t.Fatal("5000/10000 over 50 samples is resolvable")
	}
	// Правило трёх: ноль ложных на 50 образцах ≠ ноль вообще.
	if ub := route.Levels[0].UpperBound95; ub < 0.06 || ub > 0.09 {
		t.Fatalf("wilson upper for 0/50 = %v, want ~0.071", ub)
	}
}

func TestWilsonKnownValues(t *testing.T) {
	if got := wilsonUpper(0, 1000); math.Abs(got-0.00384) > 0.0002 {
		t.Errorf("0/1000 -> %v", got)
	}
	if got := wilsonUpper(50, 100); math.Abs(got-0.5962) > 0.001 {
		t.Errorf("50/100 -> %v", got)
	}
	if wilsonUpper(0, 0) != 1 {
		t.Error("empty sample must be maximally uncertain")
	}
}

func gridWith(routes map[string]Route) *Grid {
	g := NewGrid("test")
	for k, v := range routes {
		g.Routes[k] = v
	}
	return g
}

func TestResolveNeverLooserThanRequested(t *testing.T) {
	route, _ := BuildRoute(uniformBenign(5000, 5), nil, []int{0, 25, 250}, 10000)
	g := gridWith(map[string]Route{"general": route})

	r, err := g.Resolve("general", 100) // между 25 и 250 → 25
	if err != nil || r.Level.Budget != 25 {
		t.Fatalf("got %+v %v", r, err)
	}
	r, _ = g.Resolve("general", 250)
	if r.Level.Budget != 250 {
		t.Fatalf("exact match: %+v", r)
	}
	r, _ = g.Resolve("general", 999999)
	if r.Level.Budget != 250 {
		t.Fatalf("above the grid: %+v", r)
	}
}

func TestResolveStricterThanGridWarns(t *testing.T) {
	route, _ := BuildRoute(uniformBenign(5000, 6), nil, []int{25, 250}, 10000)
	g := gridWith(map[string]Route{"general": route})
	r, _ := g.Resolve("general", 5)
	if r.Level.Budget != 25 || !strings.Contains(r.Warning, "stricter than the strictest") {
		t.Fatalf("%+v", r)
	}
}

func TestResolveFallsBackForMissingAndTinyRoutes(t *testing.T) {
	general, _ := BuildRoute(uniformBenign(5000, 7), nil, []int{25}, 10000)
	tiny, _ := BuildRoute(uniformBenign(40, 8), nil, []int{25}, 10000)
	g := gridWith(map[string]Route{"general": general, "elf": tiny})

	r, _ := g.Resolve("macho", 25)
	if !r.FellBack || r.Route != "general" || !strings.Contains(r.Warning, "no calibration") {
		t.Fatalf("missing route: %+v", r)
	}
	r, _ = g.Resolve("elf", 25)
	if !r.FellBack || r.Route != "general" || !strings.Contains(r.Warning, "only 40 benign") {
		t.Fatalf("tiny route: %+v", r)
	}
	r, _ = g.Resolve("general", 25)
	if r.FellBack {
		t.Fatalf("general itself must not fall back: %+v", r)
	}
}

func TestBuildRejectsBadInput(t *testing.T) {
	ok := []float64{0.1}
	cases := []struct {
		name    string
		benign  []float64
		pos     []float64
		budgets []int
		scale   int
	}{
		{"empty benign", nil, nil, []int{1}, 100},
		{"nan", []float64{math.NaN()}, nil, []int{1}, 100},
		{"inf positive", ok, []float64{math.Inf(1)}, []int{1}, 100},
		{"no budgets", ok, nil, nil, 100},
		{"negative budget", ok, nil, []int{-1}, 100},
		{"duplicate budget", ok, nil, []int{1, 1}, 100},
		{"zero scale", ok, nil, []int{1}, 0},
	}
	for _, c := range cases {
		if _, err := BuildRoute(c.benign, c.pos, c.budgets, c.scale); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

func TestSaveLoadRoundTripAndValidation(t *testing.T) {
	route, _ := BuildRoute(uniformBenign(2000, 9), []float64{0.9}, []int{0, 100}, 10000)
	g := gridWith(map[string]Route{"general": route})
	path := filepath.Join(t.TempDir(), "grid.json")
	if err := g.Save(path); err != nil {
		t.Fatal(err)
	}
	back, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := g.Resolve("general", 100)
	b, _ := back.Resolve("general", 100)
	if a.Threshold != b.Threshold {
		t.Fatalf("round trip changed threshold: %v vs %v", a.Threshold, b.Threshold)
	}

	bad := *g
	bad.Fallback = "nope"
	if bad.Validate() == nil {
		t.Fatal("missing fallback must fail validation")
	}
	bad = *NewGrid("x")
	bad.Routes["general"] = Route{Benign: 10, Levels: []Level{{Budget: 1, Threshold: 0.2}, {Budget: 5, Threshold: 0.9}}}
	if bad.Validate() == nil {
		t.Fatal("threshold rising with budget must fail validation")
	}
}
