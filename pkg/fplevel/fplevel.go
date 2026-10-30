// Package fplevel калибрует порог срабатывания под допустимую долю ложных
// срабатываний, а не под «магическое число».
//
// Вместо «порог 0.85» пользователь просит «не более N ложных срабатываний на
// 10 000 чистых образцов». Порог для каждого бюджета вычисляется по
// размеченному корпусу чистых образцов и хранится в сетке (Grid) по маршрутам
// (формат файла: dex, elf, pe, ...).
//
// Три честных ограничения заложены в API, а не в документацию:
//
//  1. Порог никогда не мягче запрошенного бюджета: берётся ближайший
//     откалиброванный уровень не выше запроса, интерполяции нет.
//  2. Маленький корпус не умеет измерять маленькие доли. Если ожидаемое число
//     ложных на корпусе меньше единицы, уровень помечен Resolvable=false, а
//     верхняя 95% граница истинной доли (Wilson) не ниже ~3/n.
//  3. Маршрут с малой выборкой не «выдумывает» точность: Resolve откатывается
//     на общий маршрут и говорит об этом в Warning.
package fplevel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
)

// Schema — версия формата файла сетки.
const Schema = "mega.fplevel.v1"

// DefaultScale — знаменатель бюджета: ложных на 10 000 чистых образцов.
const DefaultScale = 10000

// DefaultMinBenign — минимальный размер корпуса маршрута, при котором он
// считается самостоятельным; меньше — откат на общий маршрут.
const DefaultMinBenign = 300

// Level — один откалиброванный уровень.
type Level struct {
	Budget         int     `json:"budget"`          // допустимо ложных на Scale чистых
	Threshold      float64 `json:"threshold"`       // score >= Threshold — срабатывание
	FalsePositives int     `json:"false_positives"` // наблюдено на корпусе
	Recall         float64 `json:"recall"`          // доля пойманных положительных (если были)
	UpperBound95   float64 `json:"fp_rate_upper_95"`
	Resolvable     bool    `json:"resolvable"` // корпус способен измерить этот бюджет
}

// Route — сетка одного маршрута.
type Route struct {
	Benign    int     `json:"benign"`
	Positives int     `json:"positives"`
	Levels    []Level `json:"levels"` // по возрастанию Budget
}

// Grid — сетка по маршрутам.
type Grid struct {
	Schema    string           `json:"schema"`
	Scale     int              `json:"scale"`
	MinBenign int              `json:"min_benign"`
	Fallback  string           `json:"fallback"`
	CorpusID  string           `json:"corpus_id,omitempty"`
	Routes    map[string]Route `json:"routes"`
}

// NewGrid создаёт пустую сетку с общим маршрутом по умолчанию.
func NewGrid(corpusID string) *Grid {
	return &Grid{
		Schema: Schema, Scale: DefaultScale, MinBenign: DefaultMinBenign,
		Fallback: "general", CorpusID: corpusID, Routes: map[string]Route{},
	}
}

// BuildRoute вычисляет уровни маршрута. benign и positives — оценки модели
// (больше = опаснее). budgets — допустимые числа ложных на scale чистых.
func BuildRoute(benign, positives []float64, budgets []int, scale int) (Route, error) {
	if scale <= 0 {
		return Route{}, errors.New("fplevel: scale must be positive")
	}
	if len(benign) == 0 {
		return Route{}, errors.New("fplevel: empty benign corpus")
	}
	if len(budgets) == 0 {
		return Route{}, errors.New("fplevel: no budgets")
	}
	for _, s := range benign {
		if math.IsNaN(s) || math.IsInf(s, 0) {
			return Route{}, errors.New("fplevel: non-finite benign score")
		}
	}
	for _, s := range positives {
		if math.IsNaN(s) || math.IsInf(s, 0) {
			return Route{}, errors.New("fplevel: non-finite positive score")
		}
	}

	bs := append([]int(nil), budgets...)
	sort.Ints(bs)
	for i, b := range bs {
		if b < 0 {
			return Route{}, errors.New("fplevel: negative budget")
		}
		if i > 0 && b == bs[i-1] {
			return Route{}, fmt.Errorf("fplevel: duplicate budget %d", b)
		}
	}

	desc := append([]float64(nil), benign...)
	sort.Sort(sort.Reverse(sort.Float64Slice(desc)))
	n := len(desc)

	r := Route{Benign: n, Positives: len(positives)}
	for _, budget := range bs {
		allowed := int(int64(budget) * int64(n) / int64(scale)) // floor
		var thr float64
		if allowed >= n {
			thr = math.Nextafter(desc[n-1], math.Inf(-1)) // ловим всё
		} else {
			thr = math.Nextafter(desc[allowed], math.Inf(1))
		}
		fp := 0
		for _, s := range desc {
			if s >= thr {
				fp++
			}
		}
		caught := 0
		for _, s := range positives {
			if s >= thr {
				caught++
			}
		}
		recall := 0.0
		if len(positives) > 0 {
			recall = float64(caught) / float64(len(positives))
		}
		r.Levels = append(r.Levels, Level{
			Budget:         budget,
			Threshold:      thr,
			FalsePositives: fp,
			Recall:         recall,
			UpperBound95:   wilsonUpper(fp, n),
			Resolvable:     int64(budget)*int64(n) >= int64(scale),
		})
	}
	return r, nil
}

// wilsonUpper — верхняя граница 95% доверительного интервала Уилсона для доли
// k/n. При k=0 даёт ~3.84/n (близко к «правилу трёх»), то есть «ноль ложных на
// n образцах» не означает «ноль ложных вообще».
func wilsonUpper(k, n int) float64 {
	if n <= 0 {
		return 1
	}
	const z = 1.959963984540054
	p := float64(k) / float64(n)
	nn := float64(n)
	den := 1 + z*z/nn
	centre := p + z*z/(2*nn)
	margin := z * math.Sqrt(p*(1-p)/nn+z*z/(4*nn*nn))
	return math.Min(1, (centre+margin)/den)
}

// Resolved — выбранный порог с пояснением.
type Resolved struct {
	Threshold float64
	Route     string // маршрут, чья сетка реально использована
	Level     Level
	FellBack  bool
	Warning   string // непусто, если точность порога ограничена
}

// Resolve выбирает порог для маршрута и бюджета.
func (g *Grid) Resolve(route string, budget int) (Resolved, error) {
	if budget < 0 {
		return Resolved{}, errors.New("fplevel: negative budget")
	}
	used := route
	fell := false
	warn := ""

	r, ok := g.Routes[route]
	switch {
	case !ok:
		used, fell = g.Fallback, true
		warn = fmt.Sprintf("no calibration for route %q; using %q", route, g.Fallback)
	case r.Benign < g.MinBenign && route != g.Fallback:
		used, fell = g.Fallback, true
		warn = fmt.Sprintf("route %q has only %d benign samples (< %d); using %q", route, r.Benign, g.MinBenign, g.Fallback)
	}
	if fell {
		r, ok = g.Routes[used]
		if !ok {
			return Resolved{}, fmt.Errorf("fplevel: neither route %q nor fallback %q is calibrated", route, g.Fallback)
		}
	}
	if len(r.Levels) == 0 {
		return Resolved{}, fmt.Errorf("fplevel: route %q has no levels", used)
	}

	// Ближайший уровень НЕ мягче запроса; если запрос строже самого строгого
	// уровня, берём самый строгий и предупреждаем.
	chosen := r.Levels[0]
	for _, l := range r.Levels {
		if l.Budget <= budget {
			chosen = l
		}
	}
	if chosen.Budget > budget {
		warn = joinWarn(warn, fmt.Sprintf("requested budget %d is stricter than the strictest calibrated level %d", budget, chosen.Budget))
	}
	if !chosen.Resolvable {
		warn = joinWarn(warn, fmt.Sprintf("corpus of %d benign samples cannot resolve budget %d per %d; the true false-positive rate may be up to %.4f%%",
			r.Benign, chosen.Budget, g.Scale, chosen.UpperBound95*100))
	}
	return Resolved{Threshold: chosen.Threshold, Route: used, Level: chosen, FellBack: fell, Warning: warn}, nil
}

func joinWarn(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// Validate проверяет внутреннюю согласованность сетки.
func (g *Grid) Validate() error {
	if g.Schema != Schema {
		return fmt.Errorf("fplevel: unsupported schema %q (want %q)", g.Schema, Schema)
	}
	if g.Scale <= 0 || g.MinBenign < 0 {
		return errors.New("fplevel: invalid scale/min_benign")
	}
	if _, ok := g.Routes[g.Fallback]; !ok {
		return fmt.Errorf("fplevel: fallback route %q is missing", g.Fallback)
	}
	for name, r := range g.Routes {
		if r.Benign <= 0 || len(r.Levels) == 0 {
			return fmt.Errorf("fplevel: route %q is empty", name)
		}
		for i, l := range r.Levels {
			if math.IsNaN(l.Threshold) || math.IsInf(l.Threshold, 0) {
				return fmt.Errorf("fplevel: route %q level %d has a non-finite threshold", name, l.Budget)
			}
			if i == 0 {
				continue
			}
			prev := r.Levels[i-1]
			if l.Budget <= prev.Budget {
				return fmt.Errorf("fplevel: route %q budgets must strictly increase", name)
			}
			// Мягче бюджет — не выше порог. Иначе «строже» стало бы «мягче».
			if l.Threshold > prev.Threshold {
				return fmt.Errorf("fplevel: route %q threshold rises with budget (%d -> %d)", name, prev.Budget, l.Budget)
			}
		}
	}
	return nil
}

// Load читает и строго проверяет файл сетки (неизвестные поля — ошибка).
func Load(path string) (*Grid, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var g Grid
	if err := dec.Decode(&g); err != nil {
		return nil, fmt.Errorf("fplevel: %s: %w", path, err)
	}
	if err := g.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &g, nil
}

// Save записывает сетку атомарно (временный файл + rename).
func (g *Grid) Save(path string) error {
	if err := g.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
