// Package experimental hosts the experimental Mega Analyzer modules: AEG
// (Automated Exploit Generation), Mach-O / iOS support, Binary Similarity
// and Reachability Analysis.
//
// All modules implement the same Module interface so they can be selected
// and orchestrated uniformly via the --ml-ex-apply selector and --aeg flag.
//
// The experimental package is intentionally dependency-light and self-contained:
// it must not import the full pipeline, so it can be wired into the runner
// without creating import cycles.
package experimental

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE INTERFACE
// ═══════════════════════════════════════════════════════════════════════════════

// Module represents a single experimental capability.
//
// Modules MUST be safe to skip entirely. Run() is given a per-module budget
// (Options.PerModuleTimeout) and a shared context — both are honored.
type Module interface {
	// ID returns the stable identifier used by the CLI selector
	// (e.g. "aeg", "macho", "binsim", "reach").
	ID() string

	// Name returns the human readable display name.
	Name() string

	// Description returns a short marketing-friendly blurb.
	Description() string

	// Aliases returns alternate selector tokens (e.g. "ios" -> macho).
	Aliases() []string

	// Tier returns the maturity tier ("experimental", "preview", "alpha").
	Tier() string

	// Run executes the module against the prepared target.
	Run(ctx context.Context, in Input) (*ModuleResult, error)
}

// Input is shared, read-only context passed to every module.
type Input struct {
	TargetDir   string            // Decompiled / extracted target root.
	OriginalAPK string            // Optional path to the original artifact.
	OutputDir   string            // Where modules can drop sidecar files.
	Profile     string            // quick|balanced|deep|paranoid (optional hint).
	Metadata    map[string]string // Free-form hints (package name, etc.).
}

// Severity mirrors the analyzer's severity domain without creating an import
// cycle. Modules emit Severity strings that map 1:1 to types.Severity.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Finding is a structured experimental finding.
type Finding struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Severity    Severity          `json:"severity"`
	Confidence  float64           `json:"confidence"` // 0.0-1.0
	File        string            `json:"file,omitempty"`
	Line        int               `json:"line,omitempty"`
	Symbol      string            `json:"symbol,omitempty"`
	Description string            `json:"description,omitempty"`
	Evidence    []string          `json:"evidence,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Extra       map[string]string `json:"extra,omitempty"`
}

// ModuleResult is what a module returns.
type ModuleResult struct {
	ModuleID   string         `json:"module_id"`
	ModuleName string         `json:"module_name"`
	Tier       string         `json:"tier"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
	Duration   time.Duration  `json:"duration_ns"`
	Findings   []Finding      `json:"findings,omitempty"`
	Stats      map[string]int `json:"stats,omitempty"`
	Notes      []string       `json:"notes,omitempty"`
	Skipped    bool           `json:"skipped,omitempty"`
	SkipReason string         `json:"skip_reason,omitempty"`
}

// AddFinding appends a finding to the module result.
func (r *ModuleResult) AddFinding(f Finding) {
	r.Findings = append(r.Findings, f)
}

// Bump increments a stat counter.
func (r *ModuleResult) Bump(key string, by int) {
	if r.Stats == nil {
		r.Stats = make(map[string]int)
	}
	r.Stats[key] += by
}

// ═══════════════════════════════════════════════════════════════════════════════
// REGISTRY
// ═══════════════════════════════════════════════════════════════════════════════

// Registry is the canonical, ordered list of experimental modules.
// Order matches the documented selector indices (1-based externally).
type Registry struct {
	modules []Module
	byKey   map[string]Module
}

// NewRegistry builds a registry from the provided modules.
// The order is preserved and used for numeric selectors.
func NewRegistry(modules ...Module) *Registry {
	reg := &Registry{
		modules: make([]Module, 0, len(modules)),
		byKey:   make(map[string]Module),
	}
	for _, m := range modules {
		reg.add(m)
	}
	return reg
}

// DefaultRegistry returns the canonical experimental module registry.
//
// Index ordering (for `--ml-ex-apply 1-6`):
//
//	1 -> macho   Mach-O / iOS support
//	2 -> binsim  Binary similarity (clone search)
//	3 -> reach   Reachability analysis
//	4 -> aeg     Automated Exploit Generation
//	5 -> elf     ELF / Linux hardening triage
//	6 -> pe      PE / Windows hardening triage
func DefaultRegistry() *Registry {
	return NewRegistry(
		NewMachOModule(),
		NewBinSimModule(),
		NewReachModule(),
		NewAEGModule(),
		NewELFModule(),
		NewPEModule(),
	)
}

func (r *Registry) add(m Module) {
	if m == nil {
		return
	}
	r.modules = append(r.modules, m)
	r.byKey[strings.ToLower(m.ID())] = m
	for _, a := range m.Aliases() {
		r.byKey[strings.ToLower(a)] = m
	}
}

// All returns the ordered module list.
func (r *Registry) All() []Module {
	out := make([]Module, len(r.modules))
	copy(out, r.modules)
	return out
}

// Lookup finds a module by id or alias (case-insensitive).
func (r *Registry) Lookup(key string) (Module, bool) {
	m, ok := r.byKey[strings.ToLower(strings.TrimSpace(key))]
	return m, ok
}

// IndexOf returns the 1-based registry index of a module.
func (r *Registry) IndexOf(m Module) int {
	for i, candidate := range r.modules {
		if candidate.ID() == m.ID() {
			return i + 1
		}
	}
	return -1
}

// ═══════════════════════════════════════════════════════════════════════════════
// SELECTOR PARSER
// ═══════════════════════════════════════════════════════════════════════════════

// Presets group multiple modules under a friendly name. Inspired by the
// "alice" / classic preset terminology used elsewhere in Mega Analyzer.
var Presets = map[string][]string{
	"all":     {"macho", "binsim", "reach", "aeg", "elf", "pe"},
	"alice":   {"macho", "binsim", "reach"},                     // safe research bundle
	"hunter":  {"binsim", "reach", "elf", "pe"},                 // vulnerability hunting
	"mobile":  {"macho", "reach"},                               // iOS / mobile triage
	"offense": {"reach", "aeg", "elf", "pe"},                    // adversarial research
	"deep":    {"macho", "binsim", "reach", "aeg", "elf", "pe"}, // alias for all
}

// ParseSelector turns a selector string into the resolved set of modules.
//
// Supported syntax (mirrors --ml-apply):
//
//	"all"         -> every registered module
//	"1,3"         -> modules at index 1 and 3 (1-based)
//	"1-4"         -> indices 1..4 inclusive
//	"macho,binsim"-> by id
//	"ios"         -> alias resolution
//	"alice"       -> preset bundle
//	"alice,4"     -> preset + extra index
//
// Empty / whitespace-only input returns an empty slice without error so
// callers can treat "no selector" as "no experimental modules".
func ParseSelector(input string, reg *Registry) ([]Module, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, nil
	}
	if reg == nil || len(reg.modules) == 0 {
		return nil, errors.New("experimental registry is empty")
	}

	max := len(reg.modules)
	seen := make(map[string]bool, max)
	out := make([]Module, 0, max)

	add := func(m Module) {
		if m == nil || seen[m.ID()] {
			return
		}
		seen[m.ID()] = true
		out = append(out, m)
	}

	tokens := splitSelector(input)
	for _, tok := range tokens {
		if tok == "" {
			continue
		}
		lower := strings.ToLower(tok)

		// Preset?
		if ids, ok := Presets[lower]; ok {
			for _, id := range ids {
				if m, ok := reg.Lookup(id); ok {
					add(m)
				}
			}
			continue
		}

		// Range "a-b"?
		if strings.Contains(tok, "-") && !looksLikeName(tok) {
			lo, hi, err := parseRange(tok, max)
			if err != nil {
				return nil, err
			}
			for i := lo; i <= hi; i++ {
				add(reg.modules[i-1])
			}
			continue
		}

		// Numeric index?
		if n, err := strconv.Atoi(tok); err == nil {
			if n < 1 || n > max {
				return nil, fmt.Errorf("module index out of range: %d (have %d modules)", n, max)
			}
			add(reg.modules[n-1])
			continue
		}

		// By id / alias.
		if m, ok := reg.Lookup(tok); ok {
			add(m)
			continue
		}

		return nil, fmt.Errorf("unknown experimental module selector: %q", tok)
	}

	// Stable order by registry index for predictable execution.
	sort.SliceStable(out, func(i, j int) bool {
		return reg.IndexOf(out[i]) < reg.IndexOf(out[j])
	})
	return out, nil
}

func splitSelector(s string) []string {
	// Accept commas and whitespace as separators.
	rep := strings.NewReplacer(";", ",", " ", ",", "\t", ",", "\n", ",")
	parts := strings.Split(rep.Replace(s), ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseRange(tok string, max int) (int, int, error) {
	parts := strings.SplitN(tok, "-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid range: %q", tok)
	}
	lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("invalid range: %q", tok)
	}
	if lo < 1 || hi > max || lo > hi {
		return 0, 0, fmt.Errorf("range out of bounds: %d-%d (have %d modules)", lo, hi, max)
	}
	return lo, hi, nil
}

func looksLikeName(tok string) bool {
	for _, r := range tok {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// RUNNER
// ═══════════════════════════════════════════════════════════════════════════════

// Options controls the experimental runner.
type Options struct {
	// Selected is the resolved module list (use ParseSelector).
	Selected []Module

	// PerModuleTimeout caps each module's runtime (0 = no per-module cap).
	PerModuleTimeout time.Duration

	// Parallel enables concurrent module execution. Default: false (serial).
	Parallel bool

	// Verbose prints progress to stderr via the supplied callbacks.
	OnStart  func(m Module)
	OnFinish func(m Module, res *ModuleResult, err error)
}

// Result is the aggregate output of an experimental run.
type Result struct {
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at"`
	Duration   time.Duration   `json:"duration_ns"`
	Modules    []*ModuleResult `json:"modules"`
}

// TotalFindings sums findings across modules.
func (r *Result) TotalFindings() int {
	if r == nil {
		return 0
	}
	n := 0
	for _, m := range r.Modules {
		n += len(m.Findings)
	}
	return n
}

// HighestSeverity returns the strongest severity observed, or SevInfo when empty.
func (r *Result) HighestSeverity() Severity {
	rank := map[Severity]int{
		SevInfo: 0, SevLow: 1, SevMedium: 2, SevHigh: 3, SevCritical: 4,
	}
	best := SevInfo
	if r == nil {
		return best
	}
	for _, m := range r.Modules {
		for _, f := range m.Findings {
			if rank[f.Severity] > rank[best] {
				best = f.Severity
			}
		}
	}
	return best
}

// Run orchestrates the selected modules.
func Run(ctx context.Context, in Input, opts Options) (*Result, error) {
	if len(opts.Selected) == 0 {
		return &Result{StartedAt: time.Now(), FinishedAt: time.Now()}, nil
	}

	res := &Result{StartedAt: time.Now()}

	exec := func(m Module) *ModuleResult {
		mctx := ctx
		var cancel context.CancelFunc
		if opts.PerModuleTimeout > 0 {
			mctx, cancel = context.WithTimeout(ctx, opts.PerModuleTimeout)
			defer cancel()
		}

		if opts.OnStart != nil {
			opts.OnStart(m)
		}

		start := time.Now()
		out, err := safeRun(mctx, m, in)
		end := time.Now()

		if out == nil {
			out = &ModuleResult{ModuleID: m.ID(), ModuleName: m.Name(), Tier: m.Tier()}
		}
		out.StartedAt = start
		out.FinishedAt = end
		out.Duration = end.Sub(start)

		if err != nil {
			out.Skipped = true
			out.SkipReason = err.Error()
		}

		if opts.OnFinish != nil {
			opts.OnFinish(m, out, err)
		}
		return out
	}

	if opts.Parallel {
		results := make([]*ModuleResult, len(opts.Selected))
		var wg sync.WaitGroup
		for i, m := range opts.Selected {
			wg.Add(1)
			go func(i int, m Module) {
				defer wg.Done()
				results[i] = exec(m)
			}(i, m)
		}
		wg.Wait()
		res.Modules = results
	} else {
		for _, m := range opts.Selected {
			res.Modules = append(res.Modules, exec(m))
		}
	}

	res.FinishedAt = time.Now()
	res.Duration = res.FinishedAt.Sub(res.StartedAt)
	return res, nil
}

// safeRun invokes a module while recovering from panics.
func safeRun(ctx context.Context, m Module, in Input) (out *ModuleResult, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("module %s panicked: %v", m.ID(), rec)
		}
	}()
	return m.Run(ctx, in)
}
