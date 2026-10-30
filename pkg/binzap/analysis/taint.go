package analysis

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/binzap/ir"
)

// taintInfo tracks, per register, the provenance of the tainted value.
type taintInfo struct {
	sourceID string
	kind     SourceKind
	label    string
	line     int
	path     []string // human-readable provenance steps
}

// Engine performs source-to-sink taint analysis over lowered IR.
type Engine struct {
	Sources []Source
	Sinks   []Sink
	seeds   map[string]seed
}

type seed struct {
	kind  SourceKind
	label string
}

// NewEngine returns an engine loaded with the default source/sink catalog.
func NewEngine() *Engine {
	return &Engine{Sources: DefaultSources(), Sinks: DefaultSinks(), seeds: map[string]seed{}}
}

// SeedTaint marks a register as tainted before analysis. This is how binzap
// injects credential provenance discovered by the existing secrets scanner
// (INC4): a hardcoded secret loaded into a register becomes a credential taint
// source, so reaching an insecure sink (log, network, file) is reported.
func (e *Engine) SeedTaint(reg string, kind SourceKind, label string) {
	e.seeds[reg] = seed{kind: kind, label: label}
}

func (e *Engine) matchSource(method string) (Source, bool) {
	for _, s := range e.Sources {
		if s.Substr != "" && strings.Contains(method, s.Substr) {
			return s, true
		}
	}
	return Source{}, false
}

func (e *Engine) matchSink(method string) (Sink, bool) {
	for _, s := range e.Sinks {
		if s.Substr != "" && strings.Contains(method, s.Substr) {
			return s, true
		}
	}
	return Sink{}, false
}

// Analyze runs taint analysis over every method in the program.
func (e *Engine) Analyze(p *ir.Program) []Finding {
	var out []Finding
	for _, m := range p.Methods {
		out = append(out, e.analyzeMethod(p.File, m)...)
	}
	return out
}

func (e *Engine) analyzeMethod(file string, m *ir.Method) []Finding {
	var findings []Finding
	state := map[string]taintInfo{}

	for reg, s := range e.seeds {
		state[reg] = taintInfo{
			sourceID: "SEED",
			kind:     s.kind,
			label:    s.label,
			path:     []string{fmt.Sprintf("seed: %s in %s", s.label, reg)},
		}
	}

	for _, in := range m.Instrs {
		switch in.Op {
		case ir.OpConst:
			if in.Dst != "" {
				if _, seeded := e.seeds[in.Dst]; !seeded {
					delete(state, in.Dst)
				}
			}
		case ir.OpMove:
			if in.Dst != "" && len(in.Args) >= 1 {
				if ti, ok := state[in.Args[0]]; ok {
					next := ti
					next.path = appendStep(ti.path, fmt.Sprintf("L%d: move %s <- %s", in.Line, in.Dst, in.Args[0]))
					state[in.Dst] = next
				} else {
					delete(state, in.Dst)
				}
			}
		case ir.OpInvoke:
			// 1) Does any tainted register flow into this invoke (sink check)?
			if sink, ok := e.matchSink(in.Method); ok {
				if ti, reg, tainted := e.firstTaintedArg(state, in.Args); tainted {
					findings = append(findings, buildFinding(file, in, sink, ti, reg))
				}
			}
			// 2) Is this invoke a source? Taint its result register.
			if src, ok := e.matchSource(in.Method); ok {
				result := in.ResultReg
				if result == "" && len(in.Args) > 0 {
					result = in.Args[0]
				}
				if result != "" {
					state[result] = taintInfo{
						sourceID: src.ID,
						kind:     src.Kind,
						label:    src.Label,
						line:     in.Line,
						path:     []string{fmt.Sprintf("L%d: source %s -> %s", in.Line, src.Label, result)},
					}
				}
			}
		case ir.OpFieldGet:
			if in.Dst != "" {
				if _, seeded := e.seeds[in.Dst]; !seeded {
					delete(state, in.Dst)
				}
			}
		}
	}
	return findings
}

func (e *Engine) firstTaintedArg(state map[string]taintInfo, args []string) (taintInfo, string, bool) {
	for _, a := range args {
		if ti, ok := state[a]; ok {
			return ti, a, true
		}
	}
	return taintInfo{}, "", false
}

func appendStep(path []string, step string) []string {
	out := make([]string, 0, len(path)+1)
	out = append(out, path...)
	out = append(out, step)
	return out
}

func buildFinding(file string, in *ir.Instr, sink Sink, ti taintInfo, reg string) Finding {
	path := appendStep(ti.path, fmt.Sprintf("L%d: sink %s uses %s", in.Line, sink.Title, reg))
	exploit := "Tainted data reaches a dangerous sink along a feasible intra-procedural path."
	if ti.kind == KindCredential || ti.kind == KindSeed {
		exploit = "Hardcoded credential material reaches an insecure sink (exposure/misuse)."
	}
	return Finding{
		RuleID:         "BZ-TAINT-" + sink.ID,
		Title:          sink.Title,
		CWE:            sink.CWE,
		Severity:       sink.Severity,
		Confidence:     "HIGH",
		Category:       sink.Category,
		File:           file,
		Line:           in.Line,
		Column:         in.Column,
		Evidence:       strings.TrimSpace(in.Raw),
		Remediation:    sink.Remediation,
		Exploitability: exploit,
		DetectedBy:     "taint-engine",
		Path:           path,
	}
}
