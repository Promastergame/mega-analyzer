package apkloader

// ═══════════════════════════════════════════════════════════════════════════════
// HYPERION ENGINE v3.0 — Phase 3.6: Def-Use Analysis & Taint Tracking
// ═══════════════════════════════════════════════════════════════════════════════
//
// Def-Use chains enable dataflow analysis:
//   - Given a definition (Src), find all uses (Sinks)
//   - Given a use (Sink), find reaching definitions (Sources)
//   - Taint propagation: mark sources, track flow to sinks

// DefUse is a definition-use edge in the dataflow graph.
type DefUse struct {
	Def   SSAVar    // definition site
	Use   SSAVar    // use site (may be same version or later)
	Block *SSABlock // block containing the use
	Insn  *SSAInsn  // instruction containing the use (nil if phi)
	Phi   *SSAPhi   // phi containing the use (nil if regular insn)
}

// DefUseGraph maps each variable to its uses.
type DefUseGraph struct {
	Defs   map[SSAVar][]*DefUse // var -> list of uses
	Uses   map[SSAVar][]*DefUse // var -> reaching definitions
	MaxReg uint16
}

// TaintSource classifies where tainted data originates.
type TaintSource int

const (
	TaintSourceNone          TaintSource = iota
	TaintSourceParameter                 // method parameter
	TaintSourceFieldLoad                 // field read (iget/sget)
	TaintSourceInvokeResult              // return value of sensitive call
	TaintSourceExternalInput             // external input (file, network)
)

// TaintSink classifies where tainted data should not reach.
type TaintSink int

const (
	TaintSinkNone       TaintSink = iota
	TaintSinkBranch               // conditional branch (license check)
	TaintSinkFieldStore           // field write
	TaintSinkInvokeArg            // sensitive method argument
	TaintSinkReturn               // return value
)

// TaintState tracks taint for a single SSA variable.
type TaintState struct {
	Var       SSAVar
	IsTainted bool
	Source    TaintSource
	SourceRef string    // e.g., method name for invoke
	Path      []*DefUse // propagation path
}

// TaintEngine performs source-to-sink analysis.
type TaintEngine struct {
	SSA      *SSAFunction
	DefUse   *DefUseGraph
	TaintMap map[SSAVar]*TaintState
	Sources  []SSAVar
	Sinks    []SSAVar
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEF-USE GRAPH CONSTRUCTION
// ═══════════════════════════════════════════════════════════════════════════════

// BuildDefUseGraph constructs def-use chains from SSA form.
func BuildDefUseGraph(ssa *SSAFunction) *DefUseGraph {
	du := &DefUseGraph{
		Defs:   make(map[SSAVar][]*DefUse),
		Uses:   make(map[SSAVar][]*DefUse),
		MaxReg: ssa.MaxReg,
	}

	// Process all blocks
	for _, sb := range ssa.Blocks {
		// Process phis first (they are uses of predecessor values)
		for _, phi := range sb.Phis {
			for i, operand := range phi.Operands {
				if operand.Version == 0 {
					continue // entry value, skip
				}
				edge := &DefUse{
					Def:   operand,
					Use:   phi.Dst,
					Block: sb,
					Phi:   phi,
				}
				// Record predecessor for context
				_ = i // could use to track which predecessor
				du.Defs[operand] = append(du.Defs[operand], edge)
				du.Uses[phi.Dst] = append(du.Uses[phi.Dst], edge)
			}
		}

		// Process regular instructions
		for _, insn := range sb.Insns {
			// Record uses (sources)
			for _, src := range insn.Srcs {
				edge := &DefUse{
					Def:   src,
					Use:   insn.Dst,
					Block: sb,
					Insn:  insn,
				}
				du.Defs[src] = append(du.Defs[src], edge)
				du.Uses[insn.Dst] = append(du.Uses[insn.Dst], edge)
			}

			// Record that destination is defined here
			if insn.Dst.Reg != 0 || insn.Dst.Version != 0 {
				// Mark as definition site (no outgoing edges yet)
				if _, ok := du.Defs[insn.Dst]; !ok {
					du.Defs[insn.Dst] = nil
				}
			}
		}
	}

	return du
}

// GetUses returns all uses of a given variable definition.
func (du *DefUseGraph) GetUses(v SSAVar) []*DefUse {
	return du.Defs[v]
}

// GetDefs returns reaching definitions for a use site.
func (du *DefUseGraph) GetDefs(v SSAVar) []*DefUse {
	return du.Uses[v]
}

// ═══════════════════════════════════════════════════════════════════════════════
// TAINT ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

// NewTaintEngine creates a taint analyzer for the given SSA.
func NewTaintEngine(ssa *SSAFunction) *TaintEngine {
	return &TaintEngine{
		SSA:      ssa,
		TaintMap: make(map[SSAVar]*TaintState),
		Sources:  nil,
		Sinks:    nil,
	}
}

// MarkSource marks a variable as tainted with given source type.
func (te *TaintEngine) MarkSource(v SSAVar, source TaintSource, ref string) {
	te.TaintMap[v] = &TaintState{
		Var:       v,
		IsTainted: true,
		Source:    source,
		SourceRef: ref,
		Path:      nil,
	}
	te.Sources = append(te.Sources, v)
}

// MarkSink marks a variable as a sink.
func (te *TaintEngine) MarkSink(v SSAVar, sink TaintSink) {
	te.Sinks = append(te.Sinks, v)
}

// Propagate performs forward taint propagation through def-use chains.
func (te *TaintEngine) Propagate() {
	if te.DefUse == nil {
		te.DefUse = BuildDefUseGraph(te.SSA)
	}

	// Worklist: variables whose taint state changed
	worklist := make([]SSAVar, len(te.Sources))
	copy(worklist, te.Sources)

	visited := make(map[SSAVar]bool)

	for len(worklist) > 0 {
		v := worklist[0]
		worklist = worklist[1:]

		if visited[v] {
			continue
		}
		visited[v] = true

		state, ok := te.TaintMap[v]
		if !ok || !state.IsTainted {
			continue
		}

		// Propagate to all uses
		uses := te.DefUse.GetUses(v)
		for _, edge := range uses {
			target := edge.Use
			if _, alreadyTainted := te.TaintMap[target]; !alreadyTainted {
				te.TaintMap[target] = &TaintState{
					Var:       target,
					IsTainted: true,
					Source:    state.Source,
					SourceRef: state.SourceRef,
					Path:      append(state.Path, edge),
				}
				worklist = append(worklist, target)
			}
		}
	}
}

// FindFlows returns all source-to-sink dataflow paths.
type TaintFlow struct {
	Source     SSAVar
	Sink       SSAVar
	Path       []*DefUse
	SourceType TaintSource
	SinkType   TaintSink
}

// DetectFlows finds all taint flows from sources to sinks.
func (te *TaintEngine) DetectFlows() []TaintFlow {
	te.Propagate()

	var flows []TaintFlow
	for _, sink := range te.Sinks {
		if state, ok := te.TaintMap[sink]; ok && state.IsTainted {
			flows = append(flows, TaintFlow{
				Source:     state.Var,
				Sink:       sink,
				Path:       state.Path,
				SourceType: state.Source,
			})
		}
	}

	return flows
}

// ═══════════════════════════════════════════════════════════════════════════════
// HEURISTIC DETECTORS
// ═══════════════════════════════════════════════════════════════════════════════

// LicenseGateDetector identifies license check patterns.
type LicenseGateDetector struct {
	Engine *TaintEngine
}

// NewLicenseGateDetector creates a detector for license validation gates.
func NewLicenseGateDetector(ssa *SSAFunction) *LicenseGateDetector {
	te := NewTaintEngine(ssa)
	return &LicenseGateDetector{Engine: te}
}

// Analyze scans for potential license gates.
func (lgd *LicenseGateDetector) Analyze() []TaintFlow {
	ssa := lgd.Engine.SSA

	// Pattern 1: isLicensed/isValid/checkLicense → conditional branch
	for _, sb := range ssa.Blocks {
		for _, insn := range sb.Insns {
			mir := insn.MIR
			if mir.Kind != MIR_INVOKE {
				continue
			}

			// Check for license-related method names
			// In real implementation, we'd resolve RefIdx to method name
			// For now, heuristic: check if result flows to IF
			if insn.Dst.Version > 0 {
				// Result of invoke is a potential source
				lgd.Engine.MarkSource(insn.Dst, TaintSourceInvokeResult, "license_check")
			}
		}
	}

	// Mark conditional branches as sinks
	for _, sb := range ssa.Blocks {
		for _, insn := range sb.Insns {
			if insn.MIR.Kind == MIR_IF {
				// The source operand of IF is the sink
				for _, src := range insn.Srcs {
					lgd.Engine.MarkSink(src, TaintSinkBranch)
				}
			}
		}
	}

	return lgd.Engine.DetectFlows()
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY
// ═══════════════════════════════════════════════════════════════════════════════

// BackwardSlice returns all definitions that reach the given variable.
func (du *DefUseGraph) BackwardSlice(v SSAVar) []SSAVar {
	var result []SSAVar
	visited := make(map[SSAVar]bool)

	var walk func(SSAVar)
	walk = func(cur SSAVar) {
		if visited[cur] {
			return
		}
		visited[cur] = true
		result = append(result, cur)

		// Find reaching definitions
		for _, edge := range du.Uses[cur] {
			walk(edge.Def)
		}
	}

	walk(v)
	return result
}

// ForwardSlice returns all uses reachable from the given definition.
func (du *DefUseGraph) ForwardSlice(v SSAVar) []SSAVar {
	var result []SSAVar
	visited := make(map[SSAVar]bool)

	var walk func(SSAVar)
	walk = func(cur SSAVar) {
		if visited[cur] {
			return
		}
		visited[cur] = true
		result = append(result, cur)

		// Find uses
		for _, edge := range du.Defs[cur] {
			walk(edge.Use)
		}
	}

	walk(v)
	return result
}
