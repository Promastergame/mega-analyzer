//go:build ignore
// +build ignore

// Package piracy — performance_modes.go
// Analysis modes: fast, normal, deep
//
// NOTE: This is an incomplete draft and is excluded from normal builds.
package piracy

/*
DRAFT (excluded from normal builds):

type AnalysisMode int

const (
	ModeFast   AnalysisMode = iota // AC + basic checks
	ModeNormal                     // + deobfuscation
	ModeDeep                       // + XOR + recursion + ML
)

type Detector struct {
	config          Config
	cache           *ResultCache
	configVersion   int
	deobfuscator    *DeobfuscationEngineV2
	patternMatcher  *PatternMatcher
	mode            AnalysisMode // ✅ NEW
	mu              sync.RWMutex
}

func (d *Detector) SetMode(mode AnalysisMode) { ... }
func (d *Detector) Analyze(...) (*Result, error) { ... }
func (d *Detector) analyzeBasic(...) (*Result, error) { ... }
func (d *Detector) analyzeNormal(...) (*Result, error) { ... }
func (d *Detector) analyzeDeep(...) (*Result, error) { ... }
*/
