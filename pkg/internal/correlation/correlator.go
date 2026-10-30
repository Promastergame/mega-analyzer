package correlation

import (
	"fmt"
	"sort"
	"time"

	"mega-analyzer/pkg/internal/sandbox"
	"mega-analyzer/pkg/internal/types"
)

// ChainDetector is the interface implemented by every attack-chain
// detector in the attackchain package. We declare it here (with no
// import dependency) so Engine can iterate over a heterogeneous list
// of detectors.
//
// We intentionally use a structural interface instead of importing the
// attackchain package — that lets attackchain depend on correlation
// (one-way arrow) without a cycle.
type ChainDetector interface {
	ID() string
	Name() string
	Description() string
	Detect(ctx *ExecutionContext) *AttackChain
}

// Input bundles everything Engine.Run consumes. Both fields are
// optional, but Run will return an empty Result when both are nil.
type Input struct {
	Sandbox   *sandbox.Report
	Static    *types.AnalysisResult
	SessionID string
}

// Engine is the post-processing entry point. It is stateless across
// runs — all state lives on Result — so it is safe to reuse.
type Engine struct {
	chains []ChainDetector
	now    func() time.Time
}

// NewEngine builds an engine with the given chain detectors. Pass
// attackchain.DefaultChains() in production.
func NewEngine(chains []ChainDetector) *Engine {
	return &Engine{chains: chains, now: time.Now}
}

// Run executes the full correlation pipeline:
//
//  1. ingest sandbox + static into unified Signals
//  2. run FPGuard (downgrade JIT/unreached/unbridged signals)
//  3. group into ExecutionContext
//  4. detect attack chains
//  5. promote remaining (un-chained) signals into Findings
//  6. compute timeline + overall risk/likelihood
func (e *Engine) Run(in Input) *Result {
	res := &Result{GeneratedAt: e.now(), SessionID: in.SessionID}

	if in.Sandbox == nil && in.Static == nil {
		res.OverallRisk = RiskInfo
		res.OverallLikeli = LikelihoodLow
		res.Notes = append(res.Notes,
			"No sandbox report or static analysis result was provided.")
		return res
	}

	// 1. Ingest
	signals := make([]*Signal, 0, 64)
	if in.Sandbox != nil {
		runtime := IngestSandbox(in.Sandbox)
		signals = append(signals, runtime...)
		res.HasRuntime = len(runtime) > 0 || len(in.Sandbox.Processes) > 0
	}
	if in.Static != nil {
		audit := IngestStatic(in.Static)
		signals = append(signals, audit...)
		res.HasStatic = len(audit) > 0
	}
	if !res.HasRuntime {
		res.Notes = append(res.Notes,
			"No runtime telemetry available — chains and likelihood are based on static evidence only.")
		// tag every signal so downstream knows
		for _, s := range signals {
			if s.IsStatic() {
				s.AddTag(TagNoSandboxRun)
			}
		}
	}

	// 2. FP guard
	FPGuard(signals)

	// 3. Group
	exec := Group(signals)

	// 4. Chains
	usedSignalIDs := make(map[string]struct{})
	for _, det := range e.chains {
		match := det.Detect(exec)
		if match == nil {
			continue
		}
		// Stamp ID if the detector left it blank.
		if match.ID == "" {
			match.ID = det.ID()
		}
		// Mark involved signals so we don't re-emit them as findings.
		for _, sig := range match.Evidence {
			if sig != nil {
				usedSignalIDs[sig.ID] = struct{}{}
			}
		}
		res.Chains = append(res.Chains, *match)
	}
	sort.SliceStable(res.Chains, func(i, j int) bool {
		a, b := res.Chains[i], res.Chains[j]
		if a.Risk.Rank() != b.Risk.Rank() {
			return a.Risk.Rank() > b.Risk.Rank()
		}
		if a.Likelihood.Rank() != b.Likelihood.Rank() {
			return a.Likelihood.Rank() > b.Likelihood.Rank()
		}
		return a.Name < b.Name
	})

	// 5. Promote remaining signals → Findings.
	res.Findings = e.buildFindings(signals, exec, usedSignalIDs)

	// 6. Timeline + aggregates
	res.Timeline = BuildTimeline(signals)
	res.Stats = computeStats(signals, res.Findings, res.Chains)
	res.OverallRisk = AggregateRisk(res.Findings, res.Chains)
	res.OverallLikeli = AggregateLikelihood(res.Findings, res.Chains)

	return res
}

// buildFindings groups not-yet-consumed signals by Type+Process and
// emits one Finding per group. Each Finding gets:
//
//   - a context-aware Risk (AdjustRisk)
//   - Likelihood factors (FactorsFromSignals + same-process supporting)
//   - Mitigations and Workarounds from the recommendation table
func (e *Engine) buildFindings(
	all []*Signal,
	exec *ExecutionContext,
	used map[string]struct{},
) []Finding {
	type bucketKey struct {
		typ     string
		procKey string
	}
	type bucket struct {
		primary    *Signal
		supporting []*Signal
	}
	buckets := make(map[bucketKey]*bucket)

	for _, s := range all {
		if s == nil {
			continue
		}
		if _, ok := used[s.ID]; ok {
			continue
		}
		k := bucketKey{typ: s.Type, procKey: s.ProcessKey()}
		b, ok := buckets[k]
		if !ok {
			b = &bucket{primary: s}
			buckets[k] = b
			continue
		}
		// Pick the highest-severity primary; older becomes supporting.
		if s.Severity > b.primary.Severity {
			b.supporting = append(b.supporting, b.primary)
			b.primary = s
		} else {
			b.supporting = append(b.supporting, s)
		}
	}

	findings := make([]Finding, 0, len(buckets))
	for k, b := range buckets {
		// Same-process supporting evidence (network etc.) is what
		// drives "secret + outbound = HIGH" style scoring.
		var sameProc []*Signal
		if pc := exec.Process(k.procKey); pc != nil {
			sameProc = pc.Signals
		}
		support := append([]*Signal(nil), b.supporting...)
		support = append(support, sameProc...)

		base := BaseRiskFromSeverity(b.primary.Severity)
		risk := AdjustRisk(base, b.primary, support)

		factors := FactorsFromSignals(append([]*Signal{b.primary}, support...))
		likelihood := ComputeLikelihood(factors)

		// Build evidence list = primary + supporting (deduped).
		evidence := []*Signal{b.primary}
		seen := map[string]struct{}{b.primary.ID: {}}
		for _, s := range b.supporting {
			if _, ok := seen[s.ID]; ok {
				continue
			}
			seen[s.ID] = struct{}{}
			evidence = append(evidence, s)
		}
		// Related events: same-process runtime signals not already in
		// evidence, capped to keep the report readable.
		var related []*Signal
		for _, s := range sameProc {
			if _, ok := seen[s.ID]; ok {
				continue
			}
			if !s.IsRuntime() {
				continue
			}
			seen[s.ID] = struct{}{}
			related = append(related, s)
			if len(related) >= 6 {
				break
			}
		}

		mitigations, workarounds := guidanceFor(b.primary.Type)
		findings = append(findings, Finding{
			ID:            fmt.Sprintf("finding-%s-%s", b.primary.Type, k.procKey),
			Title:         findingTitle(b.primary),
			Category:      categoryOfType(b.primary.Type),
			Risk:          risk,
			Likelihood:    likelihood,
			Factors:       factors,
			Evidence:      evidence,
			RelatedEvents: related,
			Explanation:   explain(b.primary, support, factors, risk, likelihood),
			Location:      locationOf(b.primary),
			Mitigations:   mitigations,
			Workarounds:   workarounds,
			Tags:          dedupeStrings(b.primary.Tags),
		})
	}

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Risk.Rank() != b.Risk.Rank() {
			return a.Risk.Rank() > b.Risk.Rank()
		}
		if a.Likelihood.Rank() != b.Likelihood.Rank() {
			return a.Likelihood.Rank() > b.Likelihood.Rank()
		}
		return a.Title < b.Title
	})
	return findings
}

func computeStats(signals []*Signal, findings []Finding, chains []AttackChain) ResultStats {
	stats := ResultStats{TotalFindings: len(findings), TotalChains: len(chains)}
	for _, s := range signals {
		stats.TotalSignals++
		if s.IsStatic() {
			stats.StaticSignals++
		} else if s.IsRuntime() {
			stats.RuntimeSignals++
		}
	}
	for _, f := range findings {
		switch f.Risk {
		case RiskCritical:
			stats.CriticalRisks++
		case RiskHigh:
			stats.HighRisks++
		}
	}
	for _, c := range chains {
		switch c.Risk {
		case RiskCritical:
			stats.CriticalRisks++
		case RiskHigh:
			stats.HighRisks++
		}
	}
	return stats
}

func locationOf(s *Signal) *Location {
	if s == nil {
		return nil
	}
	if s.Location.File == "" && s.Location.Line == 0 && s.Location.Method == "" {
		return nil
	}
	loc := s.Location
	return &loc
}

func findingTitle(s *Signal) string {
	if s.Title != "" {
		return s.Title
	}
	return s.Type
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// categoryOfType is a coarse human-friendly bucket for the renderer.
// We avoid importing types.Category here because the correlation report
// is consumed standalone.
func categoryOfType(t string) string {
	switch t {
	case TypeProcessInjection, TypeProcessHollowing, TypeRWXMemory,
		TypeMemoryWrite, TypeRemoteThread:
		return "memory"
	case TypeOutboundConnection, TypePublicEgress, TypeSuspiciousDNS,
		TypeOpaqueTLS, TypeRiskyServicePort, TypeHardcodedIPEndpoint,
		TypeScriptStager:
		return "network"
	case TypeRegistryAutorun, TypeFilePersistence, TypeServiceInstall,
		TypeScheduledTask, TypeMassFileChange, TypeFileDropExec,
		TypeFileDropScript, TypeSensitiveCache:
		return "persistence"
	case TypeHardcodedSecret, TypeCleartextEndpoint, TypeWeakCrypto,
		TypeWebViewJSBridge, TypeWebViewCleartext, TypeDebugEndpoint,
		TypeExportedComponent, TypeRootBypass, TypeAuthGate,
		TypeBooleanGate:
		return "security_audit"
	case TypeMITREMatch:
		return "behavior"
	}
	return "other"
}
