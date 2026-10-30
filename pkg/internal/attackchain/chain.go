// Package attackchain detects multi-step attack patterns over an
// already-correlated stream of signals.
//
// Each Chain implementation is small, self-contained, and only reads
// from correlation.ExecutionContext. Chains never mutate the context
// and never call back into the sandbox or static analyzer.
package attackchain

import (
	"sort"

	"mega-analyzer/pkg/internal/correlation"
)

// Chain is the interface every attack-chain detector implements. It
// satisfies correlation.ChainDetector by structural typing — the
// correlation engine accepts any type with these methods.
type Chain interface {
	ID() string
	Name() string
	Description() string

	// Detect returns nil when the chain does not apply, or a populated
	// AttackChain (with sequence steps + evidence) when it does.
	Detect(ctx *correlation.ExecutionContext) *correlation.AttackChain
}

// asDetectorSlice converts []Chain to []correlation.ChainDetector so
// callers can pass DefaultChains() straight into correlation.NewEngine.
func asDetectorSlice(chains []Chain) []correlation.ChainDetector {
	out := make([]correlation.ChainDetector, len(chains))
	for i, c := range chains {
		out[i] = c
	}
	return out
}

// DefaultChains returns the production set of attack chain detectors.
// Order is irrelevant — the correlation engine sorts the matches by
// risk/likelihood after detection.
func DefaultChains() []correlation.ChainDetector {
	return asDetectorSlice([]Chain{
		ProcessInjectionChain{},
		DownloaderChain{},
		PersistenceChain{},
		DataExfiltrationChain{},
		AuthBypassChain{},
		IntentToDangerousSinkChain{},
		DeepLinkWebViewRCEChain{},
		StorageProviderExfiltrationChain{},
	})
}

// ── Signal classification predicates ────────────────────────────────
//
// These are the single source of truth for "what kind of thing is this
// signal". Chains used to re-implement them inline, which let subtle
// divergences creep in (e.g. one code path treating suspicious DNS as a
// fetch while another ignored it). Keeping them here keeps every chain
// consistent.

// isOutboundNetwork reports whether s is an outbound network egress:
// a public egress or a generic outbound connection. These are the two
// types every chain treats as "traffic left the host".
func isOutboundNetwork(s *correlation.Signal) bool {
	return s != nil && s.Kind == correlation.KindNetwork &&
		(s.Type == correlation.TypePublicEgress ||
			s.Type == correlation.TypeOutboundConnection)
}

// isFetchNetwork reports whether s indicates the process reached out to
// fetch content: an outbound egress, or a suspicious DNS lookup that
// typically precedes one. Used by the downloader chain, which cares
// about the "fetch" half rather than strict egress.
func isFetchNetwork(s *correlation.Signal) bool {
	return isOutboundNetwork(s) ||
		(s != nil && s.Kind == correlation.KindNetwork &&
			s.Type == correlation.TypeSuspiciousDNS)
}

// isDroppedArtifact reports whether s represents an executable or script
// dropped to disk.
func isDroppedArtifact(s *correlation.Signal) bool {
	return s != nil && s.Kind == correlation.KindFile &&
		(s.Type == correlation.TypeFileDropExec ||
			s.Type == correlation.TypeFileDropScript)
}

// isSensitiveData reports whether s exposes sensitive material: a cached
// credential/token artifact or a hardcoded secret.
func isSensitiveData(s *correlation.Signal) bool {
	return s != nil && (s.Type == correlation.TypeSensitiveCache ||
		s.Type == correlation.TypeHardcodedSecret)
}

// ── Helpers shared across chain implementations ─────────────────────

// firstMatch returns the first signal satisfying pred, or nil if none do.
func firstMatch(signals []*correlation.Signal, pred func(*correlation.Signal) bool) *correlation.Signal {
	for _, s := range signals {
		if pred(s) {
			return s
		}
	}
	return nil
}

// uniqueSignals deduplicates a slice of *Signal by ID, preserving order.
func uniqueSignals(in []*correlation.Signal) []*correlation.Signal {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]*correlation.Signal, 0, len(in))
	for _, s := range in {
		if s == nil {
			continue
		}
		if _, ok := seen[s.ID]; ok {
			continue
		}
		seen[s.ID] = struct{}{}
		out = append(out, s)
	}
	return out
}

// involvedKinds returns the unique sorted list of SignalKinds across
// the given signals. It powers the "involved components" report field.
func involvedKinds(signals []*correlation.Signal) []correlation.SignalKind {
	if len(signals) == 0 {
		return nil
	}
	seen := make(map[correlation.SignalKind]struct{}, 4)
	for _, s := range signals {
		if s == nil {
			continue
		}
		seen[s.Kind] = struct{}{}
	}
	out := make([]correlation.SignalKind, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// firstWithType returns the first signal of the requested type from
// the provided slice, or nil if none exists. Used by chains that want
// to seed a step from the canonical evidence point.
func firstWithType(signals []*correlation.Signal, t string) *correlation.Signal {
	for _, s := range signals {
		if s != nil && s.Type == t {
			return s
		}
	}
	return nil
}

// signalsWithType returns every signal of the requested type from the
// provided slice. The returned slice is fresh and safe to mutate.
func signalsWithType(signals []*correlation.Signal, t string) []*correlation.Signal {
	out := make([]*correlation.Signal, 0, 4)
	for _, s := range signals {
		if s != nil && s.Type == t {
			out = append(out, s)
		}
	}
	return out
}

// processesWithType returns the list of process contexts that contain
// at least one signal of the requested type. Useful when a chain is
// per-process (downloader, injection, exfil).
func processesWithType(ctx *correlation.ExecutionContext, t string) []*correlation.ProcessContext {
	if ctx == nil {
		return nil
	}
	out := make([]*correlation.ProcessContext, 0, 4)
	for _, pc := range ctx.Processes {
		for _, s := range pc.Signals {
			if s.Type == t {
				out = append(out, pc)
				break
			}
		}
	}
	return out
}
