package attackchain

import (
	"fmt"

	"mega-analyzer/pkg/internal/correlation"
)

// DownloaderChain links:
//
//	network_analysis     outbound HTTP/DNS to a public host (or stager command line)
//	       ↓
//	file_analysis        executable / script artifact dropped to a writable path
//
// This is the classical "fetch + drop" shape. We do *not* require a
// follow-on process exec; many downloaders stage a payload but only run
// it on the next reboot via the persistence chain.
type DownloaderChain struct{}

func (DownloaderChain) ID() string   { return "downloader_chain" }
func (DownloaderChain) Name() string { return "Downloader Chain" }
func (DownloaderChain) Description() string {
	return "Sample fetched content from an external host and dropped an executable or script artifact on disk."
}

func (c DownloaderChain) Detect(ctx *correlation.ExecutionContext) *correlation.AttackChain {
	if ctx == nil {
		return nil
	}

	// Per-process: did this PID make an outbound request *and* drop a file?
	for _, pc := range ctx.Processes {
		netSig := firstMatch(pc.Signals, isFetchNetwork)
		dropSig := firstMatch(pc.Signals, isDroppedArtifact)

		// If the same PID has both halves, that's the strongest case.
		if netSig != nil && dropSig != nil {
			return c.build(pc.Key, netSig, dropSig, pc.Signals,
				correlation.RiskCritical)
		}
	}

	// Fallback: any net + any drop, even across PIDs (still suspicious,
	// but less certain).
	netSig := firstMatch(ctx.SignalsOfKind(correlation.KindNetwork), isFetchNetwork)
	dropSig := firstMatch(ctx.SignalsOfKind(correlation.KindFile), isDroppedArtifact)
	if netSig != nil && dropSig != nil {
		return c.build("cross-process", netSig, dropSig,
			[]*correlation.Signal{netSig, dropSig}, correlation.RiskHigh)
	}
	return nil
}

func (c DownloaderChain) build(procKey string,
	netSig, dropSig *correlation.Signal,
	contextual []*correlation.Signal,
	risk correlation.Risk,
) *correlation.AttackChain {

	evidence := uniqueSignals([]*correlation.Signal{netSig, dropSig})

	seq := []correlation.AttackChainStep{
		{
			Order:       1,
			Component:   "network_analysis",
			Title:       "Outbound fetch",
			Description: fmt.Sprintf("Outbound traffic to %s", netSig.Target),
			Timestamp:   netSig.Timestamp,
			Signals:     []*correlation.Signal{netSig},
		},
		{
			Order:       2,
			Component:   "file_analysis",
			Title:       "Executable / script dropped on disk",
			Description: fmt.Sprintf("Artifact persisted at %s", dropSig.Target),
			Timestamp:   dropSig.Timestamp,
			Signals:     []*correlation.Signal{dropSig},
		},
	}

	factors := correlation.FactorsFromSignals(evidence)
	factors.ObservedAtRuntime = true
	if factors.RuntimeEvidence == "" {
		factors.RuntimeEvidence = "outbound traffic + dropped artifact observed"
	}
	factors.Reachable = true
	if factors.ReachReason == "" {
		factors.ReachReason = "outbound connection observed"
	}

	return &correlation.AttackChain{
		ID:              "downloader_chain",
		Name:            "Downloader Chain",
		Description:     c.Description(),
		Risk:            risk,
		Likelihood:      correlation.ComputeLikelihood(factors),
		Factors:         factors,
		InvolvedKinds:   involvedKinds(evidence),
		ProcessKey:      procKey,
		Sequence:        seq,
		Evidence:        evidence,
		Explanation:     "Sample fetched remote content and dropped an artifact; classic stager / second-stage payload pattern.",
		MITRETechniques: []string{"T1105"},
		Mitigations: []string{
			"Block the outbound destination at the firewall and quarantine the dropped artifact.",
			"Rebuild the host from a known-good image if execution is suspected.",
		},
		Workarounds: []string{
			"Stand up a private HTTPS responder, redirect the sandbox's egress to it, and capture the second-stage payload safely.",
			"Hash the dropped artifact, then detonate it standalone in the sandbox to map its independent behaviour.",
		},
	}
}
