package attackchain

import (
	"strings"

	"mega-analyzer/pkg/internal/correlation"
)

// PersistenceChain matches when the sample establishes any persistence
// mechanism (registry autorun, scheduled task, service, file drop in a
// startup folder).
//
// The chain has up to two steps:
//
//	persistence_setup   registry / task / service add
//	       ↓
//	persistence_artifact (optional) dropped binary backing the entry
//
// The second step links a registry value pointing at a file we dropped
// in the same run, which dramatically increases credibility — a Run
// key alone could be a research artifact, but a Run key plus the
// matching dropped binary is the real shape.
type PersistenceChain struct{}

func (PersistenceChain) ID() string   { return "persistence_chain" }
func (PersistenceChain) Name() string { return "Persistence Chain" }
func (PersistenceChain) Description() string {
	return "Sample installed an autorun / service / scheduled-task entry so it survives reboot."
}

func (c PersistenceChain) Detect(ctx *correlation.ExecutionContext) *correlation.AttackChain {
	if ctx == nil {
		return nil
	}

	// Collect all "setup" signals across processes (persistence often
	// happens outside the root PID — e.g., spawned regsvr).
	var setup []*correlation.Signal
	for _, t := range []string{
		correlation.TypeRegistryAutorun,
		correlation.TypeServiceInstall,
		correlation.TypeScheduledTask,
		correlation.TypeFilePersistence,
	} {
		setup = append(setup, ctx.SignalsOfType(t)...)
	}
	if len(setup) == 0 {
		return nil
	}

	// Any dropped artifact lives in this set.
	drops := correlation.Filter(ctx.SignalsOfKind(correlation.KindFile), isDroppedArtifact)

	// Look for a registry value whose data points at one of our drops.
	var matchedDrop *correlation.Signal
	var anchorSetup *correlation.Signal
	for _, s := range setup {
		for _, d := range drops {
			if d.Target == "" {
				continue
			}
			if pointsAtSignal(s, d.Target) {
				anchorSetup = s
				matchedDrop = d
				break
			}
		}
		if anchorSetup != nil {
			break
		}
	}

	evidence := uniqueSignals(append(setup[:len(setup):len(setup)], drops...))

	risk := correlation.RiskHigh
	if matchedDrop != nil {
		// Persistence + matching drop is canonical malware.
		risk = correlation.RiskCritical
	}

	factors := correlation.FactorsFromSignals(evidence)
	factors.ObservedAtRuntime = true
	if factors.RuntimeEvidence == "" {
		factors.RuntimeEvidence = "persistence entry observed"
	}

	steps := []correlation.AttackChainStep{
		{
			Order:       1,
			Component:   "persistence",
			Title:       "Persistence entry created",
			Description: persistenceTitle(setup),
			Timestamp:   setup[0].Timestamp,
			Signals:     setup,
		},
	}
	if matchedDrop != nil {
		steps = append(steps, correlation.AttackChainStep{
			Order:       2,
			Component:   "file_analysis",
			Title:       "Persistence backed by a dropped artifact",
			Description: "The autorun / task / service entry references an artifact dropped in this same run.",
			Timestamp:   matchedDrop.Timestamp,
			Signals:     []*correlation.Signal{matchedDrop, anchorSetup},
		})
	}

	return &correlation.AttackChain{
		ID:            "persistence_chain",
		Name:          "Persistence Chain",
		Description:   c.Description(),
		Risk:          risk,
		Likelihood:    correlation.ComputeLikelihood(factors),
		Factors:       factors,
		InvolvedKinds: involvedKinds(evidence),
		Sequence:      steps,
		Evidence:      evidence,
		Explanation: "The sample established at least one persistence mechanism. " +
			"This means it will continue to run after the analyst closes the host, even without user interaction.",
		MITRETechniques: []string{"T1547", "T1053", "T1543"},
		Mitigations: []string{
			"Quarantine the persistence artifact and remove the registry / task / service entry.",
			"Rebuild the host from a known-good image; persistence cannot be safely cleaned in place once exploited.",
		},
		Workarounds: []string{
			"Re-run the sample with VSS snapshotting enabled and diff the snapshots offline to enumerate every persistence side-effect.",
			"Capture the dropped artifact, hash it, and detonate it standalone in the sandbox to map second-stage behaviour without the parent.",
		},
	}
}

// pointsAtSignal reports whether a persistence signal references the
// given dropped-artifact path (either directly via Target or via the
// raw evidence strings the upstream detector left behind).
func pointsAtSignal(persistence *correlation.Signal, target string) bool {
	if persistence == nil || target == "" {
		return false
	}
	low := strings.ToLower(target)
	if persistence.Target != "" && strings.Contains(strings.ToLower(persistence.Target), low) {
		return true
	}
	for _, e := range persistence.Evidence {
		if strings.Contains(strings.ToLower(e), low) {
			return true
		}
	}
	return false
}

func persistenceTitle(setup []*correlation.Signal) string {
	for _, s := range setup {
		switch s.Type {
		case correlation.TypeRegistryAutorun:
			return "Registry autorun value added"
		case correlation.TypeServiceInstall:
			return "New Windows service installed"
		case correlation.TypeScheduledTask:
			return "New scheduled task added"
		case correlation.TypeFilePersistence:
			return "Startup-folder artifact created"
		}
	}
	return "Persistence entry created"
}
