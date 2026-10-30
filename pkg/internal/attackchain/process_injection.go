package attackchain

import (
	"fmt"

	"mega-analyzer/pkg/internal/correlation"
)

// ProcessInjectionChain links the canonical injection sequence:
//
//	memory_analysis      RWX allocation / WriteProcessMemory
//	       ↓
//	memory_analysis      remote-thread or hollowing detected
//	       ↓             (plus optional outbound from the injected PID)
//	network_analysis     outbound connection, often to a C2-shaped host
//
// We require evidence from at least KindMemory. KindNetwork lifts
// likelihood when present.
type ProcessInjectionChain struct{}

func (ProcessInjectionChain) ID() string   { return "process_injection_chain" }
func (ProcessInjectionChain) Name() string { return "Process Injection Chain" }
func (ProcessInjectionChain) Description() string {
	return "Sample manipulated another process's memory (alloc + write + remote thread / hollowing) and may have followed up with outbound traffic."
}

func (c ProcessInjectionChain) Detect(ctx *correlation.ExecutionContext) *correlation.AttackChain {
	if ctx == nil {
		return nil
	}

	for _, pc := range ctx.Processes {
		var mem []*correlation.Signal
		for _, s := range pc.Signals {
			switch s.Type {
			case correlation.TypeRWXMemory,
				correlation.TypeMemoryWrite,
				correlation.TypeRemoteThread,
				correlation.TypeProcessInjection,
				correlation.TypeProcessHollowing:
				if s.HasTag(correlation.TagJIT) {
					continue // FPGuard already downgraded these
				}
				mem = append(mem, s)
			}
		}
		if len(mem) == 0 {
			continue
		}

		hasInjection := false
		for _, s := range mem {
			if s.Type == correlation.TypeProcessInjection ||
				s.Type == correlation.TypeProcessHollowing {
				hasInjection = true
				break
			}
		}
		// Require at least RWX+memory_write *or* an explicit injection
		// signal — a lone RWX alloc isn't enough on its own.
		if !hasInjection {
			hasRWX := firstWithType(mem, correlation.TypeRWXMemory) != nil
			hasWrite := firstWithType(mem, correlation.TypeMemoryWrite) != nil
			if !(hasRWX && hasWrite) {
				continue
			}
		}

		// Network follow-up from the same PID elevates the chain.
		netSignals := correlation.Filter(pc.Signals, isOutboundNetwork)

		evidence := append(mem[:len(mem):len(mem)], netSignals...)
		evidence = uniqueSignals(evidence)

		// Build sequence
		seq := []correlation.AttackChainStep{}
		order := 1
		if rwx := firstWithType(mem, correlation.TypeRWXMemory); rwx != nil {
			seq = append(seq, correlation.AttackChainStep{
				Order:       order,
				Component:   "memory_analysis",
				Title:       "Executable memory allocated",
				Description: "Process allocated/changed memory with PAGE_EXECUTE_READWRITE permissions.",
				Timestamp:   rwx.Timestamp,
				Signals:     []*correlation.Signal{rwx},
			})
			order++
		}
		if w := firstWithType(mem, correlation.TypeMemoryWrite); w != nil {
			seq = append(seq, correlation.AttackChainStep{
				Order:       order,
				Component:   "memory_analysis",
				Title:       "Memory written into another process",
				Description: "WriteProcessMemory or NtWriteVirtualMemory observed.",
				Timestamp:   w.Timestamp,
				Signals:     []*correlation.Signal{w},
			})
			order++
		}
		if hasInjection {
			injSig := firstWithType(mem, correlation.TypeProcessInjection)
			if injSig == nil {
				injSig = firstWithType(mem, correlation.TypeProcessHollowing)
			}
			seq = append(seq, correlation.AttackChainStep{
				Order:       order,
				Component:   "memory_analysis",
				Title:       "Injection sequence detected",
				Description: "Canonical alloc + write + remote-thread / hollowing pattern matched.",
				Timestamp:   injSig.Timestamp,
				Signals:     []*correlation.Signal{injSig},
			})
			order++
		}
		if len(netSignals) > 0 {
			seq = append(seq, correlation.AttackChainStep{
				Order:       order,
				Component:   "network_analysis",
				Title:       "Outbound traffic from the injected process",
				Description: "Same PID opened a network connection after the injection.",
				Timestamp:   netSignals[0].Timestamp,
				Signals:     netSignals,
			})
		}

		// Risk and likelihood
		factors := correlation.FactorsFromSignals(evidence)
		factors.ObservedAtRuntime = true
		factors.Reachable = true // Runtime signals with PIDs confirm the process executed
		if factors.RuntimeEvidence == "" {
			factors.RuntimeEvidence = "memory-injection API sequence observed"
		}
		risk := correlation.RiskHigh
		if hasInjection {
			risk = correlation.RiskCritical
		}

		return &correlation.AttackChain{
			ID:              c.ID(),
			Name:            c.Name(),
			Description:     c.Description(),
			Risk:            risk,
			Likelihood:      correlation.ComputeLikelihood(factors),
			Factors:         factors,
			InvolvedKinds:   involvedKinds(evidence),
			ProcessKey:      pc.Key,
			Sequence:        seq,
			Evidence:        evidence,
			Explanation:     fmt.Sprintf("PID %d (%s) executed memory-injection APIs", pc.PID, pc.ProcessName),
			MITRETechniques: []string{"T1055"},
			Mitigations: []string{
				"Quarantine the host and rebuild from a known-good image.",
				"Add EDR rules for the VirtualAllocEx + WriteProcessMemory + CreateRemoteThread sequence.",
			},
			Workarounds: []string{
				"Re-run with API tracing focused on the injecting PID and capture call stacks for the alloc/write/start triplet.",
				"Snapshot the target process's memory after WriteProcessMemory and dump the injected region for offline analysis.",
			},
		}
	}
	return nil
}
