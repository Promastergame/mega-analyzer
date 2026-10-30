package attackchain

import (
	"fmt"

	"mega-analyzer/pkg/internal/correlation"
)

// DataExfiltrationChain links sensitive data access with outbound
// network traffic. We deliberately keep the rules conservative — too
// many apps legitimately read SMS or contacts.
//
//	security_audit       hardcoded secret OR sensitive cache artifact
//	       ↓
//	network_analysis     outbound connection from the same process
//	       ↓ (boost)
//	security_audit       same process holds a secret usable for auth
type DataExfiltrationChain struct{}

func (DataExfiltrationChain) ID() string   { return "data_exfiltration_chain" }
func (DataExfiltrationChain) Name() string { return "Data Exfiltration Chain" }
func (DataExfiltrationChain) Description() string {
	return "Sensitive data access combined with outbound traffic from the same process; data is leaving the host."
}

func (c DataExfiltrationChain) Detect(ctx *correlation.ExecutionContext) *correlation.AttackChain {
	if ctx == nil {
		return nil
	}

	// We need a network egress; without it there is no exfil.
	netSignals := correlation.Filter(ctx.SignalsOfKind(correlation.KindNetwork), isOutboundNetwork)
	if len(netSignals) == 0 {
		return nil
	}

	// Sensitive-data signals come in two flavors:
	//   1. cache artifacts that look like creds/tokens
	//   2. hardcoded secrets in the binary
	sensitive := correlation.Filter(ctx.All, isSensitiveData)
	if len(sensitive) == 0 {
		return nil
	}

	// Try per-process pairing first — strongest case.
	var pickedNet, pickedSensitive *correlation.Signal
	pickedProcKey := "static"
	for _, pc := range ctx.Processes {
		pn := firstMatch(pc.Signals, isOutboundNetwork)
		ps := firstMatch(pc.Signals, isSensitiveData)
		if pn != nil && ps != nil {
			pickedNet = pn
			pickedSensitive = ps
			pickedProcKey = pc.Key
			break
		}
	}
	if pickedNet == nil {
		// Cross-process fallback: pair the strongest network with the
		// strongest sensitive signal. This is much weaker, so risk is
		// capped at HIGH below.
		pickedNet = netSignals[0]
		pickedSensitive = sensitive[0]
	}

	evidence := uniqueSignals([]*correlation.Signal{pickedSensitive, pickedNet})

	steps := []correlation.AttackChainStep{
		{
			Order:       1,
			Component:   "security_audit",
			Title:       sensitiveTitle(pickedSensitive),
			Description: pickedSensitive.Description,
			Timestamp:   pickedSensitive.Timestamp,
			Signals:     []*correlation.Signal{pickedSensitive},
		},
		{
			Order:       2,
			Component:   "network_analysis",
			Title:       fmt.Sprintf("Outbound traffic from same process to %s", pickedNet.Target),
			Description: pickedNet.Description,
			Timestamp:   pickedNet.Timestamp,
			Signals:     []*correlation.Signal{pickedNet},
		},
	}

	risk := correlation.RiskHigh
	if pickedProcKey != "static" {
		// per-process pairing → CRITICAL
		risk = correlation.RiskCritical
	}

	factors := correlation.FactorsFromSignals(evidence)
	factors.ObservedAtRuntime = pickedNet.IsRuntime()
	if factors.RuntimeEvidence == "" && factors.ObservedAtRuntime {
		factors.RuntimeEvidence = "outbound traffic observed alongside sensitive data"
	}
	factors.Reachable = true
	if factors.ReachReason == "" {
		factors.ReachReason = "outbound network connection observed"
	}

	return &correlation.AttackChain{
		ID:              "data_exfiltration_chain",
		Name:            "Data Exfiltration Chain",
		Description:     c.Description(),
		Risk:            risk,
		Likelihood:      correlation.ComputeLikelihood(factors),
		Factors:         factors,
		InvolvedKinds:   involvedKinds(evidence),
		ProcessKey:      pickedProcKey,
		Sequence:        steps,
		Evidence:        evidence,
		Explanation:     "A process with access to sensitive data also opened an outbound connection; the host should be treated as if data has been exposed.",
		MITRETechniques: []string{"T1041"},
		Mitigations: []string{
			"Rotate the leaked credential / sensitive material immediately.",
			"Add network egress filtering to block the destination from the affected segment.",
			"Move secrets out of the binary into a vault that delivers per-install short-lived tokens.",
		},
		Workarounds: []string{
			"Stand up a private mock backend that captures uploaded data; replay the traffic to confirm what fields the sample exfiltrates.",
			"Replace the hardcoded secret with a unique canary token in a research build; treat any external request to the canary as confirmation it is live.",
		},
	}
}

func sensitiveTitle(s *correlation.Signal) string {
	switch s.Type {
	case correlation.TypeSensitiveCache:
		return "Sensitive cache artifact persisted"
	case correlation.TypeHardcodedSecret:
		return "Hardcoded secret available to the process"
	default:
		return s.Title
	}
}
