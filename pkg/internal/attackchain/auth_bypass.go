package attackchain

import (
	"strings"

	"mega-analyzer/pkg/internal/correlation"
)

// AuthBypassChain is a *static-first* chain. It targets the
// "client-side authorization" anti-pattern:
//
//	security_audit       isPremium / isLicensed / isSubscribed found
//	       ↓
//	security_audit       same boolean drives a UI / feature gate
//	       ↓
//	network_analysis     no server-side validation observed at runtime
//
// A well-designed app would re-validate the entitlement against a
// server. If we see the gate but never see the request, the gate is
// almost certainly bypassable by patching one boolean.
type AuthBypassChain struct{}

func (AuthBypassChain) ID() string   { return "auth_bypass_chain" }
func (AuthBypassChain) Name() string { return "Client-side Auth Bypass Chain" }
func (AuthBypassChain) Description() string {
	return "Application gates premium/license features behind a client-side boolean with no observed server-side validation."
}

func (c AuthBypassChain) Detect(ctx *correlation.ExecutionContext) *correlation.AttackChain {
	if ctx == nil {
		return nil
	}

	gates := make([]*correlation.Signal, 0, len(ctx.SignalsOfType(correlation.TypeAuthGate)))
	gates = append(gates, ctx.SignalsOfType(correlation.TypeAuthGate)...)
	gates = append(gates, ctx.SignalsOfType(correlation.TypeBooleanGate)...)
	if len(gates) == 0 {
		return nil
	}

	// Drop native-library string-blob gates (.so): engine binaries match
	// entitlement substrings ("isPro" inside libunity.so) without being app
	// license logic. A chain built only on those is a false positive.
	filtered := gates[:0]
	for _, g := range gates {
		if g == nil {
			continue
		}
		if isNativeLibSignal(g) {
			continue
		}
		filtered = append(filtered, g)
	}
	gates = filtered
	if len(gates) == 0 {
		return nil
	}

	// Did we see any authentication-y network traffic? The endpoint
	// detector classifies these as "auth" in the static layer; runtime
	// equivalents are HTTPS connections to *.auth/login/license hosts.
	// Any runtime network call is *some* server interaction, so we treat
	// the bypass risk as reduced when we see one.
	serverValidated := firstMatch(ctx.SignalsOfKind(correlation.KindNetwork),
		func(s *correlation.Signal) bool {
			return s.IsRuntime() && s.Severity > 0
		}) != nil

	// Pick a representative gate for the headline.
	primary := gates[0]
	for _, g := range gates {
		if g.Severity > primary.Severity {
			primary = g
		}
	}

	risk := correlation.RiskHigh
	if serverValidated {
		risk = correlation.RiskMedium
	} else if primary.Severity < 5 && primary.Confidence < 0.7 {
		// Weak-only static evidence (low severity, low confidence, no
		// runtime observation): don't scream HIGH on a guess.
		risk = correlation.RiskMedium
	}

	factors := correlation.LikelihoodFactors{
		Reachable:     true,
		ReachReason:   "premium / license gate present in shipped binary",
		Controllable:  true,
		ControlReason: "client-side boolean is patchable by anyone who can rebuild the APK",
	}

	steps := []correlation.AttackChainStep{
		{
			Order:       1,
			Component:   "security_audit",
			Title:       "Premium / license gate detected",
			Description: "Method or field that gates premium features based on a local boolean.",
			Signals:     []*correlation.Signal{primary},
		},
	}
	if !serverValidated {
		steps = append(steps, correlation.AttackChainStep{
			Order:       2,
			Component:   "network_analysis",
			Title:       "No server-side entitlement validation observed",
			Description: "Sandbox did not record any server interaction that would re-confirm the entitlement.",
			Signals:     nil,
		})
	}

	return &correlation.AttackChain{
		ID:            "auth_bypass_chain",
		Name:          "Client-side Auth Bypass Chain",
		Description:   c.Description(),
		Risk:          risk,
		Likelihood:    correlation.ComputeLikelihood(factors),
		Factors:       factors,
		InvolvedKinds: involvedKinds(gates),
		Sequence:      steps,
		Evidence:      uniqueSignals(gates),
		Explanation: "Client-side entitlement checks can be bypassed by patching a single boolean. " +
			"Without server-side validation the user can grant themselves premium access offline.",
		MITRETechniques: []string{"T1556"},
		Mitigations: []string{
			"Move the entitlement decision to a signed, server-issued token that the client cannot forge.",
			"Add server-side rate limiting and signed receipts so tampered clients can be detected.",
			"Treat any local boolean as a UX hint, never as a security boundary.",
		},
		Workarounds: []string{
			"Patch the boolean to true on a research build; if the server still rejects unauthorized actions, the entitlement system is correctly designed.",
			"Run the app behind a private mock backend and observe whether the server is ever consulted before unlocking premium features.",
		},
	}
}

// isNativeLibSignal reports whether a gate signal points into a native
// library blob rather than app (smali/dex) code.
func isNativeLibSignal(s *correlation.Signal) bool {
	if s == nil {
		return false
	}
	file := strings.ToLower(strings.TrimSpace(s.Location.File))
	if strings.HasSuffix(file, ".so") {
		return true
	}
	target := strings.ToLower(s.Target)
	// Extremely long native string-dump targets (Unity engine blobs) are
	// never precise gate locations.
	if strings.Contains(file, "libunity") || strings.Contains(target, "libunity") {
		return true
	}
	return false
}
