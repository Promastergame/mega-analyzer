package attackchain

import "mega-analyzer/pkg/internal/correlation"

type IntentToDangerousSinkChain struct{}

func (IntentToDangerousSinkChain) ID() string   { return "android_intent_to_dangerous_sink" }
func (IntentToDangerousSinkChain) Name() string { return "Untrusted Intent to Dangerous Sink" }
func (IntentToDangerousSinkChain) Description() string {
	return "Attacker-controlled Intent data reaches a dangerous operation without an observed validation boundary."
}
func (c IntentToDangerousSinkChain) Detect(ctx *correlation.ExecutionContext) *correlation.AttackChain {
	if ctx == nil {
		return nil
	}
	entries := ctx.SignalsOfType(correlation.TypeUntrustedIntent)
	sinks := ctx.SignalsOfType(correlation.TypeDangerousSink)
	if len(entries) == 0 || len(sinks) == 0 {
		return nil
	}
	evidence := uniqueSignals(append(entries, sinks...))
	factors := correlation.LikelihoodFactors{Reachable: true, Controllable: true,
		ReachReason:   "static data-flow path connects an Android IPC source to the sink",
		ControlReason: "Intent extras or URI values are caller-controlled"}
	return androidChain(c.ID(), c.Name(), c.Description(), correlation.RiskCritical, factors, evidence,
		[]correlation.AttackChainStep{
			{Order: 1, Component: "manifest_and_ipc", Title: "Untrusted Intent input", Signals: entries},
			{Order: 2, Component: "data_flow", Title: "No validation boundary observed", Description: "The backward slice contains no recognized sanitizer."},
			{Order: 3, Component: "dangerous_operation", Title: "Dangerous sink reached", Signals: sinks},
		}, "REACHABLE: attacker-controlled IPC input has a static evidence path to the dangerous sink.")
}

type DeepLinkWebViewRCEChain struct{}

func (DeepLinkWebViewRCEChain) ID() string   { return "android_deeplink_webview_jsbridge_rce" }
func (DeepLinkWebViewRCEChain) Name() string { return "Deep Link to WebView JS-Bridge Capability" }
func (DeepLinkWebViewRCEChain) Description() string {
	return "A deep-link entry reaches remotely loaded WebView content with JavaScript and an exposed bridge capability."
}
func (c DeepLinkWebViewRCEChain) Detect(ctx *correlation.ExecutionContext) *correlation.AttackChain {
	if ctx == nil {
		return nil
	}
	entry := ctx.SignalsOfType(correlation.TypeDeepLinkEntry)
	remote := ctx.SignalsOfType(correlation.TypeWebViewRemoteLoad)
	bridge := append(ctx.SignalsOfType(correlation.TypeWebViewJSBridge), ctx.SignalsOfType(correlation.TypeJSBridgeCapability)...)
	if len(entry) == 0 || len(remote) == 0 || len(bridge) == 0 {
		return nil
	}
	evidence := uniqueSignals(append(append(entry, remote...), bridge...))
	factors := correlation.LikelihoodFactors{Reachable: true, Controllable: true,
		ReachReason:   "exported deep-link route and remote WebView load are both present",
		ControlReason: "the attacker controls the deep-link URI or remote page"}
	return androidChain(c.ID(), c.Name(), c.Description(), correlation.RiskCritical, factors, evidence,
		[]correlation.AttackChainStep{
			{Order: 1, Component: "manifest", Title: "Deep-link entry point", Signals: entry},
			{Order: 2, Component: "webview", Title: "Remote content loaded with JavaScript", Signals: remote},
			{Order: 3, Component: "webview_bridge", Title: "JavaScript interface exposes native capability", Signals: bridge},
		}, "REACHABLE: a browsable entry can influence remote WebView content that has access to a native bridge.")
}

type StorageProviderExfiltrationChain struct{}

func (StorageProviderExfiltrationChain) ID() string { return "android_storage_exported_provider" }
func (StorageProviderExfiltrationChain) Name() string {
	return "Sensitive Storage to Exported Provider"
}
func (StorageProviderExfiltrationChain) Description() string {
	return "Sensitive data is written to insecure storage that is reachable through an exported ContentProvider."
}
func (c StorageProviderExfiltrationChain) Detect(ctx *correlation.ExecutionContext) *correlation.AttackChain {
	if ctx == nil {
		return nil
	}
	storage := ctx.SignalsOfType(correlation.TypeInsecureStorage)
	provider := append(ctx.SignalsOfType(correlation.TypeExportedProvider), ctx.SignalsOfType(correlation.TypeExportedComponent)...)
	if len(storage) == 0 || len(provider) == 0 {
		return nil
	}
	evidence := uniqueSignals(append(storage, provider...))
	factors := correlation.LikelihoodFactors{Reachable: true, Controllable: false,
		ReachReason:   "an exported provider exposes app-managed storage",
		ControlReason: "external callers can query the provider, but sensitive content depends on app state"}
	return androidChain(c.ID(), c.Name(), c.Description(), correlation.RiskHigh, factors, evidence,
		[]correlation.AttackChainStep{
			{Order: 1, Component: "storage", Title: "Sensitive data stored insecurely", Signals: storage},
			{Order: 2, Component: "manifest", Title: "Provider is externally reachable", Signals: provider},
			{Order: 3, Component: "provider", Title: "External read path", Description: "Review provider URI/path and permission gates."},
		}, "REACHABLE WITH CONDITION: external access is possible when the provider URI maps to the insecure storage location.")
}

func androidChain(id, name, description string, risk correlation.Risk, factors correlation.LikelihoodFactors, evidence []*correlation.Signal, steps []correlation.AttackChainStep, explanation string) *correlation.AttackChain {
	return &correlation.AttackChain{
		ID: id, Name: name, Description: description, Risk: risk,
		Likelihood: correlation.ComputeLikelihood(factors), Factors: factors,
		InvolvedKinds: involvedKinds(evidence), Sequence: steps, Evidence: evidence,
		Explanation: explanation, Tags: []string{"android", "static", "exploit-chain"},
		Mitigations: []string{"Gate exported entry points with least-privilege permissions and validate caller-controlled input.", "Keep evidence-path sanitizers explicit so reachability can be verified."},
	}
}
