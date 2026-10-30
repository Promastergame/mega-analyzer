package correlation

import (
	"fmt"
	"strings"
)

// guidanceFor returns (mitigations, workarounds) for a Signal Type.
//
// "Mitigations" are defender-facing fixes (the traditional "how to
// patch this" advice).
//
// "Workarounds" are research-time setup recommendations the user
// asked us to surface — *how to verify the finding safely*, not how
// to exploit it. For example: "stand up a private HTTPS endpoint to
// confirm the secret is actually used", "self-host a mock C2 to see
// what the sample sends".
//
// Both lists are intentionally short — a long list of generic
// recommendations is noise. If a Type has no specific advice we
// return nil so the renderer can omit the section entirely.
func guidanceFor(typ string) (mitigations, workarounds []string) {
	switch typ {

	case TypeProcessInjection, TypeProcessHollowing, TypeRemoteThread:
		return []string{
			"Treat any process spawned by this sample as compromised; isolate the host from production.",
			"Enable EDR rules for VirtualAllocEx + WriteProcessMemory + CreateRemoteThread sequences.",
			"Block the dropped binary by hash and signing certificate at the gateway.",
		}, []string{
			"Re-run the sample in the sandbox with the API tracer enabled and capture the call stack of CreateRemoteThread.",
			"Snapshot the target process memory after WriteProcessMemory and dump the injected region for offline analysis.",
		}

	case TypeRWXMemory, TypeMemoryWrite:
		return []string{
			"Verify that the process is actually a JIT runtime (Java/.NET/Node/Browser) before treating RWX as benign.",
			"If not a JIT, alert and capture the allocated region for offline analysis.",
		}, []string{
			"Re-run with API tracing focused on the offending PID and dump the page contents at the moment of allocation.",
		}

	case TypeOutboundConnection, TypePublicEgress, TypeRiskyServicePort:
		return []string{
			"Confirm the destination is on the vendor's documented allow-list before treating the connection as benign.",
			"Block the host/port at the firewall if the destination is not required by the application.",
		}, []string{
			"Stand up a private HTTPS responder (e.g. mitmproxy or a self-signed nginx) and route the sandbox's egress to it; confirm whether the sample falls back to a hardcoded backup.",
			"Replay the captured traffic through a private server to verify whether requests carry credentials, device IDs, or PII.",
		}

	case TypeSuspiciousDNS:
		return []string{
			"Sinkhole or block the suspicious domain at the resolver.",
			"Cross-reference the domain against threat-intel feeds before allow-listing.",
		}, []string{
			"Set up a controlled DNS responder pointing the suspicious name at a private host and observe the protocol used by the sample.",
		}

	case TypeOpaqueTLS:
		return []string{
			"Require SNI or block opaque TLS at the egress proxy.",
		}, []string{
			"Install a custom root CA in the sandbox image, MITM the connection, and read the certificate the sample expects.",
		}

	case TypeHardcodedSecret:
		return []string{
			"Rotate the leaked secret immediately and revoke any tokens that share the same key prefix.",
			"Move the secret to a remote configuration service or a per-install token.",
			"Add a secret-scanning hook to the build pipeline.",
		}, []string{
			"Stand up a private mock backend that accepts the leaked credential and observe what the sample posts back.",
			"Replace the secret with a unique canary token in a research build; treat any external request to that canary as confirmation the secret is live.",
		}

	case TypeCleartextEndpoint, TypeHardcodedIPEndpoint:
		return []string{
			"Switch the endpoint to HTTPS and pin the certificate.",
			"Remove any hardcoded IPs in favor of DNS names with rotation support.",
		}, []string{
			"Run a private HTTPS endpoint with a self-signed cert and verify whether the sample falls back to cleartext or fails closed.",
			"Capture the sample's request/response with a transparent proxy to confirm what data is actually sent.",
		}

	case TypeWeakCrypto:
		return []string{
			"Replace RC4/DES/ECB with AES-GCM and SHA-256+; use a vetted crypto library.",
			"Disable trust-all SSL contexts and enforce hostname verification.",
		}, []string{
			"Capture sample-generated ciphertext, attempt decryption with the discovered weak primitive, and confirm the threat impact.",
		}

	case TypeWebViewJSBridge:
		return []string{
			"Restrict @JavascriptInterface to non-sensitive methods and require setAllowFileAccess(false).",
			"Set the WebView's targetSdk to 17+ and validate every loadUrl input.",
			"Pin the WebView to vendor domains via shouldOverrideUrlLoading.",
		}, []string{
			"Host a controlled HTML payload on a private server and load it through the WebView to enumerate which methods the bridge actually exposes.",
		}

	case TypeWebViewCleartext:
		return []string{
			"Disable JavaScript or restrict it to local content; never load remote pages with JS in a privileged WebView.",
		}, []string{
			"Replay the WebView's loadUrl through a private HTTPS responder to confirm cleartext fallback.",
		}

	case TypeDebugEndpoint:
		return []string{
			"Strip debug routes from release builds; gate them behind a build-time flag.",
			"If the endpoint must remain, require an internal-only network and authenticated access.",
		}, []string{
			"Run the sample with the debug endpoint exposed on localhost behind a private proxy and confirm what data the endpoint reveals.",
		}

	case TypeExportedComponent:
		return []string{
			"Set android:exported=\"false\" or require a signature-level permission.",
			"Validate every Intent extra before consuming it.",
		}, []string{
			"Build a controlled \"attacker\" app on the sandbox image, send Intents to the exported component, and observe what is exposed.",
		}

	case TypeRootBypass:
		return []string{
			"Treat root detection as a defense-in-depth signal, not a security boundary.",
			"Combine with Play Integrity attestation and server-side device-binding checks.",
		}, []string{
			"Run the sample on a controlled rooted research device and capture which checks it performs.",
		}

	case TypeAuthGate, TypeBooleanGate:
		return []string{
			"Move the premium / license decision to a server-validated token; never trust a local boolean.",
			"Add server-side rate limiting and signed receipts to detect tampered clients.",
		}, []string{
			"Patch the boolean to true on a research build and confirm the server still rejects unauthorized actions — that is the correct behavior.",
		}

	case TypeRegistryAutorun, TypeServiceInstall, TypeScheduledTask,
		TypeFilePersistence:
		return []string{
			"Quarantine the persistence artifact and rebuild the host from a known-good image.",
			"Add EDR detection rules for the specific Run/RunOnce key, service, or task.",
		}, []string{
			"Capture the dropped persistence binary and re-run it in isolation to map its second-stage behavior without the parent sample.",
		}

	case TypeFileDropExec, TypeFileDropScript, TypeSensitiveCache:
		return []string{
			"Block the dropped binary by hash; confirm it is not a legitimate installer.",
			"Inspect the cache artifact for embedded credentials before deletion.",
		}, []string{
			"Hash the artifact, compare against vendor-provided hashes, and detonate it standalone in the sandbox.",
		}

	case TypeMassFileChange:
		return []string{
			"Treat as ransomware until proven otherwise; isolate the host immediately.",
			"Restore from offline backups and rotate any credentials that may have been touched.",
		}, []string{
			"Re-run with VSS snapshotting on so before/after diffs can be compared offline.",
		}

	case TypeMITREMatch:
		return []string{
			"Map the matched MITRE technique to your detection backlog and verify coverage.",
		}, nil

	case TypeScriptStager:
		return []string{
			"Block the stager command line via process-creation rules (e.g. PowerShell `IEX`/`DownloadString`).",
			"Restrict outbound HTTP for shell hosts.",
		}, []string{
			"Replay the stager command in a contained shell with a private HTTPS responder and capture the second-stage payload.",
		}
	}
	return nil, nil
}

// explain produces the one-paragraph "why is this risky" string the
// finding renders. We tailor wording to the primary signal type.
func explain(primary *Signal, support []*Signal,
	factors LikelihoodFactors, risk Risk, lh Likelihood) string {

	if primary == nil {
		return ""
	}
	var b strings.Builder
	switch primary.Type {

	case TypeHardcodedSecret:
		b.WriteString("A secret was found embedded in the binary.")
		if hasRuntimeNetwork(support) {
			b.WriteString(" Runtime telemetry shows the same process making outbound requests, which means the secret is reachable in production traffic.")
		} else {
			b.WriteString(" No runtime network usage was observed; the secret may still be live but is not corroborated by execution telemetry yet.")
		}

	case TypeCleartextEndpoint, TypeHardcodedIPEndpoint:
		b.WriteString("An insecure (cleartext or hardcoded-IP) endpoint is referenced from the binary.")
		if hasRuntimeNetwork(support) {
			b.WriteString(" The sample actually opened an outbound connection during the run, so this endpoint is exercised, not dormant.")
		} else {
			b.WriteString(" The sandbox did not observe a connection to this endpoint, so the risk is potential rather than confirmed.")
		}

	case TypeProcessInjection, TypeProcessHollowing:
		b.WriteString("The sample executed the canonical process-injection API sequence (allocate executable memory in another process, write to it, start a remote thread).")

	case TypeRWXMemory, TypeMemoryWrite:
		if primary.HasTag(TagJIT) {
			b.WriteString("Executable memory was allocated, but the source is a known JIT runtime — this is expected and the signal is downgraded.")
		} else {
			b.WriteString("Executable memory was allocated outside any known JIT runtime; this is a strong indicator of code injection or shellcode staging.")
		}

	case TypeWebViewJSBridge:
		if primary.HasTag(TagSensitiveMethod) {
			b.WriteString("A WebView JavaScript bridge exposes a sensitive method to remote content; this is a remote-code-execution shape.")
		} else {
			b.WriteString("A WebView JavaScript bridge is configured. We have no evidence that it exposes sensitive methods, so the risk is reduced but worth confirming.")
		}

	case TypeDebugEndpoint:
		b.WriteString("A debug endpoint or surface was found in the binary.")
		if !primary.HasTag(TagExported) && !primary.HasTag(TagReachable) {
			b.WriteString(" It is not exported and the sandbox did not connect to it, so the risk is potential rather than confirmed.")
		} else {
			b.WriteString(" It is reachable and should be removed from release builds.")
		}

	case TypeAuthGate, TypeBooleanGate:
		b.WriteString("A client-side authorization decision (premium / license / subscription gate) was found.")
		if !factors.ObservedAtRuntime {
			b.WriteString(" No server-side validation was observed at runtime; if the gate is the only check, it can be bypassed by patching a single boolean.")
		}

	case TypeRegistryAutorun, TypeServiceInstall, TypeScheduledTask,
		TypeFilePersistence:
		b.WriteString("The sample established persistence on the host, meaning it survives a reboot and re-runs without the user's knowledge.")

	case TypeOutboundConnection, TypePublicEgress:
		b.WriteString("The sample opened an outbound connection to an external host.")
		if hasOtherType(support, TypeHardcodedSecret) {
			b.WriteString(" The same process holds a hardcoded secret, raising the chance the connection authenticates with leaked credentials.")
		}

	case TypeSuspiciousDNS:
		b.WriteString("A DNS query matched dynamic-DNS / staging-infrastructure patterns frequently used by malware operators.")

	case TypeMassFileChange:
		b.WriteString("A burst of file create/modify operations was observed; this is the canonical ransomware shape.")

	default:
		b.WriteString(primary.Description)
		if b.Len() == 0 {
			b.WriteString(primary.Title)
		}
	}

	// Closing sentence with risk + likelihood, uniformly formatted.
	if b.Len() > 0 {
		b.WriteString(" ")
	}
	b.WriteString(fmt.Sprintf("Assessed risk: %s, likelihood: %s.", risk, lh))
	return b.String()
}

func hasRuntimeNetwork(signals []*Signal) bool {
	for _, s := range signals {
		if s == nil {
			continue
		}
		if s.IsRuntime() && s.Kind == KindNetwork {
			return true
		}
	}
	return false
}

func hasOtherType(signals []*Signal, typ string) bool {
	for _, s := range signals {
		if s == nil {
			continue
		}
		if s.Type == typ {
			return true
		}
	}
	return false
}
