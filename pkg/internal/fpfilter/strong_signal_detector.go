package fpfilter

import (
	"regexp"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// StrongSignalDetector finds security signals that must not be suppressed.
type StrongSignalDetector struct{}

var cveIdentifier = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,}\b`)

func NewStrongSignalDetector() *StrongSignalDetector {
	return &StrongSignalDetector{}
}

// Detect returns a list of strong signals found in the match.
func (s *StrongSignalDetector) Detect(match *types.Match) []types.StrongSignal {
	var signals []types.StrongSignal
	if match == nil {
		return signals
	}
	if isObservation(match) {
		return signals
	}

	// 1. Hardcoded Secret / Token / API Key
	if isSecretCategory(match.Category) {
		signals = append(signals, types.StrongSignal{
			SignalType: "hardcoded_secret",
			Confidence: 0.9,
			Evidence:   "Found category: " + string(match.Category),
		})
	}

	// 2. Insecure Crypto
	if match.Category == "CRYPTO_WEAK_HASH" || match.Category == "CRYPTO_WEAK_CIPHER" {
		signals = append(signals, types.StrongSignal{
			SignalType: "insecure_crypto",
			Confidence: 0.85,
			Evidence:   "Found category: " + string(match.Category),
		})
	}

	// 3. Unsafe WebView
	if strings.Contains(strings.ToLower(match.Pattern), "addjavascriptinterface") || match.Category == "WEBVIEW_UNSAFE_BRIDGE" {
		signals = append(signals, types.StrongSignal{
			SignalType: "unsafe_webview_bridge",
			Confidence: 0.9,
			Evidence:   "JS bridge exposed",
		})
	}

	// 4. Dynamic Code Loading
	if match.Category == "DYNAMIC_CODE_LOADING" {
		signals = append(signals, types.StrongSignal{
			SignalType: "dynamic_code_loading",
			Confidence: 0.95,
			Evidence:   "DexClassLoader/PathClassLoader found",
		})
	}

	// 5. Command Execution
	if match.Category == "COMMAND_EXECUTION" {
		signals = append(signals, types.StrongSignal{
			SignalType: "command_execution",
			Confidence: 0.9,
			Evidence:   "Runtime.exec or ProcessBuilder used",
		})
	}

	// 6. Cleartext traffic
	if match.Category == "NETWORK_CLEARTEXT" {
		signals = append(signals, types.StrongSignal{
			SignalType: "cleartext_traffic",
			Confidence: 0.8,
			Evidence:   "HTTP URL or cleartext config",
		})
	}

	// 7. Dangerous Permissions
	if match.Category == "PERMISSION_DANGEROUS" || match.Category == "PERMISSION_ABUSE" {
		signals = append(signals, types.StrongSignal{
			SignalType: "dangerous_permission",
			Confidence: 0.7,
			Evidence:   "Requests sensitive permission",
		})
	}

	// 7a. Insecure deserialization (top JVM RCE sink, emitted by jarloader)
	if match.Category == "INSECURE_DESERIALIZATION" {
		signals = append(signals, types.StrongSignal{
			SignalType: "insecure_deserialization",
			Confidence: 0.9,
			Evidence:   "Native Java deserialization sink (ObjectInputStream)",
		})
	}

	// 7b. JNDI injection (Log4Shell-class)
	if match.Category == "JNDI_INJECTION" {
		signals = append(signals, types.StrongSignal{
			SignalType: "jndi_injection",
			Confidence: 0.92,
			Evidence:   "JNDI lookup sink (Log4Shell-style)",
		})
	}

	// 7c. XML external entity
	if match.Category == "XXE" {
		signals = append(signals, types.StrongSignal{
			SignalType: "xxe",
			Confidence: 0.75,
			Evidence:   "XML parser without explicit external-entity hardening",
		})
	}

	// 7d. SQL injection sink
	if match.Category == "SQL_INJECTION" {
		signals = append(signals, types.StrongSignal{
			SignalType: "sql_injection",
			Confidence: 0.75,
			Evidence:   "Raw SQL Statement sink",
		})
	}

	// 8. A structured CVE result from a dependency scanner. CWE is taxonomy;
	// prose containing "vulnerability" or a critical label is not extra proof.
	if cveIdentifier.MatchString(match.Metadata["cve"]) {
		signals = append(signals, types.StrongSignal{
			SignalType: "known_vulnerability",
			Confidence: 0.95,
			Evidence:   "Dependency scanner reported " + match.Metadata["cve"],
		})
	}

	return signals
}

func isSecretCategory(c types.Category) bool {
	s := string(c)
	return strings.Contains(s, "SECRET") || strings.Contains(s, "TOKEN") || strings.Contains(s, "KEY") || strings.Contains(s, "CREDENTIAL")
}
