package pipeline

import (
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// DETAILED TRIAGE AND SCORING OVERHAUL ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

func (p *Pipeline) triageFindings() {
	if p.result == nil {
		return
	}

	for _, fa := range p.result.Files {
		if fa == nil {
			continue
		}

		var filteredMatches []types.Match

		for _, m := range fa.Matches {
			// Initialize triage properties
			evidenceType := "string_match"
			confidence := "high"
			reasonForSeverity := "Standard heuristic match."
			falsePositiveHints := ""
			requiredNextEvidence := ""
			severity := m.Severity
			isCritical := m.IsCritical

			textLower := strings.ToLower(m.Text)
			patternLower := strings.ToLower(m.Pattern)
			contextLower := strings.ToLower(m.Context)
			pathLower := strings.ToLower(fa.Path)

			// 1. XML UI/animation/style resource files triage
			// res/animator, res/drawable, res/layout, res/color, res/mipmap
			isXMLRes := strings.Contains(pathLower, "res/animator") ||
				strings.Contains(pathLower, "res/drawable") ||
				strings.Contains(pathLower, "res/layout") ||
				strings.Contains(pathLower, "res/color") ||
				strings.Contains(pathLower, "res/mipmap")

			if isXMLRes && fa.Type == types.FileTypeXML {
				// XML resource files often contain words or properties that trigger false security findings.
				severity = types.SeverityInfo
				isCritical = false
				reasonForSeverity = "BENIGN UI RESOURCE: Downgraded because it is located inside an animation/layout/color resource file."
				falsePositiveHints = "res/animator or res/drawable XML assets contain UI animation or layout specs that are false positives for exfiltration rules."
				evidenceType = "resource"
				confidence = "low"
			}

			// 2. Protobuf/Wire decode
			// Organise square wire or protobuf decoder calls
			// methods: com.squareup.wire.ProtoAdapter.decode, ProtoReader.nextTag, readUnknownField, endMessageAndGetUnknownFields
			isProtoDecode := strings.Contains(contextLower, "protoadapter") ||
				strings.Contains(contextLower, "protoreader") ||
				strings.Contains(contextLower, "readunknownfield") ||
				strings.Contains(contextLower, "endmessageandgetunknownfields") ||
				strings.Contains(textLower, "protoadapter") ||
				strings.Contains(textLower, "protoreader") ||
				strings.Contains(patternLower, "protoadapter") ||
				strings.Contains(patternLower, "protoreader")

			if isProtoDecode {
				// Downgrade to INFO/NORMAL (SeverityInfo)
				severity = types.SeverityInfo
				isCritical = false
				reasonForSeverity = "BENIGN PROTOBUF DECODE: Legitimate Square Wire / Protobuf string/field parsing."
				evidenceType = "API_call"
				confidence = "high"
			}

			// 3. Apache Commons Codec / phonetic algorithms
			// Org/apache/commons/codec/language/dmrules or DaitchMokotoffSoundex
			isPhoneticCodec := strings.Contains(pathLower, "org/apache/commons/codec/language/dmrules") ||
				strings.Contains(pathLower, "daitchmokotoffsoundex") ||
				strings.Contains(textLower, "dmrules") ||
				strings.Contains(contextLower, "dmrules")
			if isPhoneticCodec {
				severity = types.SeverityInfo
				isCritical = false
				reasonForSeverity = "BENIGN LIBRARY RESOURCE: Apache Commons phonetic algorithm rules/tables are benign code dependencies."
				evidenceType = "resource"
				confidence = "high"
			}

			// 4. Branch false positive
			// word "branch" without sdk evidence
			if strings.Contains(textLower, "branch") || strings.Contains(patternLower, "branch") {
				// Require Branch SDK evidence
				hasBranchSDK := strings.Contains(pathLower, "com/branch/sdk") ||
					strings.Contains(pathLower, "io/branch/referral") ||
					strings.Contains(contextLower, "branch.io") ||
					strings.Contains(contextLower, "api2.branch.io") ||
					strings.Contains(contextLower, "branch_key") ||
					strings.Contains(textLower, "branch_key")

				if !hasBranchSDK {
					severity = types.SeverityInfo
					isCritical = false
					reasonForSeverity = "UNVERIFIED BRANCH METRIC: Keyword 'branch' matched but no Branch.io SDK evidence was found in the package."
					falsePositiveHints = "Benign use of word 'branch' (like git branch or code branch)."
					evidenceType = "string_match"
					confidence = "low"
				}
			}

			// 5. Official vendor endpoints (yandex.ru, alice.yandex.net, rpc.alice.yandex.net, uniproxy.alice.yandex.net)
			isYandex := strings.Contains(textLower, "yandex.ru") ||
				strings.Contains(textLower, "yandex.net") ||
				strings.Contains(textLower, "alice.yandex") ||
				strings.Contains(patternLower, "yandex.ru") ||
				strings.Contains(patternLower, "yandex.net")

			if isYandex {
				// Determine severity by content type
				if strings.Contains(textLower, "token") || strings.Contains(textLower, "session") || strings.Contains(textLower, "credentials") {
					severity = types.SeverityHigh
					reasonForSeverity = "SENSITIVE ENDPOINT: Potential credential or OAuth token exfiltration to official vendor endpoint."
					evidenceType = "dataflow"
					confidence = "medium"
				} else if strings.Contains(textLower, "voice") || strings.Contains(textLower, "audio") || strings.Contains(textLower, "location") {
					severity = types.SeverityMedium
					reasonForSeverity = "TELEMETRY ENDPOINT: Voice/audio/chat/location telemetry endpoint."
					evidenceType = "API_call"
					confidence = "medium"
				} else {
					severity = types.SeverityLow
					reasonForSeverity = "VENDOR BACKEND: Benign official Yandex/Alice vendor backend endpoint."
					evidenceType = "string_match"
					confidence = "high"
				}
				isCritical = false
			}

			// 6. SSL pinning / TrustManager
			isSSLPinning := strings.Contains(textLower, "trustmanager") ||
				strings.Contains(textLower, "sslsocketfactory") ||
				strings.Contains(contextLower, "trustmanager") ||
				strings.Contains(contextLower, "sslsocketfactory") ||
				strings.Contains(patternLower, "trustmanager")

			if isSSLPinning {
				tlsEvidence := textLower + " " + contextLower + " " + patternLower + " " + strings.ToLower(m.ReasonForSeverity)
				hasVulnerabilities := strings.Contains(tlsEvidence, "trustall") ||
					strings.Contains(tlsEvidence, "allowall") ||
					strings.Contains(tlsEvidence, "allow_all") ||
					strings.Contains(tlsEvidence, "accept all") ||
					strings.Contains(tlsEvidence, "no certificate validation") ||
					strings.Contains(tlsEvidence, "validation is completely disabled") ||
					strings.Contains(tlsEvidence, "unconditionally") ||
					strings.Contains(tlsEvidence, "empty checkservertrusted")

				if hasVulnerabilities {
					severity = types.SeverityHigh
					isCritical = true
					reasonForSeverity = "VULNERABLE TRUSTMANAGER: SSL validation is completely disabled or bypassed."
					evidenceType = "callgraph"
					confidence = "high"
				} else {
					severity = types.SeverityLow
					isCritical = false
					reasonForSeverity = "BENIGN SECURITY HARDENING: SSL pinning or custom TrustManager used for validation."
					evidenceType = "callgraph"
					confidence = "high"
				}
			}

			// 7. PackageInfo signatures
			isSignatureCheck := (strings.Contains(textLower, "getpackageinfo") || strings.Contains(contextLower, "getpackageinfo")) &&
				(strings.Contains(textLower, "signatures") || strings.Contains(textLower, "get_signatures") || strings.Contains(textLower, "64"))

			if isSignatureCheck {
				severity = types.SeverityMedium
				isCritical = false
				reasonForSeverity = "ANTI-TAMPER CHECK: Environmental signature check. Verify if it redirects flow on mismatch."
				evidenceType = "API_call"
				confidence = "high"
			}

			// 8. Feature flags / config keys
			isFeatureFlag := textLower == "is_enabled" || textLower == "is_on_variable" || textLower == "layout_provider" || textLower == "height" || textLower == "id" ||
				patternLower == "is_enabled" || patternLower == "is_on_variable" || patternLower == "layout_provider" || patternLower == "height" || patternLower == "id"
			if isFeatureFlag {
				severity = types.SeverityInfo
				isCritical = false
				reasonForSeverity = "FEATURE FLAG / CONFIG: Normal client layout or feature config flag."
				evidenceType = "string_match"
				confidence = "high"
			}

			// 9. Piracy tool regex (lp_\w+ / Lucky Patcher)
			isPiracyLPMatch := strings.Contains(textLower, "lp_") || strings.Contains(patternLower, "lp_")
			if isPiracyLPMatch {
				hasLPEvidence := strings.Contains(pathLower, "lucky") ||
					strings.Contains(pathLower, "patcher") ||
					strings.Contains(textLower, "lucky") ||
					strings.Contains(textLower, "patcher") ||
					strings.Contains(contextLower, "lucky") ||
					strings.Contains(contextLower, "patcher")

				if !hasLPEvidence {
					severity = types.SeverityInfo
					isCritical = false
					reasonForSeverity = "FALSE POSITIVE PIRACY MATCH: Matched general lp_* prefix without specific Lucky Patcher context."
					falsePositiveHints = "Many payment / wallet configurations use 'lp_' prefix for other purposes."
					evidenceType = "string_match"
					confidence = "low"
				}
			}

			// 10. Subscription / trial bypass
			isSubTrial := strings.Contains(textLower, "trial") ||
				strings.Contains(textLower, "subscription") ||
				strings.Contains(textLower, "premium") ||
				strings.Contains(textLower, "pro")

			if isSubTrial {
				hasBypassLogic := strings.Contains(textLower, "bypass") ||
					strings.Contains(textLower, "unlock") ||
					strings.Contains(textLower, "entitlement") ||
					strings.Contains(contextLower, "entitlement")

				if !hasBypassLogic {
					severity = types.SeverityLow
					isCritical = false
					reasonForSeverity = "BENIGN SUBSCRIPTION REFERENCE: Normal reference to trial, subscription, premium, or pro."
					evidenceType = "string_match"
					confidence = "low"
				}
			}

			// 11. Purchase token logging
			isPurchaseToken := strings.Contains(textLower, "purchase_token") ||
				strings.Contains(textLower, "paymenttoken")

			if isPurchaseToken {
				isAnalytics := strings.Contains(contextLower, "analytics") ||
					strings.Contains(contextLower, "log") ||
					strings.Contains(contextLower, "event")

				if isAnalytics {
					severity = types.SeverityHigh
					isCritical = false
					reasonForSeverity = "SENSITIVE DATA LOGGING: Sensitive purchase token is being sent to analytics/logs."
					falsePositiveHints = "Ensure payment tokens are hashed/redacted before sending them to logging services."
					evidenceType = "dataflow"
					confidence = "high"
				}
			}

			// 12. Generic network clients
			isGenericClient := strings.Contains(textLower, "okhttpclient") ||
				strings.Contains(textLower, "httpurlconnection") ||
				strings.Contains(patternLower, "okhttpclient") ||
				strings.Contains(patternLower, "httpurlconnection")

			if isGenericClient {
				hasSuspiciousData := strings.Contains(textLower, "http://") ||
					strings.Contains(textLower, "cleartext") ||
					strings.Contains(contextLower, "http://")

				if hasSuspiciousData {
					severity = types.SeverityMedium
					reasonForSeverity = "CLEARTEXT HTTP: okhttp or httpurlconnection used with raw cleartext http."
					evidenceType = "API_call"
					confidence = "medium"
				} else {
					severity = types.SeverityLow
					reasonForSeverity = "BENIGN NETWORK STACK: Legitimate generic HTTP client constructor/field."
					evidenceType = "API_call"
					confidence = "high"
				}
				isCritical = false
			}

			// 13. Suspicious URL rules (yandex.ru / yandex.net etc.)
			if isYandex {
				severity = types.SeverityLow
				isCritical = false
				reasonForSeverity = "VENDOR ENDPOINT: Known secure vendor endpoint."
				evidenceType = "string_match"
				confidence = "high"
			}

			// 14. Root detection (su paths / system/bin/su etc.)
			isSU := strings.Contains(textLower, "bin/su") ||
				strings.Contains(textLower, "sbin/su") ||
				strings.Contains(textLower, "xbin/su") ||
				strings.Contains(patternLower, "bin/su")

			if isSU {
				severity = types.SeverityMedium
				isCritical = false
				reasonForSeverity = "ANTI-TAMPER CHECK: Environment checking for root access (su binary existence)."
				evidenceType = "API_call"
				confidence = "high"
			}

			// 14b. Tink keygen false positives
			if strings.Contains(textLower, "keygen") || strings.Contains(patternLower, "keygen") {
				isTink := strings.Contains(pathLower, "keyset") ||
					strings.Contains(pathLower, "tink") ||
					strings.Contains(pathLower, "encryptedstorage") ||
					strings.Contains(contextLower, "keyset") ||
					strings.Contains(contextLower, "tink") ||
					strings.Contains(contextLower, "encryptedstorage")

				if isTink {
					severity = types.SeverityInfo
					isCritical = false
					confidence = "low"
					reasonForSeverity = "BENIGN CRYPTO TOOL: Downgraded because 'keygen' resides in a Google Tink or encrypted storage context."
					evidenceType = "string_match"
				}
			}

			// 14c. Java mod metadata contact URLs (fabric.mod.json,
			// quilt.mod.json, mcmod.info, META-INF/mods.toml,
			// META-INF/neoforge.mods.toml). Loader descriptors routinely carry
			// author homepage/source/issue links: a URL here is mod inventory,
			// not application traffic. Keep it visible at Info and spell out
			// exactly what would re-escalate it.
			if (m.Category == types.CategoryNetworkEndpoint || m.Category == types.CategorySuspiciousURL) &&
				isJavaModDescriptorPath(fa.Path) {
				severity = types.SeverityInfo
				isCritical = false
				confidence = "low"
				reasonForSeverity = "MOD CONTACT URL: URL lives in a Java mod-loader descriptor (contact/homepage/sources), not in executable code or app traffic."
				falsePositiveHints = "fabric.mod.json, quilt.mod.json, mods.toml and mcmod.info routinely carry author homepage/source links."
				requiredNextEvidence = "Re-escalate only if the same URL also appears in executable code (.class) or a network call site."
				evidenceType = "string_match"
				if m.Metadata == nil {
					m.Metadata = make(map[string]string)
				}
				m.Metadata["mod_contact"] = "true"
			}

			// 15. Scoring model limits for CRITICAL
			if severity == types.SeverityCritical {
				// Only give CRITICAL if we have proven high-risk behavior
				isMaliciousExfil := strings.Contains(textLower, "exfiltrat") ||
					strings.Contains(textLower, "steal") ||
					strings.Contains(textLower, "c2") ||
					strings.Contains(textLower, "command") ||
					strings.Contains(textLower, "trojan")

				if !isMaliciousExfil {
					severity = types.SeverityHigh
					isCritical = false
					reasonForSeverity = "CRITICAL LIMIT: Downgraded from Critical because no active exfiltration or C2 patterns were proven."
				}
			}

			// 16. Automatic 2-level severity downgrade for low confidence string_match
			if confidence == "low" && evidenceType == "string_match" {
				// Downgrade 2 levels
				switch severity {
				case types.SeverityCritical:
					severity = types.SeverityMedium
				case types.SeverityHigh:
					severity = types.SeverityLow
				case types.SeverityMedium:
					severity = types.SeverityInfo
				case types.SeverityLow:
					severity = types.SeverityInfo
				}
			}

			// Set the processed/enriched properties
			m.Severity = severity
			m.IsCritical = isCritical
			m.EvidenceType = evidenceType
			m.Confidence = confidence
			m.ReasonForSeverity = reasonForSeverity
			m.FalsePositiveHints = falsePositiveHints
			m.RequiredNextEvidence = requiredNextEvidence

			if m.Metadata == nil {
				m.Metadata = make(map[string]string)
			}
			m.Metadata["evidence_type"] = evidenceType
			m.Metadata["confidence"] = confidence
			m.Metadata["reason_for_severity"] = reasonForSeverity
			if falsePositiveHints != "" {
				m.Metadata["false_positive_hints"] = falsePositiveHints
			}
			if requiredNextEvidence != "" {
				m.Metadata["required_next_evidence"] = requiredNextEvidence
			}

			filteredMatches = append(filteredMatches, m)
		}

		fa.Matches = filteredMatches
	}
}

// isJavaModDescriptorPath reports whether p is a Java mod-loader descriptor —
// the same set jarloader.DetectModDescriptor owns (Fabric, Quilt, Forge,
// NeoForge, legacy Forge). URLs inside these files are author
// contact/homepage links, not endpoints the application talks to. Nested
// "!/" prefixes (e.g. BOOT-INF/lib/nested.jar!/META-INF/mods.toml) are
// stripped before matching, mirroring the jarloader behavior.
func isJavaModDescriptorPath(p string) bool {
	if i := strings.LastIndex(p, "!/"); i >= 0 {
		p = p[i+2:]
	}
	p = strings.ReplaceAll(p, "\\", "/")
	base := p
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		if p[:i] == "META-INF" {
			switch p[i+1:] {
			case "mods.toml", "neoforge.mods.toml":
				return true
			}
		}
		base = p[i+1:]
	}
	switch base {
	case "fabric.mod.json", "quilt.mod.json", "mcmod.info":
		return true
	}
	return false
}
