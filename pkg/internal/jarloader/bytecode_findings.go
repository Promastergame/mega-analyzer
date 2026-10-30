package jarloader

import (
	"fmt"
	"strconv"

	"mega-analyzer/pkg/internal/types"
)

// enrichInvocationEvidence keeps CP-only capabilities visible, but does not
// mislabel unused pool entries as call sites. Findings stay bounded: one per
// target reference, first site plus total site count, rather than one per call.
func enrichInvocationEvidence(cf *ClassFile, out []types.Match) []types.Match {
	if !cf.BytecodeParsed {
		return out
	}
	type summary struct {
		first CallSite
		count int
	}
	calls := map[string]summary{}
	for _, call := range cf.CallSites {
		if call.Opcode == "invokedynamic" {
			continue
		}
		key := call.Target.FullName() + call.Target.Descriptor
		s := calls[key]
		if s.count == 0 {
			s.first = call
		}
		s.count++
		calls[key] = s
	}
	for i := range out {
		m := &out[i]
		if m.Metadata["evidence_kind"] != "constant_pool_reference" {
			continue
		}
		s := calls[m.Text+m.Metadata["target_descriptor"]]
		m.EvidenceType = "constant_pool_reference"
		m.RequiredNextEvidence = "Establish entrypoint reachability and attacker-controlled arguments."
		if s.count == 0 {
			continue
		}
		call := s.first
		m.EvidenceType = "bytecode_invocation"
		m.Metadata["evidence_kind"] = m.EvidenceType
		m.Metadata["bytecode_offset"] = strconv.Itoa(call.Offset)
		m.Metadata["opcode"] = call.Opcode
		m.Metadata["call_site_count"] = strconv.Itoa(s.count)
		m.Metadata["caller_descriptor"] = call.CallerDescriptor
		m.Metadata["reachability_proven"] = "false"
		if cf.BytecodeTruncated {
			m.Metadata["call_site_count_is_lower_bound"] = "true"
		}
		m.MethodName, m.SourceLocation.Method = call.Caller, call.Caller+call.CallerDescriptor
		m.Context = fmt.Sprintf("%s in %s.%s%s at bytecode offset %d; reachability and data flow unproven", call.Opcode, cf.ThisClass, call.Caller, call.CallerDescriptor, call.Offset)
	}
	return append(out, trivialTLSFindings(cf)...)
}

func trivialTLSFindings(cf *ClassFile) []types.Match {
	trust, hostname := false, false
	for _, iface := range cf.Interfaces {
		trust = trust || iface == "javax.net.ssl.X509TrustManager"
		hostname = hostname || iface == "javax.net.ssl.HostnameVerifier"
	}
	var out []types.Match
	for _, m := range cf.Methods {
		// Require a public, non-static concrete override with its exact descriptor.
		if m.Access&0x0001 == 0 || m.Access&(0x0008|0x0100|0x0400) != 0 {
			continue
		}
		reason := ""
		if trust && (m.Name == "checkServerTrusted" || m.Name == "checkClientTrusted") && m.Descriptor == "([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V" && m.TrivialReturn == "void" {
			reason = "Certificate check has exactly one return instruction and performs no validation. Whether this implementation is installed is not proven."
		}
		if hostname && m.Name == "verify" && m.Descriptor == "(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z" && m.TrivialReturn == "true" {
			reason = "Hostname verifier body is exactly iconst_1; ireturn (unconditionally true). Whether it is installed is not proven."
		}
		if reason == "" {
			continue
		}
		out = append(out, types.Match{
			Categorized: types.Categorized{Category: "INSECURE_TLS_TRUST"},
			Text:        cf.ThisClass + "." + m.Name, Pattern: "JVM_TRIVIAL_TLS_BYPASS",
			ClassName: cf.ThisClass, MethodName: m.Name, Severity: types.SeverityHigh,
			IsCritical: true, Confidence: "0.95", ReasonForSeverity: reason,
			EvidenceType: "bytecode_method_body", SourceLocation: types.SourceLocation{Method: m.Name + m.Descriptor},
			Metadata:             map[string]string{"evidence_kind": "bytecode_method_body", "execution_proven": "false", "reachability_proven": "false"},
			RequiredNextEvidence: "Verify that the application installs this TLS implementation.",
		})
	}
	return out
}
