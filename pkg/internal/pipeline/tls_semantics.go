package pipeline

import (
	"bytes"
	"regexp"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

type tlsIssue struct {
	offset      int
	ruleID      string
	description string
	evidence    string
	critical    bool
	confidence  float64
}

var sourceCommentRE = regexp.MustCompile(`(?s)/\*.*?\*/|//[^\r\n]*`)

func detectTLSSemantics(content, lower []byte, fileType types.FileType) []tlsIssue {
	if !bytes.Contains(lower, []byte("trust")) &&
		!bytes.Contains(lower, []byte("verifier")) &&
		!bytes.Contains(lower, []byte("ssl")) &&
		!bytes.Contains(lower, []byte("tls")) &&
		!bytes.Contains(lower, []byte("allow_all")) {
		return nil
	}
	issues := make([]tlsIssue, 0, 2)
	for _, signature := range [][]byte{[]byte("allow_all_hostname_verifier"), []byte("allownameallhostnameverifier")} {
		if offset := bytes.Index(lower, signature); offset >= 0 {
			issues = append(issues, tlsIssue{
				offset: offset, ruleID: "network.tls.allow_all_hostname_verifier",
				description: "Hostname verification is explicitly disabled",
				evidence:    string(signature), critical: true, confidence: 0.99,
			})
			break
		}
	}

	if fileType == types.FileTypeSmali {
		issues = append(issues, detectSmaliTLSSemantics(content, lower)...)
	} else {
		issues = append(issues, detectSourceTLSSemantics(content, lower)...)
	}
	return issues
}

func detectSmaliTLSSemantics(content, lower []byte) []tlsIssue {
	type methodBlock struct {
		header string
		body   []string
		offset int
	}
	lines := strings.Split(string(lower), "\n")
	methods := make([]methodBlock, 0, 8)
	lineOffsets := make([]int, len(lines))
	for i := 1; i < len(lines); i++ {
		lineOffsets[i] = lineOffsets[i-1] + len(lines[i-1]) + 1
	}
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(trimmed, ".method ") {
			continue
		}
		block := methodBlock{header: trimmed, offset: lineOffsets[i]}
		for j := i + 1; j < len(lines); j++ {
			if strings.HasPrefix(strings.TrimSpace(lines[j]), ".end method") {
				i = j
				break
			}
			block.body = append(block.body, lines[j])
		}
		methods = append(methods, block)
	}

	issues := make([]tlsIssue, 0, 2)
	implementsVerifier := bytes.Contains(lower, []byte("ljavax/net/ssl/hostnameverifier;")) ||
		bytes.Contains(lower, []byte("hostnameverifier"))
	for _, method := range methods {
		if strings.Contains(method.header, "checkservertrusted(") && smaliMethodIsNoOp(method.body) {
			issues = append(issues, tlsIssue{
				offset: method.offset, ruleID: "network.tls.empty_check_server_trusted",
				description: "X509TrustManager.checkServerTrusted performs no certificate validation",
				evidence:    "checkServerTrusted: return-void", critical: true, confidence: 0.99,
			})
		}
		if implementsVerifier && smaliHeaderHasMethod(method.header, "verify") && smaliReturnsConstantTrue(method.body) {
			issues = append(issues, tlsIssue{
				offset: method.offset, ruleID: "network.tls.hostname_verifier_true",
				description: "HostnameVerifier.verify returns true unconditionally",
				evidence:    "verify: constant true", critical: true, confidence: 0.99,
			})
		}
	}
	_ = content
	return issues
}

func smaliHeaderHasMethod(header, name string) bool {
	open := strings.IndexByte(header, '(')
	if open < 0 {
		return false
	}
	prefix := strings.TrimSpace(header[:open])
	fields := strings.Fields(prefix)
	return len(fields) > 0 && fields[len(fields)-1] == name
}

func smaliMethodIsNoOp(body []string) bool {
	seenReturn := false
	for _, line := range body {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ".") ||
			strings.HasPrefix(line, ":") || line == "nop" {
			continue
		}
		if line == "return-void" {
			seenReturn = true
			continue
		}
		return false
	}
	return seenReturn
}

func smaliReturnsConstantTrue(body []string) bool {
	trueRegisters := make(map[string]bool, 2)
	returns := 0
	for _, raw := range body {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ".") || strings.HasPrefix(line, ":") {
			continue
		}
		fields := strings.Fields(strings.ReplaceAll(line, ",", ""))
		if len(fields) >= 3 && strings.HasPrefix(fields[0], "const") {
			trueRegisters[fields[1]] = fields[2] == "0x1" || fields[2] == "1"
			continue
		}
		if len(fields) == 2 && fields[0] == "return" {
			if !trueRegisters[fields[1]] {
				return false
			}
			returns++
			continue
		}
		// Any branch, call, comparison, or field access makes the constant-return
		// proof inconclusive; do not emit a vulnerability.
		return false
	}
	return returns > 0
}

func detectSourceTLSSemantics(content, lower []byte) []tlsIssue {
	issues := make([]tlsIssue, 0, 2)
	textLower := string(lower)
	for _, method := range []string{"checkservertrusted", "verify"} {
		searchFrom := 0
		for {
			relative := strings.Index(textLower[searchFrom:], method)
			if relative < 0 {
				break
			}
			offset := searchFrom + relative
			open := strings.IndexByte(textLower[offset:], '{')
			if open < 0 || open > 500 {
				searchFrom = offset + len(method)
				continue
			}
			open += offset
			close := matchingBrace(textLower, open)
			if close < 0 {
				break
			}
			body := strings.TrimSpace(sourceCommentRE.ReplaceAllString(string(content[open+1:close]), ""))
			if method == "checkservertrusted" && (body == "" || body == "return;") {
				issues = append(issues, tlsIssue{
					offset: offset, ruleID: "network.tls.empty_check_server_trusted",
					description: "X509TrustManager.checkServerTrusted performs no certificate validation",
					evidence:    "empty checkServerTrusted body", critical: true, confidence: 0.99,
				})
			}
			if method == "verify" && strings.Contains(textLower[max(0, offset-300):offset], "hostnameverifier") && sourceReturnsTrue(body) {
				issues = append(issues, tlsIssue{
					offset: offset, ruleID: "network.tls.hostname_verifier_true",
					description: "HostnameVerifier.verify returns true unconditionally",
					evidence:    "return true", critical: true, confidence: 0.99,
				})
			}
			searchFrom = close + 1
		}
	}

	for _, marker := range []string{"-> true", "->true"} {
		if offset := strings.Index(textLower, marker); offset >= 0 {
			windowStart := max(0, offset-300)
			window := textLower[windowStart:offset]
			if strings.Contains(window, "hostnameverifier") || strings.Contains(window, "sethostnameverifier") {
				issues = append(issues, tlsIssue{
					offset: windowStart, ruleID: "network.tls.hostname_verifier_true",
					description: "HostnameVerifier lambda returns true unconditionally",
					evidence:    marker, critical: true, confidence: 0.95,
				})
				break
			}
		}
	}
	return issues
}

func matchingBrace(value string, open int) int {
	depth := 0
	for i := open; i < len(value); i++ {
		switch value[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func sourceReturnsTrue(body string) bool {
	body = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(body), ";")))
	return body == "return true" || body == "return java.lang.boolean.true" || body == "return boolean.true"
}
