package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"mega-analyzer/pkg/binzap"
	"mega-analyzer/pkg/binzap/lex"
	"mega-analyzer/pkg/ml"
	"mega-analyzer/pkg/vulnscan"
)

// ═══════════════════════════════════════════════════════════════════════════════
// RULES CRUD ENDPOINTS (Web / Binzap / ML) — thin wrappers over generic CRUD.
// ═══════════════════════════════════════════════════════════════════════════════

func webRuleStore() crudStore[vulnscan.DynamicWebRule] {
	return crudStore[vulnscan.DynamicWebRule]{
		kind:   "web rule",
		list:   vulnscan.GetDynamicWebRules,
		add:    vulnscan.AddDynamicWebRule,
		update: vulnscan.UpdateDynamicWebRule,
		remove: vulnscan.DeleteDynamicWebRule,
		getID:  func(r vulnscan.DynamicWebRule) string { return r.ID },
		setID:  func(r *vulnscan.DynamicWebRule, id string) { r.ID = id },
	}
}

func binzapRuleStore() crudStore[binzap.DynamicBinzapRule] {
	return crudStore[binzap.DynamicBinzapRule]{
		kind:   "binzap rule",
		list:   binzap.GetRawDynamicBinzapRules,
		add:    binzap.AddDynamicBinzapRule,
		update: binzap.UpdateDynamicBinzapRule,
		remove: binzap.DeleteDynamicBinzapRule,
		getID:  func(r binzap.DynamicBinzapRule) string { return r.IDStr },
		setID:  func(r *binzap.DynamicBinzapRule, id string) { r.IDStr = id },
	}
}

func mlPatternStore() crudStore[ml.VulnerablePattern] {
	return crudStore[ml.VulnerablePattern]{
		kind:   "ml pattern",
		list:   ml.GetDynamicMLPatterns,
		add:    ml.AddDynamicMLPattern,
		update: ml.UpdateDynamicMLPattern,
		remove: ml.DeleteDynamicMLPattern,
		getID:  func(p ml.VulnerablePattern) string { return p.ID },
		setID:  func(p *ml.VulnerablePattern, id string) { p.ID = id },
	}
}

func (s *APIServer) handleWebRules(w http.ResponseWriter, r *http.Request) {
	handleCollection(w, r, webRuleStore())
}

func (s *APIServer) handleWebRuleSingle(w http.ResponseWriter, r *http.Request) {
	handleSingle(w, r, "/api/v1/rules/web/", webRuleStore())
}

// ═══════════════════════════════════════════════════════════════════════════════
// BINZAP RULES CRUD
// ═══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) handleBinzapRules(w http.ResponseWriter, r *http.Request) {
	handleCollection(w, r, binzapRuleStore())
}

func (s *APIServer) handleBinzapRuleSingle(w http.ResponseWriter, r *http.Request) {
	handleSingle(w, r, "/api/v1/rules/binzap/", binzapRuleStore())
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML/SMALI RULES CRUD
// ═══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) handleMLRules(w http.ResponseWriter, r *http.Request) {
	handleCollection(w, r, mlPatternStore())
}

func (s *APIServer) handleMLRuleSingle(w http.ResponseWriter, r *http.Request) {
	handleSingle(w, r, "/api/v1/rules/ml/", mlPatternStore())
}

// ═══════════════════════════════════════════════════════════════════════════════
// UNIVERSAL DRY-RUN TESTER
// ═══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) handleRuleTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST.", "Use POST.", nil)
		return
	}
	var req struct {
		RuleType string `json:"rule_type"` // "web", "binzap", or "ml"
		RuleJSON string `json:"rule_json"` // Serialized raw JSON of the rule struct
		Sample   string `json:"sample"`    // Testing target: URL, bytecode snippet, headers list or Smali code
	}
	if err := decodeJSONBody(r, defaultMaxJSONBytes, &req); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid Payload Schema", err.Error(), "Ensure JSON contains 'rule_type', 'rule_json', and 'sample' keys.", nil)
		return
	}

	switch req.RuleType {
	case "web":
		s.handleRuleTestWeb(w, r, req.RuleJSON, req.Sample)
	case "binzap":
		s.handleRuleTestBinzap(w, r, req.RuleJSON, req.Sample)
	case "ml":
		s.handleRuleTestML(w, r, req.RuleJSON, req.Sample)
	default:
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Unsupported Rule Type", fmt.Sprintf("Testing currently unsupported for rule type: %s", req.RuleType), "Choose 'web', 'binzap', or 'ml'.", nil)
	}
}

func (s *APIServer) handleRuleTestWeb(w http.ResponseWriter, r *http.Request, ruleJSON, sample string) {
	var rule vulnscan.DynamicWebRule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid Web Rule Layout", err.Error(), "Review Web Rule attributes fields.", nil)
		return
	}

	switch rule.Type {
	case "regex_passive":
		s.handleRuleTestWebRegex(w, r, rule, sample)
	case "header_check":
		s.handleRuleTestWebHeader(w, r, rule, sample)
	case "fuzz":
		s.handleRuleTestWebFuzz(w, r, rule, sample)
	default:
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Unsupported Web Rule Type", fmt.Sprintf("Web dry-run currently unsupported for rule type: %s", rule.Type), "Use regex_passive, header_check, or fuzz rules.", nil)
	}
}

func (s *APIServer) handleRuleTestWebRegex(w http.ResponseWriter, r *http.Request, rule vulnscan.DynamicWebRule, sample string) {
	if !strings.HasPrefix(sample, "http://") && !strings.HasPrefix(sample, "https://") {
		// Treat sample directly as raw body content if it isn't a URL
		re, err := compileRegexSafe(rule.RegexPattern)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid Regex Pattern", err.Error(), "Fix regex pattern compilation parameters.", nil)
			return
		}
		matched := re.MatchString(sample)
		var findings []interface{}
		evidence := ""
		if matched {
			evidence = re.FindString(sample)
			findings = append(findings, map[string]interface{}{
				"id": rule.ID, "name": rule.Name, "description": rule.Description,
				"severity": rule.Severity, "evidence": fmt.Sprintf("Passive match: %s", evidence),
			})
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"matched": matched, "findings_count": len(findings), "findings": findings, "evidence": evidence,
		})
		return
	}

	// URL mode - fetch actual target body
	if !isSafeTarget(sample) {
		writeProblem(w, r, http.StatusForbidden, "ERR_SSRF", "SSRF Detected", "URL points to local/internal network.", "Use public URL.", nil)
		return
	}
	client, clientErr := safeHTTPClient(30*time.Second, sample)
	if clientErr != nil {
		writeProblem(w, r, http.StatusForbidden, "ERR_SSRF", "SSRF Detected", clientErr.Error(), "Use a public URL.", nil)
		return
	}
	resp, err := client.Get(sample)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_SCAN_FAILED", "Fetch Target URL Failed", err.Error(), "Verify URL endpoint connectivity.", nil)
		return
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	body := string(bodyBytes)

	re, err := compileRegexSafe(rule.RegexPattern)
	if err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid Regex Pattern", err.Error(), "Adjust signature format.", nil)
		return
	}
	matched := re.MatchString(body)
	var findings []interface{}
	evidence := ""
	if matched {
		evidence = re.FindString(body)
		findings = append(findings, map[string]interface{}{
			"id": rule.ID, "name": rule.Name, "description": rule.Description,
			"severity": rule.Severity, "evidence": fmt.Sprintf("Passive match: %s", evidence),
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"matched": matched, "findings_count": len(findings), "findings": findings, "evidence": evidence,
	})
}

func (s *APIServer) handleRuleTestWebHeader(w http.ResponseWriter, r *http.Request, rule vulnscan.DynamicWebRule, sample string) {
	headers := make(map[string][]string)
	if strings.HasPrefix(sample, "http://") || strings.HasPrefix(sample, "https://") {
		if !isSafeTarget(sample) {
			writeProblem(w, r, http.StatusForbidden, "ERR_SSRF", "SSRF Detected", "URL points to local/internal network.", "Use public URL.", nil)
			return
		}
		client, clientErr := safeHTTPClient(30*time.Second, sample)
		if clientErr != nil {
			writeProblem(w, r, http.StatusForbidden, "ERR_SSRF", "SSRF Detected", clientErr.Error(), "Use a public URL.", nil)
			return
		}
		resp, err := client.Get(sample)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "ERR_SCAN_FAILED", "Fetch Target URL Failed", err.Error(), "Check target website.", nil)
			return
		}
		defer resp.Body.Close()
		headers = resp.Header
	} else {
		if err := json.Unmarshal([]byte(sample), &headers); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid Headers JSON", err.Error(), "Provide headers as JSON e.g. {\"X-Frame-Options\": [\"DENY\"]}.", nil)
			return
		}
	}

	triggered := false
	val := headers[rule.HeaderName]
	switch rule.HeaderCheck {
	case "missing":
		if len(val) == 0 || val[0] == "" {
			triggered = true
		}
	case "equals":
		if len(val) > 0 && val[0] == rule.HeaderValue {
			triggered = true
		}
	case "contains":
		if len(val) > 0 && strings.Contains(val[0], rule.HeaderValue) {
			triggered = true
		}
	}

	var findings []interface{}
	if triggered {
		findings = append(findings, map[string]interface{}{
			"id": rule.ID, "name": rule.Name, "description": rule.Description,
			"severity": rule.Severity, "evidence": fmt.Sprintf("Header %s matched check %s", rule.HeaderName, rule.HeaderCheck),
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"matched": triggered, "findings_count": len(findings), "findings": findings,
	})
}

func (s *APIServer) handleRuleTestWebFuzz(w http.ResponseWriter, r *http.Request, rule vulnscan.DynamicWebRule, sample string) {
	triggered := false
	evidence := ""
	payloadVal := ""
	if len(rule.Payloads) > 0 {
		payloadVal = rule.Payloads[0]
	}

	switch rule.MatchType {
	case "contains":
		matchVal := rule.MatchValue
		if matchVal == "" {
			matchVal = payloadVal
		}
		if strings.Contains(sample, matchVal) {
			triggered = true
			evidence = fmt.Sprintf("Response contains fuzzed string: %s", matchVal)
		}
	case "regex":
		if rule.MatchValue != "" {
			re, err := compileRegexSafe(rule.MatchValue)
			if err == nil && re.MatchString(sample) {
				triggered = true
				evidence = fmt.Sprintf("Response matched fuzzed pattern: %s", rule.MatchValue)
			}
		}
	case "sql_error":
		sqlErrors := []string{"SQL syntax", "sqlite3.OperationalError", "unclosed quotation mark", "database error", "SQLITE_ERROR"}
		for _, sqlErr := range sqlErrors {
			if strings.Contains(strings.ToLower(sample), strings.ToLower(sqlErr)) {
				triggered = true
				evidence = fmt.Sprintf("Database error detected: %s", sqlErr)
				break
			}
		}
	case "lfi_success":
		if strings.Contains(sample, "root:x:0:0") || strings.Contains(strings.ToLower(sample), "[extensions]") {
			triggered = true
			evidence = "Read server system file successfully in dry-run."
		}
	}

	var findings []interface{}
	if triggered {
		findings = append(findings, map[string]interface{}{
			"id": rule.ID, "name": rule.Name, "description": rule.Description,
			"severity": rule.Severity, "evidence": evidence, "payload": payloadVal,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"matched": triggered, "findings_count": len(findings), "findings": findings,
	})
}

func (s *APIServer) handleRuleTestBinzap(w http.ResponseWriter, r *http.Request, ruleJSON, sample string) {
	var rule binzap.DynamicBinzapRule
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid Binzap Rule Layout", err.Error(), "Ensure steps and severity conform to schemas.", nil)
		return
	}
	tokens := lex.LexSmali(sample)
	ctx := binzap.ScanContext{
		File:    "dry_run_sandbox.smali",
		Dialect: lex.DialectSmali,
	}
	findings := rule.Match(ctx, tokens)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"matched": len(findings) > 0, "findings_count": len(findings), "findings": findings,
	})
}

func (s *APIServer) handleRuleTestML(w http.ResponseWriter, r *http.Request, ruleJSON, sample string) {
	var pattern ml.VulnerablePattern
	if err := json.Unmarshal([]byte(ruleJSON), &pattern); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid ML Pattern Layout", err.Error(), "Verify weights, minimum scores, categories schemas.", nil)
		return
	}

	pa := ml.NewPatchAnalyzer()
	classInfo := pa.AnalyzeSmaliContent("dry_run_sandbox.smali", []byte(sample))
	if classInfo == nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Unparseable Smali Input", "The bytecode sample failed standard parsing checks.", "Supply clean smali classes structures.", nil)
		return
	}

	var matchedFindings []map[string]interface{}
	overallMatched := false

	for i := range classInfo.Methods {
		mi := &classInfo.Methods[i]

		score := 0.0
		var matchedParts []string
		nameMatched := false

		for _, name := range pattern.MethodNames {
			if strings.Contains(mi.NameLower, strings.ToLower(name)) {
				score += 20 * pattern.Weight
				matchedParts = append(matchedParts, "method_name:"+name)
				nameMatched = true
				break
			}
		}

		classMatched := false
		classLower := strings.ToLower(mi.ClassName)
		for _, clsPattern := range pattern.ClassPatterns {
			if strings.Contains(classLower, strings.ToLower(clsPattern)) {
				score += 15 * pattern.Weight
				matchedParts = append(matchedParts, "class:"+clsPattern)
				classMatched = true
				break
			}
		}

		callMatchCount := 0
		for _, reqCall := range pattern.RequiredCalls {
			reqCallLower := strings.ToLower(reqCall)
			for _, call := range mi.Calls {
				if strings.Contains(call.FullCall, reqCallLower) {
					score += 12 * pattern.Weight
					matchedParts = append(matchedParts, "call:"+reqCall)
					callMatchCount++
					break
				}
			}
		}

		stringMatchCount := 0
		for _, strPattern := range pattern.StringPatterns {
			strPatternLower := strings.ToLower(strPattern)
			for _, constStr := range mi.StringConsts {
				if strings.Contains(strings.ToLower(constStr), strPatternLower) {
					score += 8 * pattern.Weight
					matchedParts = append(matchedParts, "string:"+strPattern)
					stringMatchCount++
					break
				}
			}
		}

		if pattern.ReturnType != "" {
			if mi.ReturnType == pattern.ReturnType {
				score += 10
				matchedParts = append(matchedParts, "return_type:"+pattern.ReturnType)
			} else {
				score -= 15
			}
		}

		if mi.ReturnsBoolean && mi.HasDualReturn {
			score += 8
			matchedParts = append(matchedParts, "structure:dual_return")
		}
		if mi.HasIfWithReturn {
			score += 6
			matchedParts = append(matchedParts, "structure:if_with_return")
		}
		if mi.IsShortMethod {
			score += 4
			matchedParts = append(matchedParts, "structure:short_method")
		}

		viableMatch := nameMatched || callMatchCount > 0 || stringMatchCount > 0 || classMatched
		if viableMatch && score >= pattern.MinMatchScore {
			overallMatched = true
			matchedFindings = append(matchedFindings, map[string]interface{}{
				"method": mi.Name, "class": mi.ClassName, "score": score,
				"matched_parts": matchedParts, "category": pattern.Category,
				"patch_type": pattern.PatchType, "description": pattern.Description,
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"matched": overallMatched, "findings_count": len(matchedFindings), "findings": matchedFindings,
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// RULES EXPORT / IMPORT
// ═══════════════════════════════════════════════════════════════════════════════

func (s *APIServer) handleRulesExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use GET.", "Use GET.", nil)
		return
	}
	export := map[string]interface{}{
		"exported_at":  time.Now().UTC().Format(time.RFC3339),
		"web_rules":    vulnscan.GetDynamicWebRules(),
		"binzap_rules": binzap.GetRawDynamicBinzapRules(),
		"ml_patterns":  ml.GetDynamicMLPatterns(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="mega-analyzer-rules-%s.json"`, time.Now().Format("2006-01-02")))
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(export); err != nil {
		log.Printf("handleRulesExport encode error: %v", err)
	}
}

func (s *APIServer) handleRulesImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use POST.", "Use POST.", nil)
		return
	}
	if r.Body == nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid JSON Payload", "missing request body", "Ensure JSON matches the export format.", nil)
		return
	}
	var payload struct {
		WebRules    []vulnscan.DynamicWebRule  `json:"web_rules"`
		BinzapRules []binzap.DynamicBinzapRule `json:"binzap_rules"`
		MLPatterns  []ml.VulnerablePattern     `json:"ml_patterns"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 10*1024*1024)).Decode(&payload); err != nil {
		writeProblem(w, r, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Invalid JSON Payload", err.Error(), "Ensure JSON matches the export format.", nil)
		return
	}
	imported := map[string]int{"web_rules": 0, "binzap_rules": 0, "ml_patterns": 0}
	rejected := make([]map[string]string, 0, 8)
	reject := func(kind, id, reason string) {
		rejected = append(rejected, map[string]string{"kind": kind, "id": id, "reason": reason})
	}
	for _, rule := range payload.WebRules {
		if rule.ID == "" {
			reject("web_rules", rule.Name, "missing rule ID")
			continue
		}
		if err := vulnscan.AddDynamicWebRule(rule); err == nil {
			imported["web_rules"]++
		} else {
			reject("web_rules", rule.ID, err.Error())
		}
	}
	for _, rule := range payload.BinzapRules {
		if rule.IDStr == "" {
			reject("binzap_rules", rule.NameStr, "missing rule ID")
			continue
		}
		if err := binzap.AddDynamicBinzapRule(rule); err == nil {
			imported["binzap_rules"]++
		} else {
			reject("binzap_rules", rule.IDStr, err.Error())
		}
	}
	for _, pattern := range payload.MLPatterns {
		if pattern.ID == "" {
			reject("ml_patterns", pattern.Description, "missing pattern ID")
			continue
		}
		if err := ml.AddDynamicMLPattern(pattern); err == nil {
			imported["ml_patterns"]++
		} else {
			reject("ml_patterns", pattern.ID, err.Error())
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Import completed", "imported": imported, "rejected": rejected,
	})
}
