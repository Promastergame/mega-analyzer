package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"mega-analyzer/pkg/binzap"
	"mega-analyzer/pkg/ml"
	"mega-analyzer/pkg/vulnscan"
)

func TestAPIServerHandlers(t *testing.T) {
	// Temporarily clean configs paths
	defer func() {
		_ = os.Remove("configs/dynamic_rules/web_rules_api_test.json")
		_ = os.Remove("configs/dynamic_rules/binzap_rules_api_test.json")
		_ = os.Remove("configs/dynamic_rules/ml_patterns_api_test.json")
	}()

	server := NewAPIServer(8090)

	// 1. Test Enhanced Status Endpoint (Uptime, telemetry, storage health)
	t.Run("Status Endpoint with Telemetry", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1/status", nil)
		rr := httptest.NewRecorder()
		server.handleStatus(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got: %d", rr.Code)
		}

		var res map[string]interface{}
		_ = json.Unmarshal(rr.Body.Bytes(), &res)
		if res["status"] != "healthy" {
			t.Errorf("expected status 'healthy', got: %v", res["status"])
		}

		// Verify telemetry keys
		telemetry, ok := res["telemetry"].(map[string]interface{})
		if !ok {
			t.Fatal("expected 'telemetry' object in status response")
		}
		if _, exists := telemetry["uptime_seconds"]; !exists {
			t.Error("expected 'uptime_seconds' in telemetry")
		}
		if _, exists := telemetry["allocated_heap_mb"]; !exists {
			t.Error("expected 'allocated_heap_mb' in telemetry")
		}

		// Verify storage_health keys
		storage, ok := res["storage_health"].(map[string]interface{})
		if !ok {
			t.Fatal("expected 'storage_health' object in status")
		}
		if _, exists := storage["web_rules_writable"]; !exists {
			t.Error("expected 'web_rules_writable' in storage_health")
		}
	})

	// 2. Test Swagger Spec & UI endpoints
	t.Run("Swagger Documentation Endpoints", func(t *testing.T) {
		// Test JSON Specification
		reqSpec, _ := http.NewRequest("GET", "/api/v1/swagger.json", nil)
		rrSpec := httptest.NewRecorder()
		server.handleSwaggerJSON(rrSpec, reqSpec)

		if rrSpec.Code != http.StatusOK {
			t.Errorf("expected 200 Spec, got: %d", rrSpec.Code)
		}
		if rrSpec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json, got: %s", rrSpec.Header().Get("Content-Type"))
		}

		// Test UI Docs
		reqDocs, _ := http.NewRequest("GET", "/api/docs", nil)
		rrDocs := httptest.NewRecorder()
		server.handleSwaggerDocs(rrDocs, reqDocs)

		if rrDocs.Code != http.StatusOK {
			t.Errorf("expected 200 Docs, got: %d", rrDocs.Code)
		}
		if !strings.Contains(rrDocs.Body.String(), "/api/docs/assets/openapi.js") || strings.Contains(rrDocs.Body.String(), "cdnjs.cloudflare.com") {
			t.Error("expected the embedded offline API console")
		}
	})

	// 3. Test RFC 7807 Standardized Problem Details Errors
	t.Run("RFC 7807 Error Responses", func(t *testing.T) {
		// Post completely unparseable bad JSON
		body := []byte(`{"id": "BAD-RULE", "type": "fuzz", "payloads": `) // malformed JSON
		req, _ := http.NewRequest("POST", "/api/v1/rules/web", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		server.handleWebRules(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request on invalid JSON, got: %d", rr.Code)
		}

		if !strings.Contains(rr.Header().Get("Content-Type"), "application/problem+json") {
			t.Errorf("expected application/problem+json content header, got: %s", rr.Header().Get("Content-Type"))
		}

		var problem APIError
		_ = json.Unmarshal(rr.Body.Bytes(), &problem)
		if problem.ErrorCode != "ERR_INVALID_PAYLOAD" {
			t.Errorf("expected error code ERR_INVALID_PAYLOAD, got: %s", problem.ErrorCode)
		}
		if problem.Title != "Invalid JSON Payload" {
			t.Errorf("expected error title 'Invalid JSON Payload', got: %s", problem.Title)
		}
		if problem.Status != 400 {
			t.Errorf("expected status 400 inside body, got: %d", problem.Status)
		}
		if problem.Remediation == "" {
			t.Error("expected actionable remediation advice in problem detail")
		}
	})

	// 4. Test Web Rules CRUD
	t.Run("Web Rules CRUD Operations", func(t *testing.T) {
		_ = vulnscan.DeleteDynamicWebRule("API-TEST-WEB")

		rule := vulnscan.DynamicWebRule{
			ID:           "API-TEST-WEB",
			Name:         "API Test Web Rule",
			Description:  "API description",
			Severity:     vulnscan.SeverityHigh,
			Type:         "regex_passive",
			RegexPattern: "api-pat",
		}

		body, _ := json.Marshal(rule)
		req, _ := http.NewRequest("POST", "/api/v1/rules/web", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		server.handleWebRules(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("expected 201 Created, got: %d", rr.Code)
		}

		// List rules
		reqGet, _ := http.NewRequest("GET", "/api/v1/rules/web", nil)
		rrGet := httptest.NewRecorder()
		server.handleWebRules(rrGet, reqGet)

		var rules []vulnscan.DynamicWebRule
		_ = json.Unmarshal(rrGet.Body.Bytes(), &rules)
		found := false
		for _, r := range rules {
			if r.ID == "API-TEST-WEB" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected to find newly created rule API-TEST-WEB")
		}

		// Delete rule
		reqDel, _ := http.NewRequest("DELETE", "/api/v1/rules/web/API-TEST-WEB", nil)
		rrDel := httptest.NewRecorder()
		server.handleWebRuleSingle(rrDel, reqDel)

		if rrDel.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got: %d", rrDel.Code)
		}
	})

	// 5. Test Binzap Rules CRUD
	t.Run("Binzap Rules CRUD Operations", func(t *testing.T) {
		_ = binzap.DeleteDynamicBinzapRule("API-TEST-BZ")

		rule := binzap.DynamicBinzapRule{
			IDStr:       "API-TEST-BZ",
			NameStr:     "API Test BZ Rule",
			SeverityVal: binzap.SeverityMedium,
			Steps: []binzap.PatternStep{
				{Type: "opcode", Value: "const-string"},
			},
		}

		body, _ := json.Marshal(rule)
		req, _ := http.NewRequest("POST", "/api/v1/rules/binzap", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		server.handleBinzapRules(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("expected 201 Created, got: %d", rr.Code)
		}

		// List rules
		reqGet, _ := http.NewRequest("GET", "/api/v1/rules/binzap", nil)
		rrGet := httptest.NewRecorder()
		server.handleBinzapRules(rrGet, reqGet)

		var rules []binzap.DynamicBinzapRule
		_ = json.Unmarshal(rrGet.Body.Bytes(), &rules)
		found := false
		for _, r := range rules {
			if r.IDStr == "API-TEST-BZ" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected to find newly created rule API-TEST-BZ")
		}

		// Delete rule
		reqDel, _ := http.NewRequest("DELETE", "/api/v1/rules/binzap/API-TEST-BZ", nil)
		rrDel := httptest.NewRecorder()
		server.handleBinzapRuleSingle(rrDel, reqDel)

		if rrDel.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got: %d", rrDel.Code)
		}
	})

	// 6. Test ML Rules CRUD
	t.Run("ML Rules CRUD Operations", func(t *testing.T) {
		_ = ml.DeleteDynamicMLPattern("API-TEST-ML")

		pattern := ml.VulnerablePattern{
			ID:          "API-TEST-ML",
			Category:    "billing",
			Description: "API test ml pattern",
			ReturnType:  "Z",
			PatchType:   "return_true",
			Weight:      1.0,
		}

		body, _ := json.Marshal(pattern)
		req, _ := http.NewRequest("POST", "/api/v1/rules/ml", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		server.handleMLRules(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("expected 201 Created, got: %d", rr.Code)
		}

		// List rules
		reqGet, _ := http.NewRequest("GET", "/api/v1/rules/ml", nil)
		rrGet := httptest.NewRecorder()
		server.handleMLRules(rrGet, reqGet)

		var patterns []ml.VulnerablePattern
		_ = json.Unmarshal(rrGet.Body.Bytes(), &patterns)
		found := false
		for _, p := range patterns {
			if p.ID == "API-TEST-ML" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected to find newly created pattern API-TEST-ML")
		}

		// Delete rule
		reqDel, _ := http.NewRequest("DELETE", "/api/v1/rules/ml/API-TEST-ML", nil)
		rrDel := httptest.NewRecorder()
		server.handleMLRuleSingle(rrDel, reqDel)

		if rrDel.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got: %d", rrDel.Code)
		}
	})

	// 7. Test Rate Limiter Middleware headers
	t.Run("Rate Limiter Middleware Headers", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1/status", nil)
		// Simulating incoming requests to trigger middleware
		rr := httptest.NewRecorder()
		handler := server.rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 OK from inner handler, got: %d", rr.Code)
		}

		if rr.Header().Get("X-RateLimit-Limit") == "" {
			t.Error("expected 'X-RateLimit-Limit' header")
		}
		if rr.Header().Get("X-RateLimit-Remaining") == "" {
			t.Error("expected 'X-RateLimit-Remaining' header")
		}
		if rr.Header().Get("X-RateLimit-Reset") == "" {
			t.Error("expected 'X-RateLimit-Reset' header")
		}
	})

	// 8. Test Embedded Dashboard
	t.Run("Embedded Dashboard Content", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		server.handleDashboard(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got: %d", rr.Code)
		}

		body := rr.Body.String()
		if !strings.Contains(body, "Mega-Analyzer") || !strings.Contains(body, "Security Console") {
			t.Error("expected embedded dashboard content, got incorrect html")
		}
	})

	// 9. Test Universal Dry-Run Testing Route
	t.Run("Universal Dry-Run Testing Playground", func(t *testing.T) {
		// A. Test Web regex dry-run
		ruleWebJSON := `{"id":"DYN-XSS","name":"XSS","type":"regex_passive","regex_pattern":"xss_test_string"}`
		webPayload := map[string]string{
			"rule_type": "web",
			"rule_json": ruleWebJSON,
			"sample":    "This page contains xss_test_string in its body.",
		}
		bodyWeb, _ := json.Marshal(webPayload)
		reqWeb, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewBuffer(bodyWeb))
		rrWeb := httptest.NewRecorder()
		server.handleRuleTest(rrWeb, reqWeb)

		if rrWeb.Code != http.StatusOK {
			t.Errorf("expected web dry run 200 OK, got: %d", rrWeb.Code)
		}
		var resWeb map[string]interface{}
		_ = json.Unmarshal(rrWeb.Body.Bytes(), &resWeb)
		if resWeb["matched"] != true {
			t.Errorf("expected web pattern to match, got %v", resWeb["matched"])
		}

		// B. Test Web Headers dry-run
		ruleHeaderJSON := `{"id":"DYN-CSP","name":"CSP","type":"header_check","header_name":"Content-Security-Policy","header_check":"missing"}`
		headerPayload := map[string]string{
			"rule_type": "web",
			"rule_json": ruleHeaderJSON,
			"sample":    `{"X-XSS-Protection": ["1"]}`, // CSP is missing in this mock
		}
		bodyHeader, _ := json.Marshal(headerPayload)
		reqHeader, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewBuffer(bodyHeader))
		rrHeader := httptest.NewRecorder()
		server.handleRuleTest(rrHeader, reqHeader)

		if rrHeader.Code != http.StatusOK {
			t.Errorf("expected header dry run 200 OK, got: %d", rrHeader.Code)
		}
		var resHeader map[string]interface{}
		_ = json.Unmarshal(rrHeader.Body.Bytes(), &resHeader)
		if resHeader["matched"] != true {
			t.Errorf("expected header check to match missing CSP, got %v", resHeader["matched"])
		}

		// C. Test Web Fuzz dry-run
		ruleFuzzJSON := `{"id":"DYN-FUZZ","name":"Fuzz","type":"fuzz","payloads":["test_payload"],"match_type":"contains","match_value":"test_payload"}`
		fuzzPayload := map[string]string{
			"rule_type": "web",
			"rule_json": ruleFuzzJSON,
			"sample":    "Response matches fuzzed test_payload parameter.",
		}
		bodyFuzz, _ := json.Marshal(fuzzPayload)
		reqFuzz, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewBuffer(bodyFuzz))
		rrFuzz := httptest.NewRecorder()
		server.handleRuleTest(rrFuzz, reqFuzz)

		if rrFuzz.Code != http.StatusOK {
			t.Errorf("expected fuzz dry run 200 OK, got: %d", rrFuzz.Code)
		}
		var resFuzz map[string]interface{}
		_ = json.Unmarshal(rrFuzz.Body.Bytes(), &resFuzz)
		if resFuzz["matched"] != true {
			t.Errorf("expected fuzz match, got %v", resFuzz["matched"])
		}

		// D. Test Binzap dry-run
		ruleBinzapJSON := `{"id":"DRY-RUN-BZ","name":"Test Rule","severity":"MEDIUM","pattern_steps":[{"type":"opcode","value":"const-string"}]}`
		binzapPayload := map[string]string{
			"rule_type": "binzap",
			"rule_json": ruleBinzapJSON,
			"sample":    ".method public test()Z\n    const-string v0, \"license_validated\"\n    return-void\n.end method",
		}
		bodyBz, _ := json.Marshal(binzapPayload)
		reqBz, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewBuffer(bodyBz))
		rrBz := httptest.NewRecorder()
		server.handleRuleTest(rrBz, reqBz)

		if rrBz.Code != http.StatusOK {
			t.Errorf("expected binzap dry run 200 OK, got: %d", rrBz.Code)
		}
		var resBz map[string]interface{}
		_ = json.Unmarshal(rrBz.Body.Bytes(), &resBz)
		if resBz["matched"] != true {
			t.Errorf("expected binzap bytecode match, got %v", resBz["matched"])
		}

		// E. Test Smali ML Pattern dry-run
		ruleMLJSON := `{"id":"DYN_ML_LICENSE","category":"license_check","description":"Test ML Pattern","method_names":["checkLicense"],"class_patterns":["license"],"required_calls":["Lcom/android/vending;->check()V"],"string_patterns":["premium"],"return_type":"Z","patch_type":"return_true","weight":1.2,"min_match_score":10}`
		mlPayload := map[string]string{
			"rule_type": "ml",
			"rule_json": ruleMLJSON,
			"sample":    ".class public Lcom/app/license/Checker;\n.super Ljava/lang/Object;\n\n.method public checkLicense()Z\n    .registers 2\n    const-string v0, \"premium\"\n    invoke-static {}, Lcom/android/vending;->check()V\n    const/4 v0, 0x1\n    return v0\n.end method",
		}
		bodyML, _ := json.Marshal(mlPayload)
		reqML, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewBuffer(bodyML))
		rrML := httptest.NewRecorder()
		server.handleRuleTest(rrML, reqML)

		if rrML.Code != http.StatusOK {
			t.Errorf("expected ML dry run 200 OK, got: %d", rrML.Code)
		}
		var resML map[string]interface{}
		_ = json.Unmarshal(rrML.Body.Bytes(), &resML)
		if resML["matched"] != true {
			t.Errorf("expected ML pattern match, got %v", resML["matched"])
		}
	})
}
