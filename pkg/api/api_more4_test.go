package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPI_AllEndpoints_Coverage(t *testing.T) {
	srv := NewAPIServer(0)

	type endpoint struct {
		path    string
		handler http.HandlerFunc
	}

	endpoints := []endpoint{
		{"/api/docs", srv.handleSwaggerDocs},
		{"/api/v1/swagger.json", srv.handleSwaggerJSON},
		{"/api/v1/status", srv.handleStatus},
		{"/api/v1/rules/web", srv.handleWebRules},
		{"/api/v1/rules/binzap", srv.handleBinzapRules},
		{"/api/v1/rules/ml", srv.handleMLRules},
		{"/api/v1/scan/web", srv.handleScanWeb},
		{"/api/v1/scan/tokens", srv.handleScanTokens},
		{"/api/v1/scan/apk", srv.handleScanAPK},
		{"/api/v1/report/html", srv.handleReportHTML},
		{"/api/v1/rules/test", srv.handleRuleTest},
		{"/api/v1/rules/export", srv.handleRulesExport},
		{"/api/v1/rules/import", srv.handleRulesImport},
		{"/api/v1/recon/portscan", srv.handlePortScan},
		{"/api/v1/recon/dns", srv.handleDNSEnum},
		{"/api/v1/recon/ssl", srv.handleSSLAudit},
		{"/api/v1/recon/hostinfo", srv.handleHostInfo},
		{"/api/v1/pentest/cors", srv.handleCORSCheck},
		{"/api/v1/pentest/jwt", srv.handleJWTAnalyze},
		{"/api/v1/pentest/redirect", srv.handleOpenRedirect},
		{"/api/v1/pentest/dirscan", srv.handleDirScan},
		{"/api/v1/pentest/techdetect", srv.handleTechDetect},
		{"/api/v1/pentest/cookies", srv.handleCookieAudit},
		{"/api/v1/pentest/subdomains", srv.handleSubdomainEnum},
		{"/api/v1/mitm/start", srv.handleMITMStart},
		{"/api/v1/mitm/stop", srv.handleMITMStop},
		{"/api/v1/mitm/status", srv.handleMITMStatus},
		{"/api/v1/mitm/packets", srv.handleMITMPackets},
		{"/api/v1/mitm/clear", srv.handleMITMClear},
		{"/api/v1/mitm/inject", srv.handleMITMInject},
		{"/api/v1/mitm/ca.pem", srv.handleMITMCACert},
		{"/", srv.handleDashboard},
	}

	for _, ep := range endpoints {
		req := httptest.NewRequest(http.MethodGet, ep.path, nil)
		rec := httptest.NewRecorder()
		ep.handler(rec, req)

		reqPost := httptest.NewRequest(http.MethodPost, ep.path, bytes.NewBuffer([]byte("{}")))
		recPost := httptest.NewRecorder()
		ep.handler(recPost, reqPost)
	}
}
