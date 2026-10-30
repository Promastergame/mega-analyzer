package pipeline

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
//
//  T E S T   H E L P E R S
//
// ═══════════════════════════════════════════════════════════════════════════════

// buildLineOffsets строит таблицу смещений строк, совместимую с types.LineOffsets.
func buildLineOffsets(data []byte) *types.LineOffsets {
	return types.NewLineOffsets(data)
}

// makeCtx создаёт FileDetectContext для тестирования.
func makeCtx(content string) *FileDetectContext {
	data := []byte(content)
	return &FileDetectContext{
		Content:      data,
		ContentLower: []byte(strings.ToLower(content)),
		LineOffsets:  buildLineOffsets(data),
		FileType:     types.FileTypeSmali,
	}
}

// detect запускает детектор и возвращает все матчи.
func detect(content string) []types.Match {
	d := NewEndpointDetector()
	ctx := makeCtx(content)
	analysis := &types.FileAnalysis{Path: "test/TestClass.smali"}
	d.Detect(ctx, analysis)
	return analysis.Matches
}

// byHost ищет матч с указанным хостом.
func byHost(matches []types.Match, host string) *types.Match {
	for i := range matches {
		if matches[i].Metadata != nil && matches[i].Metadata["host"] == host {
			return &matches[i]
		}
	}
	return nil
}

// expectFound проверяет, что хост найден.
func expectFound(t *testing.T, matches []types.Match, host string) *types.Match {
	t.Helper()
	m := byHost(matches, host)
	if m == nil {
		t.Errorf("✗ expected host %q to be FOUND, but no match", host)
	}
	return m
}

// expectSkipped проверяет, что хост НЕ найден (отфильтрован).
func expectSkipped(t *testing.T, matches []types.Match, host string) {
	t.Helper()
	if m := byHost(matches, host); m != nil {
		t.Errorf("✗ expected host %q to be SKIPPED, but found: category=%s value=%s",
			host, m.Category, m.Pattern)
	}
}

// expectType проверяет endpoint_type найденного хоста.
func expectType(t *testing.T, matches []types.Match, host string, epType EndpointType) {
	t.Helper()
	m := expectFound(t, matches, host)
	if m != nil && m.Metadata["endpoint_type"] != string(epType) {
		t.Errorf("✗ host %q: expected endpoint_type=%q, got=%q",
			host, epType, m.Metadata["endpoint_type"])
	}
}

// expectCategory проверяет категорию найденного хоста.
func expectCategory(t *testing.T, matches []types.Match, host string, cat types.Category) {
	t.Helper()
	m := expectFound(t, matches, host)
	if m != nil && m.Category != cat {
		t.Errorf("✗ host %q: expected category=%q, got=%q",
			host, cat, m.Category)
	}
}

// expectCritical проверяет критичность.
func expectCritical(t *testing.T, matches []types.Match, host string, critical bool) {
	t.Helper()
	m := expectFound(t, matches, host)
	if m != nil && m.IsCritical != critical {
		t.Errorf("✗ host %q: expected critical=%v, got=%v",
			host, critical, m.IsCritical)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//  DETECTION TESTS — Серверные эндпоинты
//
// ═══════════════════════════════════════════════════════════════════════════════

func TestDetect_APIServer(t *testing.T) {
	cases := []struct {
		name    string
		content string
		host    string
		epType  EndpointType
	}{
		{
			"api subdomain",
			`const-string v0, "https://api.myapp.com/v2/users"`,
			"api.myapp.com", EndpointTypeAPI,
		},
		{
			"api path",
			`const-string v0, "https://myapp.com/api/v1/data"`,
			"myapp.com", EndpointTypeAPI,
		},
		{
			"graphql endpoint",
			`url = "https://backend.example.com/graphql"`,
			"backend.example.com", EndpointTypeAPI,
		},
		{
			"rest endpoint",
			`"https://server.example.com/rest/v2/config"`,
			"server.example.com", EndpointTypeAPI,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := detect(tc.content)
			expectType(t, matches, tc.host, tc.epType)
		})
	}
}

func TestDetect_AuthServer(t *testing.T) {
	cases := []struct {
		name    string
		content string
		host    string
	}{
		{"auth subdomain", `"https://auth.mycompany.com/oauth/token"`, "auth.mycompany.com"},
		{"login subdomain", `"https://login.example.com/v1/authenticate"`, "login.example.com"},
		{"sso subdomain", `"https://sso.corp.com/saml/login"`, "sso.corp.com"},
		{"auth in path", `"https://myapp.com/auth/login"`, "myapp.com"},
		{"oauth in path", `"https://myapp.com/oauth/callback"`, "myapp.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := detect(tc.content)
			expectType(t, matches, tc.host, EndpointTypeAuth)
			expectCritical(t, matches, tc.host, true)
		})
	}
}

func TestDetect_WebSocket(t *testing.T) {
	cases := []struct {
		name    string
		content string
		host    string
	}{
		{"wss scheme", `new WebSocket("wss://realtime.myapp.com/socket")`, "realtime.myapp.com"},
		{"ws scheme", `ws://push.example.com/events`, "push.example.com"},
		{"ws subdomain", `"wss://ws.gameserver.io/connect"`, "ws.gameserver.io"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := detect(tc.content)
			expectType(t, matches, tc.host, EndpointTypeWebSocket)
			expectCritical(t, matches, tc.host, true)
		})
	}
}

func TestDetect_MQTT(t *testing.T) {
	content := `
		broker_url = "mqtt://iot-broker.example.com:1883/devices"
		secure = "mqtts://mqtt.cloud-iot.com:8883/telemetry"
	`
	matches := detect(content)

	m1 := expectFound(t, matches, "iot-broker.example.com")
	if m1 != nil {
		expectType(t, matches, "iot-broker.example.com", EndpointTypeMQTT)
		if m1.Metadata["port"] != "1883" {
			t.Errorf("expected port 1883, got %s", m1.Metadata["port"])
		}
	}

	expectType(t, matches, "mqtt.cloud-iot.com", EndpointTypeMQTT)
}

func TestDetect_Database(t *testing.T) {
	cases := []struct {
		name   string
		url    string
		host   string
		scheme string
	}{
		{"mongodb", `mongodb://db.example.com:27017/mydb`, "db.example.com", "mongodb"},
		{"mongodb+srv", `mongodb+srv://cluster.mongo.net/appdb`, "cluster.mongo.net", "mongodb+srv"},
		{"postgresql", `postgres://dbhost.example.com:5432/prod`, "dbhost.example.com", "postgres"},
		{"mysql", `mysql://mysql-server.com:3306/userdata`, "mysql-server.com", "mysql"},
		{"redis", `redis://cache.example.com:6379/0`, "cache.example.com", "redis"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := detect(tc.url)
			m := expectFound(t, matches, tc.host)
			if m != nil {
				expectType(t, matches, tc.host, EndpointTypeDatabase)
				expectCategory(t, matches, tc.host, types.CategorySuspiciousURL)
				if m.Metadata["scheme"] != tc.scheme {
					t.Errorf("expected scheme=%s, got=%s", tc.scheme, m.Metadata["scheme"])
				}
			}
		})
	}
}

func TestDetect_CustomPort(t *testing.T) {
	cases := []struct {
		name   string
		url    string
		host   string
		port   string
		epType EndpointType
	}{
		{"8080 Tomcat", `"https://myserver.com:8080/api/health"`, "myserver.com", "8080", EndpointTypeAPI},
		{"3000 Node", `"http://backend.dev.com:3000/users"`, "backend.dev.com", "3000", EndpointTypeAPI},
		{"50051 gRPC", `"http://grpc-server.com:50051"`, "grpc-server.com", "50051", EndpointTypeGRPC},
		{"random port", `"https://mystery.com:31337/cmd"`, "mystery.com", "31337", EndpointTypeCustomPort},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := detect(tc.url)
			m := expectFound(t, matches, tc.host)
			if m != nil {
				if m.Metadata["port"] != tc.port {
					t.Errorf("expected port=%s, got=%s", tc.port, m.Metadata["port"])
				}
				expectType(t, matches, tc.host, tc.epType)
			}
		})
	}
}

func TestDetect_C2Suspect(t *testing.T) {
	cases := []struct {
		name string
		url  string
		host string
	}{
		{"TLD .tk", `"https://callback.tk/report"`, "callback.tk"},
		{"TLD .xyz", `"https://c2panel.xyz/gate"`, "c2panel.xyz"},
		{"TLD .top", `"http://exfil.top/submit"`, "exfil.top"},
		{"raw IP", `"http://185.143.223.47/gate.php"`, "185.143.223.47"},
		{"onion", `"http://hidden12345.onion/api"`, "hidden12345.onion"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := detect(tc.url)
			expectType(t, matches, tc.host, EndpointTypeC2)
			expectCategory(t, matches, tc.host, types.CategorySuspiciousURL)
			expectCritical(t, matches, tc.host, true)
		})
	}
}

func TestDetect_UpdateServer(t *testing.T) {
	cases := []struct {
		name string
		url  string
		host string
	}{
		{"update subdomain", `"https://update.myapp.com/check"`, "update.myapp.com"},
		{"update in path", `"https://myapp.com/update/latest"`, "myapp.com"},
		{"download in path", `"https://dl.myapp.com/download/v2"`, "dl.myapp.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := detect(tc.url)
			expectType(t, matches, tc.host, EndpointTypeUpdate)
		})
	}
}

func TestDetect_EscapedURLs(t *testing.T) {
	content := `"https:\/\/api.myserver.com\/v1\/data"`
	matches := detect(content)
	expectFound(t, matches, "api.myserver.com")
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//  SKIP TESTS — Мусор, который НЕ должен находиться
//
// ═══════════════════════════════════════════════════════════════════════════════

func TestSkip_SchemaNamespaces(t *testing.T) {
	content := `
		xmlns:android="http://schemas.android.com/apk/res/android"
		xmlns="http://www.w3.org/1999/xhtml"
		"http://xmlpull.org/v1/doc/features.html"
		"http://json-schema.org/draft-07/schema#"
	`
	matches := detect(content)
	expectSkipped(t, matches, "schemas.android.com")
	expectSkipped(t, matches, "www.w3.org")
	expectSkipped(t, matches, "xmlpull.org")
	expectSkipped(t, matches, "json-schema.org")
}

func TestSkip_AppStores(t *testing.T) {
	content := `
		"https://play.google.com/store/apps/details?id=com.myapp"
		"https://apps.apple.com/app/myapp/id123456"
		"https://f-droid.org/packages/com.myapp"
	`
	matches := detect(content)
	expectSkipped(t, matches, "play.google.com")
	expectSkipped(t, matches, "apps.apple.com")
	expectSkipped(t, matches, "f-droid.org")
}

func TestSkip_SocialMedia(t *testing.T) {
	content := `
		"https://www.facebook.com/myapp"
		"https://twitter.com/myapp"
		"https://www.instagram.com/myapp"
		"https://www.youtube.com/watch?v=abc123"
	`
	matches := detect(content)
	expectSkipped(t, matches, "www.facebook.com")
	expectSkipped(t, matches, "twitter.com")
	expectSkipped(t, matches, "www.instagram.com")
	expectSkipped(t, matches, "www.youtube.com")
}

func TestSkip_SDKDomains(t *testing.T) {
	content := `
		"https://www.googleapis.com/auth/cloud"
		"https://firebaseio.com/projects/myapp"
		"https://api.mixpanel.com/track"
		"https://s3.amazonaws.com/bucket/file.png"
		"https://d123.cloudfront.net/assets/logo.png"
		"https://cdn.amplitude.com/libs/analytics.min.js"
	`
	matches := detect(content)
	expectSkipped(t, matches, "www.googleapis.com")
	expectSkipped(t, matches, "firebaseio.com")
	expectSkipped(t, matches, "api.mixpanel.com")
	expectSkipped(t, matches, "s3.amazonaws.com")
	expectSkipped(t, matches, "d123.cloudfront.net")
	expectSkipped(t, matches, "cdn.amplitude.com")
}

func TestSkip_Localhost(t *testing.T) {
	content := `
		"http://localhost:8080/api"
		"http://127.0.0.1:3000/test"
		"http://0.0.0.0:5000/health"
		"http://myapp.local/debug"
	`
	matches := detect(content)
	expectSkipped(t, matches, "localhost")
	expectSkipped(t, matches, "127.0.0.1")
	expectSkipped(t, matches, "0.0.0.0")
	expectSkipped(t, matches, "myapp.local")
}

func TestSkip_StaticResources(t *testing.T) {
	content := `
		"https://mysite.com/images/logo.png"
		"https://mysite.com/css/style.css"
		"https://mysite.com/fonts/roboto.woff2"
		"https://mysite.com/videos/intro.mp4"
	`
	matches := detect(content)
	// Все URL на один хост с разными статическими путями —
	// если ПЕРВЫЙ URL статический, хост пропускается.
	// Но дедуп по host → первый выиграет.
	expectSkipped(t, matches, "mysite.com")
}

func TestSkip_LegalPages(t *testing.T) {
	content := `
		"https://legal.myapp.com/privacy-policy"
		"https://legal.myapp.com/terms-of-service"
	`
	matches := detect(content)
	expectSkipped(t, matches, "legal.myapp.com")
}

func TestSkip_DocsSites(t *testing.T) {
	content := `
		"https://developer.android.com/reference/Activity"
		"https://stackoverflow.com/questions/12345"
		"https://github.com/myorg/myrepo"
		"https://en.wikipedia.org/wiki/Android"
	`
	matches := detect(content)
	expectSkipped(t, matches, "developer.android.com")
	expectSkipped(t, matches, "stackoverflow.com")
	expectSkipped(t, matches, "github.com")
	expectSkipped(t, matches, "en.wikipedia.org")
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//  EDGE CASES
//
// ═══════════════════════════════════════════════════════════════════════════════

func TestEdge_EmptyContent(t *testing.T) {
	matches := detect("")
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestEdge_NoURLs(t *testing.T) {
	matches := detect("just regular code with no urls at all")
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestEdge_NativeFileType(t *testing.T) {
	// Native files ARE scanned since the .so strings-pass (backlog 1.txt):
	// a plain C2 URL in a native lib must surface as an endpoint match.
	d := NewEndpointDetector()
	content := []byte("https://api.malware.com/gate")
	ctx := &FileDetectContext{
		Content:      content,
		ContentLower: []byte(strings.ToLower(string(content))),
		LineOffsets:  buildLineOffsets(content),
		FileType:     types.FileTypeNative,
	}
	analysis := &types.FileAnalysis{Path: "lib/armeabi-v7a/libnative.so"}
	d.Detect(ctx, analysis)
	expectFound(t, analysis.Matches, "api.malware.com")
}

func TestEdge_ResourceFileType(t *testing.T) {
	d := NewEndpointDetector()
	content := []byte("https://api.myapp.com/v1/data")
	ctx := &FileDetectContext{
		Content:      content,
		ContentLower: []byte(strings.ToLower(string(content))),
		LineOffsets:  buildLineOffsets(content),
		FileType:     types.FileTypeResource,
	}
	analysis := &types.FileAnalysis{Path: "res/drawable/icon.xml"}
	d.Detect(ctx, analysis)
	if len(analysis.Matches) != 0 {
		t.Errorf("should skip resource files, got %d matches", len(analysis.Matches))
	}
}

func TestEdge_Deduplication(t *testing.T) {
	content := `
		"https://api.myapp.com/v1/users"
		"https://api.myapp.com/v1/orders"
		"https://api.myapp.com/v2/products"
	`
	matches := detect(content)
	count := 0
	for _, m := range matches {
		if m.Metadata != nil && m.Metadata["host"] == "api.myapp.com" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 deduplicated match, got %d", count)
	}
}

func TestEdge_MaxPerFile(t *testing.T) {
	d := NewEndpointDetector()
	d.maxPerFile = 3

	var sb strings.Builder
	for i := 0; i < 20; i++ {
		sb.WriteString(`"https://api`)
		sb.WriteByte(byte('a' + (i % 26)))
		sb.WriteString(`.unique-server.com/v1/data"`)
		sb.WriteByte('\n')
	}

	ctx := makeCtx(sb.String())
	analysis := &types.FileAnalysis{Path: "test.smali"}
	d.Detect(ctx, analysis)

	if len(analysis.Matches) > 3 {
		t.Errorf("expected max 3 matches, got %d", len(analysis.Matches))
	}
}

func TestEdge_MultipleURLsOnOneLine(t *testing.T) {
	content := `config: {"primary":"https://api.primary.com/v1","fallback":"https://api.backup.com/v1"}`
	matches := detect(content)
	expectFound(t, matches, "api.primary.com")
	expectFound(t, matches, "api.backup.com")
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//  REAL-WORLD SCENARIOS
//
// ═══════════════════════════════════════════════════════════════════════════════

func TestRealWorld_APKContent(t *testing.T) {
	content := `
		.class public Lcom/myapp/network/ApiClient;

		# Standard SDK URLs → SKIP
		const-string v0, "https://www.googleapis.com/auth/cloud-platform"
		const-string v1, "https://firebaseio.com/projects/myapp-12345"
		const-string v2, "https://play.google.com/store/apps/details?id=com.myapp"
		const-string v3, "http://schemas.android.com/apk/res/android"
		const-string v4, "https://cdn.jsdelivr.net/npm/bootstrap@5"
		const-string v5, "https://www.facebook.com/myapp"
		const-string v6, "https://developer.android.com/reference"
		const-string v7, "https://myapp.com/privacy-policy"
		const-string v8, "https://myapp.com/images/banner.png"

		# REAL SERVER ENDPOINTS → FIND
		const-string v10, "https://api.myapp-backend.com/v2/auth/login"
		const-string v11, "wss://realtime.myapp-backend.com/socket"
		const-string v12, "https://license.myapp.com/verify"
		const-string v13, "https://update.myapp.com/check?version=2.0"
		const-string v14, "https://mysterious-server.com:8443/api/config"
	`
	matches := detect(content)

	// SKIPPED
	expectSkipped(t, matches, "www.googleapis.com")
	expectSkipped(t, matches, "firebaseio.com")
	expectSkipped(t, matches, "play.google.com")
	expectSkipped(t, matches, "schemas.android.com")
	expectSkipped(t, matches, "cdn.jsdelivr.net")
	expectSkipped(t, matches, "www.facebook.com")
	expectSkipped(t, matches, "developer.android.com")

	// FOUND
	expectFound(t, matches, "api.myapp-backend.com")
	expectFound(t, matches, "realtime.myapp-backend.com")
	expectFound(t, matches, "license.myapp.com")
	expectFound(t, matches, "update.myapp.com")
	expectFound(t, matches, "mysterious-server.com")
}

func TestRealWorld_MalwareContent(t *testing.T) {
	content := `
		const-string v0, "http://185.143.223.47/gate.php"
		const-string v1, "https://evil-panel.tk/upload"
		const-string v2, "https://data-exfil.xyz/submit"
		const-string v3, "http://command.monster/bot/register"
		const-string v4, "mqtt://iot-botnet.cf:1883/commands"
		const-string v5, "mongodb://stolen-data.gq:27017/exfil"
	`
	matches := detect(content)

	expectType(t, matches, "185.143.223.47", EndpointTypeC2)
	expectType(t, matches, "evil-panel.tk", EndpointTypeC2)
	expectType(t, matches, "data-exfil.xyz", EndpointTypeC2)
	expectType(t, matches, "command.monster", EndpointTypeC2)
	expectType(t, matches, "iot-botnet.cf", EndpointTypeMQTT)      // MQTT scheme wins
	expectType(t, matches, "stolen-data.gq", EndpointTypeDatabase) // MongoDB scheme wins

	// All should be critical
	expectCritical(t, matches, "185.143.223.47", true)
	expectCritical(t, matches, "evil-panel.tk", true)
	expectCritical(t, matches, "stolen-data.gq", true)
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//  UNIT TESTS — Helper Functions
//
// ═══════════════════════════════════════════════════════════════════════════════

func TestExtractURLBytes(t *testing.T) {
	cases := []struct {
		name     string
		content  string
		start    int
		expected string
	}{
		{"basic", "https://example.com/path", 0, "https://example.com/path"},
		{"quoted", `"https://example.com/path"`, 1, "https://example.com/path"},
		{"with space", "https://example.com next", 0, "https://example.com"},
		{"with newline", "https://example.com\nnext", 0, "https://example.com"},
		{"empty", "", 0, ""},
		{"out of bounds", "abc", 10, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := extractURLBytes([]byte(tc.content), tc.start)
			if raw != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, raw)
			}
		})
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	cases := []struct {
		input, expected string
	}{
		{`https:\/\/example.com\/path`, "https://example.com/path"},
		{"https://example.com/path.,;", "https://example.com/path"},
		{`https://example.com/q\u003dval`, "https://example.com/q=val"},
		{"", ""},
		{"  https://example.com  ", "https://example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			if got := normalizeEndpoint(tc.input); got != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestParseEndpoint(t *testing.T) {
	cases := []struct {
		endpoint     string
		host, scheme string
		port, path   string
	}{
		{"https://api.example.com/v1/users", "api.example.com", "https", "", "/v1/users"},
		{"http://server.com:8080/api", "server.com", "http", "8080", "/api"},
		{"wss://ws.example.com/socket", "ws.example.com", "wss", "", "/socket"},
		{"mongodb://db.host.com:27017/mydb", "db.host.com", "mongodb", "27017", "/mydb"},
		{"invalid-url", "", "", "", ""},
		{"://no-scheme", "", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.endpoint, func(t *testing.T) {
			host, scheme, port, path := parseEndpoint(tc.endpoint)
			if host != tc.host {
				t.Errorf("host: expected %q, got %q", tc.host, host)
			}
			if scheme != tc.scheme {
				t.Errorf("scheme: expected %q, got %q", tc.scheme, scheme)
			}
			if port != tc.port {
				t.Errorf("port: expected %q, got %q", tc.port, port)
			}
			if path != tc.path {
				t.Errorf("path: expected %q, got %q", tc.path, path)
			}
		})
	}
}

func TestIsURLTerminator(t *testing.T) {
	terminators := []byte{' ', '\n', '\r', '\t', '"', '\'', '<', '>', '`', 0, '{', '}', '(', ')'}
	for _, b := range terminators {
		if !isURLTerminator(b) {
			t.Errorf("byte %d (%q) should be terminator", b, string(rune(b)))
		}
	}

	nonTerminators := []byte{'a', 'z', '/', '.', '-', '_', '0', '9', '?', '=', '&', '#', '%', '+'}
	for _, b := range nonTerminators {
		if isURLTerminator(b) {
			t.Errorf("byte %d (%q) should NOT be terminator", b, string(rune(b)))
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//  UNIT TESTS — Classification
//
// ═══════════════════════════════════════════════════════════════════════════════

func TestClassifyEndpoint(t *testing.T) {
	d := NewEndpointDetector()

	cases := []struct {
		name     string
		host     string
		scheme   string
		port     string
		path     string
		expected EndpointType
	}{
		{"wss scheme", "example.com", "wss", "", "/socket", EndpointTypeWebSocket},
		{"mqtt scheme", "broker.com", "mqtt", "", "/topic", EndpointTypeMQTT},
		{"grpc scheme", "service.com", "grpc", "", "/", EndpointTypeGRPC},
		{"mongodb scheme", "db.com", "mongodb", "", "/mydb", EndpointTypeDatabase},
		{"redis port", "cache.com", "https", "6379", "/", EndpointTypeDatabase},
		{"8080 port", "server.com", "https", "8080", "/", EndpointTypeAPI},
		{"gRPC port", "rpc.com", "https", "50051", "/", EndpointTypeGRPC},
		{"custom port", "host.com", "https", "12345", "/", EndpointTypeCustomPort},
		{"suspicious TLD", "evil.tk", "https", "", "/cmd", EndpointTypeC2},
		{"api host prefix", "api.myapp.com", "https", "", "/data", EndpointTypeAPI},
		{"auth host prefix", "auth.myapp.com", "https", "", "/verify", EndpointTypeAuth},
		{"update host prefix", "update.myapp.com", "https", "", "/check", EndpointTypeUpdate},
		{"api path", "myapp.com", "https", "", "/api/v1/users", EndpointTypeAPI},
		{"auth path", "myapp.com", "https", "", "/auth/login", EndpointTypeAuth},
		{"raw IP", "8.8.8.8", "https", "", "/", EndpointTypeC2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := d.classifyEndpoint(tc.host, tc.scheme, tc.port, tc.path, EndpointTypeBackend)
			if got != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, got)
			}
		})
	}
}

func TestCategorize(t *testing.T) {
	d := NewEndpointDetector()

	cases := []struct {
		epType       EndpointType
		expectedCat  types.Category
		expectedCrit bool
	}{
		{EndpointTypeC2, types.CategorySuspiciousURL, true},
		{EndpointTypeDatabase, types.CategorySuspiciousURL, true},
		{EndpointTypeAPI, types.CategoryServerCheck, false},
		{EndpointTypeWebSocket, types.CategoryServerCheck, true},
		{EndpointTypeMQTT, types.CategoryServerCheck, true},
		{EndpointTypeGRPC, types.CategoryServerCheck, true},
		{EndpointTypeAuth, types.CategoryServerCheck, true},
		{EndpointTypeUpdate, types.CategoryServerCheck, false},
		{EndpointTypeCustomPort, types.CategoryServerCheck, true},
		{EndpointTypeBackend, types.CategoryNetworkEndpoint, false},
	}

	for _, tc := range cases {
		t.Run(string(tc.epType), func(t *testing.T) {
			cat, crit, _ := d.categorize(tc.epType)
			if cat != tc.expectedCat {
				t.Errorf("expected category %s, got %s", tc.expectedCat, cat)
			}
			if crit != tc.expectedCrit {
				t.Errorf("expected critical=%v, got %v", tc.expectedCrit, crit)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//  UNIT TESTS — Filtering
//
// ═══════════════════════════════════════════════════════════════════════════════

func TestShouldSkip_Local(t *testing.T) {
	d := NewEndpointDetector()
	locals := []string{
		"localhost", "127.0.0.1", "0.0.0.0", "::1",
		"myhost.local", "app.localhost",
		"dev.internal", "server.lan",
		"test.home", "app.test", "demo.example",
	}
	for _, h := range locals {
		t.Run(h, func(t *testing.T) {
			if !d.shouldSkip(h, "/") {
				t.Errorf("expected %q to be skipped", h)
			}
		})
	}
}

func TestShouldSkip_Empty(t *testing.T) {
	d := NewEndpointDetector()
	if !d.shouldSkip("", "/") {
		t.Error("empty host should be skipped")
	}
}

func TestShouldSkip_SDKSuffix(t *testing.T) {
	d := NewEndpointDetector()
	suffixHosts := []string{
		"maps.googleapis.com",
		"api.segment.io",
		"sdk.sentry.io",
		"analytics.amplitude.com",
		"logs.datadoghq.com",
		"ec2.amazonaws.com",
		"d1234.cloudfront.net",
	}
	for _, h := range suffixHosts {
		t.Run(h, func(t *testing.T) {
			if !d.shouldSkip(h, "/api/v1") {
				t.Errorf("SDK domain %q should be skipped", h)
			}
		})
	}
}

func TestShouldSkip_NotSkipped(t *testing.T) {
	d := NewEndpointDetector()
	shouldNotSkip := []string{
		"api.myapp.com",
		"backend.customdomain.io",
		"myapp-server.herokuapp.com",
		"custom-api.onrender.com",
		"evil.tk",
		"185.143.223.47",
	}
	for _, h := range shouldNotSkip {
		t.Run(h, func(t *testing.T) {
			if d.shouldSkip(h, "/api/v1/data") {
				t.Errorf("host %q should NOT be skipped", h)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//  JSON CONFIG TESTS
//
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewEndpointDetectorFromJSON_Valid(t *testing.T) {
	cfg := `{
		"max_per_file": 10,
		"api_host_prefixes": ["api.", "backend."],
		"api_path_segments": ["/api/", "/v1/"],
		"auth_path_segments": ["/auth/"],
		"update_path_segments": ["/update/"],
		"suspicious_tlds": [".tk", ".ml"],
		"server_ports": {"8080": "api", "27017": "database"},
		"skip_domains": ["example.com"],
		"skip_suffixes": [".googleapis.com"],
		"skip_host_exact": ["google.com"],
		"static_extensions": [".png", ".css"],
		"legal_path_segments": ["/privacy"],
		"local_suffixes": [".local"],
		"local_hosts": ["localhost", "127.0.0.1"]
	}`

	d, err := NewEndpointDetectorFromJSON([]byte(cfg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.maxPerFile != 10 {
		t.Errorf("expected maxPerFile=10, got=%d", d.maxPerFile)
	}
	if len(d.apiHostPrefixes) != 2 {
		t.Errorf("expected 2 apiHostPrefixes, got=%d", len(d.apiHostPrefixes))
	}
	if _, ok := d.suspiciousTLDs[".tk"]; !ok {
		t.Error("expected .tk in suspiciousTLDs")
	}
	if _, ok := d.serverPorts["8080"]; !ok {
		t.Error("expected port 8080 in serverPorts")
	}
}

func TestNewEndpointDetectorFromJSON_Invalid(t *testing.T) {
	_, err := NewEndpointDetectorFromJSON([]byte(`{invalid json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestNewEndpointDetectorFromJSON_Empty(t *testing.T) {
	d, err := NewEndpointDetectorFromJSON([]byte(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// maxPerFile should default to 30
	if d.maxPerFile != 30 {
		t.Errorf("expected default maxPerFile=30, got=%d", d.maxPerFile)
	}
}

func TestCustomConfig_Detection(t *testing.T) {
	cfg := `{
		"max_per_file": 5,
		"api_host_prefixes": ["custom-api."],
		"api_path_segments": ["/myapi/"],
		"auth_path_segments": [],
		"update_path_segments": [],
		"suspicious_tlds": [".evil"],
		"server_ports": {"9999": "grpc"},
		"skip_domains": ["ignored.com"],
		"skip_suffixes": [],
		"skip_host_exact": [],
		"static_extensions": [],
		"legal_path_segments": [],
		"local_suffixes": [".local"],
		"local_hosts": ["localhost"]
	}`

	d, err := NewEndpointDetectorFromJSON([]byte(cfg))
	if err != nil {
		t.Fatalf("config error: %v", err)
	}

	content := `
		"https://custom-api.myapp.com/data"
		"https://ignored.com/api/v1"
		"https://evil-server.evil/gate"
		"https://normal.com:9999/rpc"
	`
	ctx := makeCtx(content)
	analysis := &types.FileAnalysis{Path: "test.smali"}
	d.Detect(ctx, analysis)

	found := make(map[string]bool)
	for _, m := range analysis.Matches {
		if m.Metadata != nil {
			found[m.Metadata["host"]] = true
		}
	}

	if !found["custom-api.myapp.com"] {
		t.Error("expected custom-api.myapp.com to be found")
	}
	if found["ignored.com"] {
		t.Error("expected ignored.com to be skipped")
	}
	if !found["evil-server.evil"] {
		t.Error("expected evil-server.evil to be found")
	}
	if !found["normal.com"] {
		t.Error("expected normal.com:9999 to be found")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//  BENCHMARKS
//
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkDetect_SmallFile(b *testing.B) {
	content := `
		const-string v0, "https://api.myapp.com/v2/users"
		const-string v1, "https://schemas.android.com/apk/res/android"
		const-string v2, "wss://realtime.myapp.com/socket"
		const-string v3, "https://play.google.com/store/apps"
		const-string v4, "https://www.facebook.com/myapp"
	`
	d := NewEndpointDetector()
	ctx := makeCtx(content)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		analysis := &types.FileAnalysis{Path: "test.smali"}
		d.Detect(ctx, analysis)
	}
}

func BenchmarkDetect_LargeFile(b *testing.B) {
	var sb strings.Builder
	for i := 0; i < 100; i++ {
		sb.WriteString(`const-string v0, "https://api`)
		sb.WriteByte(byte('a' + (i % 26)))
		sb.WriteString(`.server.com/v1/data"`)
		sb.WriteByte('\n')
		sb.WriteString(`const-string v1, "https://schemas.android.com/apk/res/android"`)
		sb.WriteByte('\n')
		sb.WriteString(`const-string v2, "https://play.google.com/store/apps"`)
		sb.WriteByte('\n')
	}

	d := NewEndpointDetector()
	ctx := makeCtx(sb.String())
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		analysis := &types.FileAnalysis{Path: "test.smali"}
		d.Detect(ctx, analysis)
	}
}

func BenchmarkDetect_NoURLs(b *testing.B) {
	content := strings.Repeat("this is just regular smali code\n", 1000)
	d := NewEndpointDetector()
	ctx := makeCtx(content)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		analysis := &types.FileAnalysis{Path: "test.smali"}
		d.Detect(ctx, analysis)
	}
}

func BenchmarkDetect_ManySDKURLs(b *testing.B) {
	// Worst case: lots of URLs that all get skipped
	var sb strings.Builder
	sdks := []string{
		"https://www.googleapis.com/auth/cloud",
		"https://firebaseio.com/projects/app",
		"https://api.mixpanel.com/track",
		"https://s3.amazonaws.com/bucket/file",
		"https://cdn.amplitude.com/libs/sdk.js",
		"https://play.google.com/store/apps",
		"https://developer.android.com/ref",
		"https://schemas.android.com/apk/res",
		"https://www.w3.org/2001/XMLSchema",
		"https://www.facebook.com/myapp",
	}
	for i := 0; i < 50; i++ {
		for _, sdk := range sdks {
			sb.WriteString(`const-string v0, "`)
			sb.WriteString(sdk)
			sb.WriteString(`"`)
			sb.WriteByte('\n')
		}
	}

	d := NewEndpointDetector()
	ctx := makeCtx(sb.String())
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		analysis := &types.FileAnalysis{Path: "test.smali"}
		d.Detect(ctx, analysis)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// NATIVE (.so) SCAN — strings-pass over native binaries
// ═══════════════════════════════════════════════════════════════════════════════

// nativeCtx собирает FileDetectContext с бинарным содержимым .so.
func nativeCtx(content string) *FileDetectContext {
	data := []byte(content)
	return &FileDetectContext{
		Content:      data,
		ContentLower: []byte(strings.ToLower(content)),
		LineOffsets:  buildLineOffsets(data),
		FileType:     types.FileTypeNative,
	}
}

// TestEndpointDetector_NativeSO_ChecksC2 извлекает URL из нативной библиотеки:
// малварь прячет C2-эндпоинты в libil2cpp.so / libgame.so (бэклог 1.txt).
func TestEndpointDetector_NativeSO_ChecksC2(t *testing.T) {
	d := NewEndpointDetector()
	content := "some\x00binary\x00junk\x00" +
		"https://c2-operator.example.com/gate.php\x00" +
		"ws://telemetry.example.org:8080/feed\x00"
	analysis := &types.FileAnalysis{Path: "lib/arm64-v8a/libgame.so"}
	d.Detect(nativeCtx(content), analysis)

	expectFound(t, analysis.Matches, "c2-operator.example.com")
	expectFound(t, analysis.Matches, "telemetry.example.org")
}

// TestEndpointDetector_NativeSO_StockDomainsSkipped стоковые домены Unity и
// схем не должны попадать в выдачу (факты, не шум).
func TestEndpointDetector_NativeSO_StockDomainsSkipped(t *testing.T) {
	d := NewEndpointDetector()
	content := "https://docs.unity3d.com/Manual/index.html\x00" +
		"https://sqltelemetry.sqlite.org/crash\x00" +
		"https://www.w3.org/2000/svg\x00"
	analysis := &types.FileAnalysis{Path: "lib/arm64-v8a/libil2cpp.so"}
	d.Detect(nativeCtx(content), analysis)

	expectSkipped(t, analysis.Matches, "docs.unity3d.com")
	expectSkipped(t, analysis.Matches, "sqltelemetry.sqlite.org")
	expectSkipped(t, analysis.Matches, "www.w3.org")
}

// TestEndpointDetector_NativeSO_BinaryNoiseGated бинарный мусор вокруг
// "http://" не должен порождать матчи: печатный ASCII гейт.
func TestEndpointDetector_NativeSO_BinaryNoiseGated(t *testing.T) {
	d := NewEndpointDetector()
	content := "pre\x00http://\x01\x02noise.example.net/path\x00" +
		"http://highbyte.example.net/\xC3\xA9tail\x00" +
		"post\x00"
	analysis := &types.FileAnalysis{Path: "lib/arm64-v8a/libjunk.so"}
	d.Detect(nativeCtx(content), analysis)

	expectSkipped(t, analysis.Matches, "noise.example.net")
	expectSkipped(t, analysis.Matches, "highbyte.example.net")
	if len(analysis.Matches) != 0 {
		t.Errorf("✗ binary noise leaked %d matches", len(analysis.Matches))
	}
}
