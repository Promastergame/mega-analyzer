package pipeline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"mega-analyzer/pkg/internal/configs"
	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
//
//  S E R V E R   E N D P O I N T   D E T E C T O R   v2
//
//  Фокус: реальные серверные эндпоинты, к которым приложение подключается.
//
//  Архитектура:
//    - Нулевой regexp — только strings/bytes операции
//    - Конфигурация из внешнего JSON (embed или runtime)
//    - Приоритетная цепочка: scheme → port → TLD → host → path → IP
//    - Многоуровневая фильтрация мусора через O(1) map lookups
//
// ═══════════════════════════════════════════════════════════════════════════════

// ── Endpoint Type ────────────────────────────────────────────────────────────

type EndpointType string

const (
	EndpointTypeAPI        EndpointType = "api"
	EndpointTypeWebSocket  EndpointType = "websocket"
	EndpointTypeMQTT       EndpointType = "mqtt"
	EndpointTypeGRPC       EndpointType = "grpc"
	EndpointTypeBackend    EndpointType = "backend"
	EndpointTypeC2         EndpointType = "c2_suspect"
	EndpointTypeCustomPort EndpointType = "custom_port"
	EndpointTypeDatabase   EndpointType = "database"
	EndpointTypeAuth       EndpointType = "auth"
	EndpointTypeUpdate     EndpointType = "update"
)

// ── Scheme Entry ─────────────────────────────────────────────────────────────

type schemeEntry struct {
	pattern      []byte
	endpointType EndpointType
	scheme       string
}

// ── JSON Config ──────────────────────────────────────────────────────────────

// EndpointConfig — структура JSON-конфигурации детектора.
type EndpointConfig struct {
	MaxPerFile         int                     `json:"max_per_file"`
	APIHostPrefixes    []string                `json:"api_host_prefixes"`
	APIPathSegments    []string                `json:"api_path_segments"`
	AuthPathSegments   []string                `json:"auth_path_segments"`
	UpdatePathSegments []string                `json:"update_path_segments"`
	SuspiciousTLDs     []string                `json:"suspicious_tlds"`
	ServerPorts        map[string]EndpointType `json:"server_ports"`
	SkipDomains        []string                `json:"skip_domains"`
	SkipSuffixes       []string                `json:"skip_suffixes"`
	SkipHostExact      []string                `json:"skip_host_exact"`
	StaticExtensions   []string                `json:"static_extensions"`
	LegalPathSegments  []string                `json:"legal_path_segments"`
	LocalSuffixes      []string                `json:"local_suffixes"`
	LocalHosts         []string                `json:"local_hosts"`
}

// ── Detector ─────────────────────────────────────────────────────────────────

type EndpointDetector struct {
	schemes    []schemeEntry
	maxPerFile int

	// Из конфига — предобработано для скорости
	apiHostPrefixes    []string
	apiPathSegments    []string
	authPathSegments   []string
	updatePathSegments []string

	suspiciousTLDs map[string]struct{}
	serverPorts    map[string]EndpointType

	// Skip-фильтры (O(1) lookups)
	skipDomainExact  map[string]struct{}
	skipDomainSuffix []string
	staticExtensions map[string]struct{}
	legalSegments    []string
	localHosts       map[string]struct{}
	localSuffixes    []string
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//  C O N S T R U C T O R S
//
// ═══════════════════════════════════════════════════════════════════════════════

// NewEndpointDetector создаёт детектор из встроенного endpoint_config.json.
// Возвращает пустой детектор при ошибке конфигурации вместо паники.
func NewEndpointDetector() *EndpointDetector {
	data := configs.EndpointConfig()
	d, err := NewEndpointDetectorFromJSON(data)
	if err != nil {
		// Embedded config should always be valid; log and return a safe empty detector
		// rather than panicking and crashing the whole process.
		fmt.Fprintf(os.Stderr, "endpoint_detector: invalid embedded config: %v\n", err)
		return &EndpointDetector{}
	}
	return d
}

// NewEndpointDetectorFromJSON создаёт детектор из произвольного JSON.
func NewEndpointDetectorFromJSON(jsonData []byte) (*EndpointDetector, error) {
	var cfg EndpointConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return nil, err
	}
	return buildFromConfig(&cfg), nil
}

// buildFromConfig собирает детектор из распарсенного конфига.
func buildFromConfig(cfg *EndpointConfig) *EndpointDetector {
	d := &EndpointDetector{
		maxPerFile: cfg.MaxPerFile,
	}
	if d.maxPerFile <= 0 {
		d.maxPerFile = 30
	}

	// ── Схемы (захардкожены — порядок важен: длинные сначала) ─────────────
	d.schemes = []schemeEntry{
		{[]byte("https://"), EndpointTypeBackend, "https"},
		{[]byte("http://"), EndpointTypeBackend, "http"},
		{[]byte("wss://"), EndpointTypeWebSocket, "wss"},
		{[]byte("ws://"), EndpointTypeWebSocket, "ws"},
		{[]byte("mqtts://"), EndpointTypeMQTT, "mqtts"},
		{[]byte("mqtt://"), EndpointTypeMQTT, "mqtt"},
		{[]byte("grpcs://"), EndpointTypeGRPC, "grpcs"},
		{[]byte("grpc://"), EndpointTypeGRPC, "grpc"},
		{[]byte("mongodb+srv://"), EndpointTypeDatabase, "mongodb+srv"},
		{[]byte("mongodb://"), EndpointTypeDatabase, "mongodb"},
		{[]byte("postgresql://"), EndpointTypeDatabase, "postgresql"},
		{[]byte("postgres://"), EndpointTypeDatabase, "postgres"},
		{[]byte("mysql://"), EndpointTypeDatabase, "mysql"},
		{[]byte("rediss://"), EndpointTypeDatabase, "rediss"},
		{[]byte("redis://"), EndpointTypeDatabase, "redis"},
		{[]byte("amqps://"), EndpointTypeBackend, "amqps"},
		{[]byte("amqp://"), EndpointTypeBackend, "amqp"},
		// Escaped (JSON/JS)
		{[]byte("https:\\/\\/"), EndpointTypeBackend, "https"},
		{[]byte("http:\\/\\/"), EndpointTypeBackend, "http"},
		{[]byte("wss:\\/\\/"), EndpointTypeWebSocket, "wss"},
		{[]byte("ws:\\/\\/"), EndpointTypeWebSocket, "ws"},
	}

	// ── Конфиг → оптимизированные структуры ──────────────────────────────
	d.apiHostPrefixes = toLowerSlice(cfg.APIHostPrefixes)
	d.apiPathSegments = toLowerSlice(cfg.APIPathSegments)
	d.authPathSegments = toLowerSlice(cfg.AuthPathSegments)
	d.updatePathSegments = toLowerSlice(cfg.UpdatePathSegments)

	d.suspiciousTLDs = toSet(toLowerSlice(cfg.SuspiciousTLDs))

	d.serverPorts = make(map[string]EndpointType, len(cfg.ServerPorts))
	for port, epType := range cfg.ServerPorts {
		d.serverPorts[port] = epType
	}

	d.skipDomainExact = toSet(toLowerSlice(cfg.SkipDomains))
	for _, h := range toLowerSlice(cfg.SkipHostExact) {
		d.skipDomainExact[h] = struct{}{}
	}
	d.skipDomainSuffix = toLowerSlice(cfg.SkipSuffixes)
	d.staticExtensions = toSet(toLowerSlice(cfg.StaticExtensions))
	d.legalSegments = toLowerSlice(cfg.LegalPathSegments)
	d.localHosts = toSet(toLowerSlice(cfg.LocalHosts))
	d.localSuffixes = toLowerSlice(cfg.LocalSuffixes)

	return d
}

func toLowerSlice(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToLower(s)
	}
	return out
}

func toSet(ss []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		m[s] = struct{}{}
	}
	return m
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//  D E T E C T I O N
//
// ═══════════════════════════════════════════════════════════════════════════════

func (d *EndpointDetector) Name() string { return "endpoint_detector" }

func (d *EndpointDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx.FileType == types.FileTypeResource {
		return
	}
	// Native binaries (.so) ARE scanned: game code lives in libil2cpp.so and
	// malware C2 URLs hide there too. A strings-pass over the binary with the
	// printable-ASCII gate (scanScheme) plus the stock-domain skip list
	// (Unity/Khronos/schema homes) keeps the false-positive rate flat.
	// A runtime-looking path alone must never suppress findings.
	if len(ctx.ContentLower) == 0 {
		return
	}
	if !bytes.Contains(ctx.ContentLower, []byte("://")) &&
		!bytes.Contains(ctx.ContentLower, []byte(":\\/\\/")) {
		return
	}

	seen := make(map[string]struct{}, 16)
	hits := 0

	for _, se := range d.schemes {
		d.scanScheme(ctx, analysis, se, seen, &hits)
		if d.maxPerFile > 0 && hits >= d.maxPerFile {
			return
		}
	}
}

func (d *EndpointDetector) scanScheme(
	ctx *FileDetectContext,
	analysis *types.FileAnalysis,
	se schemeEntry,
	seen map[string]struct{},
	hits *int,
) {
	data := ctx.ContentLower
	offset := 0

	for {
		idx := bytes.Index(data[offset:], se.pattern)
		if idx < 0 {
			return
		}
		absIdx := offset + idx

		raw, endPos := extractURLBytes(ctx.Content, absIdx)
		if raw != "" && ctx.FileType == types.FileTypeNative && !isPrintableASCII(raw) {
			// Strings-pass hygiene: in native binaries "http://" can be
			// surrounded by arbitrary binary bytes; only printable-ASCII
			// candidates are real embedded URLs.
			raw = ""
		}
		if raw != "" {
			if endpoint := normalizeEndpoint(raw); endpoint != "" {
				host, schemeName, port, path := parseEndpoint(endpoint)
				if host != "" && !d.shouldSkip(host, path) {
					epType := d.classifyEndpoint(host, schemeName, port, path, se.endpointType)

					key := schemeName + "://" + host
					if port != "" {
						key += ":" + port
					}

					if _, dup := seen[key]; !dup {
						seen[key] = struct{}{}

						category, isCritical, description := d.categorize(epType)
						line := lineAt(ctx.LineOffsets, absIdx)

						match := newMatch(category, analysis.Path, line, description, endpoint, isCritical)
						if match.Metadata == nil {
							match.Metadata = map[string]string{}
						}
						match.Metadata["scheme"] = schemeName
						match.Metadata["host"] = host
						match.Metadata["endpoint_type"] = string(epType)
						if port != "" {
							match.Metadata["port"] = port
						}
						if path != "" && path != "/" {
							match.Metadata["path"] = path
						}

						applyEndpointRisk(&match, schemeName, host, epType)

						analysis.Matches = append(analysis.Matches, match)
						(*hits)++
						if d.maxPerFile > 0 && *hits >= d.maxPerFile {
							return
						}
					}
				}
			}
		}

		// Advance
		next := absIdx + len(se.pattern)
		if endPos > next {
			next = endPos
		}
		if next <= offset {
			next = offset + 1
		}
		if next >= len(data) {
			return
		}
		offset = next
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//  C L A S S I F I C A T I O N
//
// ═══════════════════════════════════════════════════════════════════════════════

func (d *EndpointDetector) classifyEndpoint(host, scheme, port, path string, defaultType EndpointType) EndpointType {
	h := strings.ToLower(host)
	lpath := strings.ToLower(path)

	// 1. Протокол
	switch scheme {
	case "ws", "wss":
		return EndpointTypeWebSocket
	case "mqtt", "mqtts":
		return EndpointTypeMQTT
	case "grpc", "grpcs":
		return EndpointTypeGRPC
	case "mongodb", "mongodb+srv", "mysql", "postgres", "postgresql", "redis", "rediss":
		return EndpointTypeDatabase
	case "amqp", "amqps":
		return EndpointTypeBackend
	}

	// 2. Порт
	if port != "" {
		if epType, ok := d.serverPorts[port]; ok {
			return epType
		}
		if port != "80" && port != "443" {
			return EndpointTypeCustomPort
		}
	}

	// 3. Подозрительный TLD
	if d.hasSuspiciousTLD(h) {
		return EndpointTypeC2
	}

	// 4. Хост-префикс
	if epType := d.classifyByHostPrefix(h); epType != "" {
		return epType
	}

	// 5. Путь
	if epType := d.classifyByPath(lpath); epType != "" {
		return epType
	}

	// 6. Голый IP
	if net.ParseIP(h) != nil {
		return EndpointTypeC2
	}

	return defaultType
}

func (d *EndpointDetector) hasSuspiciousTLD(h string) bool {
	for tld := range d.suspiciousTLDs {
		if strings.HasSuffix(h, tld) && len(h) > len(tld) {
			return true
		}
	}
	return false
}

func (d *EndpointDetector) classifyByHostPrefix(h string) EndpointType {
	for _, prefix := range d.apiHostPrefixes {
		if !strings.HasPrefix(h, prefix) {
			continue
		}
		switch {
		case strings.HasPrefix(h, "auth.") || strings.HasPrefix(h, "auth-") ||
			strings.HasPrefix(h, "oauth.") || strings.HasPrefix(h, "oauth-") ||
			strings.HasPrefix(h, "login.") || strings.HasPrefix(h, "login-") ||
			strings.HasPrefix(h, "sso.") || strings.HasPrefix(h, "sso-"):
			return EndpointTypeAuth
		case strings.HasPrefix(h, "update.") || strings.HasPrefix(h, "update-"):
			return EndpointTypeUpdate
		case strings.HasPrefix(h, "dl.") || strings.HasPrefix(h, "dl-") ||
			strings.HasPrefix(h, "download.") || strings.HasPrefix(h, "download-"):
			return EndpointTypeUpdate
		case strings.HasPrefix(h, "license.") || strings.HasPrefix(h, "license-"):
			return EndpointTypeAuth
		case strings.HasPrefix(h, "ws.") || strings.HasPrefix(h, "wss.") ||
			strings.HasPrefix(h, "socket."):
			return EndpointTypeWebSocket
		case strings.HasPrefix(h, "mqtt."):
			return EndpointTypeMQTT
		case strings.HasPrefix(h, "grpc.") || strings.HasPrefix(h, "rpc."):
			return EndpointTypeGRPC
		default:
			return EndpointTypeAPI
		}
	}
	return ""
}

func (d *EndpointDetector) classifyByPath(lpath string) EndpointType {
	if lpath == "" || lpath == "/" {
		return ""
	}

	// Auth первым — специфичнее
	for _, seg := range d.authPathSegments {
		if strings.Contains(lpath, seg) {
			return EndpointTypeAuth
		}
	}
	for _, seg := range d.updatePathSegments {
		if strings.Contains(lpath, seg) {
			return EndpointTypeUpdate
		}
	}
	for _, seg := range d.apiPathSegments {
		if strings.Contains(lpath, seg) {
			return EndpointTypeAPI
		}
	}
	return ""
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//  C A T E G O R I Z A T I O N
//
// ═══════════════════════════════════════════════════════════════════════════════

func (d *EndpointDetector) categorize(epType EndpointType) (types.Category, bool, string) {
	switch epType {
	case EndpointTypeC2:
		return types.CategorySuspiciousURL, true, "Suspicious server endpoint (potential C2/callback)"
	case EndpointTypeDatabase:
		return types.CategorySuspiciousURL, true, "Direct database connection string"
	case EndpointTypeWebSocket:
		return types.CategoryServerCheck, true, "WebSocket server connection"
	case EndpointTypeMQTT:
		return types.CategoryServerCheck, true, "MQTT broker connection"
	case EndpointTypeGRPC:
		return types.CategoryServerCheck, true, "gRPC server connection"
	case EndpointTypeAuth:
		return types.CategoryServerCheck, true, "Authentication server endpoint"
	case EndpointTypeCustomPort:
		return types.CategoryServerCheck, true, "Server on non-standard port"
	case EndpointTypeAPI:
		return types.CategoryServerCheck, false, "API server endpoint"
	case EndpointTypeUpdate:
		return types.CategoryServerCheck, false, "Update/download server"
	default:
		return types.CategoryNetworkEndpoint, false, "Server endpoint"
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//  F I L T E R I N G
//
// ═══════════════════════════════════════════════════════════════════════════════

func (d *EndpointDetector) shouldSkip(host, path string) bool {
	if host == "" {
		return true
	}
	h := strings.ToLower(host)

	// 1. Localhost / reserved (O(1))
	if d.isLocal(h) {
		return true
	}

	// 2. Точное совпадение домена (O(1))
	if _, skip := d.skipDomainExact[h]; skip {
		return true
	}

	// 3. Суффиксное совпадение (SDK: .googleapis.com и т.д.)
	for _, suffix := range d.skipDomainSuffix {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}

	// 4. Статические ресурсы
	if d.isStaticResource(path) {
		return true
	}

	// 5. Legal/info страницы
	if d.isLegalPage(path) {
		return true
	}

	return false
}

func (d *EndpointDetector) isLocal(h string) bool {
	if _, ok := d.localHosts[h]; ok {
		return true
	}
	for _, suffix := range d.localSuffixes {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	if ip := net.ParseIP(h); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() ||
			ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
		if ip.To4() != nil && IsReservedIP(ip.String()) {
			return true
		}
	}
	return false
}

func (d *EndpointDetector) isStaticResource(path string) bool {
	if path == "" || path == "/" {
		return false
	}
	lp := strings.ToLower(path)
	if qIdx := strings.IndexByte(lp, '?'); qIdx > 0 {
		lp = lp[:qIdx]
	}
	dotIdx := strings.LastIndexByte(lp, '.')
	if dotIdx < 0 {
		return false
	}
	_, isStatic := d.staticExtensions[lp[dotIdx:]]
	return isStatic
}

func (d *EndpointDetector) isLegalPage(path string) bool {
	if path == "" || path == "/" {
		return false
	}
	lp := strings.ToLower(path)
	for _, seg := range d.legalSegments {
		if strings.Contains(lp, seg) {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//  U R L   P A R S I N G
//
// ═══════════════════════════════════════════════════════════════════════════════

func extractURLBytes(content []byte, start int) (string, int) {
	if start < 0 || start >= len(content) {
		return "", start
	}
	end := start
	for end < len(content) {
		if isURLTerminator(content[end]) {
			break
		}
		end++
	}
	if end == start {
		return "", start
	}
	return string(content[start:end]), end
}

func isURLTerminator(b byte) bool {
	switch b {
	case ' ', '\n', '\r', '\t',
		'"', '\'', '`',
		'<', '>',
		'{', '}', '(', ')', '[', ']',
		'|', '^',
		0:
		return true
	default:
		return false
	}
}

// isPrintableASCII reports whether s consists solely of printable,
// non-space ASCII (0x21–0x7E). Used as the strings-pass quality gate for
// native binaries, where "http://" occurrences may be surrounded by
// arbitrary binary bytes that isURLTerminator does not stop on.
func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

func normalizeEndpoint(raw string) string {
	if raw == "" {
		return ""
	}
	s := strings.TrimSpace(raw)
	s = strings.TrimRight(s, ".,;:)]}>\"'!?")
	s = strings.ReplaceAll(s, "\\/", "/")
	s = strings.ReplaceAll(s, "\\u0026", "&")
	s = strings.ReplaceAll(s, "\\u003d", "=")
	s = strings.ReplaceAll(s, "\\u003f", "?")
	s = strings.ReplaceAll(s, "\\u002f", "/")
	s = strings.ReplaceAll(s, "\\u003a", ":")
	return s
}

func parseEndpoint(endpoint string) (host, scheme, port, path string) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", "", "", ""
	}
	scheme = strings.ToLower(u.Scheme)
	host = strings.ToLower(u.Hostname())
	port = u.Port()
	path = u.EscapedPath()
	if path == "" {
		path = u.Path
	}
	return host, scheme, port, path
}

func applyEndpointRisk(match *types.Match, scheme, host string, epType EndpointType) {
	if match == nil {
		return
	}

	flags := make([]string, 0, 3)
	switch strings.ToLower(scheme) {
	case "http":
		flags = append(flags, "http")
	}
	if net.ParseIP(host) != nil {
		flags = append(flags, "ip")
	}
	if epType == EndpointTypeC2 {
		flags = append(flags, "suspicious")
	}

	if len(flags) == 0 {
		return
	}

	if match.Metadata == nil {
		match.Metadata = map[string]string{}
	}
	match.Metadata["risk_flags"] = strings.Join(flags, ",")
	match.Context = match.Context + " [" + strings.Join(flags, ", ") + "]"
	match.Score = boostEndpointScore(match.Score, flags)
}

func boostEndpointScore(base float64, flags []string) float64 {
	boost := 0.0
	for _, f := range flags {
		switch f {
		case "http":
			boost += 2
		case "ip":
			boost += 3
		case "suspicious":
			boost += 3
		}
	}
	score := base + boost
	if score > 10 {
		score = 10
	}
	return score
}
