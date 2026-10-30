package privserver

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/insights"
)

// maxEndpoints bounds how many distinct endpoints a single Discover call will
// retain. A hostile or pathological target (an APK stuffed with millions of
// IP-like strings) must not be able to make discovery allocate without limit;
// once the cap is hit we stop retaining new endpoints but keep scanning for
// pinning hints and the app package, and record a note so the truncation is
// never silent.
const maxEndpoints = 512

// DiscoverOptions controls how the discoverer walks the APK / target.
type DiscoverOptions struct {
	GameName        string
	Module          string
	ListenPort      int
	AdminPort       int
	MaxBytesPerFile int64
}

// Discover scans the target (APK / DEX / directory) and produces a Plan.
// It never connects to live infrastructure: everything is computed from
// bytes already inside the target.
func Discover(target string, opts DiscoverOptions) (*Plan, error) {
	if strings.TrimSpace(target) == "" {
		return nil, fmt.Errorf("privserver: target is empty (want an APK / DEX / directory path)")
	}
	files, err := insights.LoadFiles(target, insights.LoadOptions{
		MaxBytesPerFile: clampBytes(opts.MaxBytesPerFile),
		IncludeBinary:   true,
	})
	if err != nil {
		return nil, fmt.Errorf("privserver: load target %q: %w", target, err)
	}

	gameName := strings.TrimSpace(opts.GameName)
	if gameName == "" {
		gameName = inferGameName(target)
	}
	plan := &Plan{
		GeneratedAt: time.Now(),
		Target:      target,
		GameName:    gameName,
		Module:      sanitizeModule(firstNonEmpty(opts.Module, gameName, "PrivateServer")),
		Listen: ListenProfile{
			Host:      "0.0.0.0",
			Port:      portOr(opts.ListenPort, 9339),
			AdminPort: portOr(opts.AdminPort, 8765),
		},
	}

	endpointSet := map[string]DiscoveredEndpoint{}
	domainSet := map[string]struct{}{}
	ipSet := map[string]struct{}{}
	pinningHints := map[string]struct{}{}
	endpointsTruncated := false

	for _, f := range files {
		lower := strings.ToLower(filepath.ToSlash(f.Path))
		for _, addr := range FindServerAddresses(f.Data, lower) {
			kind := classifyAddressKind(addr.Address)
			key := strings.ToLower(strings.TrimSpace(addr.Address))
			if _, ok := endpointSet[key]; ok {
				continue
			}
			if len(endpointSet) >= maxEndpoints {
				endpointsTruncated = true
				continue
			}
			endpointSet[key] = DiscoveredEndpoint{
				Address:    addr.Address,
				Port:       addr.Port,
				FilePath:   addr.FilePath,
				FileType:   addr.FileType,
				Confidence: addr.Confidence,
				Kind:       kind,
			}
			switch kind {
			case "domain", "wss", "ws", "https", "http":
				host := extractHost(addr.Address)
				if host != "" {
					domainSet[host] = struct{}{}
				}
			case "ip":
				ipSet[addr.Address] = struct{}{}
			}
		}
		for _, hint := range detectPinningHints(f.Data) {
			pinningHints[hint] = struct{}{}
		}
		appendAppPackage(plan, f, lower)
	}

	for _, e := range endpointSet {
		plan.Endpoints = append(plan.Endpoints, e)
	}
	sort.Slice(plan.Endpoints, func(i, j int) bool {
		if plan.Endpoints[i].Confidence != plan.Endpoints[j].Confidence {
			return plan.Endpoints[i].Confidence > plan.Endpoints[j].Confidence
		}
		return plan.Endpoints[i].Address < plan.Endpoints[j].Address
	})
	plan.Domains = sortedKeys(domainSet)
	plan.IPs = sortedKeys(ipSet)

	plan.Family = inferGameFamily(plan)
	plan.Transport = inferTransport(plan)
	plan.Framing = inferFraming(plan)

	if len(pinningHints) > 0 {
		plan.Pinning = PinningProfile{Detected: true, Hints: sortedKeys(pinningHints), Reason: "string / class references inside the target"}
	}

	plan.Messages, plan.Replays = buildMessageStubs(plan)
	plan.Readiness = scoreReadiness(plan)
	plan.Notes = buildPlanNotes(plan)
	if endpointsTruncated {
		plan.Notes = append(plan.Notes, fmt.Sprintf("endpoint list truncated at %d entries — target contained more address-like strings than retained", maxEndpoints))
	}
	return plan, nil
}

// Validate performs a structural sanity check on a Plan. It is useful after
// deserialising a plan from JSON or before handing it to Generate, so that a
// malformed plan produces a clear diagnostic instead of a confusing failure
// deeper in the generator.
func (p *Plan) Validate() error {
	if p == nil {
		return fmt.Errorf("privserver: nil plan")
	}
	if strings.TrimSpace(p.Module) == "" {
		return fmt.Errorf("privserver: plan has empty module name")
	}
	if p.Listen.Port <= 0 || p.Listen.Port > 65535 {
		return fmt.Errorf("privserver: plan listen port %d out of range 1-65535", p.Listen.Port)
	}
	if p.Listen.AdminPort <= 0 || p.Listen.AdminPort > 65535 {
		return fmt.Errorf("privserver: plan admin port %d out of range 1-65535", p.Listen.AdminPort)
	}
	if p.Listen.Port == p.Listen.AdminPort {
		return fmt.Errorf("privserver: listen port and admin port must differ (both %d)", p.Listen.Port)
	}
	if p.Transport.Protocol == "" {
		return fmt.Errorf("privserver: plan has empty transport protocol")
	}
	return nil
}

var (
	pinningPatterns = []struct {
		Needle string
		Note   string
	}{
		{"okhttp3.CertificatePinner", "OkHttp CertificatePinner reference"},
		{"network_security_config", "Network Security Config file"},
		{"javax/net/ssl/X509TrustManager", "Custom TrustManager"},
		{"javax.net.ssl.HostnameVerifier", "Custom HostnameVerifier"},
		{"ssl_pinning", "string literal ssl_pinning"},
		{"PinnedCertificate", "string literal PinnedCertificate"},
		{"setVerifyHostname", "setVerifyHostname call"},
	}

	hostHint      = regexp.MustCompile(`(?:https?|wss?)://([A-Za-z0-9.\-]+)`)
	packageRe     = regexp.MustCompile(`(?m)^\s*package\s+["]?([a-z][a-z0-9_.]+)["]?`)
	manifestPkgRe = regexp.MustCompile(`package="([a-z][a-z0-9_.]+)"`)
)

func detectPinningHints(data []byte) []string {
	lower := bytes.ToLower(data)
	var out []string
	for _, p := range pinningPatterns {
		if bytes.Contains(lower, []byte(strings.ToLower(p.Needle))) {
			out = append(out, p.Note)
		}
	}
	return out
}

func classifyAddressKind(addr string) string {
	lower := strings.ToLower(addr)
	switch {
	case strings.HasPrefix(lower, "wss://"):
		return "wss"
	case strings.HasPrefix(lower, "ws://"):
		return "ws"
	case strings.HasPrefix(lower, "https://"):
		return "https"
	case strings.HasPrefix(lower, "http://"):
		return "http"
	case looksLikeIP(addr):
		return "ip"
	default:
		return "domain"
	}
}

func looksLikeIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}

func extractHost(raw string) string {
	m := hostHint.FindStringSubmatch(raw)
	if len(m) == 2 {
		return strings.ToLower(m[1])
	}
	if looksLikeIP(raw) {
		return ""
	}
	return strings.ToLower(raw)
}

func inferGameName(target string) string {
	base := filepath.Base(target)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	base = strings.ReplaceAll(base, "_", " ")
	base = strings.ReplaceAll(base, "-", " ")
	base = strings.TrimSpace(base)
	if base == "" {
		return "PrivateServer"
	}
	titled := strings.Builder{}
	for _, word := range strings.Fields(base) {
		if len(word) == 0 {
			continue
		}
		titled.WriteString(strings.ToUpper(word[:1]))
		if len(word) > 1 {
			titled.WriteString(strings.ToLower(word[1:]))
		}
		titled.WriteByte(' ')
	}
	return strings.TrimSpace(titled.String())
}

func appendAppPackage(plan *Plan, f insights.ScannedFile, lowerPath string) {
	if plan.AppPackage != "" {
		return
	}
	if strings.HasSuffix(lowerPath, "androidmanifest.xml") {
		if m := manifestPkgRe.FindSubmatch(f.Data); len(m) == 2 {
			plan.AppPackage = string(m[1])
			return
		}
	}
	if strings.HasSuffix(lowerPath, ".smali") {
		if m := packageRe.FindSubmatch(f.Data); len(m) == 2 {
			plan.AppPackage = string(m[1])
		}
	}
}

func inferGameFamily(plan *Plan) string {
	hasSupercell := false
	hasUnity := false
	hasUnreal := false
	hasGodot := false
	for _, dom := range plan.Domains {
		if strings.Contains(dom, "supercell") {
			hasSupercell = true
		}
		if strings.Contains(dom, "unity") {
			hasUnity = true
		}
		if strings.Contains(dom, "unrealgames") || strings.Contains(dom, "epicgames") {
			hasUnreal = true
		}
		if strings.Contains(dom, "godot") {
			hasGodot = true
		}
	}
	switch {
	case hasSupercell:
		return "supercell-like"
	case hasUnity:
		return "unity"
	case hasUnreal:
		return "unreal"
	case hasGodot:
		return "godot"
	}
	for _, e := range plan.Endpoints {
		if e.Kind == "wss" || e.Kind == "ws" {
			return "websocket"
		}
	}
	for _, e := range plan.Endpoints {
		if e.Kind == "https" || e.Kind == "http" {
			return "rest"
		}
	}
	if len(plan.IPs) > 0 {
		return "tcp"
	}
	return "generic"
}

func inferTransport(plan *Plan) TransportProfile {
	usesTLS := false
	usesWS := false
	hasHTTP := false
	hasTCP := len(plan.IPs) > 0
	for _, e := range plan.Endpoints {
		switch e.Kind {
		case "wss":
			usesTLS = true
			usesWS = true
		case "ws":
			usesWS = true
		case "https":
			usesTLS = true
			hasHTTP = true
		case "http":
			hasHTTP = true
		case "ip":
			hasTCP = true
		}
	}
	switch {
	case usesWS:
		return TransportProfile{Protocol: "websocket", Confidence: 0.85, UsesTLS: usesTLS, UsesWebSocket: true, Reason: "ws:// or wss:// references inside the target"}
	case usesTLS && hasHTTP:
		return TransportProfile{Protocol: "https", Confidence: 0.75, UsesTLS: true, Reason: "https:// references inside the target"}
	case hasHTTP:
		return TransportProfile{Protocol: "http", Confidence: 0.6, UsesTLS: false, Reason: "http:// references inside the target"}
	case hasTCP:
		return TransportProfile{Protocol: "tcp", Confidence: 0.55, UsesTLS: false, Reason: "raw IP addresses found, assuming TCP"}
	default:
		return TransportProfile{Protocol: "tcp", Confidence: 0.3, UsesTLS: false, Reason: "no endpoints discovered, defaulting to TCP"}
	}
}

func inferFraming(plan *Plan) FramingProfile {
	switch plan.Family {
	case "supercell-like":
		return FramingProfile{
			Style:        "supercell",
			HeaderSize:   7,
			IDOffset:     0,
			IDSize:       2,
			LengthOffset: 2,
			LengthSize:   3,
			Endian:       "big",
			Reason:       "Supercell-style: 2-byte type, 3-byte length, 2-byte version",
		}
	}
	switch plan.Transport.Protocol {
	case "websocket":
		return FramingProfile{Style: "websocket", Endian: "n/a", Reason: "RFC 6455 frames, no extra header"}
	case "http", "https":
		return FramingProfile{Style: "http", Endian: "n/a", Reason: "HTTP request/response framing"}
	default:
		return FramingProfile{
			Style:        "length-prefixed",
			HeaderSize:   6,
			IDOffset:     0,
			IDSize:       2,
			LengthOffset: 2,
			LengthSize:   4,
			Endian:       "big",
			Reason:       "default 2-byte id + 4-byte length frame",
		}
	}
}

func buildMessageStubs(plan *Plan) ([]MessageStub, []ReplayEntry) {
	if plan.Family != "supercell-like" {
		stubs := []MessageStub{
			{ID: 0x0001, Name: "Handshake", Direction: "client_to_server", Replay: true, Stateful: true, NextState: "authenticated"},
			{ID: 0x0002, Name: "HandshakeAck", Direction: "server_to_client", Replay: true},
			{ID: 0x0010, Name: "KeepAlive", Direction: "client_to_server"},
			{ID: 0x0011, Name: "KeepAliveAck", Direction: "server_to_client", Replay: true},
		}
		replays := []ReplayEntry{
			{MessageID: 0x0002, Direction: "server_to_client", PayloadHex: hexBlob(1, 0, 0, 0), Note: "default canned HandshakeAck"},
			{MessageID: 0x0011, Direction: "server_to_client", PayloadHex: hexBlob(0), Note: "empty KeepAliveAck"},
		}
		return stubs, replays
	}
	stubs := []MessageStub{
		{ID: 10100, Name: "ClientHello", Direction: "client_to_server", Replay: false, Stateful: true, NextState: "hello_sent"},
		{ID: 20100, Name: "ServerHello", Direction: "server_to_client", Replay: true},
		{ID: 10101, Name: "Login", Direction: "client_to_server", Stateful: true, NextState: "authenticated"},
		{ID: 20104, Name: "LoginOk", Direction: "server_to_client", Replay: true},
		{ID: 10108, Name: "KeepAlive", Direction: "client_to_server"},
		{ID: 20108, Name: "KeepAliveOk", Direction: "server_to_client", Replay: true},
		{ID: 14102, Name: "ExecuteCommand", Direction: "client_to_server"},
		{ID: 24101, Name: "OwnHomeData", Direction: "server_to_client", Replay: true},
	}
	replays := []ReplayEntry{
		{MessageID: 20100, Direction: "server_to_client", PayloadHex: hexBlob(0, 0, 0, 0, 0, 0, 0, 0, 0, 1), Note: "stub ServerHello"},
		{MessageID: 20104, Direction: "server_to_client", PayloadHex: hexBlob(0, 0, 0, 0, 0, 0, 0, 0), Note: "stub LoginOk"},
		{MessageID: 20108, Direction: "server_to_client", PayloadHex: hexBlob(0), Note: "stub KeepAliveOk"},
		{MessageID: 24101, Direction: "server_to_client", PayloadHex: hexBlob(0, 0, 0, 0, 0, 0, 0, 0), Note: "stub OwnHomeData"},
	}
	return stubs, replays
}

func scoreReadiness(plan *Plan) Readiness {
	r := Readiness{Score: 0}
	r.KnownMessages = len(plan.Messages)
	for _, m := range plan.Messages {
		if m.Replay {
			r.ReplayBacked++
		}
		if m.Stateful {
			r.StatefulCount++
		}
	}
	switch plan.Transport.Protocol {
	case "websocket":
		r.Score += 25
	case "https", "http":
		r.Score += 30
	case "tcp":
		r.Score += 20
	}
	if len(plan.Endpoints) > 0 {
		r.Score += 15
	}
	r.Score += r.ReplayBacked * 6
	r.Score += r.StatefulCount * 4
	if plan.Family != "generic" {
		r.Score += 10
	}
	if r.Score > 100 {
		r.Score = 100
	}
	switch {
	case r.Score >= 70:
		r.Risk = "good"
	case r.Score >= 40:
		r.Risk = "partial"
	default:
		r.Risk = "draft"
	}
	if plan.Pinning.Detected {
		r.CriticalGaps = append(r.CriticalGaps, "SSL pinning detected — clients will refuse the mock server until pinning is bypassed via --patch-client --mode research")
	}
	if r.ReplayBacked == 0 {
		r.CriticalGaps = append(r.CriticalGaps, "no canned responses — every handler will return empty payload until you record real samples")
	}
	if plan.Transport.Protocol == "tcp" && r.KnownMessages == 0 {
		r.CriticalGaps = append(r.CriticalGaps, "no message stubs generated — protocol is unknown, fill router manually")
	}
	r.Notes = append(r.Notes, "Authorized lab use only: target your own / authorized builds, never live third-party servers.")
	return r
}

func buildPlanNotes(plan *Plan) []string {
	var notes []string
	if plan.Pinning.Detected {
		notes = append(notes, "SSL / certificate pinning hints detected — see Pinning section in the report")
	}
	if len(plan.Endpoints) == 0 {
		notes = append(notes, "no endpoints found — protocol generation falls back to a generic stub")
	}
	if plan.Transport.Protocol == "tcp" && plan.Framing.Style == "supercell" {
		notes = append(notes, "Supercell-style framing chosen — verify packet layout matches your target")
	}
	return notes
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func hexBlob(values ...byte) string {
	if len(values) == 0 {
		return ""
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(values)*2)
	for _, b := range values {
		out = append(out, hex[b>>4], hex[b&0x0f])
	}
	return string(out)
}

func clampBytes(v int64) int64 {
	if v <= 0 {
		return 4 << 20
	}
	if v > 64<<20 {
		return 64 << 20
	}
	return v
}

func portOr(v, def int) int {
	if v <= 0 || v > 65535 {
		return def
	}
	return v
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}

// sanitizeModule strips characters that are not valid in an Elixir module
// name. The returned value always starts with an uppercase letter.
func sanitizeModule(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			if b.Len() > 0 {
				b.WriteRune(r)
			}
		}
	}
	out := b.String()
	if out == "" {
		return "PrivateServer"
	}
	if first := out[0]; first >= 'a' && first <= 'z' {
		out = string(first-32) + out[1:]
	}
	return out + "LabServer"
}

// EncodeFramingForReplay packs a 16-bit big-endian message id and a
// payload into a framing-style preamble. It's exposed for tests and the
// generator.
func EncodeFramingForReplay(id uint16) []byte {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, id)
	return out
}
