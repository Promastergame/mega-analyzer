package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// PCAPdroid integration — captures real device network traffic with NO ROOT by
// driving the already-installed PCAPdroid app over ADB. PCAPdroid uses Android's
// VpnService API to capture every connection in userspace, then streams the
// capture to us as a PCAP-over-UDP feed. We parse that feed live and emit the
// same `network` / `dns` telemetry events the dashboard already understands, so
// the Connections and DNS Requests counters populate in real time.
//
// Requirements on the device (one-time):
//   - PCAPdroid installed (free version is enough)
//   - Its "Control permission" granted (PCAPdroid asks the first time)
//   - Device and host on the same Wi-Fi (so the UDP feed can reach the host),
//     or an emulator (reaches the host via 10.0.2.2 automatically)
const pcapdroidComponent = "com.emanuelef.remote_capture/.activities.CaptureCtrl"

// livePcapdroidMonitor starts PCAPdroid, listens for its UDP PCAP feed, parses
// packets and emits live network/dns events until stop is closed.
func livePcapdroidMonitor(emit func(TelemetryEvent), adb, serial, pkg string, stop <-chan struct{}) {
	if adb == "" || serial == "" {
		return
	}

	// 1. Open a UDP socket on the host for PCAPdroid to export to.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		emit(TelemetryEvent{Type: "status", Process: "pcapdroid", Details: "PCAPdroid: could not open UDP collector: " + err.Error()})
		return
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port

	// Address the device should send the feed to.
	collectorIP := "10.0.2.2" // emulator → host loopback
	if !strings.HasPrefix(serial, "emulator-") {
		collectorIP = hostLANIP()
		if collectorIP == "" {
			emit(TelemetryEvent{Type: "status", Process: "pcapdroid", Details: "PCAPdroid: no host LAN IP found — connect host to the same Wi-Fi as the device"})
			return
		}
	}

	// 2. Tell PCAPdroid to start capturing and export to us.
	startArgs := []string{"-s", serial, "shell", "am", "start",
		"-e", "action", "start",
		"-e", "pcap_dump_mode", "udp_exporter",
		"-e", "collector_ip_address", collectorIP,
		"-e", "collector_port", strconv.Itoa(port),
	}
	if pkg != "" {
		startArgs = append(startArgs, "-e", "app_filter", pkg)
	}
	startArgs = append(startArgs, "-n", pcapdroidComponent)

	startCtx, startCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer startCancel()
	out, startErr := exec.CommandContext(startCtx, adb, startArgs...).CombinedOutput()
	if startErr != nil {
		emit(TelemetryEvent{Type: "status", Process: "pcapdroid", Details: "PCAPdroid start failed (is it installed with Control permission granted?): " + strings.TrimSpace(string(out))})
		return
	}
	emit(TelemetryEvent{Type: "status", Process: "pcapdroid", Details: fmt.Sprintf("PCAPdroid capturing → udp %s:%d (filter=%s)", collectorIP, port, firstNonEmpty(pkg, "all apps"))})

	// 3. Always stop PCAPdroid when we exit so it doesn't keep the VPN up.
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, adb, "-s", serial, "shell", "am", "start",
			"-e", "action", "stop", "-n", pcapdroidComponent).Run()
	}()

	// 4. Read and parse the PCAP feed until stop.
	parser := &pcapStream{}
	seenConn := map[string]bool{}
	seenDNS := map[string]bool{}
	seenHTTP := map[string]bool{}
	buf := make([]byte, 65535)

	go func() {
		<-stop
		_ = conn.SetReadDeadline(time.Now()) // unblock ReadFromUDP
	}()

	for {
		select {
		case <-stop:
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, rerr := conn.ReadFromUDP(buf)
		if rerr != nil {
			if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
				select {
				case <-stop:
					return
				default:
					continue
				}
			}
			return
		}
		for _, pkt := range parser.feed(buf[:n]) {
			emitParsedPacket(emit, pkt, seenConn, seenDNS, seenHTTP)
		}
	}
}

// emitParsedPacket turns one decoded packet into network/dns/http telemetry
// events, deduplicating so the dashboard isn't flooded.
func emitParsedPacket(emit func(TelemetryEvent), p decodedPacket, seenConn, seenDNS, seenHTTP map[string]bool) {
	if p.dstIP == "" || isLocalAddr(p.dstIP) {
		return
	}
	// DNS query → dns event (deduped by domain).
	if p.proto == "UDP" && p.dstPort == 53 && p.dnsName != "" {
		if !seenDNS[p.dnsName] {
			seenDNS[p.dnsName] = true
			emit(TelemetryEvent{Type: "dns", Details: "A " + p.dnsName})
		}
		return
	}

	// Plaintext HTTP request line → http event with the real URL.
	if p.proto == "TCP" && len(p.payload) > 0 {
		if method, host, path := parseHTTPRequest(p.payload); method != "" {
			if host == "" {
				host = p.dstIP
			}
			url := "http://" + host + path
			if !seenHTTP[url] {
				seenHTTP[url] = true
				emit(TelemetryEvent{Type: "http", Method: method, Status: "—", Host: host, URL: url})
			}
			return
		}
		// HTTPS ClientHello → surface the SNI hostname (no decryption needed).
		if sni := parseTLSSNI(p.payload); sni != "" {
			key := "TLS " + sni
			if !seenHTTP[key] {
				seenHTTP[key] = true
				emit(TelemetryEvent{Type: "http", Method: "TLS", Status: "443", Host: sni, URL: "https://" + sni})
			}
			// fall through so the raw connection is recorded too
		}
	}

	// Everything else outbound → connection event (deduped by dst host:port).
	key := fmt.Sprintf("%s:%d", p.dstIP, p.dstPort)
	if seenConn[key] {
		return
	}
	seenConn[key] = true
	emit(TelemetryEvent{Type: "network", Details: fmt.Sprintf("%s -> %s:%d (ESTABLISHED)", p.proto, p.dstIP, p.dstPort)})
}

// decodedPacket is the subset of a captured packet the dashboard cares about.
type decodedPacket struct {
	proto   string
	dstIP   string
	dstPort int
	dnsName string
	payload []byte // L4 payload (TCP/UDP data) for HTTP/TLS inspection
}

// pcapStream is a stateful parser for a PCAP byte stream that arrives split
// across UDP datagrams. PCAPdroid's udp_exporter sends a standard PCAP file
// (global header once, then records) chunked into datagrams, so we buffer bytes
// and parse as many complete records as are available.
type pcapStream struct {
	buf        []byte
	haveGlobal bool
	le         bool
	linkType   uint32
}

// feed appends new bytes and returns any packets that became fully available.
func (s *pcapStream) feed(b []byte) []decodedPacket {
	s.buf = append(s.buf, b...)
	var out []decodedPacket

	// Parse the 24-byte global header once.
	if !s.haveGlobal {
		if len(s.buf) < 24 {
			return out
		}
		magic := binary.LittleEndian.Uint32(s.buf[0:4])
		switch magic {
		case 0xa1b2c3d4, 0xa1b23c4d: // little-endian writer (us/ns)
			s.le = true
		case 0xd4c3b2a1, 0x4d3cb2a1: // big-endian writer
			s.le = false
		default:
			// Not a PCAP stream we recognise — drop a byte and resync, but if it
			// never syncs just give up to avoid unbounded growth.
			if len(s.buf) > 1<<20 {
				s.buf = nil
			}
			return out
		}
		s.linkType = s.u32(s.buf[20:24])
		s.buf = s.buf[24:]
		s.haveGlobal = true
	}

	// Parse records: 16-byte header + incl_len bytes of packet.
	for {
		if len(s.buf) < 16 {
			break
		}
		inclLen := s.u32(s.buf[8:12])
		if inclLen == 0 || inclLen > 262144 { // sanity bound
			s.buf = nil // corrupt; reset
			break
		}
		if len(s.buf) < 16+int(inclLen) {
			break // wait for the rest
		}
		pktData := s.buf[16 : 16+int(inclLen)]
		if p, ok := decodeLinkPacket(pktData, s.linkType); ok {
			out = append(out, p)
		}
		s.buf = s.buf[16+int(inclLen):]
	}
	return out
}

func (s *pcapStream) u32(b []byte) uint32 {
	if s.le {
		return binary.LittleEndian.Uint32(b)
	}
	return binary.BigEndian.Uint32(b)
}

// decodeLinkPacket strips the link layer then decodes the IP/transport headers.
func decodeLinkPacket(data []byte, linkType uint32) (decodedPacket, bool) {
	var ip []byte
	switch linkType {
	case 1: // LINKTYPE_ETHERNET
		if len(data) < 14 {
			return decodedPacket{}, false
		}
		ethType := binary.BigEndian.Uint16(data[12:14])
		if ethType != 0x0800 && ethType != 0x86DD {
			return decodedPacket{}, false
		}
		ip = data[14:]
	case 113: // LINKTYPE_LINUX_SLL
		if len(data) < 16 {
			return decodedPacket{}, false
		}
		ip = data[16:]
	case 0: // LINKTYPE_NULL
		if len(data) < 4 {
			return decodedPacket{}, false
		}
		ip = data[4:]
	default: // LINKTYPE_RAW (101) and anything else: assume raw IP
		ip = data
	}
	return decodeIPPacket(ip)
}

// decodeIPPacket decodes IPv4/IPv6 + TCP/UDP and, for DNS, the queried name.
func decodeIPPacket(ip []byte) (decodedPacket, bool) {
	if len(ip) < 1 {
		return decodedPacket{}, false
	}
	version := ip[0] >> 4
	var proto byte
	var dstIP net.IP
	var l4 []byte

	switch version {
	case 4:
		if len(ip) < 20 {
			return decodedPacket{}, false
		}
		ihl := int(ip[0]&0x0F) * 4
		if ihl < 20 || len(ip) < ihl {
			return decodedPacket{}, false
		}
		proto = ip[9]
		dstIP = net.IP(ip[16:20])
		l4 = ip[ihl:]
	case 6:
		if len(ip) < 40 {
			return decodedPacket{}, false
		}
		proto = ip[6] // next header (no ext-header chain handling — best effort)
		dstIP = net.IP(ip[24:40])
		l4 = ip[40:]
	default:
		return decodedPacket{}, false
	}

	p := decodedPacket{dstIP: dstIP.String()}
	switch proto {
	case 6: // TCP
		if len(l4) < 20 {
			return decodedPacket{}, false
		}
		p.proto = "TCP"
		p.dstPort = int(binary.BigEndian.Uint16(l4[2:4]))
		dataOff := int(l4[12]>>4) * 4
		if dataOff >= 20 && dataOff <= len(l4) {
			p.payload = l4[dataOff:]
		}
	case 17: // UDP
		if len(l4) < 8 {
			return decodedPacket{}, false
		}
		p.proto = "UDP"
		p.dstPort = int(binary.BigEndian.Uint16(l4[2:4]))
		if p.dstPort == 53 {
			p.dnsName = parseDNSQName(l4[8:])
		}
	default:
		return decodedPacket{}, false
	}
	return p, true
}

// httpMethods are the request methods we recognise at the start of a TCP payload.
var httpMethods = []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "}

// parseHTTPRequest extracts the method, Host header and path from a plaintext
// HTTP request that starts at the beginning of a TCP payload. Returns empty
// method when the payload isn't an HTTP request.
func parseHTTPRequest(payload []byte) (method, host, path string) {
	if len(payload) < 16 {
		return "", "", ""
	}
	head := payload
	if len(head) > 4096 {
		head = head[:4096]
	}
	s := string(head)
	matched := ""
	for _, m := range httpMethods {
		if strings.HasPrefix(s, m) {
			matched = strings.TrimSpace(m)
			break
		}
	}
	if matched == "" {
		return "", "", ""
	}
	// Request line: "<METHOD> <path> HTTP/1.x"
	lineEnd := strings.Index(s, "\r\n")
	if lineEnd < 0 {
		return "", "", ""
	}
	parts := strings.SplitN(s[:lineEnd], " ", 3)
	if len(parts) < 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return "", "", ""
	}
	path = parts[1]
	// Host header (case-insensitive).
	for _, ln := range strings.Split(s, "\r\n") {
		if len(ln) >= 5 && strings.EqualFold(ln[:5], "host:") {
			host = strings.TrimSpace(ln[5:])
			break
		}
	}
	return matched, host, path
}

// parseTLSSNI extracts the server_name from a TLS ClientHello at the start of a
// TCP payload. Returns "" when the payload isn't a ClientHello or has no SNI.
func parseTLSSNI(payload []byte) string {
	// TLS record: type(1)=0x16 handshake, version(2), length(2).
	if len(payload) < 5 || payload[0] != 0x16 {
		return ""
	}
	rec := payload[5:]
	// Handshake: type(1)=0x01 ClientHello, length(3).
	if len(rec) < 4 || rec[0] != 0x01 {
		return ""
	}
	b := rec[4:]
	// client_version(2) + random(32)
	if len(b) < 34 {
		return ""
	}
	b = b[34:]
	// session_id
	if len(b) < 1 {
		return ""
	}
	sidLen := int(b[0])
	b = b[1:]
	if len(b) < sidLen {
		return ""
	}
	b = b[sidLen:]
	// cipher_suites
	if len(b) < 2 {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	if len(b) < csLen {
		return ""
	}
	b = b[csLen:]
	// compression_methods
	if len(b) < 1 {
		return ""
	}
	cmLen := int(b[0])
	b = b[1:]
	if len(b) < cmLen {
		return ""
	}
	b = b[cmLen:]
	// extensions
	if len(b) < 2 {
		return ""
	}
	extTotal := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	if len(b) > extTotal {
		b = b[:extTotal]
	}
	for len(b) >= 4 {
		extType := binary.BigEndian.Uint16(b[0:2])
		extLen := int(binary.BigEndian.Uint16(b[2:4]))
		b = b[4:]
		if len(b) < extLen {
			return ""
		}
		ext := b[:extLen]
		b = b[extLen:]
		if extType != 0x0000 { // server_name
			continue
		}
		// server_name_list(2) then name_type(1)=0 + name_len(2) + name
		if len(ext) < 5 {
			return ""
		}
		nameLen := int(binary.BigEndian.Uint16(ext[3:5]))
		if len(ext) < 5+nameLen {
			return ""
		}
		return string(ext[5 : 5+nameLen])
	}
	return ""
}

// parseDNSQName extracts the first question name from a DNS message payload.
func parseDNSQName(dns []byte) string {
	if len(dns) < 13 { // 12-byte header + at least 1 label byte
		return ""
	}
	var sb strings.Builder
	i := 12 // skip DNS header
	for i < len(dns) {
		l := int(dns[i])
		if l == 0 {
			break
		}
		if l&0xC0 != 0 { // compression pointer — shouldn't appear in a question
			return ""
		}
		i++
		if i+l > len(dns) {
			return ""
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(dns[i : i+l])
		i += l
	}
	name := sb.String()
	if len(name) > 253 {
		return ""
	}
	return name
}

// hostLANIP returns the host's primary non-loopback IPv4 address.
func hostLANIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() {
				return ip4.String()
			}
		}
	}
	return ""
}
