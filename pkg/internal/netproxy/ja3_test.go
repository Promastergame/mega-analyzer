package netproxy

import (
	"strings"
	"testing"
)

func TestJA3ParsesClientHello(t *testing.T) {
	// Minimal but valid TLS 1.2 ClientHello:
	// record(0x16,0x0301,len) handshake(0x01,len) version(0x0303) random(32)
	// session_id(0) cipher_suites(len=2: 0xc02f) compression(1:0x00)
	// extensions(len=0)
	ch := []byte{
		0x01,             // handshake type = ClientHello
		0x00, 0x00, 0x2d, // handshake length (placeholder, parser ignores)
		0x03, 0x03, // client_version TLS1.2
	}
	// 32-byte random
	ch = append(ch, make([]byte, 32)...)
	ch = append(ch, 0x00)       // session_id length
	ch = append(ch, 0x00, 0x02) // cipher_suites length
	ch = append(ch, 0xc0, 0x2f) // one cipher suite
	ch = append(ch, 0x01, 0x00) // compression methods: len 1, null
	ch = append(ch, 0x00, 0x00) // extensions length = 0

	record := append([]byte{0x16, 0x03, 0x01, 0x00, byte(len(ch))}, ch...)

	ja3, hash := JA3(record)
	if ja3 == "" || hash == "" {
		t.Fatalf("expected JA3, got ja3=%q hash=%q", ja3, hash)
	}
	// version 771 (0x0303), one cipher 49199 (0xc02f), no extensions/curves/fmts
	if !strings.HasPrefix(ja3, "771,49199,") {
		t.Errorf("unexpected ja3 = %q", ja3)
	}
	if len(hash) != 32 {
		t.Errorf("hash should be md5 hex (32 chars), got %d", len(hash))
	}
}

func TestJA3RejectsNonTLS(t *testing.T) {
	if _, hash := JA3([]byte("GET / HTTP/1.1\r\n")); hash != "" {
		t.Error("expected empty hash for non-TLS data")
	}
}

func TestRewriteHTTPBodyFixesContentLength(t *testing.T) {
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: 3\r\n\r\nabc")
	newBody := []byte("// hook\nabcdef")
	out := rewriteHTTPBody(resp, newBody)
	s := string(out)
	if !strings.Contains(s, "Content-Length: "+itoa(len(newBody))) {
		t.Errorf("content-length not updated: %q", s)
	}
	if !strings.HasSuffix(s, string(newBody)) {
		t.Errorf("body not replaced: %q", s)
	}
}

func TestRewriteHTTPBodyDropsChunked(t *testing.T) {
	resp := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
	out := rewriteHTTPBody(resp, []byte("hello"))
	if strings.Contains(strings.ToLower(string(out)), "transfer-encoding") {
		t.Error("chunked transfer-encoding should be dropped")
	}
	if !strings.Contains(string(out), "Content-Length: 5") {
		t.Error("content-length should be added")
	}
}

// itoa is a tiny local helper to avoid importing strconv in the test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
