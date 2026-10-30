package netproxy

import (
	"strconv"
	"strings"
	"testing"
)

// feedChunks pushes payload through the redactor split at the given byte
// offsets, simulating TCP segmentation, and returns the concatenated output.
func feedChunks(d *headerRedactor, payload string, splits ...int) string {
	var chunks [][]byte
	prev := 0
	for _, s := range splits {
		if s <= prev || s > len(payload) {
			continue
		}
		chunks = append(chunks, []byte(payload[prev:s]))
		prev = s
	}
	chunks = append(chunks, []byte(payload[prev:]))

	var out strings.Builder
	for _, c := range chunks {
		out.Write(d.process(c))
	}
	return out.String()
}

// TestRedact_HeaderSplitAcrossSegments is the regression test for the leak: an
// Authorization header whose value lands in a later TCP segment than its name
// must still be fully redacted.
func TestRedact_HeaderSplitAcrossSegments(t *testing.T) {
	payload := "GET / HTTP/1.1\r\nAuthorization: Bearer super-secret-token\r\nX-Test: ok\r\n\r\n"

	// Split right in the middle of "Authorization: Bearer super-secret-token".
	idx := strings.Index(payload, "Bearer") + 3 // mid-value
	nameColon := strings.Index(payload, "Authorization:") + 5

	for _, split := range []int{nameColon, idx, idx + 10} {
		d := &headerRedactor{isResponse: false}
		out := feedChunks(d, payload, split)
		if strings.Contains(out, "super-secret-token") || strings.Contains(out, "Bearer") {
			t.Fatalf("split at %d leaked the secret: %q", split, out)
		}
		if !strings.Contains(out, "Authorization: <redacted>") {
			t.Fatalf("split at %d: redaction marker missing: %q", split, out)
		}
		if !strings.Contains(out, "X-Test: ok") {
			t.Fatalf("split at %d: trailing header lost: %q", split, out)
		}
	}
}

// TestRedact_ByteAtATime is the maximally adversarial segmentation: every byte
// arrives in its own Read. Nothing may leak.
func TestRedact_ByteAtATime(t *testing.T) {
	payload := "POST /login HTTP/1.1\r\n" +
		"Cookie: session=abc123def\r\n" +
		"Proxy-Authorization: Basic Zm9vOmJhcg==\r\n" +
		"Content-Length: 4\r\n\r\nbody"

	d := &headerRedactor{isResponse: false}
	var out strings.Builder
	for i := 0; i < len(payload); i++ {
		out.Write(d.process([]byte{payload[i]}))
	}
	got := out.String()

	for _, secret := range []string{"session=abc123def", "Zm9vOmJhcg==", "Basic"} {
		if strings.Contains(got, secret) {
			t.Fatalf("byte-at-a-time leaked %q: %q", secret, got)
		}
	}
	if !strings.Contains(got, "Cookie: <redacted>") ||
		!strings.Contains(got, "Proxy-Authorization: <redacted>") {
		t.Fatalf("redaction markers missing: %q", got)
	}
	// Body must survive verbatim.
	if !strings.HasSuffix(got, "body") {
		t.Fatalf("body corrupted: %q", got)
	}
}

// TestRedact_ResponseSetCookie covers the server→client direction: a status
// line (not a request line) followed by Set-Cookie.
func TestRedact_ResponseSetCookie(t *testing.T) {
	payload := "HTTP/1.1 200 OK\r\nSet-Cookie: sid=topsecret; HttpOnly\r\nContent-Type: text/html\r\n\r\n<html>"
	d := &headerRedactor{isResponse: true}
	out := feedChunks(d, payload, 20, 35)
	if strings.Contains(out, "topsecret") {
		t.Fatalf("Set-Cookie value leaked: %q", out)
	}
	if !strings.Contains(out, "Set-Cookie: <redacted>") {
		t.Fatalf("Set-Cookie not redacted: %q", out)
	}
	if !strings.Contains(out, "<html>") {
		t.Fatalf("response body lost: %q", out)
	}
}

// TestRedact_BodyCookieNotRedacted ensures cookie-looking text in a body is left
// untouched even when the body is split across segments.
func TestRedact_BodyCookieNotRedacted(t *testing.T) {
	body := "Authorization: not-a-real-header-in-body"
	payload := "POST / HTTP/1.1\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	d := &headerRedactor{isResponse: false}
	out := feedChunks(d, payload, 25, 40, 50)
	if !strings.Contains(out, body) {
		t.Fatalf("body was modified: %q", out)
	}
}

// TestRedact_PipelinedRequests verifies state resets between keep-alive requests
// so a secret in the second request is still redacted.
func TestRedact_PipelinedRequests(t *testing.T) {
	first := "GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
	second := "GET /b HTTP/1.1\r\nAuthorization: Bearer sec2\r\n\r\n"
	d := &headerRedactor{isResponse: false}
	out := feedChunks(d, first+second, len(first)-3, len(first)+10)
	if strings.Contains(out, "sec2") {
		t.Fatalf("second request's secret leaked: %q", out)
	}
	if strings.Count(out, "GET /") != 2 {
		t.Fatalf("expected both request lines preserved: %q", out)
	}
}

// TestRedact_NonHTTPPassthrough verifies binary traffic is emitted verbatim and
// nothing is buffered/lost, even split mid-stream.
func TestRedact_NonHTTPPassthrough(t *testing.T) {
	payload := "\x00\x01\x02\x03\x04\x05rubbish:not-http\xff\xfe"
	d := &headerRedactor{isResponse: false}
	out := feedChunks(d, payload, 2, 4, 8)
	if out != payload {
		t.Fatalf("binary passthrough altered stream:\n got %q\nwant %q", out, payload)
	}
}

func TestParseContentLength(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{" 42\r", 42, true},
		{"0", 0, true},
		{"  123", 123, true},
		{"abc", 0, false},
		{"", 0, false},
		{"99999999999999999999", 0, false}, // overflow guard
	}
	for _, tc := range cases {
		got, ok := parseContentLength([]byte(tc.in))
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("parseContentLength(%q) = (%d,%v), want (%d,%v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
