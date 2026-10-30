package vulnscan

import (
	"net"
	"net/http"
	"testing"
)

// ─── isPrivateIP ──────────────────────────────────────────────────────────────

func TestIsPrivateIP_Loopback(t *testing.T) {
	if !isPrivateIP(net.ParseIP("127.0.0.1")) {
		t.Error("127.0.0.1 should be private")
	}
}

func TestIsPrivateIP_IPv6Loopback(t *testing.T) {
	if !isPrivateIP(net.ParseIP("::1")) {
		t.Error("::1 should be private")
	}
}

func TestIsPrivateIP_RFC1918_10(t *testing.T) {
	if !isPrivateIP(net.ParseIP("10.0.0.1")) {
		t.Error("10.0.0.1 should be private")
	}
}

func TestIsPrivateIP_RFC1918_192(t *testing.T) {
	if !isPrivateIP(net.ParseIP("192.168.1.1")) {
		t.Error("192.168.1.1 should be private")
	}
}

func TestIsPrivateIP_RFC1918_172(t *testing.T) {
	if !isPrivateIP(net.ParseIP("172.16.0.1")) {
		t.Error("172.16.0.1 should be private")
	}
}

func TestIsPrivateIP_Public(t *testing.T) {
	if isPrivateIP(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 should NOT be private")
	}
}

func TestIsPrivateIP_CGNAT(t *testing.T) {
	if !isPrivateIP(net.ParseIP("100.64.0.1")) {
		t.Error("100.64.0.1 (CGNAT) should be private")
	}
}

func TestIsPrivateIP_LinkLocal(t *testing.T) {
	if !isPrivateIP(net.ParseIP("169.254.1.1")) {
		t.Error("169.254.1.1 link-local should be private")
	}
}

// ─── MutateJSON ───────────────────────────────────────────────────────────────

func TestMutateJSON_ValidBody(t *testing.T) {
	body := []byte(`{"username":"admin","password":"pass"}`)
	results, err := MutateJSON(body, "<script>xss</script>")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Error("expected at least one mutation")
	}
}

func TestMutateJSON_InvalidJSON(t *testing.T) {
	_, err := MutateJSON([]byte("not json"), "payload")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestMutateJSON_EmptyBody(t *testing.T) {
	_, err := MutateJSON([]byte("{}"), "xss")
	if err != nil {
		t.Errorf("unexpected error for empty object: %v", err)
	}
}

func TestMutateJSON_Nil(t *testing.T) {
	_, err := MutateJSON(nil, "payload")
	if err == nil {
		t.Error("expected error for nil body")
	}
}

// ─── CurlRequest methods ──────────────────────────────────────────────────────

func TestToHTTPRequest_Basic(t *testing.T) {
	cr := &CurlRequest{
		Method: "GET",
		URL:    "https://example.com/api",
		Headers: map[string]string{
			"Authorization": "Bearer token123",
		},
	}
	req, err := cr.ToHTTPRequest()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "GET" {
		t.Errorf("method: %q", req.Method)
	}
	if req.Header.Get("Authorization") != "Bearer token123" {
		t.Error("authorization header not set")
	}
}

func TestToHTTPRequest_WithBody(t *testing.T) {
	cr := &CurlRequest{
		Method:  "POST",
		URL:     "https://example.com/api",
		Headers: map[string]string{},
		Body:    `{"key":"value"}`,
	}
	req, err := cr.ToHTTPRequest()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Body == nil {
		t.Error("expected non-nil body")
	}
}

func TestToHTTPRequest_InvalidURL(t *testing.T) {
	cr := &CurlRequest{
		Method:  "GET",
		URL:     "://bad-url",
		Headers: map[string]string{},
	}
	_, err := cr.ToHTTPRequest()
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestBuildHTTPClient_NotInsecure(t *testing.T) {
	cr := &CurlRequest{Insecure: false}
	base := &http.Client{}
	got := cr.BuildHTTPClient(base)
	if got != base {
		t.Error("non-insecure should return same client")
	}
}

func TestBuildHTTPClient_Insecure(t *testing.T) {
	cr := &CurlRequest{Insecure: true}
	base := &http.Client{}
	got := cr.BuildHTTPClient(base)
	if got == base {
		t.Error("insecure should return new client")
	}
	if got == nil {
		t.Error("expected non-nil client")
	}
}

// ─── ParseRawHTTPRequest ──────────────────────────────────────────────────────

func TestParseRawHTTPRequest_Valid(t *testing.T) {
	raw := "GET /api/v1/users HTTP/1.1\r\nHost: example.com\r\n\r\n"
	req, err := ParseRawHTTPRequest(raw, "https")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "GET" {
		t.Errorf("expected GET, got %q", req.Method)
	}
}

func TestParseRawHTTPRequest_Post(t *testing.T) {
	raw := "POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=1234"
	req, err := ParseRawHTTPRequest(raw, "https")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST, got %q", req.Method)
	}
}

func TestParseRawHTTPRequest_MissingHost(t *testing.T) {
	raw := "GET /api HTTP/1.1\r\n\r\n"
	_, err := ParseRawHTTPRequest(raw, "https")
	if err == nil {
		t.Error("expected error for missing Host header")
	}
}

func TestParseRawHTTPRequest_InvalidInput(t *testing.T) {
	_, err := ParseRawHTTPRequest("not a request", "https")
	if err == nil {
		t.Error("expected error for invalid input")
	}
}

func TestParseRawHTTPRequest_DefaultScheme(t *testing.T) {
	raw := "GET /path HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
	req, err := ParseRawHTTPRequest(raw, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = req
}
