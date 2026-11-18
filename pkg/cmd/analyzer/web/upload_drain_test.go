package web

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

// eofCountingReader records whether the request body was read to EOF, which is
// how a drained rejection differs from one that abandons the body mid-upload.
type eofCountingReader struct {
	src     io.Reader
	readAll bool
}

func (c *eofCountingReader) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	if err == io.EOF {
		c.readAll = true
	}
	return n, err
}

// oversizedUpload builds a multipart /api/scan request with a body big enough
// that Go's own post-handler drain (256 KiB) would not mask a missing explicit
// drain. Pair it with a small MEGA_ANALYZER_MAX_UPLOAD_BYTES to force the
// pre-read 413 rejection.
func oversizedUpload(t *testing.T) (*http.Request, *eofCountingReader) {
	t.Helper()
	var body bytes.Buffer
	m := multipart.NewWriter(&body)
	if err := m.WriteField("mode", "bogus"); err != nil {
		t.Fatal(err)
	}
	f, err := m.CreateFormFile("file", "big.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(make([]byte, 512<<10)); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	src := &eofCountingReader{src: bytes.NewReader(body.Bytes())}
	r := httptest.NewRequest(http.MethodPost, "/api/scan", src)
	r.Header.Set("Content-Type", m.FormDataContentType())
	r.ContentLength = int64(body.Len())
	return r, src
}

// A rejected upload must be drained before the error response: browsers that
// are still sending when the connection closes under them report a network
// failure ("Failed to fetch") instead of the server's 413/429 message.
func TestRejectedUploadDrainsBodyBeforeError(t *testing.T) {
	t.Setenv("MEGA_ANALYZER_MAX_UPLOAD_BYTES", "1024")
	s, _ := workspaceServer(t)
	h := errorDrainHandler(http.HandlerFunc(s.handleScan))
	r, src := oversizedUpload(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d %s, want 413", rr.Code, rr.Body.String())
	}
	if !src.readAll {
		t.Fatal("rejected upload body was not drained; browsers would show 'Failed to fetch'")
	}
}

// Successful and after-read error responses must not double-drain or stall:
// the wrapper passes them through once the handler has consumed the body.
func TestScanErrorAfterFullReadStaysFast(t *testing.T) {
	s, _ := workspaceServer(t)
	h := errorDrainHandler(http.HandlerFunc(s.handleScan))
	r, src := oversizedUpload(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d %s, want 400", rr.Code, rr.Body.String())
	}
	if !src.readAll {
		t.Fatal("body should have been consumed by the multipart reader itself")
	}
}

// The UI pre-flight check tracks the server's effective upload cap.
func TestMetaExposesUploadLimit(t *testing.T) {
	t.Setenv("MEGA_ANALYZER_MAX_UPLOAD_BYTES", "1234567")
	s, _ := workspaceServer(t)
	rr := httptest.NewRecorder()
	s.handleMeta(rr, httptest.NewRequest(http.MethodGet, "/api/meta", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("meta status = %d", rr.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if got, ok := m["uploadMaxBytes"].(float64); !ok || int64(got) != 1234567 {
		t.Fatalf("uploadMaxBytes = %v, want 1234567", m["uploadMaxBytes"])
	}
	if _, ok := m["sastRules"]; !ok {
		t.Fatal("meta lost sastRules badge count")
	}
}
