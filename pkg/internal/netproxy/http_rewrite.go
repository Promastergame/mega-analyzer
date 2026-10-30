package netproxy

import (
	"bytes"
	"strconv"
	"strings"
)

// rewriteHTTPBody replaces the body of a raw HTTP response (headers + CRLFCRLF
// + body) and fixes framing so the message stays valid after the body length
// changes.
//
// The previous BundleInjector mutated the JS body but left the original
// Content-Length untouched, which truncates the response or hangs the client.
// This function:
//   - drops any Transfer-Encoding: chunked header (we send a full body),
//   - sets an accurate Content-Length,
//   - returns the reassembled response.
//
// If the input does not look like an HTTP response with a header/body split,
// the original data is returned unchanged.
func rewriteHTTPBody(resp []byte, newBody []byte) []byte {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(resp, sep)
	if idx < 0 {
		return resp
	}
	headerBlock := resp[:idx]

	lines := strings.Split(string(headerBlock), "\r\n")
	if len(lines) == 0 {
		return resp
	}

	out := make([]string, 0, len(lines)+1)
	out = append(out, lines[0]) // status line
	hasCL := false
	for _, line := range lines[1:] {
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "content-length:"):
			out = append(out, "Content-Length: "+strconv.Itoa(len(newBody)))
			hasCL = true
		case strings.HasPrefix(lower, "transfer-encoding:"):
			// Drop chunked framing; we emit a complete body.
		default:
			out = append(out, line)
		}
	}
	if !hasCL {
		out = append(out, "Content-Length: "+strconv.Itoa(len(newBody)))
	}

	var buf bytes.Buffer
	buf.WriteString(strings.Join(out, "\r\n"))
	buf.WriteString("\r\n\r\n")
	buf.Write(newBody)
	return buf.Bytes()
}
