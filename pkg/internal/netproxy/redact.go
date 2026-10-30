package netproxy

// headerRedactor masks sensitive HTTP headers (Authorization, Cookie, …) in a
// captured byte stream. Unlike a per-packet redactor, it is a stateful stream
// machine driven one direction of one connection at a time, so a header whose
// name and value straddle a TCP-segment boundary is still fully redacted — the
// previous per-packet implementation leaked any secret that spilled into the
// next Read.
//
// Correctness rests on two facts about HTTP framing:
//   - A header name ends at the first ':', and the names we care about are
//     short, so sensitivity is known the moment the colon arrives — never
//     needing the value.
//   - A header value ends at CRLF, so once a value is deemed sensitive it can
//     be dropped byte-by-byte until the newline, regardless of how the stream
//     is chunked.
//
// The body is passed through verbatim (never redacted): request/response
// framing (Content-Length, chunked, or connection-close for responses) is
// tracked so that "Cookie:"-looking text inside a body is not mistaken for a
// header. State lives entirely in the single writer goroutine, so no locking is
// needed.
type headerRedactor struct {
	// isResponse distinguishes the server→client stream (status lines, bodies
	// framed by close) from the client→server stream (request lines, no body
	// unless Content-Length/chunked says so).
	isResponse bool
	state      redactState

	decideBuf []byte // lowercased start-of-stream bytes, until HTTP is decided

	nameBuf   []byte // lowercased current header name
	nameTrunc bool   // name exceeded the cap (cannot be a sensitive header)
	curKind   redactKind
	valBuf    []byte // captured value bytes for Content-Length / Transfer-Encoding

	haveCL     bool
	contentLen int64
	chunked    bool
}

type redactState int

const (
	rsDeciding       redactState = iota // buffering start bytes to decide HTTP vs binary
	rsStartLine                         // HTTP confirmed; passing the request/status line
	rsHeaderName                        // at/inside a header name
	rsHeaderValue                       // passing a non-sensitive header value
	rsDrainValue                        // dropping a sensitive header value
	rsBody                              // passing Content-Length bytes of body
	rsBodyUntilClose                    // passing body until the stream closes
	rsPassthrough                       // not HTTP: everything passes unchanged
)

type redactKind int

const (
	kindOther redactKind = iota
	kindSensitive
	kindContentLength
	kindTransferEncoding
)

const (
	redactMaxDecide = 8  // longest start token is "options " / "OPTIONS "
	redactMaxName   = 64 // header names longer than this are never sensitive
	redactMaxVal    = 64 // enough to parse a Content-Length / find "chunked"
)

var sensitiveHeaderNames = [][]byte{
	[]byte("authorization"),
	[]byte("proxy-authorization"),
	[]byte("cookie"),
	[]byte("set-cookie"),
}

// httpStartCandidates are the lowercased tokens a stream must begin with to be
// treated as HTTP. Method tokens include the trailing space so "put"/"putx"
// paths don't false-match; responses begin with "http/".
var httpStartCandidates = [][]byte{
	[]byte("get "), []byte("post "), []byte("put "), []byte("patch "),
	[]byte("delete "), []byte("head "), []byte("options "), []byte("http/"),
}

// process returns the redacted form of in, advancing the machine's state. The
// output length may differ from the input (values are replaced with a shorter
// marker), which is fine for a capture log.
func (d *headerRedactor) process(in []byte) []byte {
	if len(in) == 0 {
		return in
	}
	out := make([]byte, 0, len(in)+16)
	for _, b := range in {
		d.feed(b, &out)
	}
	return out
}

func (d *headerRedactor) feed(b byte, out *[]byte) {
	if d.state == rsDeciding {
		// Start-line bytes are passed through in every case (HTTP start lines
		// are never redacted, and non-HTTP data passes verbatim), so emit
		// immediately — no buffering, nothing to lose on connection close.
		*out = append(*out, b)
		d.decideBuf = append(d.decideBuf, lowerASCII(b))
		switch d.decide() {
		case decideHTTP:
			d.decideBuf = nil
			if b == '\n' {
				// Single-token start line already complete.
				d.state = rsHeaderName
				d.resetLine()
			} else {
				d.state = rsStartLine
			}
		case decideNot:
			d.decideBuf = nil
			d.state = rsPassthrough
		}
		return
	}
	d.feedDecided(b, out)
}

func (d *headerRedactor) feedDecided(b byte, out *[]byte) {
	switch d.state {
	case rsStartLine:
		*out = append(*out, b)
		if b == '\n' {
			d.state = rsHeaderName
			d.resetLine()
		}

	case rsHeaderName:
		switch b {
		case '\n':
			*out = append(*out, b)
			if len(d.nameBuf) == 0 {
				d.endHeaders() // blank line: headers finished
			} else {
				d.resetLine() // header line without a colon; already passed through
			}
		case '\r':
			*out = append(*out, b) // keep CR, but it is not part of the name
		case ':':
			*out = append(*out, b)
			d.curKind = classifyHeader(d.nameBuf, d.nameTrunc)
			if d.curKind == kindSensitive {
				*out = append(*out, " <redacted>"...)
				d.state = rsDrainValue
			} else {
				d.valBuf = d.valBuf[:0]
				d.state = rsHeaderValue
			}
		default:
			*out = append(*out, b)
			if !d.nameTrunc {
				if len(d.nameBuf) < redactMaxName {
					d.nameBuf = append(d.nameBuf, lowerASCII(b))
				} else {
					d.nameTrunc = true
				}
			}
		}

	case rsHeaderValue:
		*out = append(*out, b)
		if d.curKind == kindContentLength || d.curKind == kindTransferEncoding {
			if len(d.valBuf) < redactMaxVal {
				d.valBuf = append(d.valBuf, b)
			}
		}
		if b == '\n' {
			d.finishValue()
			d.state = rsHeaderName
			d.resetLine()
		}

	case rsDrainValue:
		if b == '\n' {
			// The original CR/LF and value bytes were dropped; re-emit a clean CRLF.
			*out = append(*out, '\r', '\n')
			d.state = rsHeaderName
			d.resetLine()
		}
		// otherwise drop the byte (it is part of the secret)

	case rsBody:
		*out = append(*out, b)
		d.contentLen--
		if d.contentLen <= 0 {
			d.state = rsStartLine
			d.resetMessage()
		}

	case rsBodyUntilClose:
		*out = append(*out, b)

	case rsPassthrough:
		*out = append(*out, b)
	}
}

// endHeaders selects the body framing once the blank line after the headers is
// seen. Framing rules keep pipelined (keep-alive) messages redactable: a
// bodyless request returns straight to the next start line rather than swallowing
// it as body.
func (d *headerRedactor) endHeaders() {
	switch {
	case d.chunked:
		// Proper chunk parsing is out of scope; passing the rest through until
		// close never leaks (bodies are not redacted) and never corrupts a body.
		d.state = rsBodyUntilClose
	case d.haveCL:
		if d.contentLen <= 0 {
			d.state = rsStartLine
			d.resetMessage()
		} else {
			// Keep contentLen for the countdown; clear the rest of the per-message
			// state now so the next message starts clean.
			d.haveCL = false
			d.chunked = false
			d.resetLine()
			d.state = rsBody
		}
	default:
		if d.isResponse {
			d.state = rsBodyUntilClose // response body framed by connection close
		} else {
			d.state = rsStartLine // request with no body: next request follows
			d.resetMessage()
		}
	}
}

func (d *headerRedactor) finishValue() {
	switch d.curKind {
	case kindContentLength:
		if n, ok := parseContentLength(d.valBuf); ok {
			d.haveCL = true
			d.contentLen = n
		}
	case kindTransferEncoding:
		if containsFold(d.valBuf, []byte("chunked")) {
			d.chunked = true
		}
	}
}

func (d *headerRedactor) resetLine() {
	d.nameBuf = d.nameBuf[:0]
	d.nameTrunc = false
	d.curKind = kindOther
	d.valBuf = d.valBuf[:0]
}

func (d *headerRedactor) resetMessage() {
	d.haveCL = false
	d.contentLen = 0
	d.chunked = false
	d.resetLine()
}

type decideResult int

const (
	decideMore decideResult = iota
	decideHTTP
	decideNot
)

// decide classifies the accumulated (lowercased) start bytes as HTTP, not-HTTP,
// or needs-more-bytes.
func (d *headerRedactor) decide() decideResult {
	buf := d.decideBuf
	possible := false
	for _, cand := range httpStartCandidates {
		switch {
		case len(buf) >= len(cand):
			if bytesEqualASCII(buf[:len(cand)], cand) {
				return decideHTTP
			}
		default:
			if bytesEqualASCII(buf, cand[:len(buf)]) {
				possible = true
			}
		}
	}
	if possible && len(buf) < redactMaxDecide {
		return decideMore
	}
	return decideNot
}

// classifyHeader maps a lowercased header name to its redaction kind. A name
// that overflowed the cap can't be one of the (short) sensitive names.
func classifyHeader(name []byte, truncated bool) redactKind {
	if truncated {
		return kindOther
	}
	for _, s := range sensitiveHeaderNames {
		if bytesEqualASCII(name, s) {
			return kindSensitive
		}
	}
	if bytesEqualASCII(name, []byte("content-length")) {
		return kindContentLength
	}
	if bytesEqualASCII(name, []byte("transfer-encoding")) {
		return kindTransferEncoding
	}
	return kindOther
}

// parseContentLength extracts the leading unsigned integer from a header value,
// tolerating surrounding whitespace and the trailing CR. Returns false if no
// digits are present or the value overflows.
func parseContentLength(val []byte) (int64, bool) {
	i := 0
	for i < len(val) && (val[i] == ' ' || val[i] == '\t') {
		i++
	}
	var n int64
	seen := false
	for ; i < len(val); i++ {
		c := val[i]
		if c < '0' || c > '9' {
			break
		}
		seen = true
		n = n*10 + int64(c-'0')
		if n > (1<<40) || n < 0 { // absurd length: bail rather than trust it
			return 0, false
		}
	}
	if !seen {
		return 0, false
	}
	return n, true
}

func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// bytesEqualASCII compares two byte slices for exact byte equality. Both sides
// are expected to already be lowercased where case-insensitivity is desired.
func bytesEqualASCII(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
