// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"bytes"
	"regexp"
	"time"
)

// maxJobLines bounds the in-memory log buffer for a single job. Older lines are
// trimmed from the front; readers track an absolute cursor so trimming can
// never desynchronise them.
const maxJobLines = 32768

// Bound retained text and individual SSE payloads independently of line count.
const maxJobLogBytes = 2 << 20
const maxJobLineBytes = 8 << 10

// webUIHeartbeat is how often an idle SSE stream emits a comment frame. Without
// it, browsers and reverse proxies silently drop a connection that stays quiet
// during a long analysis phase.
const webUIHeartbeat = 15 * time.Second

// progressThrottle bounds how often an in-place progress redraw is forwarded to
// the browser. A native scan repaints its bar thousands of times per second;
// without throttling the log is unreadable and the SSE stream is saturated.
const progressThrottle = 200 * time.Millisecond

// progressEventName is the SSE event name carrying an in-place progress redraw.
// The browser half of the feature listens for exactly this name; nothing links
// the two at compile time, so TestProgressStreamHalvesStayInSync pins them.
const progressEventName = "progress"

// progressLineRE matches an in-place progress redraw such as
// "99% [20821/21000] scan_and_analyze ▓▓▓". It deliberately requires a bracketed
// counter or a run of bar glyphs rather than a bare percentage, so ordinary log
// lines that merely mention a percentage are never collapsed.
var progressLineRE = regexp.MustCompile(`\[\d+/\d+\]|[█▓▒░#=]{4,}`)

func isProgressLine(s string) bool { return progressLineRE.MatchString(s) }

// scanLinesAnyBreak splits on \n, \r, or \r\n.
//
// Progress bars end each redraw with a carriage return and only emit a newline
// when they finish. With the stock line splitter every redraw of a long scan
// accumulated into a single unbounded token that reached the browser all at
// once at the very end — which is why the log stayed empty during the run and
// then dumped thousands of concatenated redraws.
func scanLinesAnyBreak(data []byte, atEOF bool) (int, []byte, error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		if data[i] == '\r' && i+1 < len(data) && data[i+1] == '\n' {
			return i + 2, data[:i], nil
		}
		return i + 1, data[:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }
