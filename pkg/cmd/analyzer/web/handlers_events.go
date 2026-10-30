// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// handleEvents serves /api/events/.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/events/")
	jobsMu.Lock()
	job, ok := jobs[id]
	jobsMu.Unlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, canFlush := w.(http.Flusher)
	flush := func() {
		if canFlush {
			flusher.Flush()
		}
	}

	// Resume support: the browser replays Last-Event-ID after a dropped
	// connection, so a reconnect continues from where it left off instead of
	// re-sending (and re-rendering) the entire log.
	cursor := 0
	if last := r.Header.Get("Last-Event-ID"); last != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(last)); err == nil && n >= 0 {
			cursor = n
		}
	} else if q := r.URL.Query().Get("from"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n >= 0 {
			cursor = n
		}
	}

	// Ask the browser to back off politely instead of hammering on reconnect.
	fmt.Fprint(w, "retry: 2000\n\n")
	flush()

	ctx := r.Context()
	lastState := ""
	for {
		lines, next, done, code, wait := job.read(cursor)
		// read may advance a stale cursor past trimmed lines. IDs must use the
		// absolute position of the returned batch, including progress events.
		first := next - len(lines)
		if first > cursor {
			fmt.Fprintf(w, "event: gap\ndata: {\"from\":%d,\"to\":%d}\n\n", cursor, first)
			cursor = first
			flush()
		}
		if state := job.status(); state != lastState {
			fmt.Fprintf(w, "event: state\ndata: %s\n\n", state)
			lastState = state
			flush()
		}
		for i, line := range lines {
			b, _ := json.Marshal(line)
			payload := string(b[1 : len(b)-1])
			// Progress redraws go out under their own event name so the
			// browser can overwrite the previous one in place instead of
			// appending. They keep their place in the same id sequence, so
			// resuming from Last-Event-ID still works.
			if isProgressLine(line) {
				fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n",
					first+i+1, progressEventName, payload)
				continue
			}
			fmt.Fprintf(w, "id: %d\ndata: %s\n\n", first+i+1, payload)
		}
		if len(lines) > 0 {
			cursor = next
			flush()
		}
		if done {
			fmt.Fprintf(w, "event: done\ndata: %d\n\n", code)
			flush()
			return
		}
		select {
		case <-wait:
		case <-ctx.Done():
			return
		case <-time.After(webUIHeartbeat):
			// Comment frame: keeps browsers and reverse proxies from culling
			// the stream during long silent phases (unpacking, decompiling).
			fmt.Fprint(w, ": ping\n\n")
			flush()
		}
	}
}
