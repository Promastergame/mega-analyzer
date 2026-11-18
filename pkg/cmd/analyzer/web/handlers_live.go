// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// handleLiveStatus serves /api/live/status.
// /api/live/status → is an emulator/device connected and booted?
func (s *Server) handleLiveStatus(w http.ResponseWriter, r *http.Request) {
	serial := RequestDeviceSerial(r)
	booted := false
	screenOn := true
	if serial != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		out, _ := exec.CommandContext(ctx, liveADB(), "-s", serial, "shell", "getprop", "sys.boot_completed").Output()
		booted = strings.TrimSpace(string(out)) == "1"
		// Screen state: a locked/sleeping device produces a black or stale
		// frame, so the dashboard shows a "locked" overlay instead.
		if booted {
			po, _ := exec.CommandContext(ctx, liveADB(), "-s", serial, "shell", "dumpsys", "power").Output()
			ps := string(po)
			if strings.Contains(ps, "Display Power: state=OFF") ||
				strings.Contains(ps, "mWakefulness=Asleep") ||
				strings.Contains(ps, "mWakefulness=Dozing") ||
				strings.Contains(ps, "mScreenState=OFF") {
				screenOn = false
			}
		}
	}
	// scrcpy-server availability decides whether the browser uses smooth
	// H.264 (WebCodecs) or the screenshot fallback.
	scrcpyOK := findScrcpyServer() != ""
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"serial": serial, "booted": booted, "screen": screenOn, "scrcpy": scrcpyOK,
	})
}

// handleLiveScreen serves /api/live/screen.
// /api/live/screen → one PNG frame grabbed from the device right now.
func (s *Server) handleLiveScreen(w http.ResponseWriter, r *http.Request) {
	serial := RequestDeviceSerial(r)
	if serial == "" {
		http.Error(w, "no device", http.StatusNotFound)
		return
	}
	out, err := captureLivePNG(r.Context(), liveADB(), serial)
	if err != nil || len(out) == 0 {
		http.Error(w, "screencap failed", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(out)
}

// handleLiveStream serves /api/live/stream.
// /api/live/stream → continuous MJPEG-style push of frames using a single
// persistent adb shell loop, with individual captures if that loop fails.
func (s *Server) handleLiveStream(w http.ResponseWriter, r *http.Request) {
	serial := RequestDeviceSerial(r)
	if serial == "" {
		http.Error(w, "no device", http.StatusNotFound)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	adb := liveADB()
	const boundary = "megaframe"
	w.Header().Set("Content-Type", "multipart/x-mixed-replace; boundary="+boundary)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "close")
	ctx := r.Context()

	sent := false
	emitFrame := func(frame []byte) error {
		if _, err := fmt.Fprintf(w, "--%s\r\nContent-Type: image/png\r\nContent-Length: %d\r\n\r\n", boundary, len(frame)); err != nil {
			return err
		}
		if _, err := w.Write(frame); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "\r\n"); err != nil {
			return err
		}
		sent = true
		flusher.Flush()
		return nil
	}
	if err := streamLivePNGs(ctx, adb, serial, emitFrame); err == nil || ctx.Err() != nil {
		return
	}
	for ctx.Err() == nil {
		frame, err := captureLivePNG(ctx, adb, serial)
		if err != nil {
			if !sent && ctx.Err() == nil {
				http.Error(w, "screencap failed", http.StatusServiceUnavailable)
			}
			return
		}
		if err := emitFrame(frame); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(150 * time.Millisecond):
		}
	}
}

// handleLiveInput serves /api/live/input.
// /api/live/input → inject a tap (normalized 0..1) or a key into the device.
func (s *Server) handleLiveInput(w http.ResponseWriter, r *http.Request) {
	// Injects taps/keys into the attached device — state changing.
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	serial := RequestDeviceSerial(r)
	if serial == "" {
		httpError(w, r, http.StatusNotFound, "No device is attached.")
		return
	}
	var in struct {
		Type string  `json:"type"`
		NX   float64 `json:"nx"`
		NY   float64 `json:"ny"`
		NX2  float64 `json:"nx2"` // swipe end (normalized)
		NY2  float64 `json:"ny2"`
		Dur  int     `json:"dur"` // duration ms (swipe/longpress)
		Key  string  `json:"key"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	adb := liveADB()
	// Fire-and-forget: respond immediately so the browser doesn't block on adb latency.
	switch in.Type {
	case "tap":
		dw, dh := liveDeviceSize(adb, serial)
		x := int(in.NX * float64(dw))
		y := int(in.NY * float64(dh))
		liveEnqueueInput(adb, serial, "input", "tap", strconv.Itoa(x), strconv.Itoa(y))
	case "longpress":
		dw, dh := liveDeviceSize(adb, serial)
		x := int(in.NX * float64(dw))
		y := int(in.NY * float64(dh))
		dur := in.Dur
		if dur <= 0 {
			dur = 700
		}
		dur = clampLiveDur(dur)
		// Long-press = swipe from/to same point with duration
		liveEnqueueInput(adb, serial, "input", "swipe",
			strconv.Itoa(x), strconv.Itoa(y), strconv.Itoa(x), strconv.Itoa(y), strconv.Itoa(dur))
	case "swipe":
		dw, dh := liveDeviceSize(adb, serial)
		x1 := int(in.NX * float64(dw))
		y1 := int(in.NY * float64(dh))
		x2 := int(in.NX2 * float64(dw))
		y2 := int(in.NY2 * float64(dh))
		dur := in.Dur
		if dur <= 0 {
			dur = 300
		}
		dur = clampLiveDur(dur)
		liveEnqueueInput(adb, serial, "input", "swipe",
			strconv.Itoa(x1), strconv.Itoa(y1), strconv.Itoa(x2), strconv.Itoa(y2), strconv.Itoa(dur))
	case "key":
		if liveSafeKey(in.Key) {
			liveEnqueueInput(adb, serial, "input", "keyevent", in.Key)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}
