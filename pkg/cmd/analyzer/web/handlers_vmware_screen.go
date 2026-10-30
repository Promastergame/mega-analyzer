package web

import (
	"context"
	"errors"
	"net/http"

	"mega-analyzer/pkg/internal/vmware"
)

// A frame is available only for the exact active job, never an arbitrary VM or
// the host desktop. The common middleware enforces pairing/origin protections.
func (s *Server) handleVMwareScreen(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	jobsMu.Lock()
	job := jobs[r.URL.Query().Get("job")]
	jobsMu.Unlock()
	if job == nil {
		http.Error(w, "VMware session not found", http.StatusNotFound)
		return
	}
	job.mu.Lock()
	capture := job.vmwareScreen
	active := job.mode == "sandbox" && !job.done && !job.stopped && capture != nil
	job.mu.Unlock()
	if !active {
		http.Error(w, "VMware screen is unavailable for this session", http.StatusConflict)
		return
	}
	frame, err := capture(r.Context())
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, vmware.ErrBusy) {
			status = http.StatusTooManyRequests
		}
		if errors.Is(err, context.Canceled) {
			status = http.StatusConflict
		}
		http.Error(w, "VMware screen capture is unavailable; check the guest console in VMware.", status)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(frame)
}
