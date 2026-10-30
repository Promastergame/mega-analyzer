package web

import (
	"encoding/json"
	"net/http"
	"time"

	"mega-analyzer/pkg/internal/vmware"
	"mega-analyzer/pkg/internal/wsx"
)

func activeVMwareConsole(id string) *vmware.Console {
	jobsMu.Lock()
	job := jobs[id]
	jobsMu.Unlock()
	if job == nil {
		return nil
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	if job.mode != "sandbox" || job.done || job.stopped {
		return nil
	}
	return job.vmwareConsole
}

func (s *Server) handleVMwareConsoleInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	console := activeVMwareConsole(r.URL.Query().Get("job"))
	if console == nil {
		http.Error(w, "VMware console is not ready", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// Only the ephemeral VNC secret crosses the authenticated same-origin API.
	// Windows login credentials never go back to the browser.
	json.NewEncoder(w).Encode(map[string]string{"password": console.Password()})
}

func (s *Server) handleVMwareConsole(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	console := activeVMwareConsole(r.URL.Query().Get("job"))
	if console == nil {
		http.Error(w, "VMware console is not ready", http.StatusConflict)
		return
	}
	guest, err := console.Open(r.Context())
	if err != nil {
		http.Error(w, "VMware console is unavailable or already connected", http.StatusServiceUnavailable)
		return
	}
	defer guest.Close()
	browser, _, _, err := wsx.UpgradeHTTP(r, w)
	if err != nil {
		return
	}
	defer browser.Close()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		defer guest.Close()
		defer browser.Close()
		for {
			data, op, err := wsx.ReadClientData(browser)
			if err != nil || op != wsx.OpBinary || len(data) > 64<<10 {
				return
			}
			guest.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := guest.Write(data); err != nil {
				return
			}
		}
	}()
	buffer := make([]byte, 64<<10)
	for {
		n, err := guest.Read(buffer)
		if n > 0 {
			browser.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if writeErr := wsx.WriteServerBinary(browser, buffer[:n]); writeErr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	guest.Close()
	browser.Close()
	<-finished
}
