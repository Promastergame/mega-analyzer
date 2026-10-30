package web

import (
	"mega-analyzer/pkg/internal/androidsdk"
	"net/http"
)

// RequestDeviceSerial never falls back when a selected device/job is unavailable.
// Legacy unscoped calls work only when exactly one ready device exists.
func RequestDeviceSerial(r *http.Request) string {
	serial := r.URL.Query().Get("serial")
	if id := r.URL.Query().Get("job"); id != "" {
		jobsMu.Lock()
		job := jobs[id]
		jobsMu.Unlock()
		if job == nil {
			return ""
		}
		job.mu.Lock()
		serial = job.deviceSerial
		done := job.done
		job.mu.Unlock()
		if serial == "" || done {
			return ""
		}
	}
	if serial != "" && !androidsdk.ValidDeviceSerial(serial) {
		return ""
	}
	devices, err := detectedAndroidDevices()
	if err != nil {
		return ""
	}
	result, _ := androidsdk.SelectDevice(devices, serial)
	return result
}
