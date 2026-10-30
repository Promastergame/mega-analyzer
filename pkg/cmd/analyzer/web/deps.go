// Handlers that live outside this package (live video/audio, Frida, the native
// APK editor) are injected instead of imported, which keeps webui free of
// import cycles and makes every endpoint mockable in tests.

package web

import "net/http"

// Deps are the collaborators the web UI does not own.
type Deps struct {
	LiveVideo      http.HandlerFunc
	LiveAudio      http.HandlerFunc
	FridaStatus    http.HandlerFunc
	FridaStart     http.HandlerFunc
	FridaProcesses http.HandlerFunc
	FridaREPL      http.HandlerFunc
	FridaRepack    http.HandlerFunc

	// LaunchAPKEditor opens the native patch editor for a local file.
	// It mirrors the two-argument main-package launcher: an empty
	// patchesPath opens the editor without preloaded patches.
	LaunchAPKEditor func(path, patchesPath string) error
}

// fill replaces missing collaborators with a 501 stub so a partially wired
// Server can never panic on a nil handler at registration time.
func (d *Deps) fill() {
	stub := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			httpError(w, r, http.StatusNotImplemented, name+" is not wired into this build.")
		}
	}
	for _, f := range []struct {
		p    *http.HandlerFunc
		name string
	}{
		{&d.LiveVideo, "Live video"}, {&d.LiveAudio, "Live audio"},
		{&d.FridaStatus, "Frida status"}, {&d.FridaStart, "Frida start"},
		{&d.FridaProcesses, "Frida process list"}, {&d.FridaREPL, "Frida REPL"},
		{&d.FridaRepack, "Frida repack"},
	} {
		if *f.p == nil {
			*f.p = stub(f.name)
		}
	}
	if d.LaunchAPKEditor == nil {
		d.LaunchAPKEditor = func(_, _ string) error { return errNoAPKEditor }
	}
}
