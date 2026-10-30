// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"net/http"
)

// routes wires every endpoint. One table, no 780-line closure soup:
// adding an endpoint means adding one line here plus one method.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// static SPA assets (embedded, ETag + immutable caching)
	mux.Handle("/static/", s.staticHandler())

	mux.HandleFunc("/", s.serveApp)
	mux.HandleFunc("/api/live/status", s.handleLiveStatus)
	mux.HandleFunc("/api/live/screen", s.handleLiveScreen)
	mux.HandleFunc("/api/live/video", s.deps.LiveVideo)
	mux.HandleFunc("/api/live/audio", s.deps.LiveAudio)
	mux.HandleFunc("/api/live/stream", s.handleLiveStream)
	mux.HandleFunc("/api/live/input", s.handleLiveInput)
	mux.HandleFunc("/api/pkg-version", s.handlePkgVersion)
	mux.HandleFunc("/api/host", s.handleHost)
	mux.HandleFunc("/api/env", s.handleEnv)
	mux.HandleFunc("/api/vmware", s.handleVMware)
	mux.HandleFunc("/api/vmware/screen", s.handleVMwareScreen)
	mux.HandleFunc("/api/vmware/console", s.handleVMwareConsole)
	mux.HandleFunc("/api/vmware/console-info", s.handleVMwareConsoleInfo)
	mux.HandleFunc("/api/meta", s.handleMeta)
	mux.HandleFunc("/api/v1/apk-editor/open", s.handleAPKEditorOpen)
	mux.HandleFunc("/api/apk-editor/open", s.handleAPKEditorOpen)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/workspace/list", s.handleWorkspaceList)
	mux.HandleFunc("/api/workspace/mkdir", s.handleWorkspaceMkdir)
	mux.HandleFunc("/api/workspace/file", s.handleWorkspaceFile)
	mux.HandleFunc("/api/events/", s.handleEvents)
	mux.HandleFunc("/api/evidence/", s.handleEvidence)
	mux.HandleFunc("/api/result/", s.handleResult)
	mux.HandleFunc("/api/artifacts/", s.handleArtifacts)
	mux.HandleFunc("/api/sandbox/", s.handleSandbox)
	mux.HandleFunc("/api/live/frida/status", s.deps.FridaStatus)
	mux.HandleFunc("/api/live/frida/start", s.deps.FridaStart)
	mux.HandleFunc("/api/live/frida/processes", s.deps.FridaProcesses)
	mux.HandleFunc("/api/live/frida/repl", s.deps.FridaREPL)
	mux.HandleFunc("/api/live/frida/repack", s.deps.FridaRepack)
	mux.HandleFunc("/api/report/", s.handleReport)
	mux.HandleFunc("/api/stop/", s.handleStop)

	return s.middleware(mux)
}
