package main

import (
	"context"
	"os"
	"sync"

	"mega-analyzer/pkg/cmd/analyzer/web"
)

// activeServer/activeServerMu remain in package main as the test hook:
// web_ui_more_test.go shuts the server down at the end so the test binary
// can unlink cleanly on Windows.
var (
	activeServerMu sync.Mutex
	activeServer   *web.Server
)

// runWebUI is a thin wiring function: the web UI implementation lives in
// the web subpackage next to this command. Handlers owned by this package
// (live video/audio, Frida, the native APK editor) are injected, so web has
// no dependency on package main.
func runWebUI(port int) error { return runWebUIOptions(&CLIOptions{Web: true, WebPort: port}) }

func runWebUIOptions(opts *CLIOptions) error {
	srv, err := web.New(web.Options{
		Port:                  opts.WebPort,
		Token:                 opts.WebToken,
		Privileged:            opts.Admin,
		DecisionAIURL:         opts.DecisionAIURL,
		DecisionAIMaxFindings: opts.DecisionAIMaxFindings,
		DecisionAIBudget:      opts.DecisionAIBudget,
		// Never elevate the desktop browser; print the paired URL instead.
		OpenBrowser: !opts.Admin && os.Getenv("MEGA_ANALYZER_NO_BROWSER") == "",
		Deps: web.Deps{
			LiveVideo:       handleLiveVideo,
			LiveAudio:       handleLiveAudio,
			FridaStatus:     handleFridaStatus,
			FridaStart:      handleFridaStart,
			FridaProcesses:  handleFridaProcesses,
			FridaREPL:       handleFridaREPL,
			FridaRepack:     handleFridaRepackAPK,
			LaunchAPKEditor: LaunchAPKEditor,
		},
	})
	if err != nil {
		return err
	}
	activeServerMu.Lock()
	activeServer = srv
	activeServerMu.Unlock()
	return srv.ListenAndServe()
}

// stopActiveServer shuts down the server started by runWebUI, if any.
func stopActiveServer(ctx context.Context) {
	activeServerMu.Lock()
	srv := activeServer
	activeServer = nil
	activeServerMu.Unlock()
	if srv != nil {
		_ = srv.Shutdown(ctx)
	}
}
