package main

import (
	"encoding/json"
	"fmt"

	"mega-analyzer/pkg/internal/netproxy"
)

// netEventSentinel prefixes stdout lines carrying structured NetEvent JSON so
// the web UI's line-based job broadcaster (runAnalysis in web_ui.go) can pick
// them out from ordinary log/progress output and forward them to DevMega over
// /api/live/netcap. See DEVMEGA_TODO.md (M1).
const netEventSentinel = "@@NETEVENT@@ "

// emitNetEvent writes a NetEvent as a single sentinel-prefixed JSON line on
// stdout. Marshal failures are swallowed — a malformed event should never
// crash the running proxy.
func emitNetEvent(ev netproxy.NetEvent) {
	data, err := json.Marshal(ev)
	if err != nil {
		return
	}
	fmt.Println(netEventSentinel + string(data))
}
