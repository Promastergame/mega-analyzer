// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"mega-analyzer/pkg/internal/sastrules"
	"mega-analyzer/pkg/internal/trackers"
)

// uiBadgeCounts reports how many SAST rules and privacy trackers are bundled,
// so the web UI can display real numbers sourced from the embedded databases
// instead of hardcoded literals. Counts fall back to 0 on load failure.
func uiBadgeCounts() (sast int, trk int) {
	if sets, err := sastrules.LoadEmbeddedRuleSets(); err == nil {
		for _, rs := range sets {
			sast += len(rs.Rules)
		}
	}
	if db, err := trackers.LoadDB(); err == nil {
		trk = len(db)
	}
	return sast, trk
}
