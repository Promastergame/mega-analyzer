// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"sort"
	"sync"
	"time"
)

var (
	jobsMu sync.Mutex
	jobs   = map[string]*scanJob{}
)

// pruneJobs drops the oldest finished jobs so a long-lived server does not keep
// every scan's log buffer alive forever.
func pruneJobs(keep int) {
	jobsMu.Lock()
	defer jobsMu.Unlock()
	if len(jobs) <= keep {
		return
	}
	type entry struct {
		id string
		at time.Time
	}
	var finished []entry
	for id, j := range jobs {
		if j.isDone() {
			finished = append(finished, entry{id, j.started})
		}
	}
	sort.Slice(finished, func(a, b int) bool { return finished[a].at.Before(finished[b].at) })
	for _, e := range finished {
		if len(jobs) <= keep {
			return
		}
		delete(jobs, e.id)
	}
}
