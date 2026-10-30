package vmware

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"mega-analyzer/pkg/internal/sandbox"
)

// Keep a usable partial report outside the guest before it can shut down or
// damage its disk. No guest path is used as a host destination.
type liveReport struct {
	report      *sandbox.Report
	activity    *os.File
	processes   map[int]int
	connections map[string]bool
}

func newLiveReport(report *sandbox.Report) (*liveReport, error) {
	path := filepath.Join(report.SessionDir, "activity.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	report.ActivityPath = path
	return &liveReport{report: report, activity: f, processes: map[int]int{}, connections: map[string]bool{}}, nil
}

func (l *liveReport) Close() { _ = l.activity.Close() }

func (l *liveReport) Observe(e Event) error {
	r := l.report
	at, err := time.Parse(time.RFC3339Nano, e.Timestamp)
	if err != nil {
		at = time.Now().UTC()
	}
	switch e.Type {
	case "status":
		if e.Stage == "observing" && !r.Executed {
			r.Executed, r.StartedAt = true, at
			r.NetworkMode, r.NetworkGuardApplied = "vmware_disconnected", true
		}
	case "process":
		if e.PID <= 0 {
			return nil
		}
		if r.RootPID == 0 {
			r.RootPID = e.PID
		}
		if i, ok := l.processes[e.PID]; ok {
			if e.Details != "" {
				r.Processes[i].CommandLine = e.Details
			}
		} else {
			l.processes[e.PID] = len(r.Processes)
			r.Processes = append(r.Processes, sandbox.ObservedProcess{PID: e.PID, ParentPID: e.PPID, Name: e.Process, CommandLine: e.Details, FirstSeen: at})
		}
	case "network":
		c := sandbox.ObservedConnection{PID: e.PID, Protocol: e.Protocol, LocalAddr: e.LocalAddr, RemoteAddr: e.RemoteAddr, State: e.State}
		encoded, _ := json.Marshal(c)
		if !l.connections[string(encoded)] {
			l.connections[string(encoded)] = true
			c.FirstSeen = at
			r.Connections = append(r.Connections, c)
		}
	case "activity":
		a := sandbox.ActivityEvent{ID: e.EventID, ObservedAt: at, PID: e.PID, Process: e.Process, Category: e.Category, Action: e.Action, Object: e.Object, Details: e.Details, Source: e.Source, Attribution: e.Attribution}
		encoded, err := json.Marshal(a)
		if err != nil {
			return err
		}
		if _, err := l.activity.Write(append(encoded, '\n')); err != nil {
			return err
		}
		r.ActivityCount++
	}
	return nil
}

func (l *liveReport) Flush() error {
	if err := l.activity.Sync(); err != nil {
		return err
	}
	return sandbox.PersistReport(l.report)
}
