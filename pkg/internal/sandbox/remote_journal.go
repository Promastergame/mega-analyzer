package sandbox

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const remoteLineLimit = 64 * 1024
const remoteJournalLimit = 64 * 1024 * 1024
const remoteEventLimit = 100000

// RemoteCaptureStatus describes host persistence, not a hypervisor guarantee.
type RemoteCaptureStatus struct {
	Storage     string   `json:"storage"`
	Endpoint    string   `json:"endpoint"`
	JournalPath string   `json:"journal_path"`
	State       string   `json:"state"`
	Events      uint64   `json:"events"`
	Incomplete  bool     `json:"incomplete"`
	Recovered   bool     `json:"recovered"`
	Hooked      []string `json:"hooked,omitempty"`
}

// Only this bounded schema crosses the helper boundary. No guest paths select
// host files. Seq is assigned by the trusted host helper; At by the Go writer.
type remoteEvent struct {
	Seq      uint64    `json:"seq"`
	Kind     string    `json:"kind"`
	At       time.Time `json:"at,omitempty"`
	PID      int       `json:"pid,omitempty"`
	Call     *APICall  `json:"call,omitempty"`
	Hooked   []string  `json:"hooked,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	Endpoint string    `json:"endpoint,omitempty"`
	Target   string    `json:"target,omitempty"`
}

type remoteJournal struct {
	file         *os.File
	report       *Report
	crypto       *cryptoAccumulator
	bytes        int
	lastSnapshot time.Time
	terminal     bool
}

func newRemoteJournal(output, endpoint, target string) (*remoteJournal, error) {
	return newRemoteJournalAt(output, endpoint, target, time.Now().UTC())
}

func newRemoteJournalAt(output, endpoint, target string, started time.Time) (*remoteJournal, error) {
	if output == "" {
		output = "analysis_output"
	}
	root, err := filepath.Abs(output)
	if err != nil {
		return nil, err
	}
	base := filepath.Join(root, "sandbox")
	if err = os.MkdirAll(base, 0700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(base, "remote-")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "events.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	r := &Report{SessionID: filepath.Base(dir), InputType: "windows-remote", TargetOriginal: target,
		OutputRoot: root, SessionDir: dir, JSONPath: filepath.Join(dir, "sandbox_report.json"),
		MarkdownPath: filepath.Join(dir, "sandbox_report.md"), StartedAt: started, ExitCode: -1,
		NetworkMode: "configured-in-hypervisor", Warnings: []string{
			"VM isolation, network rules, memory limits and snapshots are managed outside the analyzer.",
			"Remote capture observes the root process; gated children are stopped and recorded as coverage gaps.",
		}, CryptoAnalysis: &CryptoAnalysis{Status: "not_instrumented", Materials: []CryptoMaterial{}},
		RemoteCapture: &RemoteCaptureStatus{Storage: "analyzer-host", Endpoint: endpoint, JournalPath: path, State: "starting", Incomplete: true},
		Frida:         &FridaSession{Requested: true, Mode: "remote-spawn"}}
	j := &remoteJournal{file: f, report: r, crypto: newCryptoAccumulator(r.CryptoAnalysis)}
	if err = j.appendRecord(remoteEvent{Kind: "start", Endpoint: endpoint, Target: target, At: started}); err != nil {
		f.Close()
		return nil, err
	}
	return j, nil
}

func validateRemoteEvent(e remoteEvent) error {
	if e.PID < 0 || e.PID > 1<<31-1 || len(e.Detail) > 2048 || len(e.Endpoint) > 256 || len(e.Target) > 4096 || len(e.Hooked) > 256 {
		return fmt.Errorf("remote event exceeds field bounds")
	}
	for _, s := range e.Hooked {
		if len(s) > 256 {
			return fmt.Errorf("hook name exceeds limit")
		}
	}
	switch e.Kind {
	case "start", "ready", "launch", "resumed", "heartbeat", "gap", "end", "error":
		if e.Call != nil {
			return fmt.Errorf("unexpected API payload")
		}
	case "api":
		c := e.Call
		if c == nil || c.ProcessID <= 0 || c.ProcessID > 1<<31-1 || c.ThreadID < 0 || c.ThreadID > 1<<31-1 || len(c.Function) == 0 || len(c.Function) > 256 || len(c.Module) > 256 || len(c.ReturnValue) > 1024 || len(c.Parameters) > 64 || len(c.StackTrace) > 32 {
			return fmt.Errorf("invalid remote API record")
		}
		for _, p := range c.Parameters {
			if len(p.Name) > 128 || len(p.Type) > 128 || len(p.Value) > 4096 {
				return fmt.Errorf("API parameter exceeds limit")
			}
		}
		for _, s := range c.StackTrace {
			if len(s) > 1024 {
				return fmt.Errorf("API stack exceeds limit")
			}
		}
	default:
		return fmt.Errorf("unknown remote event kind")
	}
	return nil
}

func (j *remoteJournal) check(e remoteEvent) error {
	if err := validateRemoteEvent(e); err != nil {
		return err
	}
	if j.terminal {
		return fmt.Errorf("event after terminal record")
	}
	r := j.report
	switch e.Kind {
	case "start":
		if r.RemoteCapture.Events != 0 {
			return fmt.Errorf("duplicate start")
		}
	case "ready":
		if e.PID <= 0 || r.RootPID != 0 || len(e.Hooked) == 0 {
			return fmt.Errorf("invalid ready handshake")
		}
	case "launch":
		if r.RootPID == 0 || e.PID != r.RootPID || r.RemoteCapture.State != "instrumented" {
			return fmt.Errorf("invalid launch intent")
		}
	case "resumed":
		if r.RootPID == 0 || e.PID != r.RootPID || r.Executed || r.RemoteCapture.State != "launch-requested" {
			return fmt.Errorf("invalid resume event")
		}
	case "api":
		if r.RootPID == 0 || e.Call.ProcessID != r.RootPID {
			return fmt.Errorf("unattributed API event")
		}
	case "end":
		if !r.Executed {
			return fmt.Errorf("end before execution")
		}
	}
	return nil
}

func (j *remoteJournal) apply(e remoteEvent) {
	r := j.report
	r.RemoteCapture.Events++
	switch e.Kind {
	case "start":
		r.StartedAt = e.At
	case "ready":
		r.RootPID = e.PID
		r.RemoteCapture.State = "instrumented"
		r.RemoteCapture.Hooked = e.Hooked
		r.Frida.Active = true
		r.CryptoAnalysis.Status = "no_material"
	case "launch":
		r.RemoteCapture.State = "launch-requested"
	case "resumed":
		r.Executed = true
		r.RemoteCapture.State = "running"
	case "api":
		j.crypto.observe(*e.Call)
		r.Frida.EventCount++
		// Full history is in the journal. Keep the report bounded independently.
		if len(r.APICalls) < 512 {
			r.APICalls = append(r.APICalls, *e.Call)
		}
	case "gap":
		if len(r.Warnings) < 128 {
			r.Warnings = append(r.Warnings, e.Detail)
		}
	case "end", "error":
		j.terminal = true
		r.RemoteCapture.State = e.Kind
		r.RemoteCapture.Incomplete = e.Kind != "end"
		r.FinishedAt = e.At
		r.DurationMS = e.At.Sub(r.StartedAt).Milliseconds()
		if e.Detail != "" && len(r.Warnings) < 128 {
			r.Warnings = append(r.Warnings, e.Detail)
		}
	}
}

func (j *remoteJournal) append(e remoteEvent) error {
	e.At = time.Now().UTC()
	return j.appendRecord(e)
}

func (j *remoteJournal) appendRecord(e remoteEvent) error {
	if err := j.check(e); err != nil {
		return err
	}
	e.Seq = j.report.RemoteCapture.Events + 1
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	// Reserve room for the final error record after a limit is reached.
	if len(data) > remoteLineLimit || ((j.bytes+len(data) > remoteJournalLimit || e.Seq > remoteEventLimit) && e.Kind != "error") {
		return fmt.Errorf("remote journal limit reached")
	}
	if _, err = j.file.Write(data); err != nil {
		return err
	}
	if err = j.file.Sync(); err != nil {
		return err
	}
	j.bytes += len(data)
	j.apply(e)
	// Key events get an immediate readable snapshot; all other events already
	// have a durable journal and are snapshotted at most once per second.
	keyEvent := e.Call != nil && strings.HasPrefix(e.Call.Function, "BCrypt")
	if keyEvent || e.Kind == "start" || e.Kind == "ready" || j.terminal || time.Since(j.lastSnapshot) >= time.Second {
		return j.snapshot()
	}
	return nil
}

func syncedReplace(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".snapshot-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, path)
}

func (j *remoteJournal) snapshot() error {
	data, err := json.MarshalIndent(j.report, "", "  ")
	if err != nil {
		return err
	}
	if err = syncedReplace(j.report.JSONPath, data); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Remote sandbox report\n\nStorage: analyzer host. Capture: %s. Incomplete: %t.\n\nEvents: %d. Full history: events.jsonl.\n", j.report.RemoteCapture.State, j.report.RemoteCapture.Incomplete, j.report.RemoteCapture.Events)
	b.WriteString("\nVM isolation and network restrictions require hypervisor configuration. Child execution is gated and stopped; this limits behavioral coverage.\n")
	writeCryptoAnalysisMarkdown(&b, j.report.CryptoAnalysis)
	if err = syncedReplace(j.report.MarkdownPath, []byte(b.String())); err != nil {
		return err
	}
	j.lastSnapshot = time.Now()
	return nil
}

// RecoverRemoteJournal creates fresh host output from an existing journal.
// A torn final line was never acknowledged and may be ignored. A malformed
// complete record is an error; it is never silently skipped.
func RecoverRemoteJournal(path, output string) (result *Report, resultErr error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	br := bufio.NewReaderSize(io.LimitReader(f, remoteJournalLimit+remoteLineLimit+1), remoteLineLimit+1)
	var j *remoteJournal
	defer func() {
		if j != nil {
			if resultErr != nil {
				j.report.RemoteCapture.State = "recovery-failed"
				j.report.RemoteCapture.Incomplete = true
				_ = j.snapshot()
			}
			j.file.Close()
		}
	}()
	seq := uint64(0)
	total := 0
	torn := false
	for {
		line, readErr := br.ReadSlice('\n')
		total += len(line)
		if len(line) > remoteLineLimit || total > remoteJournalLimit+remoteLineLimit || errors.Is(readErr, bufio.ErrBufferFull) {
			return nil, fmt.Errorf("journal bounds exceeded")
		}
		if errors.Is(readErr, io.EOF) {
			torn = len(line) > 0
			break
		}
		if readErr != nil {
			return nil, readErr
		}
		var e remoteEvent
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err = dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("corrupt journal record %d: %w", seq+1, err)
		}
		if dec.Decode(new(any)) != io.EOF {
			return nil, fmt.Errorf("trailing journal data")
		}
		if e.Seq != seq+1 || e.At.IsZero() {
			return nil, fmt.Errorf("invalid journal sequence")
		}
		seq = e.Seq
		if seq > remoteEventLimit+1 {
			return nil, fmt.Errorf("journal event limit exceeded")
		}
		if j == nil {
			if e.Kind != "start" {
				return nil, fmt.Errorf("journal missing start")
			}
			if err = validateRemoteEvent(e); err != nil {
				return nil, err
			}
			j, err = newRemoteJournalAt(output, e.Endpoint, e.Target, e.At)
			if err != nil {
				return nil, err
			}
			continue
		}
		if err = j.appendRecord(e); err != nil {
			return nil, err
		}
	}
	if j == nil {
		return nil, fmt.Errorf("empty journal")
	}
	j.report.RemoteCapture.Recovered = true
	if !j.terminal || torn {
		j.report.RemoteCapture.State = "recovered-incomplete"
		j.report.RemoteCapture.Incomplete = true
	}
	err = j.snapshot()
	return j.report, err
}
