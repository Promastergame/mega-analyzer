package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"mega-analyzer/pkg/cmd/analyzer/web"
	"mega-analyzer/pkg/internal/sandbox"
	"mega-analyzer/pkg/ncer"
)

// TelemetryEvent is one line of real-time sandbox telemetry streamed as JSON to
// stdout and consumed by the web dashboard. All detail fields are derived from
// the real sandbox run — never synthesized.
type TelemetryEvent struct {
	Type        string `json:"type"`              // process|fs|network|dns|api_call|alert|perf|stdout|status|report
	Timestamp   string `json:"timestamp"`         // HH:MM:SS.mmm
	PID         int    `json:"pid,omitempty"`     // owning process id
	PPID        int    `json:"ppid,omitempty"`    // parent process id
	Process     string `json:"process,omitempty"` // process name
	Details     string `json:"details,omitempty"` // human-readable detail line
	CPU         int    `json:"cpu,omitempty"`     // host CPU load %, for perf events
	RAM         int    `json:"ram,omitempty"`     // host RAM load %, for perf events
	Method      string `json:"method,omitempty"`  // HTTP method (or "TLS" for an SNI sighting)
	URL         string `json:"url,omitempty"`     // HTTP/HTTPS URL
	Status      string `json:"status,omitempty"`  // HTTP status (or "—" when unknown)
	Code        string `json:"code,omitempty"`
	Stage       string `json:"stage,omitempty"`
	MD5         string `json:"md5,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	Size        int64  `json:"size,omitempty"`
	EventID     string `json:"event_id,omitempty"`
	Source      string `json:"source,omitempty"`
	Attribution string `json:"attribution,omitempty"`
	Action      string `json:"action,omitempty"`
	Object      string `json:"object,omitempty"`
	Category    string `json:"category,omitempty"`
	Host        string `json:"host,omitempty"` // request host / SNI
}

// timelineEvent pairs a real event with its real timestamp so the final replay
// can reconstruct the run in chronological order.
type timelineEvent struct {
	at time.Time
	ev TelemetryEvent
}

// runSandboxStream runs the REAL sandbox engine against the target and streams
// its real telemetry as JSON events. While the engine runs it emits live host
// CPU/RAM samples; when the engine returns it replays the real observed
// processes, connections, DNS queries, file changes, API calls and behavioural
// alerts in chronological order. The engine produces a complete Report rather
// than per-syscall callbacks, so fine-grained events surface once the run
// reports them — the data is real, the fine-grained liveness is a follow-up.
func (a *App) runSandboxStream() error {
	enc := json.NewEncoder(os.Stdout)
	// json.Encoder is NOT safe for concurrent use, so serialise writes.
	var emitMu sync.Mutex
	return a.runSandboxStreamSink(context.Background(), func(ev TelemetryEvent) {
		emitMu.Lock()
		_ = enc.Encode(ev)
		emitMu.Unlock()
	})
}

// runSandboxStreamSink is the engine core shared by the CLI streaming path and
// the in-process web UI path. It runs the REAL sandbox against the target and
// pushes every telemetry event to rawEmit. The web server uses this directly
// (no subprocess) so antivirus can't kill a freshly-built child binary and so
// engine logs flow straight into the dashboard. ctx cancellation (Stop button)
// is honoured by the underlying sandbox run.
func (a *App) runSandboxStreamSink(ctx context.Context, rawEmit func(TelemetryEvent)) error {
	ncerCollector := ncer.NewCollector(time.Now())
	if a.opts.Output != "" {
		if evStore, err := ncer.OpenEvidenceStore(filepath.Join(a.opts.Output, "ncer_evidence")); err == nil {
			ncerCollector.SetEvidenceStore(evStore)
		}
		// The novelty baseline lives alongside the evidence store rather than
		// inside it: it's a small mutable index that gets read-then-rewritten
		// every session, unlike the append-only content-addressed evidence.
		ncerCollector.SetBaselineDir(filepath.Join(a.opts.Output, "ncer_baseline"))
	}

	// Several goroutines (process/network monitor, PCAPdroid, mitmproxy, the perf
	// ticker and the final replay) all call emit concurrently; rawEmit must be
	// safe for concurrent use (the callers serialise it).
	var observedMu sync.Mutex
	observed := make(map[string]bool)
	emit := func(ev TelemetryEvent) {
		// The final report replays the same observations; do not count them twice.
		key := ""
		if ev.Type == "process" && ev.PID > 0 {
			key = fmt.Sprintf("process:%d", ev.PID)
		}
		if ev.Type == "network" {
			key = fmt.Sprintf("network:%d:%s", ev.PID, ev.Details)
		}
		if key != "" {
			observedMu.Lock()
			seen := observed[key]
			observed[key] = true
			observedMu.Unlock()
			if seen {
				return
			}
		}

		if ev.Timestamp == "" {
			ev.Timestamp = time.Now().Format("15:04:05.000")
		}
		if ev.Type == "http" {
			ncerCollector.ObserveHTTP(ev.Method, ev.URL, ev.Status, ev.Host, ev.Timestamp)
		}
		rawEmit(ev)
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	absTarget, err := filepath.Abs(a.opts.Target)
	if err != nil {
		emit(TelemetryEvent{Type: "error", Code: "target_invalid", Stage: "preflight", Details: "invalid sandbox target: " + err.Error()})
		return fmt.Errorf("invalid sandbox target: %w", err)
	}
	if _, statErr := os.Stat(absTarget); statErr != nil {
		emit(TelemetryEvent{Type: "error", Code: "target_missing", Stage: "preflight", Details: "sandbox target not found: " + statErr.Error()})
		return fmt.Errorf("sandbox target not found: %w", statErr)
	}

	outputRoot := a.opts.SandboxOutput
	if outputRoot == "" {
		outputRoot = a.opts.Output
	}
	if outputRoot == "" {
		outputRoot = "analysis_output"
	}

	md5sum, sha256sum, sampleSize, hashErr := hashSandboxSample(absTarget)
	if hashErr != nil {
		emit(TelemetryEvent{Type: "log", Details: "Sample fingerprint unavailable: " + hashErr.Error()})
	} else {
		emit(TelemetryEvent{Type: "metadata", MD5: md5sum, SHA256: sha256sum, Size: sampleSize, Process: filepath.Base(absTarget)})
	}
	targetName := filepath.Base(absTarget)
	emit(TelemetryEvent{Type: "status", Process: "analyzer", Details: "Sandbox engine starting for " + targetName})

	cfg := sandbox.Config{
		AllowHostExecution:  a.opts.SandboxAllowHostExecution,
		TargetPath:          absTarget,
		OutputDir:           outputRoot,
		RawArgs:             a.opts.SandboxArgs,
		Duration:            time.Duration(a.opts.SandboxDuration) * time.Second,
		MaxMemoryMB:         a.opts.SandboxMemoryMB,
		BlockNetwork:        !a.opts.SandboxAllowNet,
		MonitorEvery:        time.Second,
		SandboxProfile:      a.opts.SandboxProfile,
		VSSRevert:           a.opts.SandboxVSSRevert,
		EnableKernelMonitor: a.opts.EnableKernelMonitor,
		EnableVSS:           a.opts.EnableVSS,
		EnableWFP:           a.opts.EnableWFP,
		EnableAPITracing:    a.opts.EnableAPITracing,
		EnableTimeManip:     a.opts.EnableTimeManip,
		TimeScaleFactor:     a.opts.SandboxTimeScale,
		AndroidSandbox:      a.opts.AndroidSandbox,
		AndroidAVD:          a.opts.SandboxAVD,
		AndroidAutoAVD:      a.opts.SandboxAutoAVD,
		AndroidDevice:       a.opts.SandboxDevice,
		PrivateServer:       a.opts.SandboxPrivServer,
		MaxCPUCores:         a.opts.SandboxCPUCores,
		Locale:              a.opts.SandboxLocale,
		Timezone:            a.opts.SandboxTimezone,
		Resolution:          a.opts.SandboxResolution,
		Orientation:         a.opts.SandboxOrientation,
		UninstallAfter:      a.opts.SandboxUninstall,
		CaptureTraffic:      a.opts.SandboxCapture,
		// In the streaming path we own mitmproxy ourselves (live event stream),
		// so disable the engine's internal one to avoid two proxies on :8080.
		MITMProxy:   false,
		Frida:       a.opts.SandboxFrida || a.opts.SandboxFridaSpawn || a.opts.SandboxFridaScript != "",
		FridaSpawn:  a.opts.SandboxFridaSpawn,
		FridaScript: a.opts.SandboxFridaScript,
		// Route engine log lines (device detection, APK install, launch, errors)
		// directly into the telemetry stream as structured events — no os.Stdout
		// pipe tricks needed, no interleaving with the JSON encoder.
		OnActivity: func(ev sandbox.ActivityEvent) {
			emit(TelemetryEvent{Type: "activity", Timestamp: ev.ObservedAt.UTC().Format(time.RFC3339Nano), EventID: ev.ID, PID: ev.PID, Process: ev.Process, Source: ev.Source, Attribution: ev.Attribution, Category: ev.Category, Action: ev.Action, Object: ev.Object, Details: ev.Details})
		},
		OnProcess: func(p sandbox.ObservedProcess) {
			emit(TelemetryEvent{Type: "process", Timestamp: p.FirstSeen.Local().Format("15:04:05.000"), PID: p.PID, PPID: p.ParentPID, Process: p.Name, Details: firstNonEmpty(p.CommandLine, p.ExecutablePath)})
		},
		OnConnection: func(c sandbox.ObservedConnection) {
			emit(TelemetryEvent{Type: "network", Timestamp: c.FirstSeen.Local().Format("15:04:05.000"), PID: c.PID, Details: fmt.Sprintf("%s -> %s (%s)", strings.ToUpper(c.Protocol), c.RemoteAddr, c.State)})
		},
		LogSink: func(s string) {
			s = strings.TrimRight(s, "\r\n")
			if strings.TrimSpace(s) == "" {
				return
			}
			emit(TelemetryEvent{Type: "log", Details: s})
		},
		// Pin live views to the exact serial this run is bound to; the
		// observation clock starts only when the sample itself executes.
		OnDevice: func(serial string) {
			emit(TelemetryEvent{Type: "device", Details: serial})
		},
		OnObserving: func() {
			emit(TelemetryEvent{Type: "status", Stage: "observing", Process: "analyzer", Details: "observation started"})
		},
	}
	wantLiveMITM := a.opts.SandboxMITM

	type runResult struct {
		report *sandbox.Report
		err    error
	}
	resCh := make(chan runResult, 1)
	go func() {
		report, runErr := sandbox.Run(ctx, cfg)
		resCh <- runResult{report, runErr}
	}()

	// Resolve adb path and device serial once, before any goroutine races to
	// call `adb devices` while sandbox.Run() is also using adb (install, logcat).
	liveAdb := web.LiveADB()
	liveSerial := web.LiveSerial()

	// Live Android ADB monitor: streams processes and network connections from
	// the connected device while sandbox.Run is executing. Runs in a separate
	// goroutine so it never blocks the perf ticker.
	stopAdb := make(chan struct{})
	if cfg.AndroidSandbox {
		go liveAndroidMonitor(emit, liveAdb, liveSerial, stopAdb)
		// PCAPdroid live capture (no root): drives the installed PCAPdroid app to
		// stream real connections + DNS to us via VpnService. Scoped to the target
		// package when we can resolve it. Best-effort: logs and bows out cleanly
		// if PCAPdroid isn't present / not authorised.
		go func() {
			pkg := sandbox.ResolveAPKPackage(absTarget)
			livePcapdroidMonitor(emit, liveAdb, liveSerial, pkg, stopAdb)
		}()
		// mitmproxy live HTTP(S) interception — only when the user opted in.
		if wantLiveMITM {
			go liveMitmMonitor(emit, liveAdb, liveSerial, stopAdb)
		}
	}

	// Live host CPU/RAM sampling while the engine runs.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var res runResult
	stopped := false
loop:
	for {
		select {
		case res = <-resCh:
			break loop
		case <-ctx.Done():
			// Stop button / shutdown: stop live monitors and wait for the engine
			// to unwind (sandbox.Run observes the same ctx).
			emit(TelemetryEvent{Type: "log", Details: "ℹ Stopping sandbox session…"})
			stopped = true
			break loop
		case <-ticker.C:
			if cpu, ram, ok := sampleHostStats(); ok {
				emit(TelemetryEvent{Type: "perf", CPU: cpu, RAM: ram})
			}
		}
	}
	if cfg.AndroidSandbox {
		close(stopAdb)
	}
	if stopped {
		// Drain the engine result so we still replay whatever it captured, but
		// don't hang the UI if the engine is slow to unwind.
		select {
		case res = <-resCh:
		case <-time.After(8 * time.Second):
			res = runResult{}
		}
	}

	if res.report != nil {
		res.report.MD5 = md5sum
		res.report.SHA256 = sha256sum
		if err := sandbox.PersistReport(res.report); err != nil {
			emit(TelemetryEvent{Type: "log", Details: "Report persistence warning: " + err.Error()})
		}
	}
	if res.err != nil {
		if errors.Is(res.err, context.Canceled) {
			if res.report != nil {
				emit(TelemetryEvent{Type: "report", Details: res.report.SessionID})
			}
			emit(TelemetryEvent{Type: "status", Stage: "stopped", Details: "Sandbox session stopped."})
			return nil
		}
		failure := sandbox.DescribeFailure(res.err)
		emit(TelemetryEvent{Type: "error", Code: failure.Code, Stage: failure.Stage, Details: failure.Message})
		if res.report != nil {
			emit(TelemetryEvent{Type: "report", Details: res.report.SessionID})
		}
		return res.err
	}
	if res.report == nil {
		if stopped {
			emit(TelemetryEvent{Type: "status", Stage: "stopped", Details: "Stop requested; no final report was received."})
			return nil
		}
		err := fmt.Errorf("sandbox run produced no report")
		emit(TelemetryEvent{Type: "error", Code: "report_missing", Stage: "finalizing", Details: err.Error()})
		return err
	}

	replayReport(emit, res.report)
	feedNcerAuthority(ncerCollector, res.report)
	feedNcerDNSFlow(ncerCollector, res.report)
	feedNcerMitmCapture(ncerCollector, emit)
	feedNcerConsequence(ncerCollector, res.report)

	if ncerRes, err := ncerCollector.Reconcile(); err != nil {
		emit(TelemetryEvent{Type: "log", Details: "⚠ NCER causal reconciliation warning: " + err.Error()})
	} else if ncerRes != nil {
		res.report.NcerResult = ncerRes
		if err := sandbox.PersistReport(res.report); err != nil {
			emit(TelemetryEvent{Type: "log", Details: "⚠ NCER report persistence warning: " + err.Error()})
		}
		emit(TelemetryEvent{
			Type: "ncer",
			Details: fmt.Sprintf(
				"NCER d_Causal=%.4f d_Authority=%.4f d_Information=%.4f d_Capability=%.4f d_Consequence=%.4f d_Novelty=%.4f (bound=%d, unbound=%d, orphan=%d)",
				ncerRes.DCausal, ncerRes.DAuthority, ncerRes.DInformation, ncerRes.DCapability, ncerRes.DConsequence, ncerRes.DNovelty,
				ncerRes.BoundCount, ncerRes.UnboundCount, ncerRes.OrphanCount),
		})
	}

	return nil
}

// replayReport turns a finished sandbox Report into a chronological stream of
// real telemetry events.
func replayReport(emit func(TelemetryEvent), report *sandbox.Report) {
	base := report.StartedAt
	stamp := func(t time.Time) string {
		if t.IsZero() {
			t = base
		}
		return t.Format("15:04:05.000")
	}

	// Build a process-name lookup so connection/dns/api events can be attributed.
	nameByPID := map[int]string{}
	for _, p := range report.Processes {
		nameByPID[p.PID] = p.Name
	}
	procName := func(pid int) string {
		if n, ok := nameByPID[pid]; ok && n != "" {
			return n
		}
		return ""
	}

	var timeline []timelineEvent

	// Processes.
	for _, p := range report.Processes {
		details := p.CommandLine
		if details == "" {
			details = p.ExecutablePath
		}
		timeline = append(timeline, timelineEvent{p.FirstSeen, TelemetryEvent{
			Type: "process", Timestamp: stamp(p.FirstSeen),
			PID: p.PID, PPID: p.ParentPID, Process: p.Name, Details: details,
		}})
	}

	// Network connections — prefer the richer NetworkCapture set when present.
	// Filter: skip loopback/link-local, skip noisy terminal states, deduplicate
	// by remote IP:port so the dashboard isn't flooded with TIME_WAIT noise.
	seenRemote := map[string]bool{}
	skipState := map[string]bool{
		"TIME_WAIT": true, "FIN_WAIT1": true, "FIN_WAIT2": true,
		"CLOSE_WAIT": true, "CLOSED": true, "LAST_ACK": true,
	}
	addConn := func(proto, remoteAddr string, remotePort int, state, process string, pid int, ts time.Time) {
		if skipState[strings.ToUpper(state)] {
			return
		}
		if isLocalAddr(remoteAddr) {
			return
		}
		key := fmt.Sprintf("%s:%d", remoteAddr, remotePort)
		if seenRemote[key] {
			return
		}
		seenRemote[key] = true
		remote := remoteAddr
		if remotePort != 0 {
			remote = fmt.Sprintf("%s:%d", remoteAddr, remotePort)
		}
		det := fmt.Sprintf("%s -> %s (%s)", strings.ToUpper(proto), remote, state)
		timeline = append(timeline, timelineEvent{ts, TelemetryEvent{
			Type: "network", Timestamp: stamp(ts),
			PID: pid, Process: process, Details: det,
		}})
	}
	if report.NetworkCapture != nil && len(report.NetworkCapture.Connections) > 0 {
		for _, c := range report.NetworkCapture.Connections {
			addConn(c.Protocol, c.RemoteAddr, int(c.RemotePort), c.State,
				firstNonEmpty(c.ProcessName, procName(c.ProcessID)), c.ProcessID, c.Timestamp)
		}
	} else {
		for _, c := range report.Connections {
			addConn(c.Protocol, c.RemoteAddr, 0, c.State, procName(c.PID), c.PID, c.FirstSeen)
		}
	}

	// DNS queries.
	if report.NetworkCapture != nil {
		for _, d := range report.NetworkCapture.DNSQueries {
			resp := strings.Join(d.Response, ", ")
			det := fmt.Sprintf("%s %s -> %s", d.QueryType, d.QueryName, firstNonEmpty(resp, d.ResponseCode))
			timeline = append(timeline, timelineEvent{d.Timestamp, TelemetryEvent{
				Type: "dns", Timestamp: stamp(d.Timestamp),
				PID: d.ProcessID, Process: firstNonEmpty(d.ProcessName, procName(d.ProcessID)), Details: det,
			}})
		}
	}

	// File snapshot deltas have no known action timestamp or actor. Place
	// them at report completion, and explicitly mark the snapshot source.
	for _, f := range report.FileChanges.Created {
		timeline = append(timeline, timelineEvent{report.FinishedAt, snapshotFileEvent("CREATE", f.Path, report.FinishedAt)})
	}
	for _, f := range report.FileChanges.Modified {
		timeline = append(timeline, timelineEvent{report.FinishedAt, snapshotFileEvent("WRITE", f.Path, report.FinishedAt)})
	}
	for _, f := range report.FileChanges.Deleted {
		timeline = append(timeline, timelineEvent{report.FinishedAt, snapshotFileEvent("DELETE", f.Path, report.FinishedAt)})
	}

	// API calls.
	for _, c := range report.APICalls {
		fn := c.Function
		if c.Module != "" {
			fn = c.Module + "!" + c.Function
		}
		det := fn
		if c.ReturnValue != "" {
			det = fn + " -> " + c.ReturnValue
		}
		timeline = append(timeline, timelineEvent{c.Timestamp, TelemetryEvent{
			Type: "api_call", Timestamp: stamp(c.Timestamp),
			PID: c.ProcessID, Process: procName(c.ProcessID), Details: det,
		}})
	}

	// Behavioural indicators and anti-sandbox techniques become alerts.
	if report.BehaviorAnalysis != nil {
		for _, ind := range report.BehaviorAnalysis.Indicators {
			det := ind.Type
			if ind.Description != "" {
				det = ind.Type + ": " + ind.Description
			}
			timeline = append(timeline, timelineEvent{ind.Timestamp, TelemetryEvent{
				Type: "alert", Timestamp: stamp(ind.Timestamp),
				PID: ind.ProcessID, Process: procName(ind.ProcessID), Details: det,
			}})
		}
	}
	for _, a := range report.AntiSandboxDetected {
		det := "Anti-sandbox: " + a.Type
		if a.Description != "" {
			det += " — " + a.Description
		}
		timeline = append(timeline, timelineEvent{a.Timestamp, TelemetryEvent{
			Type: "alert", Timestamp: stamp(a.Timestamp),
			PID: a.ProcessID, Process: procName(a.ProcessID), Details: det,
		}})
	}

	// Replay in chronological order. Zero timestamps fall back to StartedAt, so
	// they sort to the front in stable input order.
	sort.SliceStable(timeline, func(i, j int) bool {
		ti, tj := timeline[i].at, timeline[j].at
		if ti.IsZero() {
			ti = base
		}
		if tj.IsZero() {
			tj = base
		}
		return ti.Before(tj)
	})
	for _, te := range timeline {
		emit(te.ev)
	}

	// Stream the real captured stdout into the terminal view.
	streamCapturedOutput(emit, report.StdoutPath)

	// Final verdict + report-ready signal so the dashboard can load the full report.
	if report.BehaviorAnalysis != nil {
		emit(TelemetryEvent{Type: "status", Process: "analyzer", Details: fmt.Sprintf(
			"Run complete — classification=%s risk=%d/100",
			firstNonEmpty(report.BehaviorAnalysis.Classification, "unknown"),
			report.BehaviorAnalysis.RiskScore)})
	}
	emit(TelemetryEvent{Type: "report", Details: report.SessionID, MD5: report.MD5, SHA256: report.SHA256})
}

// liveAndroidMonitor polls the connected Android device via ADB every 2 s and
// emits real-time process and network events while the sandbox engine runs.
// Only new/unseen entries are emitted — deduplication happens here, not in JS.
func liveAndroidMonitor(emit func(TelemetryEvent), adb, serial string, stop <-chan struct{}) {
	if adb == "" || serial == "" {
		emit(TelemetryEvent{Type: "status", Process: "monitor", Details: "Live monitor: no ADB device detected (adb=" + firstNonEmpty(adb, "not found") + ", serial=" + firstNonEmpty(serial, "none") + ")"})
		return
	}
	emit(TelemetryEvent{Type: "status", Process: "monitor", Details: "Live process/network monitor attached to " + serial})

	seenPID := map[int]bool{}
	seenConn := map[string]bool{}
	procEmitted := 0
	polls := 0

	// emitProcRow keeps package-style app processes (com.foo / com.foo:service)
	// and drops kernel threads / daemons / our own shell. pidIdx/nameIdx tell it
	// which columns to read for the two ps output schemas we support.
	emitProcRow := func(f []string, pidIdx int) {
		if len(f) <= pidIdx {
			return
		}
		pid, perr := strconv.Atoi(f[pidIdx])
		if perr != nil || pid <= 1 || seenPID[pid] {
			return
		}
		ppid := 0
		if pidIdx+1 < len(f) {
			ppid, _ = strconv.Atoi(f[pidIdx+1])
		}
		name := f[len(f)-1]
		base := name
		if i := strings.IndexByte(base, ':'); i >= 0 {
			base = base[:i]
		}
		if !strings.Contains(base, ".") || strings.HasPrefix(name, "[") {
			return
		}
		seenPID[pid] = true
		procEmitted++
		emit(TelemetryEvent{Type: "process", PID: pid, PPID: ppid, Process: name, Details: name})
	}

	poll := func() {
		polls++
		// --- Processes (real app processes) ---
		// Two schemas, tried in order, because toybox `ps` on some OEM ROMs
		// (Infinix/Transsion, Xiaomi) rejects "-o PID,PPID,NAME":
		//   1. `ps -A -o PID,PPID,NAME`   → fields: PID PPID NAME      (pid at 0)
		//   2. `ps -A`                    → fields: USER PID PPID ... NAME (pid at 1)
		got := 0
		out, err := runADBOut(adb, serial, 10*time.Second, "ps", "-A", "-o", "PID,PPID,NAME")
		if err == nil && len(strings.TrimSpace(string(out))) > 0 {
			for _, ln := range strings.Split(string(out), "\n") {
				f := strings.Fields(ln)
				before := procEmitted
				emitProcRow(f, 0)
				if procEmitted > before {
					got++
				}
			}
		}
		// Fallback to plain `ps -A` when the -o form produced nothing.
		if got == 0 {
			out, err = runADBOut(adb, serial, 10*time.Second, "ps", "-A")
			if err == nil {
				for _, ln := range strings.Split(string(out), "\n") {
					f := strings.Fields(ln)
					emitProcRow(f, 1) // USER PID PPID ... NAME
				}
			}
		}

		// --- Network connections ---
		// Use `ss -tn` (available on Android 7+); skip TIME_WAIT / FIN_WAIT / localhost.
		out2, err2 := runADBOut(adb, serial, 10*time.Second, "ss", "-tn", "state", "established")
		if err2 != nil {
			// Fallback: /proc/net/tcp + tcp6 — parse hex remote addr
			out2, _ = runADBOut(adb, serial, 10*time.Second, "cat", "/proc/net/tcp", "/proc/net/tcp6")
			for _, ln := range strings.Split(string(out2), "\n") {
				f := strings.Fields(ln)
				if len(f) < 4 || f[3] != "01" { // 01 = ESTABLISHED
					continue
				}
				rem := parseHexAddr(f[2])
				if rem == "" || isLocalAddr(rem) {
					continue
				}
				if seenConn[rem] {
					continue
				}
				seenConn[rem] = true
				emit(TelemetryEvent{Type: "network", Details: "TCP -> " + rem + " (ESTABLISHED)"})
			}
			return
		}
		for _, ln := range strings.Split(string(out2), "\n") {
			f := strings.Fields(ln)
			if len(f) < 4 {
				continue
			}
			// ss -tn output: Netid State Recv-Q Send-Q Local Peer
			// With "state established" filter the state column is omitted → 4 fields
			remote := f[len(f)-1] // last field is peer addr
			if isLocalAddr(remote) {
				continue
			}
			key := remote
			if seenConn[key] {
				continue
			}
			seenConn[key] = true
			emit(TelemetryEvent{Type: "network", Details: "TCP -> " + remote + " (ESTABLISHED)"})
		}
	}

	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()
	// First poll after a short delay (apps need a moment to start).
	time.Sleep(1500 * time.Millisecond)
	poll()
	if procEmitted == 0 {
		emit(TelemetryEvent{Type: "status", Process: "monitor", Details: "Live monitor: device returned no readable process list (ps may be restricted on this ROM)"})
	}
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			poll()
		}
	}
}

// parseHexAddr converts a /proc/net/tcp hex "AABBCCDD:PPPP" entry to "IP:port".
func parseHexAddr(h string) string {
	parts := strings.SplitN(h, ":", 2)
	if len(parts) != 2 {
		return ""
	}
	addrHex, portHex := parts[0], parts[1]
	port64, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return ""
	}
	// IPv4 in /proc/net/tcp: 4 bytes little-endian hex
	if len(addrHex) == 8 {
		b0, _ := strconv.ParseUint(addrHex[6:8], 16, 8)
		b1, _ := strconv.ParseUint(addrHex[4:6], 16, 8)
		b2, _ := strconv.ParseUint(addrHex[2:4], 16, 8)
		b3, _ := strconv.ParseUint(addrHex[0:2], 16, 8)
		return fmt.Sprintf("%d.%d.%d.%d:%d", b0, b1, b2, b3, port64)
	}
	// IPv6 in /proc/net/tcp6
	if len(addrHex) == 32 {
		var b [16]byte
		for i := 0; i < 4; i++ {
			word, _ := strconv.ParseUint(addrHex[i*8:(i+1)*8], 16, 32)
			b[i*4+0] = byte(word)
			b[i*4+1] = byte(word >> 8)
			b[i*4+2] = byte(word >> 16)
			b[i*4+3] = byte(word >> 24)
		}
		return fmt.Sprintf("[%s]:%d", net.IP(b[:]).String(), port64)
	}
	return ""
}

// isLocalAddr returns true for loopback or link-local addresses.
func isLocalAddr(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func snapshotFileEvent(op, path string, observedAt time.Time) TelemetryEvent {
	return TelemetryEvent{Type: "fs", Timestamp: observedAt.UTC().Format(time.RFC3339Nano), Source: "final_workspace_snapshot", Attribution: "unknown", Action: op, Object: path, Details: "Snapshot difference (actor and exact action time unknown): " + op + " " + path}
}

func fsEvent(op, path string) TelemetryEvent {
	return TelemetryEvent{Type: "fs", Timestamp: time.Now().Format("15:04:05.000"), Details: op + " " + path}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// streamCapturedOutput emits the last lines of the target's real captured
// stdout as terminal events. Bounded so a chatty sample cannot flood the UI.
func streamCapturedOutput(emit func(TelemetryEvent), path string) {
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	const maxLines = 400
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > maxLines {
			lines = lines[1:]
		}
	}
	for _, ln := range lines {
		emit(TelemetryEvent{Type: "stdout", Details: ln})
	}
}
