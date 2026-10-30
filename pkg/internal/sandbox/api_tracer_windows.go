//go:build windows

package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// Primary Windows API-tracing approach justification:
// We use a local Frida user-mode instrumentation backend (frida CLI / local
// frida-server + frida_windows_default.js) injected into the target process
// while it is still created with CREATE_SUSPENDED, before resumeProcess() runs.
// Frida's Interceptor.attach hooks exported Win32 and Native API functions in
// kernel32.dll, kernelbase.dll, ntdll.dll, advapi32.dll, bcrypt.dll, and
// ws2_32.dll inside user space, capturing typed parameters (hProcess, PID,
// handles, flags), truthful return values, and thread GetLastError() at exit.
// By waiting for a synchronous "ready" handshake from the injected JS agent
// before Attach returns, all hooks are active before the main thread resumes,
// and child processes spawned via CreateProcessA/W are automatically followed.
// By contrast, ETW (Event Tracing for Windows) observes kernel/provider process,
// image, file, and network telemetry — ETW is NOT arbitrary WinAPI interception
// and is never presented as hooked WinAPI calls.

var (
	errAPITracingUnavailable = errors.New("Windows API tracing is unavailable: no real hook backend is installed")
	errFridaCLIMissing       = fmt.Errorf("%w: frida CLI not found on PATH", errAPITracingUnavailable)
	errFridaServerMissing    = fmt.Errorf("%w: matching Windows frida-server binary not found", errAPITracingUnavailable)
	errFridaVersionMismatch  = fmt.Errorf("%w: frida host CLI and frida-server version mismatch", errAPITracingUnavailable)
	errFridaABIMismatch      = fmt.Errorf("%w: frida architecture/ABI mismatch for target process", errAPITracingUnavailable)
	errAPITracerPrivileges   = fmt.Errorf("%w: insufficient privileges to open or instrument target process", errAPITracingUnavailable)
	errTargetProcessExited   = fmt.Errorf("%w: target process exited or crashed before hook installation completed", errAPITracingUnavailable)
	errAttachTimeout         = fmt.Errorf("%w: timed out waiting for pre-resume hook installation handshake", errAPITracingUnavailable)
)

const (
	defaultAPITracerChannelSize = 4096
	defaultAttachHandshakeWait  = 10 * time.Second
	winStillActiveExitCode      = 259
	processQueryLimitedInfo     = 0x1000
)

var (
	modKernel32APITracer = syscall.NewLazyDLL("kernel32.dll")
	procIsWow64Process   = modKernel32APITracer.NewProc("IsWow64Process")
)

// apiTracerStatusProvider is an internal interface queried by
// windowsEnhancedComponents to surface backpressure drops, coverage gaps,
// child-attach errors, and Frida session metadata in the sandbox report
// without altering the exported APITracer interface.
type apiTracerStatusProvider interface {
	DroppedCalls() uint64
	DegradedStatuses() []ComponentStatus
	FridaSessionSnapshot() *FridaSession
}

// targetProcessInfo describes the probed state and bitness of a Windows PID.
type targetProcessInfo struct {
	PID         int
	Arch        string // "x86", "x86_64", or "arm64"
	PointerSize int    // 4 or 8
	IsWow64     bool
}

// fridaToolchainInfo holds verified Frida CLI and optional local server details.
type fridaToolchainInfo struct {
	FridaBin      string
	HostVersion   string
	ServerBinary  string
	ServerVersion string
	ServerHost    string
	TargetArch    string
}

// fridaSessionStream abstracts a running Frida agent stream for a single PID.
type fridaSessionStream interface {
	Stdout() io.Reader
	Close() error
}

// fridaBackendDriver allows deterministic testing of the full windowsAPITracer
// pipeline (handshake, JSON event parsing, 32/64-bit checks, child follow,
// backpressure, target crash, Detach/Stop cleanup) without launching a real EXE.
type fridaBackendDriver interface {
	ProbeProcess(pid int) (targetProcessInfo, error)
	ResolveToolchain(targetArch string, pid int) (fridaToolchainInfo, error)
	StartSession(ctx context.Context, pid int, info targetProcessInfo, tc fridaToolchainInfo, categories []string) (fridaSessionStream, string, error)
}

type fridaAPIMessage struct {
	Timestamp  int64          `json:"ts"`
	ProcessID  int            `json:"pid"`
	ThreadID   int            `json:"tid"`
	Category   string         `json:"cat"`
	Module     string         `json:"mod"`
	Function   string         `json:"fn"`
	Parameters []APIParameter `json:"params"`
	ReturnVal  string         `json:"ret"`
	LastError  uint32         `json:"err"`
	StackTrace []string       `json:"stack,omitempty"`
}

type fridaChildMessage struct {
	ParentPID int    `json:"parent_pid"`
	ChildPID  int    `json:"child_pid"`
	ChildTID  int    `json:"child_tid"`
	Suspended bool   `json:"suspended"`
	Function  string `json:"fn"`
}

type fridaHookGap struct {
	Category string `json:"category"`
	Module   string `json:"module"`
	Function string `json:"function"`
	Reason   string `json:"reason"`
}

type fridaSessionHandshake struct {
	Type        string         `json:"type"`
	PID         int            `json:"pid"`
	Arch        string         `json:"arch"`
	PointerSize int            `json:"pointer_size"`
	Hooked      []string       `json:"hooked"`
	Gaps        []fridaHookGap `json:"gaps"`
	Error       string         `json:"error,omitempty"`
}

type fridaProcessSession struct {
	pid        int
	arch       string
	stream     fridaSessionStream
	tempDir    string
	stopOnce   sync.Once
	stopCh     chan struct{}
	doneCh     chan struct{}
	detached   atomic.Bool
	readyEvent fridaSessionHandshake
}

func (s *fridaProcessSession) requestStop() {
	s.stopOnce.Do(func() {
		s.detached.Store(true)
		close(s.stopCh)
		if s.stream != nil {
			_ = s.stream.Close()
		}
		if s.tempDir != "" {
			_ = os.RemoveAll(s.tempDir)
		}
	})
}

// windowsAPITracer implements APITracer on Windows using Frida user-mode hooks.
type windowsAPITracer struct {
	calls               chan APICall
	channelCap          int
	requestedCategories []string
	supportedCategories []string
	categorySet         map[string]bool

	mu               sync.Mutex
	stateMu          sync.RWMutex
	stopped          bool
	sessions         map[int]*fridaProcessSession
	degradedStatuses []ComponentStatus
	fridaSession     FridaSession

	childCtx       context.Context
	childCtxCancel context.CancelFunc
	wg             sync.WaitGroup

	emittedCalls uint64
	droppedCalls uint64

	driver        fridaBackendDriver
	handshakeWait time.Duration
}

var newWindowsFridaDriver = func() fridaBackendDriver {
	return &osWindowsFridaDriver{}
}

func newAPITracer(categories []string) APITracer {
	return newWindowsAPITracerWithConfig(categories, defaultAPITracerChannelSize, newWindowsFridaDriver())
}

func newWindowsAPITracerWithConfig(categories []string, channelCap int, driver fridaBackendDriver) *windowsAPITracer {
	if channelCap <= 0 {
		channelCap = defaultAPITracerChannelSize
	}
	if driver == nil {
		driver = newWindowsFridaDriver()
	}

	childCtx, childCancel := context.WithCancel(context.Background())
	t := &windowsAPITracer{
		calls:               make(chan APICall, channelCap),
		channelCap:          channelCap,
		requestedCategories: append([]string(nil), categories...),
		categorySet:         make(map[string]bool),
		sessions:            make(map[int]*fridaProcessSession),
		childCtx:            childCtx,
		childCtxCancel:      childCancel,
		driver:              driver,
		handshakeWait:       defaultAttachHandshakeWait,
		fridaSession: FridaSession{
			Requested: true,
			Mode:      "attach-pre-resume",
		},
	}

	if len(categories) == 0 {
		for _, cat := range SupportedAPICategories() {
			t.supportedCategories = append(t.supportedCategories, cat)
			t.categorySet[strings.ToLower(cat)] = true
		}
	} else {
		for _, cat := range categories {
			trimmed := strings.TrimSpace(cat)
			if trimmed == "" {
				continue
			}
			if IsSupportedAPICategory(trimmed) {
				t.supportedCategories = append(t.supportedCategories, trimmed)
				t.categorySet[strings.ToLower(trimmed)] = true
			} else {
				t.recordDegradedLocked("coverage_gap", fmt.Sprintf(
					"unsupported API trace category %q (supported: %s)",
					trimmed, strings.Join(SupportedAPICategories(), ", "),
				))
			}
		}
	}

	return t
}

func (t *windowsAPITracer) recordDegraded(phase, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.recordDegradedLocked(phase, reason)
}

func (t *windowsAPITracer) recordDegradedLocked(phase, reason string) {
	for _, existing := range t.degradedStatuses {
		if existing.Phase == phase && existing.Reason == reason {
			return
		}
	}
	t.degradedStatuses = append(t.degradedStatuses, ComponentStatus{
		Name:   "api_tracing",
		Phase:  phase,
		Reason: reason,
	})
	t.fridaSession.warn("%s: %s", phase, reason)
}

// Attach connects the Frida WinAPI hook agent to pid and waits until hooks are
// installed before returning, ensuring zero attach race prior to resumeProcess.
func (t *windowsAPITracer) Attach(ctx context.Context, pid int) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if pid <= 0 {
		return fmt.Errorf("invalid process ID %d", pid)
	}

	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return fmt.Errorf("api tracer is stopped")
	}
	if _, exists := t.sessions[pid]; exists {
		t.mu.Unlock()
		return nil
	}
	if len(t.requestedCategories) > 0 && len(t.supportedCategories) == 0 {
		err := fmt.Errorf("%w: none of the requested categories (%s) are supported",
			errAPITracingUnavailable, strings.Join(t.requestedCategories, ", "))
		t.fridaSession.warn("attach: %v", err)
		t.mu.Unlock()
		return err
	}
	driver := t.driver
	categories := append([]string(nil), t.supportedCategories...)
	handshakeWait := t.handshakeWait
	t.mu.Unlock()

	procInfo, err := driver.ProbeProcess(pid)
	if err != nil {
		wrapped := classifyAttachError(pid, err)
		t.mu.Lock()
		t.fridaSession.warn("attach PID %d: %v", pid, wrapped)
		t.mu.Unlock()
		return wrapped
	}

	tc, err := driver.ResolveToolchain(procInfo.Arch, pid)
	if err != nil {
		wrapped := classifyAttachError(pid, err)
		t.mu.Lock()
		t.fridaSession.warn("attach PID %d: %v", pid, wrapped)
		t.mu.Unlock()
		return wrapped
	}

	attachCtx, cancel := context.WithTimeout(ctx, handshakeWait)
	defer cancel()

	stream, tempDir, err := driver.StartSession(attachCtx, pid, procInfo, tc, categories)
	if err != nil {
		if tempDir != "" {
			_ = os.RemoveAll(tempDir)
		}
		wrapped := classifyAttachError(pid, err)
		t.mu.Lock()
		t.fridaSession.warn("attach PID %d: %v", pid, wrapped)
		t.mu.Unlock()
		return wrapped
	}

	sess := &fridaProcessSession{
		pid:     pid,
		arch:    procInfo.Arch,
		stream:  stream,
		tempDir: tempDir,
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}

	reader := bufio.NewReaderSize(stream.Stdout(), 64*1024)
	handshakeCh := make(chan error, 1)

	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		sess.requestStop()
		return fmt.Errorf("api tracer is stopped")
	}
	t.sessions[pid] = sess
	t.fridaSession.DeviceABI = procInfo.Arch
	t.fridaSession.HostVersion = tc.HostVersion
	t.fridaSession.ServerBinary = tc.ServerBinary
	t.fridaSession.ServerVersion = tc.ServerVersion
	t.wg.Add(1)
	t.mu.Unlock()

	go t.runSessionReader(sess, reader, handshakeCh)

	select {
	case err := <-handshakeCh:
		if err != nil {
			t.cleanupFailedSession(pid, sess)
			wrapped := classifyAttachError(pid, err)
			t.mu.Lock()
			t.fridaSession.warn("attach PID %d: %v", pid, wrapped)
			t.mu.Unlock()
			return wrapped
		}
	case <-attachCtx.Done():
		t.cleanupFailedSession(pid, sess)
		var timeoutErr error
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			timeoutErr = fmt.Errorf("%w: PID %d: %v", errAttachTimeout, pid, ctx.Err())
		} else {
			timeoutErr = fmt.Errorf("%w: PID %d did not complete pre-resume hook handshake within %s", errAttachTimeout, pid, handshakeWait)
		}
		t.mu.Lock()
		t.fridaSession.warn("attach PID %d: %v", pid, timeoutErr)
		t.mu.Unlock()
		return timeoutErr
	}

	t.mu.Lock()
	t.fridaSession.Active = true
	for _, gap := range sess.readyEvent.Gaps {
		t.recordDegradedLocked("hook_gap", fmt.Sprintf(
			"PID %d (%s) %s!%s: %s",
			pid, procInfo.Arch, gap.Module, gap.Function, gap.Reason,
		))
	}
	t.mu.Unlock()

	return nil
}

func (t *windowsAPITracer) cleanupFailedSession(pid int, sess *fridaProcessSession) {
	sess.requestStop()
	<-sess.doneCh
	t.mu.Lock()
	delete(t.sessions, pid)
	t.mu.Unlock()
}

func (t *windowsAPITracer) runSessionReader(sess *fridaProcessSession, reader *bufio.Reader, handshakeCh chan<- error) {
	defer t.wg.Done()
	defer close(sess.doneCh)

	handshakeDone := false
	var lastDiagnosticLine string

	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				if !handshakeDone {
					if strings.HasPrefix(trimmed, "FRIDA_SESSION ") {
						payload := strings.TrimSpace(strings.TrimPrefix(trimmed, "FRIDA_SESSION "))
						var hs fridaSessionHandshake
						if jerr := json.Unmarshal([]byte(payload), &hs); jerr != nil {
							handshakeDone = true
							handshakeCh <- fmt.Errorf("%w: invalid session handshake from PID %d: %v", errAPITracingUnavailable, sess.pid, jerr)
							return
						}
						if hs.Type == "error" || hs.Error != "" {
							handshakeDone = true
							handshakeCh <- fmt.Errorf("%w: agent error in PID %d: %s", errAPITracingUnavailable, sess.pid, hs.Error)
							return
						}
						if hs.Type == "ready" {
							if hs.PointerSize > 0 && ((sess.arch == "x86" && hs.PointerSize != 4) || (sess.arch == "x86_64" && hs.PointerSize != 8)) {
								handshakeDone = true
								handshakeCh <- fmt.Errorf("%w: PID %d probed as %s but agent reported pointer_size=%d",
									errFridaABIMismatch, sess.pid, sess.arch, hs.PointerSize)
								return
							}
							sess.readyEvent = hs
							handshakeDone = true
							handshakeCh <- nil
						}
						continue
					}
					lastDiagnosticLine = trimmed
				} else {
					t.handleStreamLine(sess, trimmed)
				}
			}
		}

		if err != nil {
			if !handshakeDone {
				handshakeDone = true
				if sess.detached.Load() {
					handshakeCh <- fmt.Errorf("%w: session detached during handshake for PID %d", errAPITracingUnavailable, sess.pid)
				} else if lastDiagnosticLine != "" {
					handshakeCh <- classifyDiagnosticLine(sess.pid, lastDiagnosticLine)
				} else if errors.Is(err, io.EOF) {
					handshakeCh <- fmt.Errorf("%w: PID %d terminated before hook handshake completed", errTargetProcessExited, sess.pid)
				} else {
					handshakeCh <- fmt.Errorf("%w: stream error on PID %d before handshake: %v", errAPITracingUnavailable, sess.pid, err)
				}
				return
			}

			// Post-handshake stream termination: if not explicitly detached/stopped,
			// record unexpected errors if any occurred.
			if !sess.detached.Load() && !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) {
				t.recordDegraded("runtime", fmt.Sprintf("PID %d stream closed with error: %v", sess.pid, err))
			}
			t.mu.Lock()
			delete(t.sessions, sess.pid)
			t.mu.Unlock()
			sess.requestStop()
			return
		}
	}
}

func (t *windowsAPITracer) handleStreamLine(sess *fridaProcessSession, line string) {
	switch {
	case strings.HasPrefix(line, "FRIDA_API "):
		payload := strings.TrimSpace(strings.TrimPrefix(line, "FRIDA_API "))
		var msg fridaAPIMessage
		if err := json.Unmarshal([]byte(payload), &msg); err != nil {
			t.recordDegraded("parse_error", fmt.Sprintf("PID %d malformed FRIDA_API event: %v", sess.pid, err))
			return
		}
		t.processAPIMessage(sess.pid, msg)

	case strings.HasPrefix(line, "FRIDA_CHILD "):
		payload := strings.TrimSpace(strings.TrimPrefix(line, "FRIDA_CHILD "))
		var child fridaChildMessage
		if err := json.Unmarshal([]byte(payload), &child); err != nil {
			t.recordDegraded("parse_error", fmt.Sprintf("PID %d malformed FRIDA_CHILD event: %v", sess.pid, err))
			return
		}
		t.followChildProcess(sess.pid, child)

	case strings.HasPrefix(line, "FRIDA_SESSION "):
		payload := strings.TrimSpace(strings.TrimPrefix(line, "FRIDA_SESSION "))
		var hs fridaSessionHandshake
		if err := json.Unmarshal([]byte(payload), &hs); err == nil && hs.Error != "" {
			t.recordDegraded("runtime", fmt.Sprintf("PID %d agent runtime error: %s", sess.pid, hs.Error))
		}
	}
}

func (t *windowsAPITracer) processAPIMessage(defaultPID int, msg fridaAPIMessage) {
	fn := strings.TrimSpace(msg.Function)
	if fn == "" {
		return
	}
	if len(t.categorySet) > 0 && msg.Category != "" && !t.categorySet[strings.ToLower(strings.TrimSpace(msg.Category))] {
		return
	}
	pid := msg.ProcessID
	if pid <= 0 {
		pid = defaultPID
	}
	ts := time.Now().UTC()
	if msg.Timestamp > 0 {
		ts = time.UnixMilli(msg.Timestamp).UTC()
	}
	mod := strings.TrimSpace(msg.Module)
	if mod == "" {
		mod = "unknown.dll"
	}

	call := APICall{
		Timestamp:   ts,
		ProcessID:   pid,
		ThreadID:    msg.ThreadID,
		Module:      mod,
		Function:    fn,
		Parameters:  msg.Parameters,
		ReturnValue: strings.TrimSpace(msg.ReturnVal),
		LastError:   msg.LastError,
		StackTrace:  msg.StackTrace,
	}

	t.stateMu.RLock()
	defer t.stateMu.RUnlock()
	if t.stopped {
		return
	}

	select {
	case t.calls <- call:
		atomic.AddUint64(&t.emittedCalls, 1)
	default:
		atomic.AddUint64(&t.droppedCalls, 1)
	}
}

func (t *windowsAPITracer) followChildProcess(parentPID int, child fridaChildMessage) {
	if child.ChildPID <= 0 || child.ChildPID == parentPID {
		return
	}
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}
	if _, already := t.sessions[child.ChildPID]; already {
		t.mu.Unlock()
		return
	}
	childCtx := t.childCtx
	t.wg.Add(1)
	t.mu.Unlock()

	go func() {
		defer t.wg.Done()
		if err := t.Attach(childCtx, child.ChildPID); err != nil {
			t.recordDegraded("child_attach", fmt.Sprintf(
				"failed to attach to child PID %d (spawned by PID %d via %s): %v",
				child.ChildPID, parentPID, child.Function, err,
			))
			return
		}
		if !child.Suspended {
			t.mu.Lock()
			t.fridaSession.warn(
				"child PID %d spawned without CREATE_SUSPENDED via %s; attached post-spawn",
				child.ChildPID, child.Function,
			)
			t.mu.Unlock()
		}
	}()
}

// Detach removes the Frida agent from pid and waits for its reader goroutine to exit.
func (t *windowsAPITracer) Detach(pid int) error {
	t.mu.Lock()
	sess, ok := t.sessions[pid]
	if !ok {
		t.mu.Unlock()
		return fmt.Errorf("not attached to process %d", pid)
	}
	delete(t.sessions, pid)
	t.mu.Unlock()

	sess.requestStop()
	<-sess.doneCh
	return nil
}

// Calls returns the read-only channel of observed API calls.
func (t *windowsAPITracer) Calls() <-chan APICall {
	return t.calls
}

// Stop detaches all active sessions, waits for all background goroutines to
// finish, and closes the Calls channel once.
func (t *windowsAPITracer) Stop() error {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return nil
	}
	t.childCtxCancel()
	active := make([]*fridaProcessSession, 0, len(t.sessions))
	for pid, sess := range t.sessions {
		active = append(active, sess)
		delete(t.sessions, pid)
	}
	t.mu.Unlock()

	for _, sess := range active {
		sess.requestStop()
	}

	t.wg.Wait()

	t.stateMu.Lock()
	t.mu.Lock()
	if !t.stopped {
		t.stopped = true
		t.fridaSession.EventCount = int(atomic.LoadUint64(&t.emittedCalls))
		t.fridaSession.Categories = append([]string(nil), t.supportedCategories...)
		if dropped := atomic.LoadUint64(&t.droppedCalls); dropped > 0 {
			t.recordDegradedLocked("backpressure", fmt.Sprintf(
				"dropped %d API calls due to bounded channel capacity (%d)",
				dropped, t.channelCap,
			))
		}
		close(t.calls)
	}
	t.mu.Unlock()
	t.stateMu.Unlock()

	return nil
}

// DroppedCalls returns the total number of API calls dropped due to backpressure.
func (t *windowsAPITracer) DroppedCalls() uint64 {
	return atomic.LoadUint64(&t.droppedCalls)
}

// DegradedStatuses returns a snapshot of all recorded API-tracing degradation
// and coverage-gap statuses.
func (t *windowsAPITracer) DegradedStatuses() []ComponentStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]ComponentStatus, len(t.degradedStatuses))
	copy(out, t.degradedStatuses)
	if dropped := atomic.LoadUint64(&t.droppedCalls); dropped > 0 {
		hasBackpressure := false
		for _, s := range out {
			if s.Phase == "backpressure" {
				hasBackpressure = true
				break
			}
		}
		if !hasBackpressure {
			out = append(out, ComponentStatus{
				Name:  "api_tracing",
				Phase: "backpressure",
				Reason: fmt.Sprintf(
					"dropped %d API calls due to bounded channel capacity (%d)",
					dropped, t.channelCap,
				),
			})
		}
	}
	return out
}

// FridaSessionSnapshot returns a copy of the FridaSession telemetry.
func (t *windowsAPITracer) FridaSessionSnapshot() *FridaSession {
	t.mu.Lock()
	defer t.mu.Unlock()
	snap := t.fridaSession
	snap.EventCount = int(atomic.LoadUint64(&t.emittedCalls))
	snap.Categories = append([]string(nil), t.supportedCategories...)
	snap.Warnings = append([]string(nil), t.fridaSession.Warnings...)
	return &snap
}

func classifyDiagnosticLine(pid int, line string) error {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "access is denied") || strings.Contains(lower, "permission denied") || strings.Contains(lower, "elevated"):
		return fmt.Errorf("%w: PID %d: %s", errAPITracerPrivileges, pid, line)
	case strings.Contains(lower, "version mismatch") || strings.Contains(lower, "protocolmismatch") || strings.Contains(lower, "incompatible"):
		return fmt.Errorf("%w: PID %d: %s", errFridaVersionMismatch, pid, line)
	case strings.Contains(lower, "architecture") || strings.Contains(lower, "32-bit") || strings.Contains(lower, "64-bit") || strings.Contains(lower, "wow64"):
		return fmt.Errorf("%w: PID %d: %s", errFridaABIMismatch, pid, line)
	case strings.Contains(lower, "process not found") || strings.Contains(lower, "unable to find process") || strings.Contains(lower, "terminated"):
		return fmt.Errorf("%w: PID %d: %s", errTargetProcessExited, pid, line)
	default:
		return fmt.Errorf("%w: PID %d: %s", errAPITracingUnavailable, pid, line)
	}
}

func classifyAttachError(pid int, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, errAPITracingUnavailable) {
		return err
	}
	return classifyDiagnosticLine(pid, err.Error())
}

// osWindowsFridaDriver is the production implementation of fridaBackendDriver.
type osWindowsFridaDriver struct{}

func (d *osWindowsFridaDriver) ProbeProcess(pid int) (targetProcessInfo, error) {
	handle, err := syscall.OpenProcess(processQueryLimitedInfo, false, uint32(pid))
	if err != nil {
		if errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			return targetProcessInfo{}, fmt.Errorf("%w: OpenProcess(%d) access denied: %v", errAPITracerPrivileges, pid, err)
		}
		return targetProcessInfo{}, fmt.Errorf("%w: OpenProcess(%d) failed: %v", errTargetProcessExited, pid, err)
	}
	defer syscall.CloseHandle(handle)

	var exitCode uint32
	if err := syscall.GetExitCodeProcess(handle, &exitCode); err != nil {
		return targetProcessInfo{}, fmt.Errorf("%w: GetExitCodeProcess(%d) failed: %v", errAPITracingUnavailable, pid, err)
	}
	if exitCode != winStillActiveExitCode {
		return targetProcessInfo{}, fmt.Errorf("%w: PID %d already exited with code %d", errTargetProcessExited, pid, exitCode)
	}

	hostArch := fridaWindowsArchForABI(runtime.GOARCH)
	if hostArch == "" {
		hostArch = "x86_64"
	}

	isWow64 := false
	if procIsWow64Process.Find() == nil {
		var wow64Val int32
		r1, _, _ := procIsWow64Process.Call(uintptr(handle), uintptr(unsafe.Pointer(&wow64Val)))
		if r1 != 0 && wow64Val != 0 {
			isWow64 = true
		}
	}

	targetArch := hostArch
	ptrSize := 8
	if hostArch == "x86" || isWow64 {
		targetArch = "x86"
		ptrSize = 4
	}

	return targetProcessInfo{
		PID:         pid,
		Arch:        targetArch,
		PointerSize: ptrSize,
		IsWow64:     isWow64,
	}, nil
}

func (d *osWindowsFridaDriver) ResolveToolchain(targetArch string, pid int) (fridaToolchainInfo, error) {
	fridaBin := strings.TrimSpace(os.Getenv("MEGA_FRIDA_BIN"))
	if fridaBin == "" {
		found, err := exec.LookPath("frida")
		if err != nil {
			return fridaToolchainInfo{}, fmt.Errorf("%w: install frida-tools or set MEGA_FRIDA_BIN (%v)", errFridaCLIMissing, err)
		}
		fridaBin = found
	} else if _, err := os.Stat(fridaBin); err != nil {
		return fridaToolchainInfo{}, fmt.Errorf("%w: MEGA_FRIDA_BIN %q not found: %v", errFridaCLIMissing, fridaBin, err)
	}

	hostVer := fridaHostVersion(fridaBin)
	if hostVer == "" {
		return fridaToolchainInfo{}, fmt.Errorf("%w: failed to execute %q --version", errFridaCLIMissing, fridaBin)
	}

	// If a 32-bit host build tries to instrument a 64-bit target, reject upfront.
	hostArch := fridaWindowsArchForABI(runtime.GOARCH)
	if hostArch == "x86" && targetArch == "x86_64" {
		return fridaToolchainInfo{}, fmt.Errorf("%w: 32-bit sandbox host cannot instrument 64-bit PID %d", errFridaABIMismatch, pid)
	}

	srvPath, srvVer, mismatched := fridaWindowsServerForArch(targetArch)
	if srvPath == "" && len(mismatched) > 0 {
		return fridaToolchainInfo{}, fmt.Errorf("%w: target PID %d requires %s but only found %s",
			errFridaABIMismatch, pid, targetArch, strings.Join(mismatched, ", "))
	}
	if srvPath != "" && srvVer != "" && fridaMajorMinor(hostVer) != fridaMajorMinor(srvVer) {
		return fridaToolchainInfo{}, fmt.Errorf("%w: host frida %s vs %s (%s)",
			errFridaVersionMismatch, hostVer, filepath.Base(srvPath), srvVer)
	}
	if strings.TrimSpace(os.Getenv("MEGA_FRIDA_REQUIRE_SERVER")) == "1" && srvPath == "" {
		return fridaToolchainInfo{}, fmt.Errorf("%w: MEGA_FRIDA_REQUIRE_SERVER=1 and no %s frida-server found in %s",
			errFridaServerMissing, targetArch, strings.Join(fridaSearchDirs(), ", "))
	}

	srvBinary := ""
	if srvPath != "" {
		srvBinary = filepath.Base(srvPath)
	}

	return fridaToolchainInfo{
		FridaBin:      fridaBin,
		HostVersion:   hostVer,
		ServerBinary:  srvBinary,
		ServerVersion: srvVer,
		ServerHost:    strings.TrimSpace(os.Getenv("MEGA_FRIDA_HOST")),
		TargetArch:    targetArch,
	}, nil
}

type osFridaCmdStream struct {
	cmd       *exec.Cmd
	stdout    io.ReadCloser
	stdin     io.WriteCloser
	closeOnce sync.Once
}

func (s *osFridaCmdStream) Stdout() io.Reader {
	return s.stdout
}

func (s *osFridaCmdStream) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		if s.stdin != nil {
			_ = s.stdin.Close()
		}
		if s.cmd != nil && s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
			_, _ = s.cmd.Process.Wait()
		}
		if s.stdout != nil {
			closeErr = s.stdout.Close()
		}
	})
	return closeErr
}

func (d *osWindowsFridaDriver) StartSession(ctx context.Context, pid int, _ targetProcessInfo, tc fridaToolchainInfo, categories []string) (fridaSessionStream, string, error) {
	tempDir, err := os.MkdirTemp("", fmt.Sprintf("mega-frida-win-%d-*", pid))
	if err != nil {
		return nil, "", fmt.Errorf("%w: create script temp dir: %v", errAPITracingUnavailable, err)
	}

	userScript := strings.TrimSpace(os.Getenv("MEGA_FRIDA_WINDOWS_SCRIPT"))
	scriptPath, err := fridaWriteWindowsScript(tempDir, userScript, categories)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, "", fmt.Errorf("%w: prepare windows frida script: %v", errAPITracingUnavailable, err)
	}

	args := []string{"-p", fmt.Sprintf("%d", pid), "-l", scriptPath, "-q"}
	if tc.ServerHost != "" {
		args = append([]string{"-H", tc.ServerHost}, args...)
	}

	cmd := exec.CommandContext(ctx, tc.FridaBin, args...)
	pr, pw, err := os.Pipe()
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, "", fmt.Errorf("%w: create stdout pipe: %v", errAPITracingUnavailable, err)
	}
	cmd.Stdout = pw
	cmd.Stderr = pw
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		_ = os.RemoveAll(tempDir)
		return nil, "", fmt.Errorf("%w: create stdin pipe: %v", errAPITracingUnavailable, err)
	}

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = pr.Close()
		_ = pw.Close()
		_ = os.RemoveAll(tempDir)
		return nil, "", fmt.Errorf("%w: start frida CLI for PID %d: %v", errAPITracingUnavailable, pid, err)
	}
	// Close parent write-end so pr sees EOF as soon as child process exits.
	_ = pw.Close()

	return &osFridaCmdStream{
		cmd:    cmd,
		stdout: pr,
		stdin:  stdin,
	}, tempDir, nil
}
