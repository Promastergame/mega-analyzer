package vmware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/sandbox"
)

type guestVMFixture struct {
	host               fakeVMware
	files              map[string][]byte
	guestDir           string
	request            GuestRequest
	commands           []string
	denyLogin          bool
	startingLogin      int
	onLaunch           context.CancelFunc
	outside            string
	powerOffAfterDrain bool
	guestGone          bool
}

func (f *guestVMFixture) complete(done bool) {
	state, _ := json.Marshal(guestState{Version: 1, ID: f.request.ID, PID: 300, Done: done})
	f.files[f.guestDir+`\state.json`] = state
	result, _ := json.Marshal(guestResult{ID: f.request.ID, Report: &sandbox.Report{
		SessionID: "untrusted-guest-session", JSONPath: f.outside, MarkdownPath: f.outside + ".md",
		SHA256: f.request.SHA256, Executed: true, RootPID: 400, ExitCode: 0,
		NetworkMode: "vmware_disconnected", NetworkGuardApplied: true,
		Processes:          []sandbox.ObservedProcess{{PID: 400, Name: "sample.exe"}},
		SandboxPermissions: sandbox.SandboxPermissions{MaxMemoryMB: f.request.MemoryMB},
	}})
	f.files[f.guestDir+`\result.json`] = result
	var events []byte
	for i, event := range []Event{{Type: "status", Stage: "observing"}, {Type: "process", PID: 400, Process: "sample.exe"}, {Type: "activity", EventID: "event-1", Category: "file", Action: "appeared", Object: "appdata/marker.txt", Source: "workspace_metadata_snapshot", Attribution: "unknown"}, {Type: "network", PID: 400, Protocol: "TCP", RemoteAddr: "192.0.2.1:80", State: "SYN_SENT"}} {
		line, _ := json.Marshal(guestEvent{f.request.ID, uint64(i + 1), event})
		events = append(events, append(line, '\n')...)
	}
	f.files[f.guestDir+`\events.jsonl`] = events
	f.files[f.guestDir+`\stdout.log`] = []byte("benign guest fixture\n")
	f.files[f.guestDir+`\stderr.log`] = nil
	f.files[f.guestDir+`\activity.jsonl`] = nil
}

func (f *guestVMFixture) run(ctx context.Context, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if args[0] != "-gu" {
		f.commands = append(f.commands, args[0])
		switch args[0] {
		case "checkToolsState":
			return []byte("installed\n"), nil
		case "start":
			f.host.active = true
			return nil, nil
		case "stop":
			if args[2] != "soft" {
				return nil, errors.New("unexpected hard poweroff")
			}
			f.host.active = false
			return nil, nil
		default:
			return f.host.run(ctx, args...)
		}
	}
	if len(args) < 6 || args[1] != "guest-user" || args[2] != "-gp" || args[5] != f.host.path {
		return nil, errors.New("invalid guest invocation")
	}
	command := args[4]
	f.commands = append(f.commands, command)
	if f.guestGone {
		return nil, errors.New("guest operating system is not running")
	}
	switch command {
	case "listProcessesInGuest":
		if f.startingLogin > 0 {
			f.startingLogin--
			return nil, errors.New("The VMware Tools are not running in the virtual machine")
		}
		if f.denyLogin {
			return nil, errors.New("guest authentication denied")
		}
		return []byte("Process list"), nil
	case "createDirectoryInGuest":
		if f.guestDir == "" {
			f.guestDir = args[6]
		} else if args[6] != f.guestDir+`\input` {
			return nil, errors.New("unexpected guest subdirectory")
		}
		return nil, nil
	case "CopyFileFromHostToGuest":
		data, err := os.ReadFile(args[6])
		if err != nil {
			return nil, err
		}
		f.files[args[7]] = data
		if strings.HasSuffix(args[7], `\control.txt`) && strings.HasSuffix(string(data), "|stop") {
			f.complete(true)
		}
		return nil, nil
	case "CopyFileFromGuestToHost":
		data, ok := f.files[args[6]]
		if !ok {
			return nil, os.ErrNotExist
		}
		err := os.WriteFile(args[7], data, 0600)
		if f.powerOffAfterDrain && strings.HasSuffix(args[6], `\events.jsonl`) {
			f.guestGone, f.host.active = true, false
		}
		return nil, err
	case "runProgramInGuest":
		if (len(args) == 12 && args[6] == "-noWait" && args[7] == "-interactive" && args[8] == `C:\Windows\System32\cmd.exe` && args[9] == "/c" && args[10] == "exit" && args[11] == "0") || (len(args) == 11 && args[6] == "-interactive" && args[7] == `C:\Windows\System32\cmd.exe` && args[8] == "/c" && args[9] == "exit" && args[10] == "0") {
			return nil, nil
		}
		expected := 10
		launch := 7
		if len(args) > 7 && args[7] == "-interactive" {
			expected, launch = 11, 8
		}
		if len(args) != expected || args[6] != "-noWait" || args[launch] != f.guestDir+`\collector.exe` || args[launch+1] != "--vmware-guest-session" || args[launch+2] != f.guestDir {
			return nil, errors.New("unexpected guest executable or launch flags")
		}
		if err := decodeJSON(f.files[f.guestDir+`\request.json`], &f.request); err != nil {
			return nil, err
		}
		f.complete(f.onLaunch == nil && !f.powerOffAfterDrain)
		if f.onLaunch != nil {
			f.onLaunch()
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected operation %s", command)
	}
}

func TestVMwarePowerOffRetainsHostObservations(t *testing.T) {
	fake, req := hostExecutionFixture(t)
	fake.powerOffAfterDrain = true
	var checkpoint sandbox.Report
	var reason string
	report, err := New(fake.run, t.TempDir()).RunSession(context.Background(), req, func(e Event) {
		if e.Type == "report" {
			reason = e.CompletionReason
		}
		// The next host status after interruption sees the persisted checkpoint.
	})
	if err == nil || report == nil || report.ExecutionError == nil || report.ExecutionError.Code != "guest_powered_off" {
		t.Fatalf("missing shutdown cause: %+v, %v", report, err)
	}
	if !report.Executed || !report.VMware.PoweredOff || !report.VMware.Incomplete || report.TimedOut || reason != "interrupted" {
		t.Fatalf("incorrect interrupted session: %+v", report)
	}
	data, err := os.ReadFile(report.JSONPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		t.Fatal(err)
	}
	if len(checkpoint.Processes) != 1 || checkpoint.Processes[0].PID != 400 || len(checkpoint.Connections) != 1 || checkpoint.Connections[0].RemoteAddr != "192.0.2.1:80" {
		t.Fatalf("host report lost received observations: %+v", checkpoint)
	}
	if checkpoint.ActivityPath == "" {
		t.Fatal("checkpoint missing ActivityPath")
	}
	activity, err := os.ReadFile(report.ActivityPath)
	if err != nil || !strings.Contains(string(activity), "appdata/marker.txt") || checkpoint.ActivityCount != 1 {
		t.Fatalf("host activity lost: %s, %v", activity, err)
	}
	for _, command := range fake.commands {
		if command == "stop" {
			t.Fatal("shutdown requested for an already powered-off guest")
		}
	}
}

func hostExecutionFixture(t *testing.T) (*guestVMFixture, ExecutionRequest) {
	t.Helper()
	path := executionFixture(t)
	dir := t.TempDir()
	sample := filepath.Join(dir, "fixture.exe")
	collector := filepath.Join(dir, "analyzer.exe")
	for _, name := range []string{sample, collector} {
		if err := os.WriteFile(name, []byte("MZ fixture data; cannot be executed"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for attempt := 0; attempt < 10; attempt++ {
			if err := os.RemoveAll(dir); err == nil || os.IsNotExist(err) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	fake := &guestVMFixture{host: fakeVMware{path: path}, files: map[string][]byte{}, outside: filepath.Join(t.TempDir(), "must-not-exist.json")}
	req := ExecutionRequest{VMX: path, Name: "Fixture VM", Username: "guest-user", Password: "test-only-secret", SamplePath: sample, CollectorPath: collector, OutputDir: filepath.Join(dir, "reports"), MemoryMB: 256, CPUCores: 2, Duration: 0, Args: `--name "A B"`}
	return fake, req
}

func TestVMwareSessionUsesGuestAndImportsOnlyBoundReportPaths(t *testing.T) {
	fake, req := hostExecutionFixture(t)
	var events []Event
	report, err := New(fake.run, t.TempDir()).RunSession(context.Background(), req, func(e Event) { events = append(events, e) })
	if err != nil {
		t.Fatal(err)
	}
	if !report.Executed || !report.VMware.PoweredOff || report.VMware.Incomplete || fake.host.active {
		t.Fatalf("session = %+v", report)
	}
	if fake.request.CPUCores != 2 || fake.request.MemoryMB != 256 || fake.request.DurationSeconds != 0 || fake.request.Args != req.Args {
		t.Fatal("execution parameters were not forwarded")
	}
	if _, err := os.Stat(fake.outside); !os.IsNotExist(err) {
		t.Fatal("guest chose a host report path")
	}
	for _, path := range []string{report.JSONPath, report.MarkdownPath, report.StdoutPath, report.StderrPath, report.ActivityPath} {
		rel, err := filepath.Rel(report.SessionDir, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			t.Fatalf("artifact escaped session: %q", path)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
	observed := false
	for _, event := range events {
		observed = observed || event.Stage == "observing"
	}
	if !observed {
		t.Fatal("guest observation never reached the host")
	}
	if data := string(fake.files[fake.guestDir+`\request.json`]); strings.Contains(data, "password") || strings.Contains(data, "guest-user") {
		t.Fatal("guest request contains host credentials")
	}
}

func TestVMwareSessionWaitsForGuestOperationAfterToolsInstalled(t *testing.T) {
	fake, req := hostExecutionFixture(t)
	fake.startingLogin = 1
	report, err := New(fake.run, t.TempDir()).RunSession(context.Background(), req, nil)
	if err != nil || report == nil || !report.Executed || report.VMware.Incomplete {
		t.Fatalf("guest never became ready: %+v, %v", report, err)
	}
	probes := 0
	for _, command := range fake.commands {
		if command == "listProcessesInGuest" {
			probes++
		}
		if command == "CopyFileFromHostToGuest" && probes < 2 {
			t.Fatal("sample transferred before successful guest login")
		}
	}
}

func TestVMwareCancelStopsGuestAndCollectsReport(t *testing.T) {
	fake, req := hostExecutionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake.onLaunch = cancel
	report, err := New(fake.run, t.TempDir()).RunSession(ctx, req, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation = %v", err)
	}
	if report == nil || !report.Executed || !report.VMware.PoweredOff || report.VMware.Incomplete {
		t.Fatalf("stopped session lost its result: %+v", report)
	}
	if string(fake.files[fake.guestDir+`\control.txt`]) != fake.request.ID+"|stop" {
		t.Fatal("guest stop command missing")
	}
}

func TestVMwareLoginFailureNeverTransfersOrExecutesSample(t *testing.T) {
	fake, req := hostExecutionFixture(t)
	fake.denyLogin = true
	req.Password = "test-only-secret"
	report, err := New(fake.run, t.TempDir()).RunSession(context.Background(), req, nil)
	if err == nil || report == nil || report.Executed || !report.VMware.PoweredOff {
		t.Fatalf("login failure = %+v %v", report, err)
	}
	for _, command := range fake.commands {
		if command == "CopyFileFromHostToGuest" || command == "runProgramInGuest" {
			t.Fatal("authentication failure reached sample transfer or execution")
		}
	}
	data, _ := os.ReadFile(report.JSONPath)
	if strings.Contains(string(data), req.Password) || strings.Contains(err.Error(), req.Password) {
		t.Fatal("password escaped into diagnostics")
	}
	if !strings.Contains(err.Error(), req.Username) {
		t.Fatal("login failure does not identify the rejected account")
	}
}

func TestVMwareEmptyPasswordDoesNotBootGuest(t *testing.T) {
	fake, req := hostExecutionFixture(t)
	req.Password = ""
	report, err := New(fake.run, t.TempDir()).RunSession(context.Background(), req, nil)
	if err == nil || report != nil || len(fake.commands) != 0 {
		t.Fatalf("empty password reached VMware: report=%v, err=%v, commands=%v", report, err, fake.commands)
	}
}

func TestGuestDownloadLimitAndCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "download.json")
	if _, err := downloadGuestFile(context.Background(), path, 32, func(context.Context) error { return os.WriteFile(path, make([]byte, 33), 0600) }); err == nil {
		t.Fatal("oversized guest download accepted")
	}
	if ValidateCredentials("guest-user", " test-only-+$! ") != nil {
		t.Fatal("valid password with special characters rejected")
	}
	for _, username := range []string{"", " ", "user\nother", strings.Repeat("a", 257)} {
		if ValidateCredentials(username, "test-only-secret") == nil {
			t.Fatal("invalid username accepted")
		}
	}
	for _, password := range []string{"", "pass\nword", "pass\x00word", strings.Repeat("a", 1025)} {
		if ValidateCredentials("guest-user", password) == nil {
			t.Fatal("invalid password accepted")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := downloadGuestFile(ctx, path, 32, func(ctx context.Context) error {
		if err := os.WriteFile(path, make([]byte, 33), 0600); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("growing download was not cancelled: %v", err)
	}
}

func TestVMwarePreservesSelectedSampleName(t *testing.T) {
	fake, req := hostExecutionFixture(t)
	report, err := New(fake.run, t.TempDir()).RunSession(context.Background(), req, nil)
	if err != nil { t.Fatal(err) }
	if fake.request.SampleName != "fixture.exe" { t.Fatalf("lost filename: %+v", fake.request) }
	if _, ok := fake.files[fake.guestDir+`\input\fixture.exe`]; !ok { t.Fatal("selected file not copied to input directory") }
	if _, ok := fake.files[fake.guestDir+`\sample.exe`]; ok { t.Fatal("sample.exe placeholder used for new session") }
	if report.TargetCopied != fake.guestDir+`\input\fixture.exe` { t.Fatalf("wrong target: %q", report.TargetCopied) }
}

func TestVMwareInteractiveLaunchIsExplicit(t *testing.T) {
	for _, interactive := range []bool{false, true} {
		fake, req := hostExecutionFixture(t)
		req.Interactive = interactive
		seen := false
		invoke := func(ctx context.Context, args ...string) ([]byte, error) {
			if len(args) > 6 && args[4] == "runProgramInGuest" && strings.HasSuffix(args[len(args)-1], fake.guestDir) {
				seen = true
				got := len(args) > 7 && args[7] == "-interactive"
				if got != interactive { t.Fatalf("interactive=%v, args=%v", interactive, args[4:]) }
			}
			return fake.run(ctx, args...)
		}
		if _, err := New(invoke, t.TempDir()).RunSession(context.Background(), req, nil); err != nil { t.Fatal(err) }
		if !seen { t.Fatal("collector was not launched") }
	}
}

func TestVMwareInteractiveFailureDoesNotFallBack(t *testing.T) {
	fake, req := hostExecutionFixture(t)
	req.Interactive = true
	launches := 0
	invoke := func(ctx context.Context, args ...string) ([]byte, error) {
		if len(args) > 6 && args[4] == "runProgramInGuest" && strings.HasSuffix(args[len(args)-1], fake.guestDir) {
			launches++
			return nil, errors.New("user not logged in")
		}
		return fake.run(ctx, args...)
	}
	_, err := New(invoke, t.TempDir()).RunSession(context.Background(), req, nil)
	if err == nil || !strings.Contains(err.Error(), "видимый запуск") || launches != 1 {
		t.Fatalf("unexpected fallback: launches=%d, err=%v", launches, err)
	}
}

func TestWaitForGuestDesktopRetriesHarmlessProbe(t *testing.T) {
	calls := 0
	err := waitForGuestDesktop(context.Background(), func(context.Context) error {
		calls++
		if calls < 3 { return errors.New("user not logged in") }
		return nil
	}, time.Millisecond)
	if err != nil || calls != 3 { t.Fatalf("desktop wait: calls=%d, err=%v", calls, err) }
}

func TestWaitForGuestDesktopHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := waitForGuestDesktop(ctx, func(context.Context) error {
		calls++
		cancel()
		return errors.New("user not logged in")
	}, time.Millisecond)
	if !errors.Is(err, context.Canceled) || calls != 1 { t.Fatalf("desktop wait ignored cancel: %d, %v", calls, err) }
}
