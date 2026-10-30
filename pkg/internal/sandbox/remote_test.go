package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func remoteTestKey() *APICall {
	return &APICall{Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), ProcessID: 42, ThreadID: 7, Module: "bcrypt.dll", Function: "BCryptGenerateSymmetricKey", ReturnValue: "0x0",
		Parameters: []APIParameter{{Name: "hKey", Value: "0x123"}, {Name: "Algorithm", Value: "AES"}, {Name: "KeyHex", Value: "2b7e151628aed2a6abf7158809cf4f3c"}}}
}

func newTestRemoteJournal(t *testing.T) *remoteJournal {
	t.Helper()
	j, err := newRemoteJournal(t.TempDir(), "192.168.222.222:27042", `C:\Lab\fixture.exe`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.file.Close() })
	return j
}

func readyTestRemote(t *testing.T, j *remoteJournal) {
	t.Helper()
	for _, e := range []remoteEvent{{Kind: "ready", PID: 42, Hooked: []string{"bcrypt.dll!BCryptGenerateSymmetricKey"}}, {Kind: "launch", PID: 42}, {Kind: "resumed", PID: 42}} {
		if err := j.append(e); err != nil {
			t.Fatal(err)
		}
	}
}

func readRemoteReport(t *testing.T, path string) Report {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var r Report
	if err = json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRemoteKeySurvivesGuestDisconnectAndRecovery(t *testing.T) {
	j := newTestRemoteJournal(t)
	readyTestRemote(t, j)
	if err := j.append(remoteEvent{Kind: "api", Call: remoteTestKey()}); err != nil {
		t.Fatal(err)
	}
	// The readable snapshot exists BEFORE any stop/final-report operation.
	live := readRemoteReport(t, j.report.JSONPath)
	if len(live.CryptoAnalysis.Materials) != 1 || !live.RemoteCapture.Incomplete {
		t.Fatalf("live snapshot: %+v", live.RemoteCapture)
	}
	if err := j.file.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate an interrupted final write after a sudden guest/collector loss.
	f, err := os.OpenFile(j.report.RemoteCapture.JournalPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(`{"seq":6,"kind":"api"`)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	r, err := RecoverRemoteJournal(j.report.RemoteCapture.JournalPath, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !r.RemoteCapture.Recovered || !r.RemoteCapture.Incomplete || r.RemoteCapture.State != "recovered-incomplete" {
		t.Fatalf("status: %+v", r.RemoteCapture)
	}
	if len(r.CryptoAnalysis.Materials) != 1 || r.CryptoAnalysis.Materials[0].KeyHex != remoteTestKey().Parameters[2].Value || !r.CryptoAnalysis.Materials[0].ObservedAt.Equal(remoteTestKey().Timestamp) {
		t.Fatalf("lost captured key: %+v", r.CryptoAnalysis)
	}
	if r.SessionDir == j.report.SessionDir {
		t.Fatal("recovery overwrote source")
	}
}

func TestRemoteRecoveryRejectsCorruptCompleteRecords(t *testing.T) {
	for _, bad := range []string{"garbage\n", `{"seq":99,"kind":"heartbeat","at":"2026-01-01T00:00:00Z"}` + "\n", `{"seq":2,"kind":"heartbeat","at":"2026-01-01T00:00:00Z","extra":1}` + "\n"} {
		j := newTestRemoteJournal(t)
		j.file.Close()
		f, err := os.OpenFile(j.report.RemoteCapture.JournalPath, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString(bad)
		f.Close()
		if _, err = RecoverRemoteJournal(j.report.RemoteCapture.JournalPath, t.TempDir()); err == nil {
			t.Fatalf("accepted corruption: %q", bad)
		}
	}
}

type remoteAckChecker struct {
	t *testing.T
	j *remoteJournal
	bytes.Buffer
}

func (w *remoteAckChecker) Write(b []byte) (int, error) {
	// The bridge must never receive an ACK before the journal is readable.
	var ack struct {
		Ack uint64 `json:"ack"`
	}
	if err := json.Unmarshal(b, &ack); err != nil {
		w.t.Fatal(err)
	}
	data, err := os.ReadFile(w.j.report.RemoteCapture.JournalPath)
	if err != nil {
		w.t.Fatal(err)
	}
	if uint64(bytes.Count(data, []byte{'\n'})) != ack.Ack+1 {
		w.t.Fatal("ACK preceded journal write")
	}
	if ack.Ack == 4 && len(readRemoteReport(w.t, w.j.report.JSONPath).CryptoAnalysis.Materials) != 1 {
		w.t.Fatal("key ACK preceded snapshot")
	}
	return w.Buffer.Write(b)
}

func TestRemoteBridgeEOFAndAcknowledgment(t *testing.T) {
	j := newTestRemoteJournal(t)
	lines := make(chan []byte, 4)
	eof := make(chan error, 1)
	for i, e := range []remoteEvent{{Kind: "ready", PID: 42, Hooked: []string{"bcrypt.dll!BCryptGenerateSymmetricKey"}}, {Kind: "launch", PID: 42}, {Kind: "resumed", PID: 42}, {Kind: "api", Call: remoteTestKey()}} {
		e.Seq = uint64(i + 1)
		b, _ := json.Marshal(e)
		lines <- b
	}
	eof <- nil
	w := &remoteAckChecker{t: t, j: j}
	if err := consumeRemote(context.Background(), j, lines, eof, w); err == nil {
		t.Fatal("abrupt EOF looked complete")
	}
	if len(j.report.CryptoAnalysis.Materials) != 1 {
		t.Fatal("lost key at EOF")
	}
	if bytes.Count(w.Bytes(), []byte{'\n'}) != 4 {
		t.Fatal("missing ACKs")
	}
}

func TestRemoteProtocolRejectsUntrustedMetadata(t *testing.T) {
	for _, e := range []remoteEvent{{Seq: 2, Kind: "heartbeat"}, {Seq: 1, Kind: "start"}, {Seq: 1, Kind: "heartbeat", Target: "host-file"}, {Seq: 1, Kind: "api", Call: remoteTestKey()}, {Seq: 1, Kind: "ready", PID: 42}} {
		j := newTestRemoteJournal(t)
		lines := make(chan []byte, 1)
		b, _ := json.Marshal(e)
		lines <- b
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		var ack bytes.Buffer
		err := consumeRemote(ctx, j, lines, make(chan error), &ack)
		cancel()
		if err == nil || ack.Len() != 0 || j.report.RemoteCapture.Events != 1 {
			t.Fatalf("accepted invalid event %+v", e)
		}
	}
}

func TestRemoteJournalBoundsAndTerminalState(t *testing.T) {
	j := newTestRemoteJournal(t)
	readyTestRemote(t, j)
	bad := *remoteTestKey()
	bad.ProcessID = 99
	if err := j.append(remoteEvent{Kind: "api", Call: &bad}); err == nil {
		t.Fatal("accepted wrong PID")
	}
	bad = *remoteTestKey()
	bad.Parameters = append(bad.Parameters, APIParameter{Name: "large", Value: strings.Repeat("a", 4097)})
	if err := j.append(remoteEvent{Kind: "api", Call: &bad}); err == nil {
		t.Fatal("accepted oversized parameter")
	}
	j.bytes = remoteJournalLimit
	if err := j.append(remoteEvent{Kind: "heartbeat"}); err == nil {
		t.Fatal("ignored journal limit")
	}
	if err := j.append(remoteEvent{Kind: "error", Detail: "limit reached"}); err != nil {
		t.Fatal(err)
	}
	if err := j.append(remoteEvent{Kind: "heartbeat"}); err == nil {
		t.Fatal("accepted event after end")
	}
}

func TestRemoteCompletedRecoveryAndCanceledReader(t *testing.T) {
	j := newTestRemoteJournal(t)
	readyTestRemote(t, j)
	if err := j.append(remoteEvent{Kind: "end", Detail: "root terminated"}); err != nil {
		t.Fatal(err)
	}
	r, err := RecoverRemoteJournal(j.report.RemoteCapture.JournalPath, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if r.RemoteCapture.Incomplete || !r.Executed || r.ExitCode != -1 || !r.FinishedAt.Equal(j.report.FinishedAt) {
		t.Fatalf("incorrect recovery: %+v", r.RemoteCapture)
	}
	second, err := RecoverRemoteJournal(r.RemoteCapture.JournalPath, t.TempDir())
	if err != nil || !second.StartedAt.Equal(j.report.StartedAt) || second.DurationMS != j.report.DurationMS {
		t.Fatal("repeated recovery changed original times", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = consumeRemote(ctx, newTestRemoteJournal(t), make(chan []byte), make(chan error), io.Discard); err != context.Canceled {
		t.Fatal(err)
	}
}

func TestRemoteProfileProvisioningAndValidation(t *testing.T) {
	python, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	} // Existing trusted file; not executed.
	dir := filepath.Join(t.TempDir(), "profile")
	path, err := CreateRemoteProfile(dir, "192.168.222.222:27042", python)
	if err != nil {
		t.Fatal(err)
	}
	p, err := loadRemoteProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Token) != 64 || p.Endpoint != "192.168.222.222:27042" || !filepath.IsAbs(p.Certificate) {
		t.Fatal("bad profile")
	}
	if _, err = CreateRemoteProfile(dir, p.Endpoint, python); err == nil {
		t.Fatal("overwrote profile")
	}
	cert, err := os.ReadFile(p.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cert, []byte("PRIVATE KEY")) {
		t.Fatal("host pin contains private key")
	}
	guest, err := os.ReadFile(filepath.Join(dir, "guest", "agent.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(guest, []byte("PRIVATE KEY")) {
		t.Fatal("guest identity missing")
	}
	p.Token = "short"
	data, _ := json.Marshal(p)
	os.WriteFile(path, data, 0600)
	if _, err = loadRemoteProfile(path); err == nil {
		t.Fatal("accepted weak token")
	}
}

func TestRemoteRejectsHostPublicAndAmbiguousTargets(t *testing.T) {
	for _, endpoint := range []string{"localhost:27042", "127.0.0.1:27042", "[::1]:27042", "0.0.0.0:27042", "8.8.8.8:27042", "192.168.5.6:0", "192.168.5.6:70000", "guest.local:27042"} {
		if err := validateRemoteEndpoint(endpoint); err == nil {
			t.Fatalf("accepted %s", endpoint)
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		ip, _, e := net.ParseCIDR(a.String())
		if e == nil && ip.IsPrivate() {
			if err := validateRemoteEndpoint(net.JoinHostPort(ip.String(), "27042")); err == nil {
				t.Fatal("accepted host interface")
			}
		}
	}
	for _, target := range []string{"sample.exe", `\\host\share\sample.exe`, `C:\Lab\x.exe:stream.exe`, `C:\Lab\x.cmd`, "C:\\x\n.exe"} {
		if err := validateGuestTarget(target); err == nil {
			t.Fatalf("accepted target %q", target)
		}
	}
	if err := validateGuestTarget(`C:\Lab\My fixture.exe`); err != nil {
		t.Fatal(err)
	}
}

// Executed only by the following test's own child process. It impersonates
// the trusted bridge, never a Windows sample or a Frida agent.
func TestRemoteBridgeSubprocess(t *testing.T) {
	mode := os.Getenv("MEGA_REMOTE_TEST_BRIDGE")
	if mode == "" {
		return
	}
	var cfg struct {
		Target string `json:"target"`
		Script string `json:"script"`
		Token  string `json:"token"`
	}
	d := json.NewDecoder(os.Stdin)
	if d.Decode(&cfg) != nil || cfg.Target != `C:\Lab\not-present-on-host.exe` || !strings.Contains(cfg.Script, "BCryptGenerateSymmetricKey") || len(cfg.Token) != 64 {
		os.Exit(2)
	}
	events := []remoteEvent{{Kind: "ready", PID: 42, Hooked: []string{"bcrypt.dll!BCryptGenerateSymmetricKey"}}, {Kind: "launch", PID: 42}, {Kind: "resumed", PID: 42}, {Kind: "api", Call: remoteTestKey()}}
	if mode == "complete" {
		events = append(events, remoteEvent{Kind: "end", Detail: "fixture complete"})
	}
	if mode == "oversized" {
		fmtLine := strings.Repeat("x", remoteLineLimit+1) + "\n"
		os.Stdout.WriteString(fmtLine)
		os.Exit(0)
	}
	for i, e := range events {
		e.Seq = uint64(i + 1)
		// Omit host-owned timestamps entirely in the bridge wire format.
		b, _ := json.Marshal(e)
		var wire map[string]any
		json.Unmarshal(b, &wire)
		delete(wire, "at")
		if json.NewEncoder(os.Stdout).Encode(wire) != nil {
			os.Exit(3)
		}
		var a struct {
			Ack uint64 `json:"ack"`
		}
		if d.Decode(&a) != nil || a.Ack != e.Seq {
			os.Exit(4)
		}
	}
	if mode == "cancel" {
		var stop any
		_ = d.Decode(&stop)
	} // EOF from parent triggers clean exit.
	os.Exit(0)
}

func TestRemoteRunnerHostPersistenceThroughRealPipes(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path, err := CreateRemoteProfile(filepath.Join(t.TempDir(), "profile"), "192.168.222.222:27042", exe)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"complete", "disconnect", "oversized", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if mode == "cancel" {
				var c context.CancelFunc
				ctx, c = context.WithTimeout(ctx, 2*time.Second)
				defer c()
			}
			command := func(python string) *exec.Cmd {
				if python != exe {
					t.Fatal("unexpected trusted interpreter")
				}
				cmd := exec.Command(exe, "-test.run=^TestRemoteBridgeSubprocess$")
				cmd.Env = append(os.Environ(), "MEGA_REMOTE_TEST_BRIDGE="+mode)
				return cmd
			}
			r, err := runRemote(ctx, RemoteOptions{ProfilePath: path, Target: `C:\Lab\not-present-on-host.exe`, OutputDir: t.TempDir(), Duration: 5 * time.Second}, command)
			if r == nil {
				t.Fatal("missing host report", err)
			}
			if (err == nil) != (mode == "complete") {
				t.Fatalf("mode %s: %v", mode, err)
			}
			if r.RemoteCapture.Incomplete != (mode != "complete") {
				t.Fatal("wrong completion status")
			}
			if mode != "oversized" && len(r.CryptoAnalysis.Materials) != 1 {
				t.Fatal("runner lost captured key")
			}
			onDisk := readRemoteReport(t, r.JSONPath)
			if onDisk.RemoteCapture.State != r.RemoteCapture.State {
				t.Fatal("final report not persisted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = RunRemote(ctx, RemoteOptions{}); err != context.Canceled {
		t.Fatal("canceled run started", err)
	}
}
