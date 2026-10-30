package androidruntime

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// ── Mock Emulator Console ────────────────────────────────────

// mockConsole is a minimal TCP server that emulates the Android Emulator
// Console protocol for snapshot testing.
type mockConsole struct {
	listener  net.Listener
	responses map[string]string // command prefix → response body
}

func newMockConsole(t *testing.T) *mockConsole {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock console listen: %v", err)
	}
	mc := &mockConsole{
		listener: l,
		responses: map[string]string{
			"avd snapshot save":   "",
			"avd snapshot load":   "",
			"avd snapshot delete": "",
			"avd snapshot list":   "ID            TAG            SIZE\n1             clean          50M\n2             infected       120M\n",
		},
	}
	go mc.serve()
	return mc
}

func (mc *mockConsole) port() int {
	return mc.listener.Addr().(*net.TCPAddr).Port
}

func (mc *mockConsole) close() {
	mc.listener.Close()
}

func (mc *mockConsole) serve() {
	for {
		conn, err := mc.listener.Accept()
		if err != nil {
			return
		}
		go mc.handle(conn)
	}
}

func (mc *mockConsole) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send banner.
	fmt.Fprintf(conn, "Android Console: type 'help' for commands\r\nOK\r\n")

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		line := strings.TrimSpace(string(buf[:n]))

		if line == "quit" {
			return
		}

		// Check if any response prefix matches.
		responded := false
		for prefix, body := range mc.responses {
			if strings.HasPrefix(line, prefix) {
				if body != "" {
					fmt.Fprintf(conn, "%s", body)
				}
				fmt.Fprintf(conn, "OK\r\n")
				responded = true
				break
			}
		}
		if !responded {
			fmt.Fprintf(conn, "KO: unknown command %q\r\n", line)
		}
	}
}

// ── Console Snapshot Manager Tests ───────────────────────────

func TestConsoleSnapshotManagerSave(t *testing.T) {
	mc := newMockConsole(t)
	defer mc.close()

	mgr, err := NewConsoleSnapshotManager(mc.port())
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	// Clear auth token since our mock doesn't require it.
	mgr.authToken = ""

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := mgr.Save(ctx, "test_snap"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	ops := mgr.Operations()
	if len(ops) != 1 {
		t.Fatalf("expected 1 op, got %d", len(ops))
	}
	if ops[0].Action != "save" {
		t.Errorf("expected action 'save', got %q", ops[0].Action)
	}
	if ops[0].Name != "test_snap" {
		t.Errorf("expected name 'test_snap', got %q", ops[0].Name)
	}
}

func TestConsoleSnapshotManagerLoad(t *testing.T) {
	mc := newMockConsole(t)
	defer mc.close()

	mgr, _ := NewConsoleSnapshotManager(mc.port())
	mgr.authToken = ""

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := mgr.Load(ctx, "clean"); err != nil {
		t.Fatalf("Load: %v", err)
	}

	ops := mgr.Operations()
	if len(ops) != 1 || ops[0].Action != "load" {
		t.Errorf("unexpected ops: %+v", ops)
	}
}

func TestConsoleSnapshotManagerDelete(t *testing.T) {
	mc := newMockConsole(t)
	defer mc.close()

	mgr, _ := NewConsoleSnapshotManager(mc.port())
	mgr.authToken = ""

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := mgr.Delete(ctx, "old_snap"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestConsoleSnapshotManagerList(t *testing.T) {
	mc := newMockConsole(t)
	defer mc.close()

	mgr, _ := NewConsoleSnapshotManager(mc.port())
	mgr.authToken = ""

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	snaps, err := mgr.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(snaps) < 1 {
		t.Fatalf("expected at least 1 snapshot, got %d", len(snaps))
	}
}

func TestConsoleSnapshotManagerMultipleOps(t *testing.T) {
	mc := newMockConsole(t)
	defer mc.close()

	mgr, _ := NewConsoleSnapshotManager(mc.port())
	mgr.authToken = ""

	ctx := context.Background()

	_ = mgr.Save(ctx, "s1")
	_ = mgr.Load(ctx, "s1")
	_ = mgr.Delete(ctx, "s1")

	ops := mgr.Operations()
	if len(ops) != 3 {
		t.Fatalf("expected 3 ops, got %d", len(ops))
	}
	if ops[0].Action != "save" || ops[1].Action != "load" || ops[2].Action != "delete" {
		t.Errorf("unexpected op sequence: %v %v %v", ops[0].Action, ops[1].Action, ops[2].Action)
	}
}

// ── parseSnapshotList Tests ──────────────────────────────────

func TestParseSnapshotList(t *testing.T) {
	output := `ID            TAG            SIZE
--            ---            ----
1             clean          50M
2             infected       120M
3             patched        30M
`
	snaps := parseSnapshotList(output)
	if len(snaps) != 3 {
		t.Fatalf("expected 3 snapshots, got %d", len(snaps))
	}
	// First non-numeric fields should be snapshot names.
	names := make([]string, len(snaps))
	for i, s := range snaps {
		names[i] = s.Name
	}
	for _, expected := range []string{"clean", "infected", "patched"} {
		found := false
		for _, name := range names {
			if name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected snapshot %q not found in %v", expected, names)
		}
	}
}

func TestParseSnapshotListEmpty(t *testing.T) {
	snaps := parseSnapshotList("")
	if len(snaps) != 0 {
		t.Errorf("expected 0, got %d", len(snaps))
	}
}

// ── Noop Snapshot Manager Tests ──────────────────────────────

func TestNoopSnapshotManager(t *testing.T) {
	mgr := NewNoopSnapshotManager()
	ctx := context.Background()

	if err := mgr.Save(ctx, "test"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := mgr.Load(ctx, "test"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := mgr.Delete(ctx, "test"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	snaps, err := mgr.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if snaps != nil {
		t.Errorf("expected nil list, got %v", snaps)
	}

	ops := mgr.Operations()
	if len(ops) != 4 {
		t.Fatalf("expected 4 ops, got %d", len(ops))
	}
}

// ── Connection Error Tests ───────────────────────────────────

func TestConsoleSnapshotManagerConnectionRefused(t *testing.T) {
	// Use a port that's definitely not listening.
	mgr, _ := NewConsoleSnapshotManager(19999)
	mgr.authToken = ""

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := mgr.Save(ctx, "test")
	if err == nil {
		t.Fatal("expected error for connection refused")
	}

	ops := mgr.Operations()
	if len(ops) != 1 {
		t.Fatalf("expected 1 op, got %d", len(ops))
	}
	if ops[0].Error == "" {
		t.Error("expected error in op")
	}
}
