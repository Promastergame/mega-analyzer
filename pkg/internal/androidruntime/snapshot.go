package androidruntime

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SnapshotInfo describes one AVD snapshot.
type SnapshotInfo struct {
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
}

// SnapshotOp records a snapshot operation for the session report.
type SnapshotOp struct {
	Action    string    `json:"action"` // "save", "load", "delete", "list"
	Name      string    `json:"name,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Duration  int64     `json:"duration_ms"`
	Error     string    `json:"error,omitempty"`
}

// SnapshotManager manages AVD snapshots.
type SnapshotManager interface {
	Save(ctx context.Context, name string) error
	Load(ctx context.Context, name string) error
	Delete(ctx context.Context, name string) error
	List(ctx context.Context) ([]SnapshotInfo, error)
	Operations() []SnapshotOp
}

// ── Console-based Snapshot Manager ───────────────────────────

// ConsoleSnapshotManager interacts with the Android Emulator console
// (telnet interface on localhost:5554+) to manage snapshots.
type ConsoleSnapshotManager struct {
	consolePort int
	authToken   string
	mu          sync.Mutex
	ops         []SnapshotOp
}

// NewConsoleSnapshotManager creates a Snapshot Manager that communicates
// with the Emulator Console on the given port.
func NewConsoleSnapshotManager(consolePort int) (*ConsoleSnapshotManager, error) {
	token, err := readConsoleAuthToken()
	if err != nil {
		// Auth token is optional on some emulator versions / configs.
		token = ""
	}
	return &ConsoleSnapshotManager{
		consolePort: consolePort,
		authToken:   token,
		ops:         make([]SnapshotOp, 0, 8),
	}, nil
}

// Save creates a named snapshot via the emulator console.
func (m *ConsoleSnapshotManager) Save(ctx context.Context, name string) error {
	return m.execOp(ctx, "save", name, fmt.Sprintf("avd snapshot save %s", name))
}

// Load restores a named snapshot via the emulator console.
func (m *ConsoleSnapshotManager) Load(ctx context.Context, name string) error {
	return m.execOp(ctx, "load", name, fmt.Sprintf("avd snapshot load %s", name))
}

// Delete removes a named snapshot via the emulator console.
func (m *ConsoleSnapshotManager) Delete(ctx context.Context, name string) error {
	return m.execOp(ctx, "delete", name, fmt.Sprintf("avd snapshot delete %s", name))
}

// List returns all available snapshots.
func (m *ConsoleSnapshotManager) List(ctx context.Context) ([]SnapshotInfo, error) {
	start := time.Now()
	output, err := m.sendCommand(ctx, "avd snapshot list")

	op := SnapshotOp{
		Action:    "list",
		Timestamp: start.UTC(),
		Duration:  time.Since(start).Milliseconds(),
	}
	if err != nil {
		op.Error = err.Error()
	}
	m.recordOp(op)

	if err != nil {
		return nil, err
	}

	return parseSnapshotList(output), nil
}

// Operations returns all snapshot operations performed during this session.
func (m *ConsoleSnapshotManager) Operations() []SnapshotOp {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SnapshotOp, len(m.ops))
	copy(out, m.ops)
	return out
}

// execOp executes a console command and records the operation.
func (m *ConsoleSnapshotManager) execOp(ctx context.Context, action, name, cmd string) error {
	start := time.Now()
	_, err := m.sendCommand(ctx, cmd)

	op := SnapshotOp{
		Action:    action,
		Name:      name,
		Timestamp: start.UTC(),
		Duration:  time.Since(start).Milliseconds(),
	}
	if err != nil {
		op.Error = err.Error()
	}
	m.recordOp(op)
	return err
}

func (m *ConsoleSnapshotManager) recordOp(op SnapshotOp) {
	m.mu.Lock()
	m.ops = append(m.ops, op)
	m.mu.Unlock()
}

// sendCommand opens a telnet connection to the emulator console,
// authenticates if needed, sends the command, and reads the response.
func (m *ConsoleSnapshotManager) sendCommand(ctx context.Context, command string) (string, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", m.consolePort)

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("connect to emulator console %s: %w", addr, err)
	}
	defer conn.Close()

	// Set deadline from context or 30s default.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	conn.SetDeadline(deadline)

	reader := bufio.NewReader(conn)

	// Read initial banner (e.g. "Android Console: type 'help' for a list...OK\r\n").
	if err := readUntilOK(reader); err != nil {
		return "", fmt.Errorf("read console banner: %w", err)
	}

	// Authenticate if we have a token.
	if m.authToken != "" {
		if _, err := fmt.Fprintf(conn, "auth %s\r\n", m.authToken); err != nil {
			return "", fmt.Errorf("send auth: %w", err)
		}
		if err := readUntilOK(reader); err != nil {
			return "", fmt.Errorf("auth response: %w", err)
		}
	}

	// Send the actual command.
	if _, err := fmt.Fprintf(conn, "%s\r\n", command); err != nil {
		return "", fmt.Errorf("send command %q: %w", command, err)
	}

	// Read the response until we see "OK" or "KO".
	var output strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return output.String(), fmt.Errorf("read response: %w", err)
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "OK" {
			break
		}
		if strings.HasPrefix(trimmed, "KO:") {
			return output.String(), fmt.Errorf("emulator console error: %s", trimmed)
		}
		output.WriteString(line)
	}

	// Send quit command.
	fmt.Fprintf(conn, "quit\r\n")

	return output.String(), nil
}

// readUntilOK reads lines from the console until "OK" is encountered.
func readUntilOK(reader *bufio.Reader) error {
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.TrimSpace(line) == "OK" {
			return nil
		}
	}
}

// parseSnapshotList parses the output of "avd snapshot list".
func parseSnapshotList(output string) []SnapshotInfo {
	var snapshots []SnapshotInfo
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "ID") || strings.HasPrefix(line, "--") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// The snapshot name is typically the last field or first field
		// depending on emulator version. We take the first non-numeric field.
		name := fields[0]
		for _, f := range fields {
			if f != "" && (f[0] < '0' || f[0] > '9') {
				name = f
				break
			}
		}
		snapshots = append(snapshots, SnapshotInfo{Name: name})
	}
	return snapshots
}

// readConsoleAuthToken reads the emulator console auth token from
// the user's home directory.
func readConsoleAuthToken() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	tokenPath := filepath.Join(home, ".emulator_console_auth_token")
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// ── Noop Snapshot Manager (for testing / mini mode) ──────────

// NoopSnapshotManager is a no-op implementation for testing or mini mode.
type NoopSnapshotManager struct {
	ops []SnapshotOp
}

func NewNoopSnapshotManager() *NoopSnapshotManager {
	return &NoopSnapshotManager{ops: make([]SnapshotOp, 0)}
}

func (n *NoopSnapshotManager) Save(_ context.Context, name string) error {
	n.ops = append(n.ops, SnapshotOp{Action: "save", Name: name, Timestamp: time.Now().UTC()})
	return nil
}

func (n *NoopSnapshotManager) Load(_ context.Context, name string) error {
	n.ops = append(n.ops, SnapshotOp{Action: "load", Name: name, Timestamp: time.Now().UTC()})
	return nil
}

func (n *NoopSnapshotManager) Delete(_ context.Context, name string) error {
	n.ops = append(n.ops, SnapshotOp{Action: "delete", Name: name, Timestamp: time.Now().UTC()})
	return nil
}

func (n *NoopSnapshotManager) List(_ context.Context) ([]SnapshotInfo, error) {
	n.ops = append(n.ops, SnapshotOp{Action: "list", Timestamp: time.Now().UTC()})
	return nil, nil
}

func (n *NoopSnapshotManager) Operations() []SnapshotOp {
	return n.ops
}
