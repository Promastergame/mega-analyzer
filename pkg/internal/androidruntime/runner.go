package androidruntime

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"mega-analyzer/pkg/internal/labdns"
	"mega-analyzer/pkg/logger"
)

// evasionEngine is a local interface matching antivm.Evasion so
// the runner does not import the antivm package directly.
type evasionEngine interface {
	Apply(ctx context.Context, adbPath string, serial string) error
	Report() interface{}
}

// RunnerState describes the current lifecycle state of the emulator.
type RunnerState int

const (
	StateIdle RunnerState = iota
	StateStarting
	StateBooting
	StateApplyingEvasion
	StateRunning
	StateStopping
	StateStopped
	StateFailed
)

func (s RunnerState) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateStarting:
		return "starting"
	case StateBooting:
		return "booting"
	case StateApplyingEvasion:
		return "applying-evasion"
	case StateRunning:
		return "running"
	case StateStopping:
		return "stopping"
	case StateStopped:
		return "stopped"
	case StateFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// EmulatorRunner orchestrates the full lifecycle of an Android Emulator
// (AVD) session, including DNS sinkhole, snapshot management, and
// anti-VM evasion.
type EmulatorRunner struct {
	profile     Profile
	emulatorBin string
	adbBin      string

	// Injected dependencies.
	dnsServer       labdns.DNSServer
	snapshotMgr     SnapshotManager
	evasion         evasionEngine
	reportCollector *SessionAggregator

	// Runtime state.
	mu          sync.Mutex
	state       RunnerState
	cmd         *exec.Cmd
	consolePort int
	emulatorPID int
	startedAt   time.Time
	stoppedAt   time.Time
	stdoutPath  string
	stderrPath  string
	warnings    []string

	// Shutdown coordination.
	cancel   context.CancelFunc
	stopOnce sync.Once
}

// RunnerConfig provides the external dependencies for the EmulatorRunner.
type RunnerConfig struct {
	Profile     Profile
	EmulatorBin string // path to emulator binary
	ADBBin      string // path to adb binary
	SessionDir  string // directory to store session artifacts
	DNSServer   labdns.DNSServer
	SnapshotMgr SnapshotManager
	Evasion     evasionEngine
}

// NewEmulatorRunner creates a new AVD lifecycle orchestrator.
func NewEmulatorRunner(cfg RunnerConfig) (*EmulatorRunner, error) {
	if cfg.EmulatorBin == "" {
		return nil, fmt.Errorf("emulator binary path is required")
	}
	if cfg.ADBBin == "" {
		return nil, fmt.Errorf("adb binary path is required")
	}
	if err := cfg.Profile.Validate(); err != nil {
		return nil, fmt.Errorf("invalid profile: %w", err)
	}

	stdoutPath := ""
	stderrPath := ""
	if cfg.SessionDir != "" {
		stdoutPath = cfg.SessionDir + "/emulator_stdout.log"
		stderrPath = cfg.SessionDir + "/emulator_stderr.log"
	}

	r := &EmulatorRunner{
		profile:         cfg.Profile,
		emulatorBin:     cfg.EmulatorBin,
		adbBin:          cfg.ADBBin,
		dnsServer:       cfg.DNSServer,
		snapshotMgr:     cfg.SnapshotMgr,
		evasion:         cfg.Evasion,
		state:           StateIdle,
		stdoutPath:      stdoutPath,
		stderrPath:      stderrPath,
		warnings:        make([]string, 0),
		reportCollector: NewSessionAggregator(cfg.Profile),
	}
	return r, nil
}

// Start launches the emulator and all supporting services.
// It blocks until the emulator is fully booted and anti-VM patches are applied.
func (r *EmulatorRunner) Start(ctx context.Context) error {
	r.mu.Lock()
	if r.state != StateIdle {
		r.mu.Unlock()
		return fmt.Errorf("runner is in state %s, expected idle", r.state)
	}
	r.state = StateStarting
	r.startedAt = time.Now().UTC()
	r.mu.Unlock()

	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel

	// Step 1: Start Lab DNS server if provided.
	if r.dnsServer != nil {
		logger.Info("starting lab DNS sinkhole", "addr", r.dnsServer.Addr())
		if labDNS, ok := r.dnsServer.(*labdns.LabDNS); ok {
			if err := labDNS.StartBackground(); err != nil {
				r.setState(StateFailed)
				return fmt.Errorf("start lab DNS: %w", err)
			}
		}
	}

	// Step 2: Build emulator arguments.
	args, err := BuildEmulatorArgs(r.profile)
	if err != nil {
		r.setState(StateFailed)
		return fmt.Errorf("build emulator args: %w", err)
	}

	logger.Info("launching emulator",
		"binary", r.emulatorBin,
		"avd", r.profile.AVDName,
		"args", strings.Join(args, " "),
	)

	// Step 3: Start emulator process.
	r.cmd = exec.CommandContext(runCtx, r.emulatorBin, args...)
	r.cmd.Env = os.Environ()

	// Capture stdout/stderr to log files.
	if r.stdoutPath != "" {
		stdoutFile, err := os.Create(r.stdoutPath)
		if err != nil {
			r.addWarning(fmt.Sprintf("create emulator stdout log: %v", err))
		} else {
			r.cmd.Stdout = stdoutFile
			defer stdoutFile.Close()
		}
	}
	if r.stderrPath != "" {
		stderrFile, err := os.Create(r.stderrPath)
		if err != nil {
			r.addWarning(fmt.Sprintf("create emulator stderr log: %v", err))
		} else {
			r.cmd.Stderr = stderrFile
			defer stderrFile.Close()
		}
	}

	if err := r.cmd.Start(); err != nil {
		r.setState(StateFailed)
		return fmt.Errorf("start emulator process: %w", err)
	}
	r.emulatorPID = r.cmd.Process.Pid
	logger.Info("emulator process started", "pid", r.emulatorPID)

	// Step 4: Wait for the emulator to boot.
	r.setState(StateBooting)
	logger.Info("waiting for emulator boot")

	bootTimeout := 120 * time.Second

	if err := r.waitForBoot(runCtx, bootTimeout); err != nil {
		r.addWarning(fmt.Sprintf("boot wait failed: %v", err))
		r.setState(StateFailed)
		return fmt.Errorf("emulator boot: %w", err)
	}

	// Detect console port (typically 5554 for first emulator).
	r.consolePort = 5554
	logger.Info("emulator booted", "console_port", r.consolePort)

	// Step 5: Apply lab MITM proxy / CA setup.
	if r.profile.MITM.Enabled {
		logger.Info("applying lab MITM emulator settings")
		if err := r.applyMITMSetup(runCtx); err != nil {
			r.addWarning(fmt.Sprintf("MITM setup failed: %v", err))
		} else {
			logger.Info("lab MITM emulator settings applied")
		}
	}

	// Step 6: Apply anti-VM evasion.
	if r.evasion != nil {
		r.setState(StateApplyingEvasion)
		logger.Info("applying anti-VM evasion patches")
		if err := r.evasion.Apply(runCtx, r.adbBin, ""); err != nil {
			r.addWarning(fmt.Sprintf("anti-VM evasion failed: %v", err))
			// Non-fatal: we continue even if evasion partially fails.
		} else {
			logger.Info("anti-VM evasion applied successfully")
		}
	}

	r.setState(StateRunning)
	logger.Info("emulator runner is active")
	return nil
}

// Wait blocks until the emulator process exits or the context is cancelled.
func (r *EmulatorRunner) Wait() error {
	if r.cmd == nil || r.cmd.Process == nil {
		return fmt.Errorf("emulator not started")
	}
	return r.cmd.Wait()
}

// Stop performs a graceful shutdown of the emulator and all services.
func (r *EmulatorRunner) Stop() error {
	var firstErr error
	r.stopOnce.Do(func() {
		r.setState(StateStopping)
		logger.Info("stopping emulator runner")

		// Try graceful shutdown via ADB first.
		if r.adbBin != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			killCmd := exec.CommandContext(ctx, r.adbBin, "emu", "kill")
			if err := killCmd.Run(); err != nil {
				r.addWarning(fmt.Sprintf("adb emu kill failed: %v", err))
			}

			// Wait for process to exit gracefully.
			done := make(chan struct{})
			go func() {
				if r.cmd != nil && r.cmd.Process != nil {
					r.cmd.Wait()
				}
				close(done)
			}()

			select {
			case <-done:
				logger.Info("emulator exited gracefully")
			case <-time.After(10 * time.Second):
				logger.Warn("emulator did not exit gracefully, force killing")
				if r.cmd != nil && r.cmd.Process != nil {
					r.cmd.Process.Kill()
				}
			}
		} else if r.cmd != nil && r.cmd.Process != nil {
			r.cmd.Process.Kill()
		}

		// Cancel the runner context.
		if r.cancel != nil {
			r.cancel()
		}

		// Stop DNS server.
		if r.dnsServer != nil {
			if err := r.dnsServer.Stop(); err != nil {
				r.addWarning(fmt.Sprintf("DNS server stop: %v", err))
				if firstErr == nil {
					firstErr = err
				}
			}
		}

		r.stoppedAt = time.Now().UTC()
		r.setState(StateStopped)
		logger.Info("emulator runner stopped",
			"duration", r.stoppedAt.Sub(r.startedAt).String(),
		)
	})
	return firstErr
}

// State returns the current runner lifecycle state.
func (r *EmulatorRunner) State() RunnerState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

// ConsolePort returns the emulator console telnet port.
func (r *EmulatorRunner) ConsolePort() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.consolePort
}

// EmulatorPID returns the PID of the emulator process.
func (r *EmulatorRunner) EmulatorPID() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.emulatorPID
}

// StartedAt returns when the runner was started.
func (r *EmulatorRunner) StartedAt() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.startedAt
}

// StoppedAt returns when the runner was stopped.
func (r *EmulatorRunner) StoppedAt() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stoppedAt
}

// Warnings returns all collected warnings.
func (r *EmulatorRunner) Warnings() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.warnings))
	copy(out, r.warnings)
	return out
}

// GenerateReport creates the final session report.
func (r *EmulatorRunner) GenerateReport() *SessionReport {
	r.mu.Lock()
	defer r.mu.Unlock()

	report := &SessionReport{
		SessionID:   fmt.Sprintf("avd_%d", r.startedAt.Unix()),
		Profile:     r.profile,
		StartedAt:   r.startedAt,
		FinishedAt:  r.stoppedAt,
		EmulatorPID: r.emulatorPID,
		ConsolePort: r.consolePort,
		EmulatorLog: r.stdoutPath,
		Warnings:    r.warnings,
	}

	if !r.stoppedAt.IsZero() {
		report.DurationMs = r.stoppedAt.Sub(r.startedAt).Milliseconds()
	}

	// Collect DNS log and stats.
	if r.dnsServer != nil {
		report.DNSLog = r.dnsServer.QueryLog()
		report.DNSStats = r.dnsServer.Stats()
	}

	// Collect snapshot operations.
	if r.snapshotMgr != nil {
		report.SnapshotOps = r.snapshotMgr.Operations()
	}

	// Collect anti-VM report.
	if r.evasion != nil {
		report.AntiVMApplied = r.evasion.Report()
	}

	return report
}

// ── Internal helpers ─────────────────────────────────────────

func (r *EmulatorRunner) setState(s RunnerState) {
	r.mu.Lock()
	r.state = s
	r.mu.Unlock()
}

func (r *EmulatorRunner) addWarning(msg string) {
	r.mu.Lock()
	r.warnings = append(r.warnings, msg)
	r.mu.Unlock()
}

func (r *EmulatorRunner) applyMITMSetup(ctx context.Context) error {
	commands, err := BuildMITMAdbCommands(r.profile)
	if err != nil {
		return err
	}
	for _, command := range commands {
		parts := strings.Fields(command)
		if len(parts) == 0 {
			continue
		}
		cmd := exec.CommandContext(ctx, r.adbBin, parts...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("adb %s: %w (%s)", command, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// waitForBoot polls ADB until sys.boot_completed == 1.
func (r *EmulatorRunner) waitForBoot(ctx context.Context, timeout time.Duration) error {
	// First wait for ADB to see the device.
	waitCtx, waitCancel := context.WithTimeout(ctx, timeout/2)
	defer waitCancel()

	waitCmd := exec.CommandContext(waitCtx, r.adbBin, "wait-for-device")
	if err := waitCmd.Run(); err != nil {
		return fmt.Errorf("adb wait-for-device: %w", err)
	}

	// Then poll sys.boot_completed.
	deadline := time.After(timeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("boot timeout after %v", timeout)
		case <-ticker.C:
			propCmd := exec.CommandContext(ctx, r.adbBin, "shell", "getprop", "sys.boot_completed")
			out, err := propCmd.Output()
			if err != nil {
				continue
			}
			if strings.TrimSpace(string(out)) == "1" {
				return nil
			}
		}
	}
}
