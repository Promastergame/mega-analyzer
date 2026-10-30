package sandbox

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"time"
)

//go:embed remote_frida.py
var remoteFridaHelper string

type RemoteOptions struct {
	ProfilePath string
	Target      string // Absolute Windows path INSIDE the guest, never opened on host.
	OutputDir   string
	Duration    time.Duration
}

// RunRemote launches only the trusted embedded Python bridge on the host.
// The bridge has no local-device fallback and receives credentials over stdin.
func RunRemote(ctx context.Context, opts RemoteOptions) (*Report, error) {
	return runRemote(ctx, opts, func(python string) *exec.Cmd {
		return exec.Command(python, "-I", "-u", "-c", remoteFridaHelper)
	})
}

func runRemote(ctx context.Context, opts RemoteOptions, bridgeCommand func(string) *exec.Cmd) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	profile, err := loadRemoteProfile(opts.ProfilePath)
	if err != nil {
		return nil, err
	}
	if err = validateGuestTarget(opts.Target); err != nil {
		return nil, err
	}
	if opts.Duration < 0 || (opts.Duration > 0 && opts.Duration < 5*time.Second) {
		return nil, fmt.Errorf("remote duration must be 0 or at least 5s")
	}
	j, err := newRemoteJournal(opts.OutputDir, profile.Endpoint, opts.Target)
	if err != nil {
		return nil, err
	}
	defer j.file.Close()
	script, err := fridaScripts.ReadFile("frida_windows_default.js")
	if err != nil {
		return j.report, err
	}
	cmd := bridgeCommand(profile.Python)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return j.report, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return j.report, err
	}
	// Arbitrary guest logs and exceptions never enter host console or files.
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		_ = j.append(remoteEvent{Kind: "error", Detail: "Trusted Python bridge could not start"})
		return j.report, fmt.Errorf("start host Python bridge: %w", err)
	}
	defer stdin.Close()
	done := make(chan error, 1)
	defer func() {
		stdin.Close() // EOF asks the bridge to clean up remote processes.
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}()
	lines := make(chan []byte, 1)
	readDone := make(chan error, 1)
	readCtx, stopRead := context.WithCancel(context.Background())
	defer stopRead()
	go func() {
		s := bufio.NewScanner(stdout)
		s.Buffer(make([]byte, 4096), remoteLineLimit)
		for s.Scan() {
			b := bytes.Clone(s.Bytes())
			select {
			case lines <- b:
			case <-readCtx.Done():
				readDone <- readCtx.Err()
				return
			}
		}
		readDone <- s.Err()
	}()
	// Wait must not close StdoutPipe before the scanner drains it.
	go func() { <-readCtx.Done(); done <- cmd.Wait() }()
	cfg := struct {
		Endpoint    string   `json:"endpoint"`
		Certificate string   `json:"certificate"`
		Token       string   `json:"token"`
		Target      string   `json:"target"`
		Args        []string `json:"args"`
		Script      string   `json:"script"`
		Duration    float64  `json:"duration_seconds"`
	}{profile.Endpoint, profile.Certificate, profile.Token, opts.Target, profile.Args, string(script), opts.Duration.Seconds()}
	if err = json.NewEncoder(stdin).Encode(cfg); err == nil {
		err = consumeRemote(ctx, j, lines, readDone, stdin)
	}
	stopRead()
	if err != nil && !j.terminal {
		persistErr := j.append(remoteEvent{Kind: "error", Detail: "Capture interrupted; already synced events retained. Guest cleanup is unconfirmed."})
		if persistErr != nil {
			err = fmt.Errorf("%w; final snapshot failed: %v", err, persistErr)
		}
	}
	return j.report, err
}

func consumeRemote(ctx context.Context, j *remoteJournal, lines <-chan []byte, readDone <-chan error, control io.Writer) error {
	timer := time.NewTimer(25 * time.Second)
	defer timer.Stop()
	seq := uint64(0)
	process := func(line []byte) error {
		var e remoteEvent
		d := json.NewDecoder(bytes.NewReader(line))
		d.DisallowUnknownFields()
		if err := d.Decode(&e); err != nil {
			return fmt.Errorf("invalid remote bridge record")
		}
		if d.Decode(new(any)) != io.EOF || e.Seq != seq+1 || e.Kind == "start" || !e.At.IsZero() || e.Endpoint != "" || e.Target != "" {
			return fmt.Errorf("invalid bridge sequence or metadata")
		}
		seq++
		if err := j.append(e); err != nil {
			return err
		}
		// Acknowledgment follows Sync and, for keys, the readable snapshot.
		if err := json.NewEncoder(control).Encode(map[string]uint64{"ack": seq}); err != nil {
			return err
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(25 * time.Second)
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("remote bridge heartbeat timed out")
		case line := <-lines:
			if err := process(line); err != nil {
				return err
			}
			if j.terminal {
				if j.report.RemoteCapture.Incomplete {
					return fmt.Errorf("remote capture incomplete; see host report")
				}
				return nil
			}
		case err := <-readDone:
			// The final buffered event may arrive alongside EOF.
			for {
				select {
				case line := <-lines:
					if e := process(line); e != nil {
						return e
					}
				default:
					if err != nil {
						return fmt.Errorf("remote bridge read failed: %w", err)
					}
					if !j.terminal || j.report.RemoteCapture.Incomplete {
						return fmt.Errorf("remote bridge disconnected; host journal retained")
					}
					return nil
				}
			}
		}
	}
}
