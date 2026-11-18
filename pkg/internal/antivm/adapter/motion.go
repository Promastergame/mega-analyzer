package adapter

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

//go:embed probes/sensors.dex
var sensorProbeDEX []byte

const sensorProbeGuest = "/data/local/tmp/mega-antivm/sensors.dex"

type motionRun struct {
	cancel   context.CancelFunc
	done     chan struct{}
	active   bool
	err      error
	frames   uint64
	interval int
}

type SensorPlaybackStatus struct {
	Active bool
	Frames uint64
	Error  string
}

func (a *ADBAdapter) SensorPlaybackStatus() SensorPlaybackStatus {
	a.motionMu.Lock()
	defer a.motionMu.Unlock()
	if a.motion == nil {
		return SensorPlaybackStatus{}
	}
	status := SensorPlaybackStatus{Active: a.motion.active && a.motion.err == nil, Frames: a.motion.frames}
	if a.motion.err != nil {
		status.Error = a.motion.err.Error()
	}
	return status
}

// BindSensorLifetime gives playback the analysis/session context rather than a
// short-lived module timeout. Stop also cancels playback and waits for restore.
func (a *ADBAdapter) BindSensorLifetime(ctx context.Context) {
	a.motionMu.Lock()
	a.motionLife = ctx
	a.motionMu.Unlock()
}

func validateMotion(cfg MotionConfig) error {
	if len(cfg.Frames) < 2 || len(cfg.Frames) > 256 || cfg.IntervalMillis < 100 || cfg.IntervalMillis > 5000 || cfg.DurationSeconds < 5 || cfg.DurationSeconds > 900 {
		return fmt.Errorf("invalid bounded sensor playback configuration")
	}
	for _, frame := range cfg.Frames {
		if len(frame.Readings) == 0 || len(frame.Readings) > 2 {
			return fmt.Errorf("invalid sensor frame")
		}
		seen := map[string]bool{}
		for _, reading := range frame.Readings {
			if (reading.Name != "acceleration" && reading.Name != "gyroscope") || seen[reading.Name] {
				return fmt.Errorf("invalid sensor name %q", reading.Name)
			}
			seen[reading.Name] = true
			for _, value := range reading.Values {
				if math.IsNaN(value) || math.IsInf(value, 0) {
					return fmt.Errorf("non-finite sensor value")
				}
			}
		}
	}
	return nil
}

func (a *ADBAdapter) emu(ctx context.Context, args ...string) (string, error) {
	if !strings.HasPrefix(a.Serial, "emulator-") {
		return "", fmt.Errorf("sensor playback requires an explicit emulator serial")
	}
	out, err := a.run(ctx, append([]string{"emu"}, args...)...)
	if err != nil {
		return out, err
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "KO") {
			return out, fmt.Errorf("emulator console: %s", strings.TrimSpace(line))
		}
	}
	return out, nil
}

func parseSensorVector(out, name string) (SensorVector, error) {
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) != name {
			continue
		}
		values := strings.Split(strings.TrimSpace(parts[1]), ":")
		if len(values) != 3 {
			break
		}
		reading := SensorVector{Name: name}
		for i, value := range values {
			v, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
				return SensorVector{}, fmt.Errorf("invalid %s sensor reading", name)
			}
			reading.Values[i] = v
		}
		return reading, nil
	}
	return SensorVector{}, fmt.Errorf("missing %s console reading: %s", name, out)
}

func (a *ADBAdapter) writeVector(ctx context.Context, value SensorVector) error {
	values := fmt.Sprintf("%.6f:%.6f:%.6f", value.Values[0], value.Values[1], value.Values[2])
	_, err := a.emu(ctx, "sensor", "set", value.Name, values)
	return err
}

func (a *ADBAdapter) installSensorProbe(ctx context.Context) error {
	file, err := os.CreateTemp("", "mega-sensors-*.dex")
	if err != nil {
		return err
	}
	path := file.Name()
	defer os.Remove(path)
	if _, err := file.Write(sensorProbeDEX); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if _, err := a.shell(ctx, "mkdir -p /data/local/tmp/mega-antivm"); err != nil {
		return err
	}
	if _, err := a.run(ctx, "push", path, sensorProbeGuest); err != nil {
		return err
	}
	if _, err := a.shell(ctx, "chmod 444 "+quoteShell(sensorProbeGuest)); err != nil {
		return err
	}
	a.motionMu.Lock()
	a.probeReady = true
	a.motionMu.Unlock()
	return nil
}

func (a *ADBAdapter) startMotion(ctx context.Context, cfg MotionConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !strings.HasPrefix(a.Serial, "emulator-") {
		return fmt.Errorf("sensor playback requires an explicit emulator serial")
	}
	if err := validateMotion(cfg); err != nil {
		return err
	}
	if err := a.stopMotion(ctx); err != nil {
		return err
	}
	var original []SensorVector
	seen := map[string]bool{}
	frames := make([]MotionFrame, len(cfg.Frames))
	for i, frame := range cfg.Frames {
		frames[i].Readings = append([]SensorVector(nil), frame.Readings...)
		for _, reading := range frame.Readings {
			if seen[reading.Name] {
				continue
			}
			out, err := a.emu(ctx, "sensor", "get", reading.Name)
			if err != nil {
				return err
			}
			previous, err := parseSensorVector(out, reading.Name)
			if err != nil {
				return err
			}
			original = append(original, previous)
			seen[reading.Name] = true
		}
	}
	if err := a.installSensorProbe(ctx); err != nil {
		return fmt.Errorf("install Android sensor observer: %w", err)
	}
	a.motionMu.Lock()
	life := a.motionLife
	a.motionMu.Unlock()
	if life == nil {
		life = ctx
	}
	life, cancel := context.WithTimeout(life, time.Duration(cfg.DurationSeconds)*time.Second)
	run := &motionRun{cancel: cancel, done: make(chan struct{}), active: true, interval: cfg.IntervalMillis}
	// Check the first frame synchronously; launch success alone is insufficient.
	for _, value := range frames[0].Readings {
		if err := a.writeVector(life, value); err != nil {
			cancel()
			restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer restoreCancel()
			for _, previous := range original {
				if restoreErr := a.writeVector(restoreCtx, previous); restoreErr != nil {
					err = errors.Join(err, fmt.Errorf("restore sensor: %w", restoreErr))
				}
			}
			return err
		}
	}
	run.frames = 1
	a.motionMu.Lock()
	a.motion = run
	a.motionMu.Unlock()
	go func() {
		defer close(run.done)
		defer cancel()
		defer func() {
			a.motionMu.Lock()
			run.active = false
			a.motionMu.Unlock()
			restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer restoreCancel()
			for _, previous := range original {
				if err := a.writeVector(restoreCtx, previous); err != nil {
					a.motionMu.Lock()
					if run.err == nil {
						run.err = fmt.Errorf("restore sensor: %w", err)
					}
					a.motionMu.Unlock()
				}
			}
			a.motionMu.Lock()
			run.active = false
			a.motionMu.Unlock()
		}()
		ticker := time.NewTicker(time.Duration(cfg.IntervalMillis) * time.Millisecond)
		defer ticker.Stop()
		for index := 1; ; index++ {
			select {
			case <-life.Done():
				return
			case <-ticker.C:
			}
			for _, value := range frames[index%len(frames)].Readings {
				if err := a.writeVector(life, value); err != nil {
					if life.Err() == nil {
						a.motionMu.Lock()
						run.err = err
						a.motionMu.Unlock()
					}
					return
				}
			}
			a.motionMu.Lock()
			run.frames++
			a.motionMu.Unlock()
		}
	}()
	return nil
}

func (a *ADBAdapter) stopMotion(ctx context.Context) error {
	a.motionMu.Lock()
	run := a.motion
	a.motionMu.Unlock()
	if run == nil {
		return nil
	}
	run.cancel()
	select {
	case <-run.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	a.motionMu.Lock()
	err := run.err
	a.motionMu.Unlock()
	return err
}

func (a *ADBAdapter) readMotionState(ctx context.Context, st *DeviceState) {
	a.motionMu.Lock()
	ready, run := a.probeReady, a.motion
	window := 1200
	if run != nil {
		st.Sensors["motion.active"] = strconv.FormatBool(run.active && run.err == nil)
		st.Sensors["motion.frames"] = strconv.FormatUint(run.frames, 10)
		if run.err != nil {
			st.Extra["sensor-playback.error"] = run.err.Error()
		}
		if wanted := 2*run.interval + 500; wanted > window {
			window = wanted
		}
	}
	a.motionMu.Unlock()
	if !ready {
		return
	}
	if window > 10000 {
		window = 10000
	}
	command := "CLASSPATH=" + quoteShell(sensorProbeGuest) + " app_process /system/bin MegaSensorProbe " + strconv.Itoa(window)
	out, err := a.shell(ctx, command)
	if err != nil {
		st.Extra["sensor-probe.error"] = err.Error()
		return
	}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) != 2 || !strings.HasPrefix(parts[0], "sensor.") {
			continue
		}
		key := strings.TrimPrefix(parts[0], "sensor.")
		value := strings.TrimSpace(parts[1])
		if strings.HasSuffix(key, ".samples") {
			if n, err := strconv.Atoi(value); err != nil || n < 0 {
				continue
			}
		} else if value != "true" && value != "false" {
			continue
		}
		st.Sensors[key] = value
	}
	if run != nil {
		a.motionMu.Lock()
		st.Sensors["motion.active"] = strconv.FormatBool(run.active && run.err == nil)
		st.Sensors["motion.frames"] = strconv.FormatUint(run.frames, 10)
		if run.err != nil {
			st.Extra["sensor-playback.error"] = run.err.Error()
		}
		a.motionMu.Unlock()
	}
}
