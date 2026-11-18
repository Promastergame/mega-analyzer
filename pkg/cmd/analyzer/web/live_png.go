package web

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

const (
	livePNGSignature = "\x89PNG\r\n\x1a\n"
	maxLivePNGBytes  = 16 << 20
	liveFrameTimeout = 10 * time.Second
)

var livePNGFileTransport sync.Map // adb + serial -> bool; reset when the server restarts

// readLivePNG reads through IEND, without waiting for another frame or EOF.
// ADB reads can split any PNG header or chunk, including the signature.
func readLivePNG(r io.Reader) ([]byte, error) {
	var header [8]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if string(header[:]) != livePNGSignature {
		return nil, fmt.Errorf("invalid screen PNG signature")
	}
	var frame bytes.Buffer
	frame.Write(header[:])
	first := true
	for {
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return nil, err
		}
		size := uint64(binary.BigEndian.Uint32(header[:4]))
		kind := string(header[4:])
		if first && (kind != "IHDR" || size != 13) {
			return nil, fmt.Errorf("invalid screen PNG header")
		}
		first = false
		if uint64(frame.Len())+size+12 > maxLivePNGBytes {
			return nil, fmt.Errorf("screen PNG exceeds %d bytes", maxLivePNGBytes)
		}
		if kind == "IEND" && size != 0 {
			return nil, fmt.Errorf("invalid screen PNG terminator")
		}
		frame.Write(header[:])
		if _, err := io.CopyN(&frame, r, int64(size)+4); err != nil {
			return nil, err
		}
		if kind == "IEND" {
			return frame.Bytes(), nil
		}
	}
}

func captureLivePNG(ctx context.Context, adb, serial string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, liveFrameTimeout)
	defer cancel()
	key := adb + "\x00" + serial
	if _, useFiles := livePNGFileTransport.Load(key); !useFiles {
		if frame, err := captureLivePNGDirect(ctx, adb, serial); err == nil {
			return frame, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	frame, err := captureLivePNGFile(ctx, adb, serial)
	if err == nil {
		livePNGFileTransport.Store(key, true)
	}
	return frame, err
}

func captureLivePNGDirect(ctx context.Context, adb, serial string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, adb, "-s", serial, "exec-out", "screencap", "-p")
	prepareProbeCommand(cmd)
	cmd.WaitDelay = time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	return readLivePNG(stdout)
}

// Some ADB targets send screencap's small stdout writes very slowly. Pulling
// a completed file uses ADB's file transfer protocol and avoids that pipe.
func captureLivePNGFile(ctx context.Context, adb, serial string) ([]byte, error) {
	file, err := os.CreateTemp("", "mega-live-screen-*.png")
	if err != nil {
		return nil, err
	}
	local := file.Name()
	file.Close()
	defer os.Remove(local)
	remote := "/data/local/tmp/" + filepath.Base(local)
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		cmd := exec.CommandContext(cleanupCtx, adb, "-s", serial, "shell", "rm", "-f", remote)
		prepareProbeCommand(cmd)
		cmd.WaitDelay = time.Second
		_ = cmd.Run()
	}()
	cmd := exec.CommandContext(ctx, adb, "-s", serial, "shell", "screencap", "-p", remote)
	prepareProbeCommand(cmd)
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	cmd = exec.CommandContext(ctx, adb, "-s", serial, "pull", remote, local)
	prepareProbeCommand(cmd)
	cmd.WaitDelay = time.Second
	pullErr := cmd.Run()
	file, err = os.Open(local)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	frame, err := readLivePNG(file)
	if err != nil && pullErr != nil {
		return nil, pullErr
	}
	// A complete PNG is usable even if the target reports EOF after transfer.
	return frame, err
}

func streamLivePNGs(ctx context.Context, adb, serial string, emit func([]byte) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Stop a stalled ADB pipe so the handler can fall back to individual captures.
	idle := time.AfterFunc(3*time.Second, cancel)
	defer idle.Stop()
	cmd := exec.CommandContext(ctx, adb, "-s", serial, "exec-out",
		"sh", "-c", "while screencap -p; do sleep 0.15; done")
	prepareProbeCommand(cmd)
	cmd.WaitDelay = time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	for ctx.Err() == nil {
		frame, err := readLivePNG(stdout)
		if err != nil {
			return err
		}
		idle.Reset(3 * time.Second)
		if err := emit(frame); err != nil {
			return err
		}
	}
	return ctx.Err()
}
