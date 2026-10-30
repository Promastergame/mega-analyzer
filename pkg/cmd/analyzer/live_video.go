package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"mega-analyzer/pkg/cmd/analyzer/web"
	"mega-analyzer/pkg/internal/wsx"
)

// Live H.264 streaming using the scrcpy-server protocol.
//
// scrcpy-server runs as an Android process and pushes H.264 NAL units directly
// over a local socket (forwarded via ADB). Latency is ~50 ms vs 500 ms+ for
// screenrecord, because the server encodes frames with MediaCodec configured for
// low-latency output and does not buffer them in GOP-sized chunks.
//
// If scrcpy-server is not available we fall back to screenrecord so older
// installations still work.

const (
	scrcpyLocalPort      = 27183
	scrcpyAudioLocalPort = 27184 // companion port for audio socket
	scrcpyVersion        = "2.7" // fallback when the real version can't be detected

	// Distinct session ids so the video and audio server processes bind
	// different abstract sockets (scrcpy_<scid>) and never collide.
	scrcpyVideoSCID = "1bad7e57"
	scrcpyAudioSCID = "2bad7e57"
)

var scrcpyVerRe = regexp.MustCompile(`v?(\d+\.\d+(?:\.\d+)?)`)

// detectScrcpyVersion returns the scrcpy-server version string that MUST be
// passed as the first arg to com.genymobile.scrcpy.Server. The server refuses
// to start if this does not exactly match its built-in version, which is why a
// hardcoded "2.7" silently breaks newer installs (e.g. scrcpy v4.0) and falls
// back to the black screenrecord path. We read it from the install directory
// name (scrcpy-win64-v4.0 → 4.0), then from `scrcpy --version`.
func detectScrcpyVersion(serverPath string) string {
	dir := filepath.Dir(serverPath)
	if m := scrcpyVerRe.FindStringSubmatch(filepath.Base(dir)); len(m) == 2 {
		return m[1]
	}
	// Ask the binary directly.
	for _, name := range []string{"scrcpy.exe", "scrcpy"} {
		bin := filepath.Join(dir, name)
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		out, _ := exec.CommandContext(ctx, bin, "--version").CombinedOutput()
		cancel()
		if m := scrcpyVerRe.FindStringSubmatch(string(out)); len(m) == 2 {
			return m[1]
		}
		break
	}
	return scrcpyVersion
}

// findScrcpyServerInfo returns the scrcpy-server path and its matching version.
func findScrcpyServerInfo() (string, string) {
	p := web.FindScrcpyServer()
	if p == "" {
		return "", ""
	}
	return p, detectScrcpyVersion(p)
}

// handleLiveVideo upgrades the request to a WebSocket and streams H.264.
// It tries scrcpy-server first for low latency; if that fails it falls back
// to screenrecord.
func handleLiveVideo(w http.ResponseWriter, r *http.Request) {
	serial := web.LiveSerial()
	if serial == "" {
		http.Error(w, "no device", http.StatusNotFound)
		return
	}
	conn, _, _, err := wsx.UpgradeHTTP(r, w)
	if err != nil {
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			if _, _, err := wsx.ReadClientData(conn); err != nil {
				cancel()
				return
			}
		}
	}()

	adb := web.LiveADB()
	serverPath, serverVer := findScrcpyServerInfo()

	if serverPath != "" {
		// Try scrcpy-server protocol (~50 ms latency).
		if err := streamScrcpy(ctx, adb, serial, serverPath, serverVer, conn); err == nil || ctx.Err() != nil {
			return
		}
	}

	// Fallback: screenrecord (works on all Android, higher latency).
	for ctx.Err() == nil {
		if err := streamH264Once(ctx, adb, serial, conn); err != nil && ctx.Err() == nil {
			time.Sleep(500 * time.Millisecond)
		}
	}
}

// streamScrcpy pushes scrcpy-server to the device and streams H.264 frames
// from it over an ADB-forwarded TCP socket.
//
// version MUST match the installed server exactly — pass the value detected by
// detectScrcpyVersion. The abstract socket the server binds is scrcpy_<scid>,
// so the adb forward target and the scid arg must agree. raw_stream=true turns
// off all framing (device/frame/codec meta + dummy byte), so the socket carries
// a bare H.264 Annex-B stream with no header to strip.
func streamScrcpy(ctx context.Context, adb, serial, serverPath, version string, conn net.Conn) error {
	// 1. Push the server JAR.
	// MediaTek / some vendor ROMs return a spurious EOF on the copy-response even
	// though the file transfers successfully ("1 file pushed").  Treat that as
	// success so the server still starts; only hard-fail when nothing was pushed.
	pushCmd := exec.CommandContext(ctx, adb, "-s", serial, "push", serverPath, "/data/local/tmp/scrcpy-server")
	pushOut, pushErr := pushCmd.CombinedOutput()
	if pushErr != nil && !bytes.Contains(pushOut, []byte("file pushed")) {
		return fmt.Errorf("push: %w — %s", pushErr, pushOut)
	}

	// 2. Forward a local port to the abstract socket the server will create.
	socketName := "scrcpy_" + scrcpyVideoSCID
	fwdCmd := exec.CommandContext(ctx, adb, "-s", serial,
		"forward", fmt.Sprintf("tcp:%d", scrcpyLocalPort),
		"localabstract:"+socketName)
	if err := fwdCmd.Run(); err != nil {
		return fmt.Errorf("forward: %w", err)
	}
	defer exec.Command(adb, "-s", serial, "forward", "--remove",
		fmt.Sprintf("tcp:%d", scrcpyLocalPort)).Run() //nolint:errcheck

	// 3. Launch the server process on the device.
	//    We use CLASSPATH trick — scrcpy-server is both a JAR and a DEX archive.
	args := []string{
		"-s", serial, "shell",
		"CLASSPATH=/data/local/tmp/scrcpy-server",
		"app_process", "/", "com.genymobile.scrcpy.Server",
		version,
		"scid=" + scrcpyVideoSCID,
		"tunnel_forward=true",
		"audio=false",
		"control=false",
		"max_size=1280",
		fmt.Sprintf("max_fps=%d", 30),
		fmt.Sprintf("video_bit_rate=%d", 6_000_000),
		// Disable all framing headers individually — raw_stream=true is equivalent
		// but these individual flags work across a wider range of server versions.
		"send_device_meta=false",
		"send_frame_meta=false",
		"send_dummy_byte=false",
	}
	srvCmd := exec.CommandContext(ctx, adb, args...)
	srvCmd.Stdout = io.Discard
	var srvStderr bytes.Buffer
	srvCmd.Stderr = &srvStderr
	if err := srvCmd.Start(); err != nil {
		return fmt.Errorf("server start: %w", err)
	}
	defer func() {
		_ = srvCmd.Process.Kill()
		_ = srvCmd.Wait()
	}()

	// 4. Connect to the forwarded port.  Real devices (especially MediaTek) can
	// take several seconds to start the JVM; retry for up to 10 s.
	var sock net.Conn
	for i := 0; i < 50; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		time.Sleep(200 * time.Millisecond)
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", scrcpyLocalPort), 500*time.Millisecond)
		if err == nil {
			sock = c
			break
		}
	}
	if sock == nil {
		if srvStderr.Len() > 0 {
			return fmt.Errorf("scrcpy socket timeout — server stderr: %s", strings.TrimSpace(srvStderr.String()))
		}
		return fmt.Errorf("could not connect to scrcpy socket after 10 s")
	}
	defer sock.Close()

	// 5. Forward raw H.264 Annex-B frames to the WebSocket (no dummy byte: we
	//    disabled it above so the very first bytes are already the SPS NAL).
	return forwardAccessUnits(ctx, sock, conn)
}

// streamH264Once runs one screenrecord session and forwards its access units
// until the stream ends or the context is cancelled. Used as fallback when
// scrcpy-server is unavailable.
func streamH264Once(ctx context.Context, adb, serial string, conn net.Conn) error {
	// Pick a reasonable resolution: cap at 720p to keep bitrate and latency low.
	dw, dh := web.LiveDeviceSize(adb, serial)
	size := ""
	if dw > 0 && dh > 0 {
		// Keep aspect ratio, limit longer dimension to 720.
		if dh > dw {
			if dh > 720 {
				dw = dw * 720 / dh
				dh = 720
			}
		} else {
			if dw > 720 {
				dh = dh * 720 / dw
				dw = 720
			}
		}
		size = fmt.Sprintf("--size=%dx%d", dw, dh)
	}

	args := []string{"-s", serial, "exec-out",
		"screenrecord", "--output-format=h264", "--time-limit=170",
		"--bit-rate=2000000"}
	if size != "" {
		args = append(args, size)
	}
	args = append(args, "-")

	cmd := exec.CommandContext(ctx, adb, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	return forwardAccessUnits(ctx, stdout, conn)
}

// handleLiveAudio streams system audio from the device via scrcpy-server's audio
// channel (AAC-ADTS, raw stream). Falls back to 503 if scrcpy-server is absent.
// The server is launched with audio=true, video=false so it only captures audio.
func handleLiveAudio(w http.ResponseWriter, r *http.Request) {
	serial := web.LiveSerial()
	if serial == "" {
		http.Error(w, "no device", http.StatusNotFound)
		return
	}
	serverPath, serverVer := findScrcpyServerInfo()
	if serverPath == "" {
		http.Error(w, "scrcpy-server not found — install scrcpy to enable audio", http.StatusServiceUnavailable)
		return
	}
	conn, _, _, err := wsx.UpgradeHTTP(r, w)
	if err != nil {
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			if _, _, err := wsx.ReadClientData(conn); err != nil {
				cancel()
				return
			}
		}
	}()

	adb := web.LiveADB()

	// Push the server JAR (reuse the same binary as video).
	// Ignore spurious EOF copy-response on MediaTek ROMs — the file IS on the device
	// when "file pushed" appears in the output.
	audioPushOut, audioPushErr := exec.CommandContext(ctx, adb, "-s", serial,
		"push", serverPath, "/data/local/tmp/scrcpy-server").CombinedOutput()
	if audioPushErr != nil && !bytes.Contains(audioPushOut, []byte("file pushed")) {
		return // silent — video stream overlay already shows any scrcpy issues
	}

	// Audio-only server: with video=false the single socket connection carries the
	// audio stream. It binds scrcpy_<scid>; use a scid distinct from the video one
	// so the two server processes never fight over the same abstract socket name.
	socketName := "scrcpy_" + scrcpyAudioSCID
	fwdAudio := exec.CommandContext(ctx, adb, "-s", serial,
		"forward",
		fmt.Sprintf("tcp:%d", scrcpyAudioLocalPort),
		"localabstract:"+socketName)
	if err := fwdAudio.Run(); err != nil {
		wsx.WriteServerText(conn, []byte("audio forward failed: "+err.Error()))
		return
	}
	defer exec.Command(adb, "-s", serial, "forward", "--remove",
		fmt.Sprintf("tcp:%d", scrcpyAudioLocalPort)).Run() //nolint:errcheck

	// Launch server with audio-only (video=false).
	args := []string{
		"-s", serial, "shell",
		"CLASSPATH=/data/local/tmp/scrcpy-server",
		"app_process", "/", "com.genymobile.scrcpy.Server",
		serverVer,
		"scid=" + scrcpyAudioSCID,
		"tunnel_forward=true",
		"video=false",
		"audio=true",
		"audio_codec=aac",
		"audio_source=output",
		"control=false",
		"send_device_meta=false",
		"send_frame_meta=false",
		"send_dummy_byte=false",
	}
	srvCmd := exec.CommandContext(ctx, adb, args...)
	srvCmd.Stdout = io.Discard
	srvCmd.Stderr = io.Discard
	if err := srvCmd.Start(); err != nil {
		return
	}
	defer func() { _ = srvCmd.Process.Kill(); _ = srvCmd.Wait() }()

	// Connect to audio socket with retry (up to 10 s).
	var sock net.Conn
	for i := 0; i < 50 && ctx.Err() == nil; i++ {
		time.Sleep(200 * time.Millisecond)
		c, dialErr := net.DialTimeout("tcp",
			fmt.Sprintf("127.0.0.1:%d", scrcpyAudioLocalPort), 500*time.Millisecond)
		if dialErr == nil {
			sock = c
			break
		}
	}
	if sock == nil {
		return // silent — if server never opened the socket just exit quietly
	}
	defer sock.Close()

	// No dummy byte / metadata: send_dummy_byte and send_*_meta are off, so the
	// socket carries the raw AAC stream from the first byte.

	// Pipe raw AAC to the browser as binary WebSocket frames.
	buf := make([]byte, 32*1024)
	for ctx.Err() == nil {
		n, err := sock.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			if writeErr := wsx.WriteServerBinary(conn, buf[:n]); writeErr != nil {
				return
			}
		}
	}
}

// forwardAccessUnits reads an Annex-B H.264 stream, groups NAL units into
// access units, and writes each access unit as one binary WebSocket message.
func forwardAccessUnits(ctx context.Context, r io.Reader, conn net.Conn) error {
	const chunk = 1 << 15
	rd := make([]byte, chunk)

	var stream bytes.Buffer
	var au bytes.Buffer
	auHasVCL := false

	emit := func() error {
		if au.Len() == 0 {
			return nil
		}
		frame := make([]byte, au.Len())
		copy(frame, au.Bytes())
		au.Reset()
		auHasVCL = false
		return wsx.WriteServerBinary(conn, frame)
	}

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, err := r.Read(rd)
		if n > 0 {
			stream.Write(rd[:n])
			data := stream.Bytes()
			for {
				s := indexStartCode(data, 0)
				if s < 0 {
					break
				}
				next := indexStartCode(data, s+3)
				if next < 0 {
					break
				}
				nal := data[s:next]
				if e := appendNAL(&au, &auHasVCL, nal, emit); e != nil {
					return e
				}
				data = data[next:]
			}
			tail := make([]byte, len(data))
			copy(tail, data)
			stream.Reset()
			stream.Write(tail)
		}
		if err != nil {
			_ = emit()
			return err
		}
	}
}

func appendNAL(au *bytes.Buffer, auHasVCL *bool, nal []byte, emit func() error) error {
	t := nalTypeAt(nal)
	if (t == 1 || t == 5) && *auHasVCL {
		if err := emit(); err != nil {
			return err
		}
	}
	au.Write(nal)
	if t == 1 || t == 5 {
		*auHasVCL = true
	}
	return nil
}

func indexStartCode(b []byte, from int) int {
	for i := from; i+3 <= len(b); i++ {
		if b[i] == 0 && b[i+1] == 0 && b[i+2] == 1 {
			return i
		}
	}
	return -1
}

func nalTypeAt(nal []byte) byte {
	s := indexStartCode(nal, 0)
	if s < 0 || s+3 >= len(nal) {
		return 0
	}
	return nal[s+3] & 0x1f
}
