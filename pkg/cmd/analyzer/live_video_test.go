package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"
)

func TestLiveVideoRejectsUnavailableSelectedJob(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/live/video?job=missing-screen-job", nil)
	handleLiveVideo(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unavailable job fell back to another device: %d", w.Code)
	}
}

func scrcpyPacket(flags uint64, payload []byte) []byte {
	packet := make([]byte, 12+len(payload))
	binary.BigEndian.PutUint64(packet[:8], flags)
	binary.BigEndian.PutUint32(packet[8:12], uint32(len(payload)))
	copy(packet[12:], payload)
	return packet
}

type unexpectedVideoRead struct{ t *testing.T }

func (r unexpectedVideoRead) Read([]byte) (int, error) {
	r.t.Fatal("the first video frame must not wait for another packet")
	return 0, io.EOF
}

func TestScrcpyEmitsFirstKeyframeWithCodecConfig(t *testing.T) {
	config := []byte{0, 0, 0, 1, 0x67, 0x42, 0, 0x1e, 0, 0, 0, 1, 0x68, 0x80}
	keyframe := []byte{0, 0, 0, 1, 0x65, 0x80}
	for _, protocol := range []struct {
		version        string
		config, key    uint64
		initialSession bool
	}{
		{"2.7", 1 << 63, 1 << 62, false},
		{"3.3.4", 1 << 63, 1 << 62, false},
		{"4.0", 1 << 62, 1 << 61, true},
	} {
		t.Run(protocol.version, func(t *testing.T) {
			var input []byte
			if protocol.initialSession {
				input = scrcpySession(720, 1280, false)
			}
			input = append(input, scrcpyPacket(protocol.config, config)...)
			input = append(input, scrcpyPacket(protocol.key, keyframe)...)
			emitted := errors.New("first frame delivered")
			reader := io.MultiReader(iotest.OneByteReader(bytes.NewReader(input)), unexpectedVideoRead{t})
			err := forwardScrcpyFrames(context.Background(), reader, protocol.version, func(frame []byte) error {
				if !bytes.Equal(frame, append(append([]byte(nil), config...), keyframe...)) {
					t.Fatalf("keyframe contains metadata or lost codec config: %x", frame)
				}
				return emitted
			})
			if !errors.Is(err, emitted) {
				t.Fatal(err)
			}
		})
	}
}

func scrcpySession(width, height uint32, clientResize bool) []byte {
	header := make([]byte, 12)
	header[0] = 0x80
	if clientResize {
		header[3] = 1
	}
	binary.BigEndian.PutUint32(header[4:8], width)
	binary.BigEndian.PutUint32(header[8:12], height)
	return header
}

func TestScrcpySessionRestartClearsOldCodecConfig(t *testing.T) {
	config := []byte{0, 0, 0, 1, 0x67, 0x42, 0, 0x1e}
	keyframe := []byte{0, 0, 0, 1, 0x65, 0x80}
	input := append(scrcpyPacket(1<<62, config), scrcpyPacket(1<<61, keyframe)...)
	input = append(input, scrcpySession(1280, 720, true)...)
	input = append(input, scrcpyPacket(1<<61, keyframe)...)
	frames := 0
	err := forwardScrcpyFrames(context.Background(), bytes.NewReader(input), "4.0", func(frame []byte) error {
		frames++
		want := keyframe
		if frames == 1 {
			want = append(append([]byte(nil), config...), keyframe...)
		}
		if !bytes.Equal(frame, want) {
			t.Fatalf("session reused old metadata: %x", frame)
		}
		return nil
	})
	if !errors.Is(err, io.EOF) || frames != 2 {
		t.Fatalf("received %d frames, err=%v", frames, err)
	}
}

func TestScrcpyRejectsTruncatedAndOversizedPackets(t *testing.T) {
	packet := scrcpyPacket(1<<61, []byte{0, 0, 0, 1, 0x65, 0x80})
	oversized := append([]byte(nil), packet[:12]...)
	binary.BigEndian.PutUint32(oversized[8:], 1<<30)
	for _, input := range [][]byte{packet[:11], packet[:len(packet)-1], oversized} {
		err := forwardScrcpyFrames(context.Background(), bytes.NewReader(input), "4.0", func([]byte) error { t.Fatal("malformed packet emitted"); return nil })
		if err == nil {
			t.Fatal("malformed packet accepted")
		}
	}
}

func TestScrcpyRetriesForwardedSocketUntilServerIsReady(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var accepted atomic.Int32
	packet := scrcpyPacket(1<<62, []byte{0, 0, 0, 1, 0x65, 0x80})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if accepted.Add(1) == 3 {
				_, _ = conn.Write(packet)
				_ = conn.Close()
				return
			}
			_ = conn.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, header, err := connectScrcpyVideoSocket(ctx, listener.Addr().(*net.TCPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !bytes.Equal(header, packet[:12]) || accepted.Load() != 3 {
		t.Fatal("accepted an ADB connection before the video server was ready")
	}
	payload, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(payload, packet[12:]) {
		t.Fatalf("first packet was not preserved: %x, %v", payload, err)
	}
}
