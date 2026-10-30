package netproxy

import (
	"encoding/binary"
	"testing"
)

func maskedWSFrame(opcode WSOpcode, payload []byte, mask [4]byte) []byte {
	out := []byte{0x80 | byte(opcode)}
	out = append(out, 0x80|byte(len(payload)))
	out = append(out, mask[:]...)
	for i, b := range payload {
		out = append(out, b^mask[i%4])
	}
	return out
}

func TestDecodeWSFrame_UnmasksClientFrame(t *testing.T) {
	mask := [4]byte{0xde, 0xad, 0xbe, 0xef}
	raw := maskedWSFrame(WSText, []byte("hello ws"), mask)
	frame, n, ok := DecodeWSFrame(raw)
	if !ok {
		t.Fatal("expected a complete frame")
	}
	if n != len(raw) {
		t.Errorf("consumed %d bytes, want %d", n, len(raw))
	}
	if !frame.Fin || frame.Opcode != WSText || !frame.Masked {
		t.Errorf("unexpected header: %+v", frame)
	}
	if string(frame.Payload) != "hello ws" {
		t.Errorf("payload = %q, want %q", frame.Payload, "hello ws")
	}
}

func TestDecodeWSFrame_IncompleteReturnsNotOK(t *testing.T) {
	if _, _, ok := DecodeWSFrame([]byte{0x81}); ok {
		t.Error("expected ok=false for a 1-byte frame")
	}
	// Declares a 200-byte payload but only supplies a few bytes.
	if _, _, ok := DecodeWSFrame([]byte{0x82, 200, 1, 2, 3}); ok {
		t.Error("expected ok=false when payload is short")
	}
}

func TestDecodeWSFrames_Multiple(t *testing.T) {
	mask := [4]byte{1, 2, 3, 4}
	buf := append(maskedWSFrame(WSText, []byte("one"), mask), maskedWSFrame(WSBinary, []byte("two"), mask)...)
	buf = append(buf, 0x81) // trailing partial frame
	frames, rem := DecodeWSFrames(buf)
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
	if string(frames[0].Payload) != "one" || string(frames[1].Payload) != "two" {
		t.Errorf("unexpected payloads: %q %q", frames[0].Payload, frames[1].Payload)
	}
	if rem != 1 {
		t.Errorf("expected 1 trailing byte, got %d", rem)
	}
}

func TestWSOpcode_String(t *testing.T) {
	if WSText.String() != "text" || WSClose.String() != "close" {
		t.Error("unexpected opcode name")
	}
}

func h2Frame(ftype H2FrameType, flags uint8, streamID uint32, payload []byte) []byte {
	out := make([]byte, 9)
	out[0] = byte(len(payload) >> 16)
	out[1] = byte(len(payload) >> 8)
	out[2] = byte(len(payload))
	out[3] = byte(ftype)
	out[4] = flags
	binary.BigEndian.PutUint32(out[5:9], streamID&0x7fffffff)
	return append(out, payload...)
}

func TestDecodeH2Frame_DataFrame(t *testing.T) {
	raw := h2Frame(H2Data, 0x1, 3, []byte("grpc-body"))
	frame, n, ok := DecodeH2Frame(raw)
	if !ok || n != len(raw) {
		t.Fatalf("decode failed: ok=%v n=%d", ok, n)
	}
	if frame.Type != H2Data || frame.StreamID != 3 || !frame.EndStream() {
		t.Errorf("unexpected frame: %+v", frame)
	}
	if string(frame.Payload) != "grpc-body" {
		t.Errorf("payload = %q", frame.Payload)
	}
}

func TestStripH2Preface(t *testing.T) {
	buf := append([]byte(H2Preface), h2Frame(H2Settings, 0, 0, nil)...)
	rest, ok := StripH2Preface(buf)
	if !ok {
		t.Fatal("expected preface to be stripped")
	}
	frames, rem := DecodeH2Frames(buf)
	if len(frames) != 1 || frames[0].Type != H2Settings {
		t.Fatalf("expected 1 SETTINGS frame, got %d", len(frames))
	}
	if rem != 0 {
		t.Errorf("expected no trailing bytes, got %d", rem)
	}
	if len(rest) != 9 {
		t.Errorf("stripped remainder length = %d, want 9", len(rest))
	}
}

func TestDecodeH2Frames_MultiplexedStreams(t *testing.T) {
	buf := h2Frame(H2Headers, 0x4, 1, []byte{0x82})
	buf = append(buf, h2Frame(H2Data, 0x0, 1, []byte("part"))...)
	buf = append(buf, h2Frame(H2Data, 0x1, 3, []byte("other"))...)
	frames, rem := DecodeH2Frames(buf)
	if len(frames) != 3 || rem != 0 {
		t.Fatalf("expected 3 frames and no remainder, got %d frames, rem=%d", len(frames), rem)
	}
	if frames[0].Type != H2Headers || frames[2].StreamID != 3 {
		t.Errorf("unexpected frame decode: %+v", frames)
	}
}
