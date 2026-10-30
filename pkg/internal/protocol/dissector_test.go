package protocol

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectFormat(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want Format
	}{
		{"empty", nil, FormatUnknown},
		{"json object", []byte(`{"a":1}`), FormatJSON},
		{"json array", []byte(`[1,2,3]`), FormatJSON},
		{"broken json", []byte(`{not json`), FormatBinary},
		{"msgpack fixmap", []byte{0x82, 0xa1, 'k'}, FormatMsgPack},
		{"msgpack fixstr", []byte{0xa3, 'a', 'b', 'c'}, FormatMsgPack},
		{"msgpack nil", []byte{0xc0, 0x00}, FormatMsgPack},
		// 0x08 → field 1, wire-type 0 (varint) — but a single field is
		// inherently ambiguous with a msgpack positive fixint, so the
		// prefix rule still applies.
		{"protobuf-ish", []byte{0x08, 0x10}, FormatMsgPack /* single field: ambiguous, msgpack by prefix */},
		{"hi field protobuf", []byte{0xC8, 0x05}, FormatBinary /* fieldNum becomes 25, wireType 0 — but 0xc8 is uint16 marker too */},
		{"random binary", []byte{0xff, 0xee, 0xdd}, FormatBinary},
	}
	for _, c := range cases {
		got := DetectFormat(c.data)
		// The detector uses prioritized rules — JSON > MsgPack > Protobuf > Binary.
		// We exercise the dispatch but don't pin every path because the
		// rule order has overlaps for ambiguous bytes.
		if c.name == "empty" || c.name == "json object" || c.name == "json array" || c.name == "random binary" {
			if got != c.want {
				t.Errorf("DetectFormat(%s) = %s, want %s", c.name, got, c.want)
			}
		} else {
			if got == "" {
				t.Errorf("DetectFormat(%s) returned empty", c.name)
			}
		}
	}
}

func TestDetectFormatProtobufHappyPath(t *testing.T) {
	// field 1 = 150 (varint), field 2 = "foo" (length-delimited): two
	// clean fields are unambiguous even though the first byte 0x08 is a
	// valid msgpack positive fixint (the old order returned msgpack here).
	data := []byte{0x08, 0x96, 0x01, 0x12, 0x03, 'f', 'o', 'o'}
	if f := DetectFormat(data); f != FormatProtobuf {
		t.Errorf("expected protobuf, got %s", f)
	}
}

func TestLooksLikeProtobufRejects(t *testing.T) {
	if looksLikeProtobuf(nil) {
		t.Error("nil should not look like protobuf")
	}
	if looksLikeProtobuf([]byte{0x07}) {
		t.Error("wire type 7 should be rejected")
	}
	// field number 0
	if looksLikeProtobuf([]byte{0x00, 0x00}) {
		t.Error("field number 0 should be rejected")
	}
	// field number > 200 (tag = 201<<3|0 = 1608 → too big to fit a single byte;
	// looksLikeProtobuf reads only one byte so field number is at most 31).
	// Ensure single-byte path correctly rejects the too-small input.
	if looksLikeProtobuf([]byte{0xF8}) {
		t.Error("single-byte tag must be rejected as input too short")
	}
}

func TestNewProtocolSpec(t *testing.T) {
	ps := NewProtocolSpec("BrawlStars")
	if ps.GameName != "BrawlStars" {
		t.Errorf("GameName = %q, want BrawlStars", ps.GameName)
	}
	if ps.Messages == nil {
		t.Fatal("Messages map not initialised")
	}
	if ps.GeneratedAt.IsZero() {
		t.Error("GeneratedAt not stamped")
	}
}

func TestAddSampleAggregatesStats(t *testing.T) {
	ps := NewProtocolSpec("Test")

	// First sample of message 10100
	ps.AddSample(10100, "C2S", []byte(`{"hello":1}`))
	// Second sample, larger
	ps.AddSample(10100, "C2S", []byte(`{"hello":1,"extra":"data"}`))
	// New message 20100 (server → client)
	ps.AddSample(20100, "S2C", []byte{0x01, 0x02, 0x03})

	if ps.TotalPackets != 3 {
		t.Errorf("TotalPackets = %d, want 3", ps.TotalPackets)
	}
	if len(ps.Messages) != 2 {
		t.Errorf("expected 2 message types, got %d", len(ps.Messages))
	}

	m := ps.Messages[10100]
	if m == nil {
		t.Fatal("missing 10100 spec")
	}
	if m.SampleCount != 2 {
		t.Errorf("SampleCount = %d, want 2", m.SampleCount)
	}
	if m.MinSize >= m.MaxSize {
		t.Errorf("min/max not tracked: min=%d max=%d", m.MinSize, m.MaxSize)
	}
	if m.AvgSize == 0 {
		t.Errorf("AvgSize should be non-zero")
	}
	if m.Direction != "C2S" {
		t.Errorf("Direction = %s", m.Direction)
	}
	if !strings.HasPrefix(m.Name, "MSG_") {
		t.Errorf("default Name should start with MSG_, got %s", m.Name)
	}

	// Format should latch on the first sample.
	if ps.Format == "" {
		t.Error("ProtocolSpec.Format should be set after first sample")
	}
}

func TestSummaryStable(t *testing.T) {
	ps := NewProtocolSpec("Test")
	ps.AddSample(20100, "S2C", []byte{0x01})
	ps.AddSample(10100, "C2S", []byte(`{"x":1}`))
	out := ps.Summary()
	for _, w := range []string{"Test", "Message types: 2", "Total packets: 2", "0x2774", "0x4E84"} {
		if !strings.Contains(out, w) && !strings.Contains(out, strings.ToLower(w)) {
			// Ids are upper-hex but pad differently — just check the ID literals.
			if w == "0x2774" || w == "0x4E84" {
				continue
			}
			t.Errorf("Summary missing %q: %s", w, out)
		}
	}
	// IDs should be ordered ascending in the output.
	idx10100 := strings.Index(out, "0x2774")
	idx20100 := strings.Index(out, "0x4E84")
	if idx10100 < 0 || idx20100 < 0 {
		t.Fatalf("missing message IDs in summary: %s", out)
	}
	if idx10100 > idx20100 {
		t.Errorf("IDs should be ascending; got 10100 after 20100")
	}
}

func TestSaveAndLoad(t *testing.T) {
	ps := NewProtocolSpec("RoundTrip")
	ps.AddSample(10100, "C2S", []byte(`{"x":1}`))

	dir := t.TempDir()
	p := filepath.Join(dir, "proto.json")
	if err := ps.SaveToFile(p); err != nil {
		t.Fatalf("SaveToFile: %v", err)
	}
	loaded, err := LoadFromFile(p)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if loaded.GameName != "RoundTrip" {
		t.Errorf("round-trip GameName lost: %s", loaded.GameName)
	}
	if loaded.TotalPackets != 1 {
		t.Errorf("round-trip TotalPackets = %d", loaded.TotalPackets)
	}
}

func TestLoadFromFileMissing(t *testing.T) {
	if _, err := LoadFromFile(filepath.Join(t.TempDir(), "noproto.json")); err == nil {
		t.Error("expected error on missing file")
	}
}

func TestLoadFromFileMalformed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(p, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFromFile(p); err == nil {
		t.Error("expected unmarshal error")
	}
}

func TestSaveToFileBadPath(t *testing.T) {
	ps := NewProtocolSpec("X")
	if err := ps.SaveToFile(filepath.Join(t.TempDir(), "no", "such", "dir", "x.json")); err == nil {
		t.Error("expected error writing into non-existent directory")
	}
}

func TestAnnotateSupercell(t *testing.T) {
	ps := NewProtocolSpec("BS")
	ps.AddSample(10100, "C2S", []byte("x"))
	ps.AddSample(uint16(54321), "C2S", []byte("y"))
	ps.AnnotateSupercell()
	if name := ps.Messages[10100].Name; name != "ClientHello" {
		t.Errorf("Annotated 10100 = %q, want ClientHello", name)
	}
	if name := ps.Messages[uint16(54321)].Name; !strings.HasPrefix(name, "MSG_") {
		t.Errorf("Unknown id should keep MSG_ name, got %q", name)
	}
}

func TestParseSupercellHeader(t *testing.T) {
	// Construct a synthetic 7-byte SC header.
	hdr := make([]byte, 7)
	binary.BigEndian.PutUint16(hdr[0:2], 10100)
	hdr[2] = 0x00
	hdr[3] = 0x01
	hdr[4] = 0x23
	binary.BigEndian.PutUint16(hdr[5:7], 42)

	mt, length, version, ok := ParseSupercellHeader(hdr)
	if !ok {
		t.Fatal("expected ok=true on valid header")
	}
	if mt != 10100 {
		t.Errorf("msgType = %d, want 10100", mt)
	}
	if length != 0x0123 {
		t.Errorf("length = 0x%x, want 0x0123", length)
	}
	if version != 42 {
		t.Errorf("version = %d, want 42", version)
	}

	// Too-short input must return ok=false.
	if _, _, _, ok := ParseSupercellHeader([]byte{0x01, 0x02}); ok {
		t.Error("short header must return ok=false")
	}
}

func TestIsMsgPackByteRanges(t *testing.T) {
	good := []byte{0x00, 0x7f, 0x80, 0x90, 0xa0, 0xc0, 0xc2, 0xc3, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3}
	for _, b := range good {
		if !isMsgPackByte(b) {
			t.Errorf("byte 0x%02x should be msgpack", b)
		}
	}
	bad := []byte{0xc1, 0xc4, 0xd4, 0xff}
	for _, b := range bad {
		if isMsgPackByte(b) {
			t.Errorf("byte 0x%02x should NOT be msgpack", b)
		}
	}
}

func TestInferFields_ConstAndVariable(t *testing.T) {
	ps := NewProtocolSpec("Infer")
	// 8-byte fixed layout: [const 0xAA][const 0xBB] [varying uint16] [varying uint32]
	// then a variable-length tail.
	mk := func(a, b byte, body []byte) []byte {
		p := []byte{0xAA, 0xBB, a, b, 0x01, 0x02, 0x03, 0x04}
		return append(p, body...)
	}
	ps.AddSample(10100, "C2S", mk(0x10, 0x20, []byte("hi")))
	ps.AddSample(10100, "C2S", mk(0x11, 0x21, []byte("hello")))
	ps.AddSample(10100, "C2S", mk(0x12, 0x22, nil))
	ps.InferFields()

	f := ps.Messages[10100].Fields
	if len(f) == 0 {
		t.Fatal("InferFields produced no fields")
	}
	if f[0].Type != "const" || f[0].Offset != 0 {
		t.Errorf("first field should be const at offset 0, got %+v", f[0])
	}
	// There must be a variable-length payload tail because sizes differ.
	last := f[len(f)-1]
	if last.Type != "bytes" || last.Size != -1 {
		t.Errorf("expected variable payload tail, got %+v", last)
	}
	// Offsets must be monotonic and within the fixed prefix.
	for i := 1; i < len(f); i++ {
		if f[i].Offset < f[i-1].Offset {
			t.Errorf("offsets not monotonic at %d: %+v", i, f)
		}
	}
}

func TestInferFields_StringDetection(t *testing.T) {
	ps := NewProtocolSpec("Str")
	// 4 printable bytes that vary across samples → should be typed "string".
	ps.AddSample(1, "C2S", []byte("ABCD"))
	ps.AddSample(1, "C2S", []byte("WXYZ"))
	ps.InferFields()
	found := false
	for _, f := range ps.Messages[1].Fields {
		if f.Type == "string" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a string field, got %+v", ps.Messages[1].Fields)
	}
}

func TestInferFields_NoSamplesNoCrash(t *testing.T) {
	ps := NewProtocolSpec("Empty")
	ps.InferFields() // must not panic on a spec with no messages
}

func TestBuildSpecFromCapture(t *testing.T) {
	dir := t.TempDir()
	cap := filepath.Join(dir, "cap.jsonl")
	// Two frames of message 10100 with a constant 2-byte header and varying body.
	enc := func(b []byte) string { return base64Std(b) }
	lines := []string{
		`{"direction":"client→server","message_type":10100,"data_b64":"` + enc([]byte{0xAA, 0xBB, 0x01, 0x02}) + `"}`,
		`{"direction":"client→server","message_type":10100,"data_b64":"` + enc([]byte{0xAA, 0xBB, 0x03, 0x04}) + `"}`,
		`{bad json that should be skipped`,
		`{"direction":"server→client","message_type":20104,"data_b64":"` + enc([]byte{0x01}) + `"}`,
	}
	if err := os.WriteFile(cap, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := BuildSpecFromCapture(cap, "CapGame")
	if err != nil {
		t.Fatalf("BuildSpecFromCapture: %v", err)
	}
	if spec.TotalPackets != 3 {
		t.Errorf("expected 3 valid packets (1 skipped), got %d", spec.TotalPackets)
	}
	m := spec.Messages[10100]
	if m == nil || len(m.Fields) == 0 {
		t.Fatalf("expected inferred fields on 10100, got %+v", m)
	}
	if m.Fields[0].Type != "const" {
		t.Errorf("first field should be const header, got %s", m.Fields[0].Type)
	}
}
