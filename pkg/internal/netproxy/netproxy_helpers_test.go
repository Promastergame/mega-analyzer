package netproxy

import (
	"encoding/binary"
	"testing"
)

// ─── readBE helper ────────────────────────────────────────────────────────

func TestReadBE_SingleByte(t *testing.T) {
	result := readBE([]byte{0x42})
	if result != 0x42 {
		t.Errorf("expected 0x42, got 0x%x", result)
	}
}

func TestReadBE_TwoBytes(t *testing.T) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, 0x1234)
	result := readBE(b)
	if result != 0x1234 {
		t.Errorf("expected 0x1234, got 0x%x", result)
	}
}

func TestReadBE_ThreeBytes(t *testing.T) {
	b := []byte{0x12, 0x34, 0x56}
	result := readBE(b)
	// 0x12 << 16 | 0x34 << 8 | 0x56 = 0x123456
	if result != 0x123456 {
		t.Errorf("expected 0x123456, got 0x%x", result)
	}
}

func TestReadBE_FourBytes(t *testing.T) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, 0x12345678)
	result := readBE(b)
	if result != 0x12345678 {
		t.Errorf("expected 0x12345678, got 0x%x", result)
	}
}

func TestReadBE_EmptySlice(t *testing.T) {
	result := readBE([]byte{})
	if result != 0 {
		t.Errorf("expected 0 for empty slice, got %d", result)
	}
}

func TestReadBE_UnknownLength(t *testing.T) {
	// 5 bytes - unknown case
	result := readBE([]byte{1, 2, 3, 4, 5})
	if result != 0 {
		t.Errorf("expected 0 for unknown length, got %d", result)
	}
}

// ─── minInt helper ────────────────────────────────────────────────────────

func TestMinInt_FirstSmaller(t *testing.T) {
	result := minInt(5, 10)
	if result != 5 {
		t.Errorf("expected 5, got %d", result)
	}
}

func TestMinInt_SecondSmaller(t *testing.T) {
	result := minInt(10, 5)
	if result != 5 {
		t.Errorf("expected 5, got %d", result)
	}
}

func TestMinInt_Equal(t *testing.T) {
	result := minInt(7, 7)
	if result != 7 {
		t.Errorf("expected 7, got %d", result)
	}
}

func TestMinInt_Negative(t *testing.T) {
	result := minInt(-5, -10)
	if result != -10 {
		t.Errorf("expected -10, got %d", result)
	}
}

func TestMinInt_MixedSigns(t *testing.T) {
	result := minInt(-5, 5)
	if result != -5 {
		t.Errorf("expected -5, got %d", result)
	}
}

func TestMinInt_Zero(t *testing.T) {
	result := minInt(0, 5)
	if result != 0 {
		t.Errorf("expected 0, got %d", result)
	}
}

// ─── upstreamAllowed helper ───────────────────────────────────────────────

func TestUpstreamAllowed_Localhost(t *testing.T) {
	if !upstreamAllowed("localhost") {
		t.Error("expected localhost to be allowed")
	}
}

func TestUpstreamAllowed_LocalhostWithPort(t *testing.T) {
	if !upstreamAllowed("localhost:8080") {
		t.Error("expected localhost:8080 to be allowed")
	}
}

func TestUpstreamAllowed_LoopbackIP(t *testing.T) {
	if !upstreamAllowed("127.0.0.1") {
		t.Error("expected 127.0.0.1 to be allowed")
	}
}

func TestUpstreamAllowed_LoopbackIPWithPort(t *testing.T) {
	if !upstreamAllowed("127.0.0.1:9000") {
		t.Error("expected 127.0.0.1:9000 to be allowed")
	}
}

func TestUpstreamAllowed_PrivateIP(t *testing.T) {
	if !upstreamAllowed("192.168.1.1") {
		t.Error("expected 192.168.1.1 (private) to be allowed")
	}
}

func TestUpstreamAllowed_PrivateIP_Class_A(t *testing.T) {
	if !upstreamAllowed("10.0.0.1") {
		t.Error("expected 10.0.0.1 (private) to be allowed")
	}
}

func TestUpstreamAllowed_PrivateIP_Class_B(t *testing.T) {
	if !upstreamAllowed("172.16.0.1") {
		t.Error("expected 172.16.0.1 (private) to be allowed")
	}
}

func TestUpstreamAllowed_EmptyString(t *testing.T) {
	if upstreamAllowed("") {
		t.Error("expected empty string to not be allowed")
	}
}

func TestUpstreamAllowed_PortOnly(t *testing.T) {
	if upstreamAllowed(":8080") {
		t.Error("expected port-only to not be allowed")
	}
}

func TestUpstreamAllowed_IPv6Loopback(t *testing.T) {
	if !upstreamAllowed("::1") {
		t.Error("expected ::1 (IPv6 loopback) to be allowed")
	}
}

func TestUpstreamAllowed_IPv6WithBrackets(t *testing.T) {
	if !upstreamAllowed("[::1]") {
		t.Error("expected [::1] with brackets to be allowed")
	}
}
