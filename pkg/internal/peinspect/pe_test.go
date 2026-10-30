package peinspect

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Review round: the package had zero tests for a binary parser. These pin
// the tri-state contract consumers rely on (nil = unknown, not disabled),
// the happy paths, and panic-freedom on truncated input.
//
// Fixtures are hand-built minimal PEs: DOS(64) + PE sig + COFF + optional
// header + 1 .text section + optional load-config struct inside .text raw
// + optional Authenticode overlay past the sections.

// ─── fixture builder ─────────────────────────────────────────────────────────

type peFixtureOpts struct {
	machine  uint16 // 0x14c x86, 0x8664 x64
	dllChars uint16
	ndirs    bool // emit 16 data directories (load-config + cert live here)
	// load-config struct bytes placed at .text raw start (nil = zero dir10);
	// sehCount < 0 leaves the count field zero.
	loadCfg  []byte
	sehCount int32
	// certDER, when non-nil, is wrapped in WIN_CERTIFICATE and appended as
	// an 8-aligned overlay; certOverlap points dir4 at .text raw instead.
	certDER     []byte
	certOverlap bool
}

const (
	fixtureImageBase = 0x400000
	fixtureTextRVA   = 0x1000
	fixtureRawSize   = 0x200
)

func buildFixturePE(t *testing.T, o peFixtureOpts) []byte {
	t.Helper()
	is64 := o.machine == 0x8664 || o.machine == 0xaa64 || o.machine == 0xa641 || o.machine == 0xa64e
	var fixed uint64 = 96
	if is64 {
		fixed = 112
	}
	var optSize uint64 = fixed
	if o.ndirs {
		optSize = fixed + 16*8
	}
	secAt := uint64(64 + 4 + 20 + optSize)
	rawPtr := uint64(512)

	buf := new(bytes.Buffer)
	dos := make([]byte, 64)
	copy(dos, "MZ")
	binary.LittleEndian.PutUint32(dos[0x3c:], 64)
	buf.Write(dos)
	buf.WriteString("PE\x00\x00")
	coff := make([]byte, 20)
	binary.LittleEndian.PutUint16(coff[0:], o.machine)
	binary.LittleEndian.PutUint16(coff[2:], 1) // nsec
	binary.LittleEndian.PutUint16(coff[16:], uint16(optSize))
	buf.Write(coff)

	opt := make([]byte, optSize)
	if is64 {
		binary.LittleEndian.PutUint16(opt[0:], 0x20b)
		binary.LittleEndian.PutUint64(opt[24:], fixtureImageBase)
	} else {
		binary.LittleEndian.PutUint16(opt[0:], 0x10b)
		binary.LittleEndian.PutUint32(opt[28:], fixtureImageBase)
	}
	binary.LittleEndian.PutUint16(opt[70:], o.dllChars)
	if o.ndirs {
		binary.LittleEndian.PutUint32(opt[fixed-4:], 16)
	}
	buf.Write(opt)
	if uint64(buf.Len()) != secAt {
		t.Fatalf("layout drift: at section table, len=%d want %d", buf.Len(), secAt)
	}

	sec := make([]byte, 40)
	copy(sec, ".text")
	binary.LittleEndian.PutUint32(sec[8:], 0x100) // virtual size
	binary.LittleEndian.PutUint32(sec[12:], fixtureTextRVA)
	binary.LittleEndian.PutUint32(sec[16:], fixtureRawSize)
	binary.LittleEndian.PutUint32(sec[20:], uint32(rawPtr))
	binary.LittleEndian.PutUint32(sec[36:], 0x60000020)
	buf.Write(sec)

	for uint64(buf.Len()) < rawPtr {
		buf.WriteByte(0)
	}
	textRaw := make([]byte, fixtureRawSize)
	if o.loadCfg != nil {
		copy(textRaw, o.loadCfg)
		if o.sehCount >= 0 {
			if is64 {
				// x64 SEH table/count live elsewhere; keep count field zero.
			} else {
				binary.LittleEndian.PutUint32(textRaw[68:], uint32(o.sehCount))
			}
		}
	}
	buf.Write(textRaw)

	if o.ndirs {
		// Back-patch directory entries: [10] load-config, [4] certificates.
		optBase := 64 + 4 + 20
		if o.loadCfg != nil {
			binary.LittleEndian.PutUint32(opt[fixed+10*8:], fixtureTextRVA)
			binary.LittleEndian.PutUint32(opt[fixed+10*8+4:], uint32(len(o.loadCfg)))
		}
		if o.certDER != nil {
			certOff := uint64(buf.Len())
			if o.certOverlap {
				certOff = rawPtr
			} else {
				for certOff%8 != 0 {
					buf.WriteByte(0)
					certOff++
				}
			}
			wincert := make([]byte, 8+len(o.certDER))
			binary.LittleEndian.PutUint32(wincert[0:], uint32(8+len(o.certDER)))
			binary.LittleEndian.PutUint16(wincert[4:], 0x0200)
			binary.LittleEndian.PutUint16(wincert[6:], 0x0002)
			copy(wincert[8:], o.certDER)
			if !o.certOverlap {
				buf.Write(wincert)
				for uint64(buf.Len())%8 != 0 {
					buf.WriteByte(0)
				}
			}
			binary.LittleEndian.PutUint32(opt[fixed+4*8:], uint32(certOff))
			// Directory size covers the entry *including* its 8-byte
			// alignment padding, like real files: the parser walks
			// aligned chunks inside this window.
			padded := (8 + len(o.certDER) + 7) &^ 7
			binary.LittleEndian.PutUint32(opt[fixed+4*8+4:], uint32(padded))
		}
		// Re-emit the optional header with patched directories.
		out := buf.Bytes()
		copy(out[optBase:optBase+int(optSize)], opt)
		return out
	}
	return buf.Bytes()
}

// load-config structs: cookie VA + SEH table VA valid (imageBase + text RVA).
func x86LoadCfg(cookieVA, sehTableVA uint64) []byte {
	b := make([]byte, 92)
	binary.LittleEndian.PutUint32(b[0:], 92)
	binary.LittleEndian.PutUint32(b[60:], uint32(cookieVA))
	binary.LittleEndian.PutUint32(b[64:], uint32(sehTableVA))
	binary.LittleEndian.PutUint32(b[72:], fixtureImageBase+fixtureTextRVA+0x100)
	binary.LittleEndian.PutUint32(b[88:], 0x100) // GuardFlags: CF instrumented
	return b
}

func x64LoadCfg(cookieVA uint64) []byte {
	b := make([]byte, 148)
	binary.LittleEndian.PutUint32(b[0:], 148)
	binary.LittleEndian.PutUint64(b[88:], cookieVA)
	binary.LittleEndian.PutUint64(b[112:], fixtureImageBase+fixtureTextRVA+0x100)
	binary.LittleEndian.PutUint32(b[144:], 0x100)
	return b
}

// ─── minimal DER SignedData (for the "present" certificate path) ────────────

func derTLV(tag byte, body []byte) []byte {
	var out []byte
	out = append(out, tag)
	out = append(out, derLen(len(body))...)
	return append(out, body...)
}

func derLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var tmp []byte
	for v := n; v > 0; v >>= 8 {
		tmp = append([]byte{byte(v)}, tmp...)
	}
	return append([]byte{byte(0x80 | len(tmp))}, tmp...)
}

var (
	oidSHA256      = []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}
	oidSignedData  = []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02}
	oidSpcIndirect = []byte{0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04}
)

func testSignedDataDER() []byte {
	digestAlgo := derTLV(0x30, oidSHA256)
	digests := derTLV(0x31, digestAlgo)
	content := derTLV(0x30, oidSpcIndirect)
	signer := derTLV(0x04, []byte("x"))
	signers := derTLV(0x31, signer)
	var signed []byte
	signed = append(signed, derTLV(0x02, []byte{0x01})...)
	signed = append(signed, digests...)
	signed = append(signed, content...)
	signed = append(signed, signers...)
	signedSeq := derTLV(0x30, signed)
	explicit := derTLV(0xA0, signedSeq)
	var ci []byte
	ci = append(ci, oidSignedData...)
	ci = append(ci, explicit...)
	return derTLV(0x30, ci)
}

// ─── happy paths ─────────────────────────────────────────────────────────────

func TestReviewX86Full(t *testing.T) {
	va := uint64(fixtureImageBase + fixtureTextRVA)
	data := buildFixturePE(t, peFixtureOpts{
		machine:  0x14c,
		dllChars: 0x40 | 0x100, // dynamic base + NX, no NO_SEH
		ndirs:    true,
		loadCfg:  x86LoadCfg(va, va),
		sehCount: 2,
	})
	m, err := Inspect(data)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if m.Architecture != "x86" || m.Is64Bit {
		t.Errorf("arch = %q 64bit=%v", m.Architecture, m.Is64Bit)
	}
	if !m.LoadConfigPresent {
		t.Error("LoadConfigPresent should be true")
	}
	if m.StackCookie == nil || !*m.StackCookie {
		t.Errorf("StackCookie should be *true, got %v", boolPtrStr(m.StackCookie))
	}
	if m.SafeSEH == nil || !*m.SafeSEH {
		t.Errorf("SafeSEH should be *true, got %v", boolPtrStr(m.SafeSEH))
	}
	if m.Signature.Status != "absent" || m.Signature.Integrity != "unknown" || m.Signature.Trust != "unknown" {
		t.Errorf("unexpected signature state: %+v", m.Signature)
	}
}

func TestReviewX64Cookie(t *testing.T) {
	va := uint64(fixtureImageBase + fixtureTextRVA)
	data := buildFixturePE(t, peFixtureOpts{
		machine: 0x8664,
		ndirs:   true,
		loadCfg: x64LoadCfg(va),
	})
	m, err := Inspect(data)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if m.Architecture != "x86_64" || !m.Is64Bit {
		t.Errorf("arch = %q 64bit=%v", m.Architecture, m.Is64Bit)
	}
	if m.StackCookie == nil || !*m.StackCookie {
		t.Errorf("StackCookie should be *true, got %v", boolPtrStr(m.StackCookie))
	}
	if m.SafeSEH != nil {
		t.Error("SafeSEH must stay nil on non-x86")
	}
}

func TestReviewNoLoadConfig(t *testing.T) {
	data := buildFixturePE(t, peFixtureOpts{machine: 0x14c, ndirs: false})
	m, err := Inspect(data)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if m.LoadConfigPresent {
		t.Error("LoadConfigPresent should be false")
	}
	if m.StackCookie != nil {
		t.Error("StackCookie must be nil (unknown), not false")
	}
	if m.SafeSEH == nil || *m.SafeSEH {
		t.Errorf("SafeSEH should be *false, got %v", boolPtrStr(m.SafeSEH))
	}
}

func TestReviewSafeSEHFalseWithEmptyTable(t *testing.T) {
	va := uint64(fixtureImageBase + fixtureTextRVA)
	data := buildFixturePE(t, peFixtureOpts{
		machine:  0x14c,
		ndirs:    true,
		loadCfg:  x86LoadCfg(0, va), // zero cookie, empty SEH table
		sehCount: 0,
	})
	m, err := Inspect(data)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if m.StackCookie != nil {
		t.Error("zero cookie VA must yield nil StackCookie")
	}
	if m.SafeSEH == nil || *m.SafeSEH {
		t.Errorf("SafeSEH should be *false, got %v", boolPtrStr(m.SafeSEH))
	}
}

func boolPtrStr(b *bool) string {
	if b == nil {
		return "nil"
	}
	if *b {
		return "true"
	}
	return "false"
}

// ─── certificates ────────────────────────────────────────────────────────────

func TestReviewCertPresent(t *testing.T) {
	data := buildFixturePE(t, peFixtureOpts{
		machine: 0x8664,
		ndirs:   true,
		certDER: testSignedDataDER(),
	})
	m, err := Inspect(data)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if m.Signature.Status != "present" {
		t.Errorf("Signature.Status = %q, want present", m.Signature.Status)
	}
}

func TestReviewCertGarbage(t *testing.T) {
	data := buildFixturePE(t, peFixtureOpts{
		machine: 0x8664,
		ndirs:   true,
		certDER: []byte("not-a-cms-envelope...................."),
	})
	m, err := Inspect(data)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if m.Signature.Status != "invalid" {
		t.Errorf("Signature.Status = %q, want invalid", m.Signature.Status)
	}
}

func TestReviewCertOverlappingSection(t *testing.T) {
	// Directory points inside .text raw: overlay rule violated → invalid,
	// even though the bytes themselves are a valid envelope.
	data := buildFixturePE(t, peFixtureOpts{
		machine:     0x8664,
		ndirs:       true,
		certDER:     testSignedDataDER(),
		certOverlap: true,
	})
	m, err := Inspect(data)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if m.Signature.Status != "invalid" {
		t.Errorf("Signature.Status = %q, want invalid", m.Signature.Status)
	}
}

// ─── architecture table ──────────────────────────────────────────────────────

func TestReviewArchitecture(t *testing.T) {
	cases := map[uint16]string{
		0x14c: "x86", 0x8664: "x86_64",
		0x1c0: "arm", 0x1c2: "arm", 0x1c4: "arm",
		0xaa64: "arm64", 0xa641: "arm64ec", 0xa64e: "arm64x",
		0x200: "ia64", 0x1234: "unknown",
	}
	for machine, want := range cases {
		if got := Architecture(machine); got != want {
			t.Errorf("Architecture(0x%x) = %q, want %q", machine, got, want)
		}
	}
	// Unknown machine still inspects; SafeSEH stays nil off-x86.
	data := buildFixturePE(t, peFixtureOpts{machine: 0x1c0, ndirs: false})
	m, err := Inspect(data)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if m.Architecture != "arm" || m.SafeSEH != nil {
		t.Errorf("arch = %q safeseh = %v", m.Architecture, boolPtrStr(m.SafeSEH))
	}
}

// ─── truncated / hostile inputs: error, never panic ──────────────────────────

func TestReviewTruncatedInputs(t *testing.T) {
	full := buildFixturePE(t, peFixtureOpts{
		machine:  0x14c,
		dllChars: 0x40 | 0x100,
		ndirs:    true,
		loadCfg:  x86LoadCfg(uint64(fixtureImageBase+fixtureTextRVA), uint64(fixtureImageBase+fixtureTextRVA)),
		sehCount: 1,
		certDER:  testSignedDataDER(),
	})
	if _, err := Inspect(full); err != nil {
		t.Fatalf("full fixture should parse: %v", err)
	}
	// Every strict prefix must fail cleanly (or, at worst, parse) — panic is
	// the only unacceptable outcome for attacker-controlled bytes.
	for i := 0; i < len(full); i += 7 {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Inspect panicked on %d-byte prefix: %v", i, r)
				}
			}()
			_, _ = Inspect(full[:i])
		}()
	}

	for name, data := range map[string][]byte{
		"empty":         {},
		"short":         {'M', 'Z'},
		"no pe":         bytes.Repeat([]byte{0}, 128),
		"huge e_lfanew": append(append([]byte("MZ"), bytes.Repeat([]byte{0}, 0x3c-2)...), 0xFF, 0xFF, 0xFF, 0x7F),
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: panic: %v", name, r)
				}
			}()
			if _, err := Inspect(data); err == nil {
				t.Errorf("%s: expected an error, got ok", name)
			}
		}()
	}
}
