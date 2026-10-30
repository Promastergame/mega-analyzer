// Package peinspect reads PE hardening metadata without executing the image.
package peinspect

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math"
)

// Signature separates an embedded certificate from cryptographic verification.
// Integrity and Trust remain unknown offline: this parser validates structure
// only. Kind is "embedded" (cert dir), "catalog" reserved for catalog-signed
// files verified via Windows APIs; Certs/Signers count parsed envelopes.
type Signature struct {
	Status    string `json:"status"`
	Kind      string `json:"kind"`
	Integrity string `json:"integrity"`
	Trust     string `json:"trust"`
	Certs     int    `json:"certificates"`
	Signers   int    `json:"signers"`
	// Signer names the embedded signer certificate CN from the offline
	// self-consistency check (empty unless Integrity is valid).
	Signer       string `json:"signer,omitempty"`
	CertSHA256   string `json:"cert_sha256,omitempty"`
	ClaimedTime  string `json:"claimed_time,omitempty"`
	Note         string `json:"note,omitempty"`
	Verification string `json:"verification,omitempty"`
	Revocation   string `json:"revocation,omitempty"`
}

type SectionView struct {
	Name            string  `json:"name"`
	VA              uint64  `json:"rva"`
	VirtualSize     uint64  `json:"virtual_size"`
	Raw             uint64  `json:"file_offset"`
	RawSize         uint64  `json:"file_size"`
	Characteristics uint32  `json:"characteristics"`
	Permissions     string  `json:"permissions"`
	Entropy         float64 `json:"entropy"`
}

type Metadata struct {
	Machine              uint16        `json:"machine"`
	Architecture         string        `json:"architecture"`
	Is64Bit              bool          `json:"is_64_bit"`
	ImageBase            uint64        `json:"image_base"`
	FileCharacteristics  uint16        `json:"file_characteristics"`
	DllCharacteristics   uint16        `json:"dll_characteristics"`
	HasRelocations       bool          `json:"has_relocations"`
	RelocValid           bool          `json:"relocations_valid"`
	RelocationStatus     string        `json:"relocation_status"`
	RelocationEntries    uint64        `json:"relocation_entries"`
	StackCookie          *bool         `json:"stack_cookie"`
	SafeSEH              *bool         `json:"safe_seh"`
	LoadConfigPresent    bool          `json:"load_config_present"`
	GuardFlags           uint32        `json:"guard_flags"`
	CFValid              bool          `json:"cfg_valid"`
	CFGStatus            string        `json:"cfg_status"`
	EntryPointRVA        uint64        `json:"entry_point_rva"`
	EntryPointVA         uint64        `json:"entry_point_va"`
	EntryPointSection    string        `json:"entry_point_section,omitempty"`
	TLSCallbacks         uint64        `json:"tls_callbacks"`
	TLSCallbackAddresses []uint64      `json:"tls_callback_addresses,omitempty"`
	TLSStatus            string        `json:"tls_status"`
	Sections             []SectionView `json:"sections"`
	OverlaySize          uint64        `json:"overlay_size"`
	Signature            Signature     `json:"signature"`
	AnalysisStatus       string        `json:"analysis_status"`
	Diagnostics          []string      `json:"diagnostics,omitempty"`
}

type section struct {
	va, virtualSize, raw, rawSize uint64
	characteristics               uint32
}

// Inspect rejects truncated headers, tables and raw sections. All file-offset
// arithmetic is widened before addition, including on 32-bit hosts.
func Inspect(data []byte) (*Metadata, error) {
	span := func(off, size uint64) bool { return off <= uint64(len(data)) && size <= uint64(len(data))-off }
	u16 := func(off uint64) uint16 { return binary.LittleEndian.Uint16(data[off : off+2]) }
	u32 := func(off uint64) uint64 { return uint64(binary.LittleEndian.Uint32(data[off : off+4])) }
	if !span(0, 64) || string(data[:2]) != "MZ" {
		return nil, fmt.Errorf("invalid DOS header")
	}
	pe := u32(0x3c)
	if pe < 64 || !span(pe, 24) || string(data[pe:pe+4]) != "PE\x00\x00" {
		return nil, fmt.Errorf("invalid PE header offset or signature")
	}
	coff, opt := pe+4, pe+24
	nsec, optSize := uint64(u16(coff+2)), uint64(u16(coff+16))
	if nsec > 512 || optSize < 2 || !span(opt, optSize) {
		return nil, fmt.Errorf("invalid section count or optional header")
	}
	m := &Metadata{Machine: u16(coff), AnalysisStatus: "complete", CFGStatus: "absent", TLSStatus: "absent", RelocationStatus: "absent"}
	var fixed uint64
	switch u16(opt) {
	case 0x10b:
		fixed = 96
	case 0x20b:
		fixed = 112
		m.Is64Bit = true
	default:
		return nil, fmt.Errorf("unsupported PE optional header magic")
	}
	if optSize < fixed {
		return nil, fmt.Errorf("truncated PE optional header")
	}
	m.Architecture = Architecture(m.Machine)
	// DllCharacteristics sits at optional-header offset 70 in both PE32 and
	// PE32+: from SectionAlignment (offset 32) onward the two layouts share
	// field offsets, because PE32+'s 8-byte ImageBase at 24 exactly covers
	// PE32's BaseOfData + 4-byte ImageBase.
	m.FileCharacteristics = u16(coff + 18)
	m.DllCharacteristics = u16(opt + 70)
	ndirs := u32(opt + fixed - 4)
	if ndirs > (optSize-fixed)/8 {
		return nil, fmt.Errorf("data directories exceed optional header")
	}
	directory := func(index uint64) (uint64, uint64) {
		if index >= ndirs {
			return 0, 0
		}
		at := opt + fixed + index*8
		return u32(at), u32(at + 4)
	}
	secAt := opt + optSize
	if !span(secAt, nsec*40) {
		return nil, fmt.Errorf("truncated PE section table")
	}
	headers := u32(opt + 60)
	if headers == 0 {
		headers = secAt + nsec*40
	}
	if !span(0, headers) {
		return nil, fmt.Errorf("truncated PE headers")
	}
	sections := make([]section, 0, nsec)
	for i := uint64(0); i < nsec; i++ {
		at := secAt + i*40
		s := section{va: u32(at + 12), virtualSize: u32(at + 8), raw: u32(at + 20), rawSize: u32(at + 16), characteristics: uint32(u32(at + 36))}
		if s.rawSize > 0 && !span(s.raw, s.rawSize) {
			return nil, fmt.Errorf("section raw data exceeds file")
		}
		if s.va+max(s.virtualSize, s.rawSize) > 1<<32 {
			return nil, fmt.Errorf("section RVA overflows")
		}
		sections = append(sections, s)
	}
	rvaRange := func(rva, size uint64) (uint64, bool) {
		if rva == 0 || rva+size > 1<<32 {
			return 0, false
		}
		for _, s := range sections {
			if rva >= s.va {
				delta := rva - s.va
				if delta < s.rawSize && size <= s.rawSize-delta && span(s.raw+delta, size) {
					return s.raw + delta, true
				}
			}
		}
		if rva < headers && size <= headers-rva && span(rva, size) {
			return rva, true
		}
		return 0, false
	}
	imageBase := u32(opt + 28)
	ptrSize := uint64(4)
	if m.Is64Bit {
		imageBase = binary.LittleEndian.Uint64(data[opt+24 : opt+32])
		ptrSize = 8
	}
	m.ImageBase = imageBase
	validVA := func(va, size uint64) bool {
		if va < imageBase || va-imageBase >= 1<<32 {
			return false
		}
		rva := va - imageBase
		for _, s := range sections {
			if rva >= s.va {
				delta := rva - s.va
				limit := max(s.virtualSize, s.rawSize)
				if delta < limit && size <= limit-delta {
					return true
				}
			}
		}
		return false
	}
	if m.Machine == 0x14c {
		value := m.DllCharacteristics&0x400 != 0
		m.SafeSEH = &value
	}
	// Sections view + entropy + entry point + overlay.
	m.EntryPointRVA = u32(opt + 16)
	if m.EntryPointRVA != 0 && imageBase <= ^uint64(0)-m.EntryPointRVA {
		m.EntryPointVA = imageBase + m.EntryPointRVA
	}
	for _, s := range sections {
		// Section names live in the section table; recover best-effort.
		var entropy float64
		if s.rawSize > 0 {
			entropy = shannon(data[s.raw : s.raw+s.rawSize])
		}
		m.Sections = append(m.Sections, SectionView{VA: s.va, VirtualSize: s.virtualSize, Raw: s.raw, RawSize: s.rawSize, Characteristics: s.characteristics, Permissions: sectionPermissions(s.characteristics), Entropy: entropy})
	}
	// Attach names.
	for i := range m.Sections {
		at := secAt + uint64(i)*40
		name := string(data[at : at+8])
		for len(name) > 0 && name[len(name)-1] == 0 {
			name = name[:len(name)-1]
		}
		m.Sections[i].Name = name
		if m.EntryPointRVA >= m.Sections[i].VA && m.EntryPointRVA < m.Sections[i].VA+max(sections[i].virtualSize, sections[i].rawSize) {
			m.EntryPointSection = name
		}
	}
	// Overlay: bytes past the last raw section data and past headers, excluding cert dir.
	endRaw := headers
	for _, s := range sections {
		if s.rawSize > 0 && s.raw+s.rawSize > endRaw {
			endRaw = s.raw + s.rawSize
		}
	}
	if uint64(len(data)) > endRaw {
		m.OverlaySize = uint64(len(data)) - endRaw
	}

	if rva, size := directory(5); rva != 0 || size != 0 {
		m.inspectRelocations(data, rva, size, rvaRange, validVA)
	}
	if rva, size := directory(10); rva != 0 || size != 0 {
		off, ok := rvaRange(rva, size)
		if !ok || size < 4 {
			return nil, fmt.Errorf("invalid load config directory")
		}
		structSize := u32(off)
		if structSize < 4 || structSize > size {
			return nil, fmt.Errorf("invalid load config structure size")
		}
		m.LoadConfigPresent = true
		m.inspectLoadConfig(data[off:off+structSize], ptrSize, validVA, rvaRange, data)
	}
	if rva, size := directory(9); rva != 0 || size != 0 {
		m.inspectTLS(data, rva, size, ptrSize, rvaRange, validVA)
	}
	m.Signature = Signature{Status: "absent", Kind: "none", Integrity: "unknown", Trust: "unknown"}
	if off, size := directory(4); off != 0 || size != 0 {
		m.Signature.Status = "invalid"
		m.Signature.Kind = "embedded"
		m.Signature.Note = "certificate directory present but failed structural validation"
		// Certificates are an aligned overlay, never part of mapped sections.
		outside := off >= headers
		for _, s := range sections {
			if s.rawSize > 0 && off < s.raw+s.rawSize && s.raw < off+size {
				outside = false
			}
		}
		if outside && off%8 == 0 && size >= 8 && span(off, size) {
			if certs, signers, ok := parseCertificates(data[off : off+size]); ok {
				m.Signature.Status = "present"
				if off >= endRaw {
					m.OverlaySize -= size
				}
				m.Signature.Certs = certs
				m.Signature.Signers = signers
				// Offline self-consistency check: image digest + RSA signature
				// against the embedded certificate. Chain building and
				// revocation need the OS trust store, so Trust stays unknown.
				ar := VerifyEmbeddedSignature(data, opt+64, opt+fixed+32, off, size)
				m.Signature.Integrity = ar.Integrity
				m.Signature.Verification = ar.Verification
				m.Signature.Signer = ar.Signer
				m.Signature.CertSHA256 = ar.CertSHA256
				m.Signature.ClaimedTime = ar.ClaimedTime
				note := "embedded PKCS#7 structure valid; chain/revocation require OS verification (WinVerifyTrust)"
				if ar.Note != "" {
					note += "; " + ar.Note
				}
				m.Signature.Note = note
			}
		}
	}
	return m, nil
}

// Architecture decodes COFF.Machine, independently of PE32/PE32+ bitness.
func Architecture(machine uint16) string {
	switch machine {
	case 0x14c:
		return "x86"
	case 0x8664:
		return "x86_64"
	case 0x1c0, 0x1c2, 0x1c4:
		return "arm"
	case 0xaa64:
		return "arm64"
	case 0xa641:
		return "arm64ec"
	case 0xa64e:
		return "arm64x"
	case 0x200:
		return "ia64"
	default:
		return "unknown"
	}
}

func validCertificates(data []byte) bool {
	_, _, ok := parseCertificates(data)
	return ok
}

func parseCertificates(data []byte) (certs int, signers int, ok bool) {
	for len(data) > 0 {
		if len(data) < 8 {
			return 0, 0, false
		}
		n := uint64(binary.LittleEndian.Uint32(data))
		if n <= 8 || n > uint64(len(data)) || binary.LittleEndian.Uint16(data[4:]) != 0x200 || binary.LittleEndian.Uint16(data[6:]) != 2 {
			return 0, 0, false
		}
		s, ok := signedDataCounts(data[8:n])
		if !ok {
			return 0, 0, false
		}
		certs++
		signers += s
		aligned := (n + 7) &^ 7
		if aligned > uint64(len(data)) {
			return 0, 0, false
		}
		for _, b := range data[n:aligned] {
			if b != 0 {
				return 0, 0, false
			}
		}
		data = data[aligned:]
	}
	return certs, signers, certs > 0
}

func shannon(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, v := range b {
		freq[v]++
	}
	var e float64
	n := float64(len(b))
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

// Validate the CMS envelope, not its signature. No trust decision follows from
// ASN.1 being well formed; the report explicitly preserves both unknown states.
func signedDataEnvelope(der []byte) bool {
	var ci struct {
		OID     asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil || len(rest) != 0 || !ci.OID.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) || ci.Content.Class != 2 || ci.Content.Tag != 0 || !ci.Content.IsCompound {
		return false
	}
	var signed struct {
		Version int
		Digests []asn1.RawValue `asn1:"set"`
		Content struct {
			OID   asn1.ObjectIdentifier
			Value asn1.RawValue `asn1:"optional,explicit,tag:0"`
		}
		Certificates asn1.RawValue   `asn1:"optional,tag:0"`
		CRLs         asn1.RawValue   `asn1:"optional,tag:1"`
		Signers      []asn1.RawValue `asn1:"set"`
	}
	rest, err = asn1.Unmarshal(ci.Content.Bytes, &signed)
	if err != nil || len(rest) != 0 || signed.Version <= 0 || len(signed.Digests) == 0 || len(signed.Signers) == 0 || !signed.Content.OID.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}) {
		return false
	}
	return true
}

func signedDataCounts(der []byte) (int, bool) {
	var ci struct {
		OID     asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil || len(rest) != 0 || !ci.OID.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) || ci.Content.Class != 2 || ci.Content.Tag != 0 || !ci.Content.IsCompound {
		return 0, false
	}
	var signed struct {
		Version int
		Digests []asn1.RawValue `asn1:"set"`
		Content struct {
			OID   asn1.ObjectIdentifier
			Value asn1.RawValue `asn1:"optional,explicit,tag:0"`
		}
		Certificates asn1.RawValue   `asn1:"optional,tag:0"`
		CRLs         asn1.RawValue   `asn1:"optional,tag:1"`
		Signers      []asn1.RawValue `asn1:"set"`
	}
	rest, err = asn1.Unmarshal(ci.Content.Bytes, &signed)
	if err != nil || len(rest) != 0 || signed.Version <= 0 || len(signed.Digests) == 0 || len(signed.Signers) == 0 || !signed.Content.OID.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}) {
		return 0, false
	}
	return len(signed.Signers), true
}
