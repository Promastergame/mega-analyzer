package protocol

import (
	"fmt"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PROTOCOL-AWARE FRAME FUZZER
// ═══════════════════════════════════════════════════════════════════════════════
//
// Passive interception tells you what a client *does* send. This turns that
// knowledge around: given a captured frame and the field layout inferred by
// InferFields, it generates a corpus of mutated frames that probe the server's
// validation — boundary values on each field, length-prefix desyncs, bit flips,
// truncation/extension, and cross-opcode type confusion.
//
// The output is deterministic (no RNG): the same seed + layout always yields the
// same corpus, so a finding is reproducible and a regression test is stable.

// FrameLayout describes the wire structure of a frame so the mutator can target
// the header's length field and the payload region precisely.
type FrameLayout struct {
	// HeaderLen is the number of header bytes before the application payload.
	// 0 means the whole frame is payload (no header).
	HeaderLen int
	// LenOffset is the byte offset of the length field within the header, or -1
	// when the protocol has no length prefix.
	LenOffset int
	// LenSize is the width of the length field in bytes (1–4). Ignored when
	// LenOffset < 0.
	LenSize int
	// LenInclHeader is true when the length field counts the header bytes too.
	LenInclHeader bool
}

// SupercellLayout is the [2B type][3B length][2B version] header; the 3-byte
// length counts the payload only. Mirrors SupercellFramer in netproxy.
func SupercellLayout() FrameLayout {
	return FrameLayout{HeaderLen: 7, LenOffset: 2, LenSize: 3, LenInclHeader: false}
}

// Mutation is one generated test case derived from a seed frame.
type Mutation struct {
	// Name is a short, stable identifier (e.g. "field:field_4:0xFF").
	Name string `json:"name"`
	// Strategy is the family of mutation that produced this case.
	Strategy string `json:"strategy"`
	// Data is the full mutated frame (header + payload).
	Data []byte `json:"-"`
	// DataHex is Data rendered as hex for JSON manifests.
	DataHex string `json:"data_hex"`
	// Description explains what the mutation probes and why it might matter.
	Description string `json:"description"`
	// TargetField is the inferred field this case targets, when applicable.
	TargetField string `json:"target_field,omitempty"`
}

// Mutation strategy identifiers.
const (
	StrategyFieldBoundary = "field-boundary"
	StrategyLengthDesync  = "length-desync"
	StrategyBitFlip       = "bit-flip"
	StrategyTruncate      = "truncate"
	StrategyExtend        = "extend"
)

// maxBitFlipSamples caps how many single-bit-flip cases are emitted per frame so
// a large payload does not generate millions of near-identical cases. The flips
// are spread evenly across the payload.
const maxBitFlipSamples = 32

// MutateFrame produces field-aware and structural mutations of a single seed
// frame. fields are the inferred FieldSpecs for the frame's payload (offsets are
// payload-relative, i.e. relative to layout.HeaderLen).
func MutateFrame(seed []byte, layout FrameLayout, fields []FieldSpec) []Mutation {
	var out []Mutation
	emit := func(m Mutation) {
		m.DataHex = toHex(m.Data)
		out = append(out, m)
	}

	// ── 1. Field boundary values ────────────────────────────────────────────
	for _, f := range fields {
		if f.Size <= 0 {
			continue // variable-length / unknown — handled by extend/truncate
		}
		abs := layout.HeaderLen + f.Offset
		if abs < 0 || abs+f.Size > len(seed) {
			continue
		}
		for _, bv := range boundaryValues(f.Size) {
			m := cloneBytes(seed)
			copy(m[abs:abs+f.Size], bv.pattern)
			emit(Mutation{
				Name:        fmt.Sprintf("field:%s:%s", f.Name, bv.label),
				Strategy:    StrategyFieldBoundary,
				Data:        m,
				Description: fmt.Sprintf("Set %s (%s @%d) to %s — probes range/overflow handling.", f.Name, f.Type, f.Offset, bv.label),
				TargetField: f.Name,
			})
		}
	}

	// ── 2. Length-prefix desync ─────────────────────────────────────────────
	if layout.LenOffset >= 0 && layout.LenSize >= 1 && layout.LenSize <= 4 &&
		layout.LenOffset+layout.LenSize <= len(seed) {
		actualPayload := len(seed) - layout.HeaderLen
		if layout.LenInclHeader {
			actualPayload = len(seed)
		}
		for _, d := range lengthDesyncValues(actualPayload) {
			m := cloneBytes(seed)
			putUintBE(m[layout.LenOffset:layout.LenOffset+layout.LenSize], d.value)
			emit(Mutation{
				Name:        fmt.Sprintf("len:%s", d.label),
				Strategy:    StrategyLengthDesync,
				Data:        m,
				Description: fmt.Sprintf("Declared length=%d while actual=%d — probes framing/reassembly (%s).", d.value, actualPayload, d.label),
			})
		}
	}

	// ── 3. Bit flips across the payload ─────────────────────────────────────
	payloadStart := layout.HeaderLen
	if payloadStart < 0 {
		payloadStart = 0
	}
	payloadLen := len(seed) - payloadStart
	if payloadLen > 0 {
		bitCount := payloadLen * 8
		samples := bitCount
		if samples > maxBitFlipSamples {
			samples = maxBitFlipSamples
		}
		step := bitCount / samples
		if step < 1 {
			step = 1
		}
		for s := 0; s < samples; s++ {
			bit := s * step
			byteIdx := payloadStart + bit/8
			if byteIdx >= len(seed) {
				break
			}
			m := cloneBytes(seed)
			m[byteIdx] ^= 1 << uint(bit%8)
			emit(Mutation{
				Name:        fmt.Sprintf("bitflip:%d.%d", bit/8, bit%8),
				Strategy:    StrategyBitFlip,
				Data:        m,
				Description: fmt.Sprintf("Flip payload bit %d (byte %d, bit %d).", bit, bit/8, bit%8),
			})
		}
	}

	// ── 4. Truncation ───────────────────────────────────────────────────────
	for _, t := range truncationLengths(len(seed), layout.HeaderLen) {
		emit(Mutation{
			Name:        fmt.Sprintf("truncate:%d", t.size),
			Strategy:    StrategyTruncate,
			Data:        cloneBytes(seed[:t.size]),
			Description: t.why,
		})
	}

	// ── 5. Extension (trailing garbage) ─────────────────────────────────────
	for _, n := range []int{1, 16, 256} {
		m := make([]byte, len(seed)+n)
		copy(m, seed)
		for i := 0; i < n; i++ {
			m[len(seed)+i] = byte(0xA5 ^ i) // deterministic filler
		}
		emit(Mutation{
			Name:        fmt.Sprintf("extend:+%d", n),
			Strategy:    StrategyExtend,
			Data:        m,
			Description: fmt.Sprintf("Append %d trailing bytes past the declared frame — probes over-read / desync.", n),
		})
	}

	return out
}

// MutateSpec generates mutations for every message in a spec that retained a
// sample, keyed by message ID. layout applies to all messages. Use after
// BuildSpecFromCapture + InferFields.
func (ps *ProtocolSpec) MutateSpec(layout FrameLayout) map[uint16][]Mutation {
	result := make(map[uint16][]Mutation, len(ps.Messages))
	for id, spec := range ps.Messages {
		if len(spec.samples) == 0 {
			continue
		}
		seed := frameSeed(id, spec.samples[0], layout)
		result[id] = MutateFrame(seed, layout, spec.Fields)
	}
	return result
}

// SeedFrame reconstructs the un-mutated seed frame for a message (header +
// retained payload sample) under the given layout. It is the baseline a
// Replayer should send before the mutations so anomalies can be compared
// against normal server behavior. Returns false when no sample was retained.
func (ps *ProtocolSpec) SeedFrame(id uint16, layout FrameLayout) ([]byte, bool) {
	spec, ok := ps.Messages[id]
	if !ok || len(spec.samples) == 0 {
		return nil, false
	}
	return frameSeed(id, spec.samples[0], layout), true
}

// frameSeed prepends a header of the right size to a payload sample so that
// payload-relative field offsets line up, reconstructing the opcode in the
// first two header bytes.
func frameSeed(id uint16, payload []byte, layout FrameLayout) []byte {
	if layout.HeaderLen <= 0 {
		return cloneBytes(payload)
	}
	framed := make([]byte, layout.HeaderLen+len(payload))
	putUintBE16(framed[0:2], id)
	// Fill the length field if the layout declares one, so the seed is a valid
	// frame the server will accept as the baseline.
	if layout.LenOffset >= 0 && layout.LenSize >= 1 && layout.LenSize <= 4 &&
		layout.LenOffset+layout.LenSize <= layout.HeaderLen {
		declared := len(payload)
		if layout.LenInclHeader {
			declared += layout.HeaderLen
		}
		putUintBE(framed[layout.LenOffset:layout.LenOffset+layout.LenSize], uint32(declared))
	}
	copy(framed[layout.HeaderLen:], payload)
	return framed
}

// ── helpers ──────────────────────────────────────────────────────────────────

type boundaryVal struct {
	label   string
	pattern []byte
}

// boundaryValues returns interesting width-byte values: all-zero, all-ones, and
// the signed/unsigned extremes that commonly break range checks.
func boundaryValues(size int) []boundaryVal {
	zeros := make([]byte, size)
	ones := make([]byte, size)
	signMin := make([]byte, size) // 0x80 0x00 ... → most-negative when read signed
	for i := range ones {
		ones[i] = 0xFF
	}
	if size > 0 {
		signMin[0] = 0x80
	}
	return []boundaryVal{
		{"zero", zeros},
		{"0xFF", ones},
		{"signMin", signMin},
	}
}

type lenDesync struct {
	label string
	value uint32
}

func lengthDesyncValues(actual int) []lenDesync {
	a := uint32(actual)
	return []lenDesync{
		{"zero", 0},
		{"minus1", sub1(a)},
		{"plus1", a + 1},
		{"huge", 0x00FFFFFF},
	}
}

func sub1(v uint32) uint32 {
	if v == 0 {
		return 0
	}
	return v - 1
}

type truncSpec struct {
	size int
	why  string
}

func truncationLengths(total, headerLen int) []truncSpec {
	var specs []truncSpec
	seen := map[int]bool{}
	add := func(sz int, why string) {
		if sz >= 0 && sz < total && !seen[sz] {
			seen[sz] = true
			specs = append(specs, truncSpec{sz, why})
		}
	}
	if headerLen > 0 {
		add(headerLen, "header only, payload removed")
		add(headerLen-1, "header itself truncated by one byte")
	}
	add(total/2, "frame cut in half")
	add(0, "empty frame")
	return specs
}

func cloneBytes(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

func putUintBE(dst []byte, v uint32) {
	switch len(dst) {
	case 1:
		dst[0] = byte(v)
	case 2:
		dst[0] = byte(v >> 8)
		dst[1] = byte(v)
	case 3:
		dst[0] = byte(v >> 16)
		dst[1] = byte(v >> 8)
		dst[2] = byte(v)
	case 4:
		dst[0] = byte(v >> 24)
		dst[1] = byte(v >> 16)
		dst[2] = byte(v >> 8)
		dst[3] = byte(v)
	}
}

func putUintBE16(dst []byte, v uint16) {
	if len(dst) >= 2 {
		dst[0] = byte(v >> 8)
		dst[1] = byte(v)
	}
}

const hexDigits = "0123456789abcdef"

func toHex(b []byte) string {
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexDigits[c>>4]
		out[i*2+1] = hexDigits[c&0x0f]
	}
	return string(out)
}
