// Package protocol provides automatic protocol dissection for intercepted
// game traffic. Given a stream of raw packets, it detects the serialization
// format and generates a protocol specification.
//
// Supported formats:
//   - Protobuf (varint-encoded fields, wire types)
//   - MessagePack (compact binary)
//   - Custom binary (fixed-size headers, TLV patterns)
//   - JSON/text (fallback)
package protocol

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// FORMAT DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

// Format represents a detected serialization format.
type Format string

const (
	FormatProtobuf Format = "protobuf"
	FormatMsgPack  Format = "msgpack"
	FormatJSON     Format = "json"
	FormatBinary   Format = "binary"
	FormatUnknown  Format = "unknown"
)

// DetectFormat analyzes raw packet data and guesses the serialization format.
//
// Order matters: protobuf goes before msgpack because the msgpack check is a
// single first byte (every byte ≤ 0x7f "is" a positive fixint) while the
// protobuf check below walks ≥2 real fields. A weak prefix must never shadow
// stronger structural evidence — the old order classified virtually every
// small protobuf message (field 1-15 tags live at 0x08-0x7d) as msgpack.
func DetectFormat(data []byte) Format {
	if len(data) == 0 {
		return FormatUnknown
	}

	// JSON detection: starts with { or [
	if data[0] == '{' || data[0] == '[' {
		if json.Valid(data) {
			return FormatJSON
		}
	}

	// Protobuf detection: walk varint-encoded fields structurally.
	if looksLikeProtobuf(data) {
		return FormatProtobuf
	}

	// MessagePack detection: specific first-byte ranges
	if isMsgPackByte(data[0]) {
		return FormatMsgPack
	}

	return FormatBinary
}

func isMsgPackByte(b byte) bool {
	// MessagePack format family bytes
	switch {
	case b <= 0x7f: // positive fixint
		return true
	case b >= 0x80 && b <= 0x8f: // fixmap
		return true
	case b >= 0x90 && b <= 0x9f: // fixarray
		return true
	case b >= 0xa0 && b <= 0xbf: // fixstr
		return true
	case b == 0xc0: // nil
		return true
	case b == 0xc2 || b == 0xc3: // false, true
		return true
	case b >= 0xcc && b <= 0xcf: // uint8-64
		return true
	case b >= 0xd0 && b <= 0xd3: // int8-64
		return true
	}
	return false
}

// minProtobufFields is the minimum number of cleanly parsed fields for a
// buffer to count as protobuf. One field (2-3 bytes) is inherently ambiguous
// with msgpack positive-fixint prefixes; two independent fields plus a sane
// field number each is the cheapest reliable signal.
const minProtobufFields = 2

// maxProtobufFieldNum caps accepted field numbers. Real game protocols use
// low numbers; huge ones mean the "tag" is actually something else.
const maxProtobufFieldNum = 200

func looksLikeProtobuf(data []byte) bool {
	pos, fields := 0, 0
	for pos < len(data) && fields < 8 {
		tag, n := decodeVarint(data[pos:])
		if n <= 0 {
			break // truncated tag: judge by the fields parsed so far
		}
		pos += n
		wireType := tag & 0x07
		fieldNum := tag >> 3
		if fieldNum == 0 || fieldNum > maxProtobufFieldNum {
			return false
		}
		var need int
		switch wireType {
		case 0: // varint
			_, n := decodeVarint(data[pos:])
			if n <= 0 {
				break
			}
			need = n
		case 1: // 64-bit
			need = 8
		case 2: // length-delimited
			ln, n := decodeVarint(data[pos:])
			if n <= 0 || ln > uint64(len(data)-pos-n) {
				break
			}
			need = n + int(ln)
		case 5: // 32-bit
			need = 4
		default: // groups (3, 4) and reserved (6, 7): not walkable
			return false
		}
		if need <= 0 || pos+need > len(data) {
			break // truncated value: judge by the fields parsed so far
		}
		pos += need
		fields++
	}
	return fields >= minProtobufFields
}

// decodeVarint reads a protobuf varint. Returns (0, 0) on truncation or an
// overlong (>10 byte) encoding; callers treat that as "need more bytes".
func decodeVarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		v |= uint64(b[i]&0x7F) << (7 * uint(i))
		if b[i] < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}

// ═══════════════════════════════════════════════════════════════════════════════
// MESSAGE TYPES
// ═══════════════════════════════════════════════════════════════════════════════

// MessageSpec describes a detected message type in the protocol.
type MessageSpec struct {
	// ID is the numeric message type identifier
	ID uint16 `json:"id"`
	// Name is the inferred human-readable name (if available)
	Name string `json:"name"`
	// Direction indicates if this is C→S, S→C, or bidirectional
	Direction string `json:"direction"`
	// Format is the detected serialization format
	Format Format `json:"format"`
	// Fields describes the detected fields in the message
	Fields []FieldSpec `json:"fields,omitempty"`
	// SampleCount is how many times this message was observed
	SampleCount int `json:"sample_count"`
	// AvgSize is the average payload size
	AvgSize int `json:"avg_size"`
	// MinSize is the minimum observed size
	MinSize int `json:"min_size"`
	// MaxSize is the maximum observed size
	MaxSize int `json:"max_size"`

	// samples retains up to maxInferenceSamples raw payloads for field
	// inference. Not serialized — it is scratch state consumed by InferFields.
	samples [][]byte
}

// maxInferenceSamples caps how many payloads we retain per message for field
// inference. A handful is plenty to tell constant bytes from variable ones, and
// it keeps memory flat on a long capture.
const maxInferenceSamples = 64

// FieldSpec describes a detected field within a message.
type FieldSpec struct {
	// Name is the inferred field name
	Name string `json:"name"`
	// Type is the detected type (uint32, string, bytes, etc.)
	Type string `json:"type"`
	// Offset is the byte offset within the payload
	Offset int `json:"offset"`
	// Size is the field size (-1 for variable-length)
	Size int `json:"size"`
	// Required indicates if this field appears in every sample
	Required bool `json:"required"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROTOCOL SPEC
// ═══════════════════════════════════════════════════════════════════════════════

// ProtocolSpec is a complete specification of a game's network protocol,
// generated from intercepted traffic.
type ProtocolSpec struct {
	// GameName is the detected game name (from APK package name, etc.)
	GameName string `json:"game_name"`
	// Version is the detected game version
	Version string `json:"version,omitempty"`
	// Format is the primary serialization format
	Format Format `json:"format"`
	// HeaderSize is the size of the packet header (before payload)
	HeaderSize int `json:"header_size"`
	// Messages is a map of message type ID → specification
	Messages map[uint16]*MessageSpec `json:"messages"`
	// GeneratedAt is when this spec was created
	GeneratedAt time.Time `json:"generated_at"`
	// TotalPackets is the total number of analyzed packets
	TotalPackets int `json:"total_packets"`

	// formatVotes tallies per-message formats so Format tracks the majority,
	// not just the first sample (a JSON handshake followed by a protobuf
	// stream used to lock the whole spec to JSON). Runtime-only: not
	// serialized, so a loaded spec keeps its stored Format until new
	// samples arrive.
	formatVotes map[Format]int
}

// NewProtocolSpec creates a new empty protocol spec.
func NewProtocolSpec(gameName string) *ProtocolSpec {
	return &ProtocolSpec{
		GameName:    gameName,
		Messages:    make(map[uint16]*MessageSpec),
		GeneratedAt: time.Now(),
	}
}

// majorityFormat returns the most-voted format and its tally. Fixed
// candidate order keeps ties deterministic.
func majorityFormat(votes map[Format]int) (Format, int) {
	var best Format
	bestVotes := -1
	for _, f := range []Format{FormatProtobuf, FormatMsgPack, FormatJSON, FormatBinary, FormatUnknown} {
		if votes[f] > bestVotes {
			best, bestVotes = f, votes[f]
		}
	}
	return best, bestVotes
}

// AddSample records a packet sample for analysis.
func (ps *ProtocolSpec) AddSample(msgType uint16, direction string, payload []byte) {
	ps.TotalPackets++

	spec, ok := ps.Messages[msgType]
	if !ok {
		format := DetectFormat(payload)
		spec = &MessageSpec{
			ID:        msgType,
			Name:      fmt.Sprintf("MSG_%04X", msgType),
			Direction: direction,
			Format:    format,
			MinSize:   len(payload),
			MaxSize:   len(payload),
		}
		ps.Messages[msgType] = spec

		if ps.formatVotes == nil {
			ps.formatVotes = make(map[Format]int)
		}
		ps.formatVotes[format]++
		// Strict majority handover keeps ties deterministic: the incumbent
		// format stays until another one strictly outvotes it.
		if best, votes := majorityFormat(ps.formatVotes); votes > ps.formatVotes[ps.Format] {
			ps.Format = best
		}
	}

	spec.SampleCount++
	spec.AvgSize = (spec.AvgSize*(spec.SampleCount-1) + len(payload)) / spec.SampleCount

	if len(payload) < spec.MinSize {
		spec.MinSize = len(payload)
	}
	if len(payload) > spec.MaxSize {
		spec.MaxSize = len(payload)
	}

	if len(spec.samples) < maxInferenceSamples {
		spec.samples = append(spec.samples, append([]byte(nil), payload...))
	}
}

// InferFields walks every message's retained samples and reconstructs a field
// layout for the fixed-header region by comparing bytes position-by-position
// across samples. The heuristic:
//
//   - A byte offset that holds the SAME value in every sample is a constant
//     (opcode tag, version, flags) and is folded into a "const" field.
//   - A byte offset that varies is part of a value field. Consecutive varying
//     offsets are coalesced; runs of 1/2/4/8 bytes are typed as uint8/16/32/64,
//     longer runs as bytes/string (string when every sample is printable ASCII).
//   - Inference covers only the common prefix (min observed size); the tail is
//     reported as one variable-length "payload" field when sizes differ.
//
// This populates MessageSpec.Fields, which the generators and Summary surface.
// It is safe to call multiple times; each call rebuilds Fields from scratch.
func (ps *ProtocolSpec) InferFields() {
	for _, spec := range ps.Messages {
		spec.Fields = inferFields(spec.samples)
	}
}

func inferFields(samples [][]byte) []FieldSpec {
	if len(samples) == 0 {
		return nil
	}
	// Common prefix length = smallest sample. Beyond it, layout is ambiguous.
	prefix := len(samples[0])
	uniformSize := true
	for _, s := range samples {
		if len(s) != prefix {
			uniformSize = false
		}
		if len(s) < prefix {
			prefix = len(s)
		}
	}
	if prefix == 0 {
		return nil
	}

	// Classify each offset as constant or variable across all samples.
	constByte := make([]bool, prefix)
	for off := 0; off < prefix; off++ {
		v := samples[0][off]
		constByte[off] = true
		for _, s := range samples {
			if s[off] != v {
				constByte[off] = false
				break
			}
		}
	}

	var fields []FieldSpec
	off := 0
	for off < prefix {
		start := off
		isConst := constByte[off]
		for off < prefix && constByte[off] == isConst {
			off++
		}
		run := off - start
		if isConst {
			fields = append(fields, FieldSpec{
				Name:     fmt.Sprintf("const_%d", start),
				Type:     "const",
				Offset:   start,
				Size:     run,
				Required: true,
			})
			continue
		}
		// Split a variable run into natural machine-word widths.
		for run > 0 {
			w := wordWidth(run)
			fields = append(fields, FieldSpec{
				Name:     fmt.Sprintf("field_%d", start),
				Type:     fieldType(samples, start, w),
				Offset:   start,
				Size:     w,
				Required: true,
			})
			start += w
			run -= w
		}
	}

	// Variable-length tail when sizes differ across samples.
	if !uniformSize {
		fields = append(fields, FieldSpec{
			Name:     "payload",
			Type:     "bytes",
			Offset:   prefix,
			Size:     -1,
			Required: false,
		})
	}
	return fields
}

// wordWidth picks the largest natural integer width (8/4/2/1) that fits in n.
func wordWidth(n int) int {
	switch {
	case n >= 8:
		return 8
	case n >= 4:
		return 4
	case n >= 2:
		return 2
	default:
		return 1
	}
}

// fieldType names a width-byte field, upgrading to "string" when every sample
// holds printable ASCII at that span.
func fieldType(samples [][]byte, off, width int) string {
	if width >= 2 && allPrintable(samples, off, width) {
		return "string"
	}
	switch width {
	case 1:
		return "uint8"
	case 2:
		return "uint16"
	case 4:
		return "uint32"
	case 8:
		return "uint64"
	default:
		return "bytes"
	}
}

func allPrintable(samples [][]byte, off, width int) bool {
	for _, s := range samples {
		if off+width > len(s) {
			return false
		}
		for _, b := range s[off : off+width] {
			if b < 0x20 || b >= 0x7f {
				return false
			}
		}
	}
	return true
}

// Summary returns a human-readable summary of the protocol.
func (ps *ProtocolSpec) Summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Protocol: %s\n", ps.GameName))
	sb.WriteString(fmt.Sprintf("Format: %s\n", ps.Format))
	sb.WriteString(fmt.Sprintf("Message types: %d\n", len(ps.Messages)))
	sb.WriteString(fmt.Sprintf("Total packets: %d\n", ps.TotalPackets))
	sb.WriteString("\nMessages:\n")

	// Sort by ID
	ids := make([]uint16, 0, len(ps.Messages))
	for id := range ps.Messages {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	for _, id := range ids {
		m := ps.Messages[id]
		sb.WriteString(fmt.Sprintf("  0x%04X [%s] %s — %d samples, avg %d bytes\n",
			m.ID, m.Direction, m.Name, m.SampleCount, m.AvgSize))
		for _, f := range m.Fields {
			size := fmt.Sprintf("%d", f.Size)
			if f.Size < 0 {
				size = "var"
			}
			sb.WriteString(fmt.Sprintf("      @%-4d %-10s %s (%s bytes)\n",
				f.Offset, f.Type, f.Name, size))
		}
	}

	return sb.String()
}

// SaveToFile writes the spec as JSON.
func (ps *ProtocolSpec) SaveToFile(path string) error {
	data, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal spec: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// LoadFromFile reads a spec from JSON.
func LoadFromFile(path string) (*ProtocolSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read spec: %w", err)
	}
	var spec ProtocolSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("unmarshal spec: %w", err)
	}
	return &spec, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUPERCELL-SPECIFIC HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// SupercellMessageNames maps known Supercell message IDs to names.
// These are commonly reversed from Brawl Stars / Clash Royale / CoC.
var SupercellMessageNames = map[uint16]string{
	// Client → Server
	10100: "ClientHello",
	10101: "Login",
	10108: "KeepAlive",
	10113: "SetDeviceToken",
	10116: "AttackHome",
	10117: "SurrenderAttack",
	10212: "ChangeAvatarName",
	10905: "AskForTCPInfo",
	14102: "ExecuteCommand",
	14109: "EndClientTurn",

	// Server → Client
	20100: "ServerHello",
	20104: "LoginOk",
	20108: "KeepAliveOk",
	24101: "OwnHomeData",
	24104: "AttackHomeData",
	24111: "DisconnectedMessage",
	24112: "OutOfSync",
	24301: "AllianceData",
}

// AnnotateSupercell adds human-readable names to known Supercell message types.
func (ps *ProtocolSpec) AnnotateSupercell() {
	for id, spec := range ps.Messages {
		if name, ok := SupercellMessageNames[id]; ok {
			spec.Name = name
		}
		_ = id
	}
}

// ParseSupercellHeader parses a Supercell-style packet header.
// Format: [2 bytes msg_type] [3 bytes length] [2 bytes version]
func ParseSupercellHeader(data []byte) (msgType uint16, length uint32, version uint16, ok bool) {
	if len(data) < 7 {
		return 0, 0, 0, false
	}
	msgType = binary.BigEndian.Uint16(data[0:2])
	length = uint32(data[2])<<16 | uint32(data[3])<<8 | uint32(data[4])
	version = binary.BigEndian.Uint16(data[5:7])
	return msgType, length, version, true
}

// ═══════════════════════════════════════════════════════════════════════════════
// CAPTURE REPLAY
// ═══════════════════════════════════════════════════════════════════════════════

// captureLine mirrors the stable netproxy JSONL recording schema. It is
// duplicated here (rather than imported) so the protocol package stays free of
// any dependency on the proxy.
type captureLine struct {
	Direction   string `json:"direction"`
	MessageType uint16 `json:"message_type"`
	DataBase64  string `json:"data_b64"`
}

// BuildSpecFromCapture replays a netproxy JSONL recording into a ProtocolSpec,
// aggregating per-message statistics and running field inference. This is the
// bridge that turns a real captured session into a spec the server generator
// can consume — previously specs could only be hand-authored or loaded.
//
// Malformed lines are skipped rather than aborting the whole replay, so a
// truncated final line (common when a capture is cut short) is tolerated.
func BuildSpecFromCapture(path, gameName string) (*ProtocolSpec, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open capture: %w", err)
	}
	defer f.Close()

	ps := NewProtocolSpec(gameName)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec captureLine
		if err := json.Unmarshal(line, &rec); err != nil {
			continue // tolerate a truncated / corrupt line
		}
		payload, err := base64.StdEncoding.DecodeString(rec.DataBase64)
		if err != nil {
			continue
		}
		ps.AddSample(rec.MessageType, rec.Direction, payload)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan capture: %w", err)
	}
	ps.AnnotateSupercell()
	ps.InferFields()
	return ps, nil
}
