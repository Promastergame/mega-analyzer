// On-disk record framing for the content-addressed cache.
//
// Before this, Store wrote raw payload bytes. Any truncated, half-written or
// swapped file was returned to the caller as a valid entry; for namespaces
// like cfg/ssa/taint/dfg that silently corrupts analysis input, and for gnn it
// only worked because gnncache carried its own record integrity.
//
// Layout (little endian):
//
//	magic          4   "OMNC"
//	format_ver     1
//	namespace_len  4
//	namespace      namespace_len
//	key           32
//	payload_len    8
//	payload_sha   32
//	payload        payload_len
//
// The namespace and key are inside the authenticated header, so a file moved
// or renamed into another slot is rejected instead of being served.
package contentcache

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

const (
	recordMagic               = "OMNC"
	recordFormatVersion uint8 = 1
	// recordFixedBytes is everything except the namespace string and payload.
	recordFixedBytes = 4 + 1 + 4 + 32 + 8 + 32
	// maxNamespaceLen bounds the length prefix before any allocation.
	maxNamespaceLen = 64
)

func recordOverhead(ns Namespace) int64 {
	return int64(recordFixedBytes + len(ns))
}

// encodeRecord frames a payload for one (namespace, key) slot.
func encodeRecord(ns Namespace, key ContentKey, payload []byte) []byte {
	sum := sha256.Sum256(payload)
	out := make([]byte, 0, recordFixedBytes+len(ns)+len(payload))
	out = append(out, recordMagic...)
	out = append(out, recordFormatVersion)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(ns)))
	out = append(out, ns...)
	out = append(out, key[:]...)
	out = binary.LittleEndian.AppendUint64(out, uint64(len(payload)))
	out = append(out, sum[:]...)
	out = append(out, payload...)
	return out
}

// decodeRecord validates the frame and returns the payload. Every failure is
// reported as ErrCorruptEntry so callers uniformly purge and recompute.
func decodeRecord(ns Namespace, key ContentKey, raw []byte) ([]byte, error) {
	if len(raw) < recordFixedBytes {
		return nil, fmt.Errorf("%w: record shorter than header (%d bytes)", ErrCorruptEntry, len(raw))
	}
	if string(raw[:4]) != recordMagic {
		return nil, fmt.Errorf("%w: bad magic", ErrCorruptEntry)
	}
	if raw[4] != recordFormatVersion {
		return nil, fmt.Errorf("%w: unsupported record format %d", ErrCorruptEntry, raw[4])
	}
	pos := 5
	nsLen := int(binary.LittleEndian.Uint32(raw[pos : pos+4]))
	pos += 4
	if nsLen <= 0 || nsLen > maxNamespaceLen || len(raw) < recordFixedBytes+nsLen {
		return nil, fmt.Errorf("%w: bad namespace length %d", ErrCorruptEntry, nsLen)
	}
	gotNS := string(raw[pos : pos+nsLen])
	pos += nsLen
	if gotNS != string(ns) {
		return nil, fmt.Errorf("%w: namespace mismatch (want %q, got %q)", ErrCorruptEntry, ns, gotNS)
	}
	if subtle.ConstantTimeCompare(raw[pos:pos+32], key[:]) != 1 {
		return nil, fmt.Errorf("%w: key mismatch", ErrCorruptEntry)
	}
	pos += 32
	payloadLen := binary.LittleEndian.Uint64(raw[pos : pos+8])
	pos += 8
	wantSum := raw[pos : pos+32]
	pos += 32
	if uint64(len(raw)-pos) != payloadLen {
		return nil, fmt.Errorf("%w: payload length mismatch (header %d, file %d)", ErrCorruptEntry, payloadLen, len(raw)-pos)
	}
	payload := raw[pos:]
	gotSum := sha256.Sum256(payload)
	if subtle.ConstantTimeCompare(gotSum[:], wantSum) != 1 {
		return nil, fmt.Errorf("%w: payload checksum mismatch", ErrCorruptEntry)
	}
	return payload, nil
}
