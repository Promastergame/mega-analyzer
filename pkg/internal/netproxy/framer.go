package netproxy

import "encoding/binary"

// Framer splits a reassembled byte stream into discrete protocol frames.
//
// TCP is a byte stream: a single Read may carry half a frame, or three frames
// glued together. Without a Framer the proxy emits one Packet per raw Read,
// which means the opcode, the recorded boundaries and the interactive-edit
// offset are all computed against an arbitrary network chunk rather than a real
// message. Supply a Framer to recover true message boundaries.
//
// Given the bytes buffered so far, NextFrame returns:
//   - frameLen:  total length of the leading complete frame (header + payload),
//     or 0 when more bytes are needed before a frame can be cut.
//   - headerLen: number of header bytes before the application payload; the
//     interactive-edit callback receives this as payloadOff.
//   - ok:        false when the buffer is structurally broken (e.g. an absurd
//     length field) and the stream should fall back to raw relaying.
//
// A Framer must be a pure function of its input and must never return a
// frameLen larger than len(buf).
type Framer func(buf []byte) (frameLen, headerLen int, ok bool)

// LengthPrefixFramer builds a Framer for the common "fixed header with a
// big-endian length field" wire format.
//
//	headerLen      total header size in bytes (payload starts here)
//	lenOff         byte offset of the length field within the header
//	lenSize        width of the length field: 1, 2, 3 or 4 bytes
//	lenInclHeader  true when the length field counts the header too
//	maxFrame       reject frames claiming more than this many payload bytes
//	               (0 ⇒ default 16 MiB guard against a desync reading forever)
//
// This is not a SaaS-style safety limit — a length field that decodes to
// gigabytes means we have lost frame sync, and the only sane recovery is to
// drop back to raw relaying rather than buffer unbounded garbage.
func LengthPrefixFramer(headerLen, lenOff, lenSize int, lenInclHeader bool, maxFrame int) Framer {
	if maxFrame <= 0 {
		maxFrame = 16 << 20
	}
	return func(buf []byte) (int, int, bool) {
		if headerLen <= 0 || lenOff < 0 || lenSize < 1 || lenSize > 4 {
			return 0, 0, false
		}
		if lenOff+lenSize > headerLen {
			return 0, 0, false
		}
		if len(buf) < headerLen {
			return 0, 0, true // wait for the full header
		}
		payloadLen := readBE(buf[lenOff : lenOff+lenSize])
		if lenInclHeader {
			payloadLen -= headerLen
			if payloadLen < 0 {
				return 0, 0, false // length field smaller than its own header
			}
		}
		if payloadLen > maxFrame {
			return 0, 0, false // lost sync — bail to raw relay
		}
		frameLen := headerLen + payloadLen
		if len(buf) < frameLen {
			return 0, 0, true // wait for the rest of the payload
		}
		return frameLen, headerLen, true
	}
}

// SupercellFramer frames Supercell's [2B type][3B length][2B version] header,
// where the 3-byte length counts the payload only (not the 7-byte header).
// Matches ParseSupercellHeader in the protocol package.
func SupercellFramer() Framer {
	return LengthPrefixFramer(7, 2, 3, false, 16<<20)
}

// readBE decodes a 1–4 byte big-endian unsigned integer.
func readBE(b []byte) int {
	switch len(b) {
	case 1:
		return int(b[0])
	case 2:
		return int(binary.BigEndian.Uint16(b))
	case 3:
		return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	case 4:
		return int(binary.BigEndian.Uint32(b))
	}
	return 0
}
