package main

import (
	"encoding/binary"
	"errors"
	"io"
)

// The lab speaks a tiny length-prefixed binary game protocol over TCP. Every
// message on the wire is:
//
//	[2B msgType big-endian][4B payloadLen big-endian][payloadLen bytes payload]
//
// This is a deliberately ordinary "fixed header + length field" framing — the
// same shape countless real game clients use — so the message boundaries are
// unambiguous even though TCP delivers an arbitrary byte stream. The server
// knows nothing about how a client (or anything sitting between it and the
// client) is implemented; it only speaks these bytes.
const (
	headerLen  = 6
	maxPayload = 1 << 20 // 1 MiB: a desync guard, not a business limit

	// Client → server opcodes.
	msgHello    uint16 = 0x0001 // payload: none
	msgBuyItem  uint16 = 0x0010 // payload: BuyItem (see logic.go)
	msgGetState uint16 = 0x0020 // payload: none

	// Server → client opcodes.
	msgWelcome   uint16 = 0x8001 // payload: State
	msgBuyOK     uint16 = 0x8010 // payload: State (post-purchase)
	msgBuyDenied uint16 = 0x8011 // payload: reason string
	msgState     uint16 = 0x8020 // payload: State
	msgError     uint16 = 0x80FF // payload: reason string
)

// frame is one decoded protocol message.
type frame struct {
	msgType uint16
	payload []byte
}

var errShortHeader = errors.New("coinproto: short header")

// readFrame reads exactly one framed message from r, blocking until a full
// frame is available. It returns io.EOF only when the stream ends cleanly on a
// frame boundary.
func readFrame(r io.Reader) (frame, error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return frame{}, errShortHeader
		}
		return frame{}, err
	}
	msgType := binary.BigEndian.Uint16(hdr[0:2])
	payloadLen := binary.BigEndian.Uint32(hdr[2:6])
	if payloadLen > maxPayload {
		return frame{}, errors.New("coinproto: payload too large")
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return frame{}, err
	}
	return frame{msgType: msgType, payload: payload}, nil
}

// encodeFrame serialises a message to its wire form.
func encodeFrame(msgType uint16, payload []byte) []byte {
	buf := make([]byte, headerLen+len(payload))
	binary.BigEndian.PutUint16(buf[0:2], msgType)
	binary.BigEndian.PutUint32(buf[2:6], uint32(len(payload)))
	copy(buf[headerLen:], payload)
	return buf
}

// writeFrame writes one framed message to w.
func writeFrame(w io.Writer, msgType uint16, payload []byte) error {
	_, err := w.Write(encodeFrame(msgType, payload))
	return err
}
