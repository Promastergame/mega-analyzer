package netproxy

import (
	"encoding/json"
)

// NetEvent is the wire format sent to remote inspectors (DevMega) over the
// @@NETEVENT@@ / @@EDITREQ@@ stdout sentinel-line protocol (see
// DEVMEGA_TODO.md). It is deliberately small — a live per-packet feed, not a
// full protocol-analysis event bus.
type NetEvent struct {
	ConnectionID  string `json:"connectionId,omitempty"`
	ClientAddr    string `json:"clientAddr,omitempty"`
	ServerAddr    string `json:"serverAddr,omitempty"`
	V             int    `json:"v"`               // wire protocol version, start at 1
	Kind          string `json:"kind"`            // "packet" | "edit-request"
	ReqID         uint64 `json:"reqId,omitempty"` // only set for "edit-request"
	Timestamp     string `json:"ts"`              // RFC3339Nano
	Direction     string `json:"dir"`
	MessageType   uint16 `json:"msgType"`
	Size          int    `json:"size"`
	PayloadOffset int    `json:"payloadOff,omitempty"`
	Decoded       any    `json:"decoded,omitempty"`
	HexPreview    string `json:"hexPreview,omitempty"`
}

// NewNetEvent builds a NetEvent from an intercepted Packet, decoding the
// payload as JSON when recognizable and falling back to a hex preview
// otherwise.
func NewNetEvent(kind string, pkt Packet, payloadOff int) NetEvent {
	ev := NetEvent{
		ConnectionID:  pkt.ConnectionID,
		ClientAddr:    pkt.ClientAddr,
		ServerAddr:    pkt.ServerAddr,
		V:             1,
		Kind:          kind,
		Timestamp:     pkt.Timestamp.Format("2006-01-02T15:04:05.000000000Z07:00"),
		Direction:     string(pkt.Direction),
		MessageType:   pkt.MessageType,
		Size:          pkt.Size,
		PayloadOffset: payloadOff,
	}

	var payload []byte
	if payloadOff >= 0 && payloadOff < len(pkt.Data) {
		payload = pkt.Data[payloadOff:]
	}

	if len(payload) > 0 && (payload[0] == '{' || payload[0] == '[') {
		var parsed any
		if json.Unmarshal(payload, &parsed) == nil {
			ev.Decoded = parsed
			return ev
		}
	}

	ev.HexPreview = pkt.HexDump(256)
	return ev
}

// EditResponse is what a remote client (DevMega) sends back for a pending
// "edit-request" NetEvent, over the @@EDITRESP@@ stdout->stdin protocol.
type EditResponse struct {
	ReqID  uint64 `json:"reqId"`
	Action string `json:"action"`         // "edit" | "pass" | "ignore"
	Data   []byte `json:"data,omitempty"` // new payload bytes (base64 via encoding/json), only for "edit"
}
