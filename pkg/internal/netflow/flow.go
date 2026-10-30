package netflow

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Direction identifies which half of a flow a payload travelled on. It matches
// the semantic direction the proxy already knows (client vs. upstream), so no
// SYN inference is needed here.
type Direction string

const (
	// C2S is client→server (request) traffic.
	C2S Direction = "c2s"
	// S2C is server→client (response) traffic.
	S2C Direction = "s2c"
)

// FlowKey is a canonical, direction-independent 5-tuple. The two endpoints are
// sorted so a packet and its reply map to the same key.
type FlowKey struct {
	Transport string
	AIP       string
	APort     uint16
	BIP       string
	BPort     uint16
}

// String renders the key as e.g. "tcp 10.0.0.1:1234<->93.1.2.3:443".
func (k FlowKey) String() string {
	return fmt.Sprintf("%s %s:%d<->%s:%d", k.Transport, k.AIP, k.APort, k.BIP, k.BPort)
}

// newFlowKey canonicalises an observed (src,dst) pair into a stable key.
func newFlowKey(transport, srcIP string, srcPort uint16, dstIP string, dstPort uint16) FlowKey {
	if less(srcIP, srcPort, dstIP, dstPort) {
		return FlowKey{transport, srcIP, srcPort, dstIP, dstPort}
	}
	return FlowKey{transport, dstIP, dstPort, srcIP, srcPort}
}

func less(aIP string, aPort uint16, bIP string, bPort uint16) bool {
	if aIP != bIP {
		return aIP < bIP
	}
	return aPort < bPort
}

// Flow is a tracked bidirectional conversation with per-direction reassembled
// streams and a best-effort protocol classification.
type Flow struct {
	Key       FlowKey
	FirstSeen time.Time
	LastSeen  time.Time
	Packets   int
	BytesC2S  int
	BytesS2C  int
	Protocol  Protocol
	SNI       string

	clientStream []byte
	serverStream []byte
}

// ClientStream returns the reassembled client→server bytes.
func (f *Flow) ClientStream() []byte { return f.clientStream }

// ServerStream returns the reassembled server→client bytes.
func (f *Flow) ServerStream() []byte { return f.serverStream }

// Record projects the flow into a filterable Record (client-side view).
func (f *Flow) Record() Record {
	return Record{
		Protocol: f.Protocol,
		SrcIP:    f.Key.AIP,
		DstIP:    f.Key.BIP,
		SrcPort:  f.Key.APort,
		DstPort:  f.Key.BPort,
		Length:   f.BytesC2S + f.BytesS2C,
		SNI:      f.SNI,
		Payload:  f.clientStream,
	}
}

// FlowTable groups observed payloads into flows. It is safe for concurrent use.
type FlowTable struct {
	mu    sync.Mutex
	flows map[FlowKey]*Flow
}

// NewFlowTable returns an empty flow table.
func NewFlowTable() *FlowTable {
	return &FlowTable{flows: make(map[FlowKey]*Flow)}
}

// Observe records one payload observation and returns the per-observation
// Record (useful for streaming filters) plus the flow it belongs to.
func (t *FlowTable) Observe(transport, srcIP string, srcPort uint16, dstIP string, dstPort uint16, dir Direction, ts time.Time, payload []byte) (Record, *Flow) {
	key := newFlowKey(transport, srcIP, srcPort, dstIP, dstPort)

	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.flows[key]
	if !ok {
		f = &Flow{Key: key, FirstSeen: ts, LastSeen: ts, Protocol: ProtoUnknown}
		t.flows[key] = f
	}
	f.Packets++
	if ts.After(f.LastSeen) {
		f.LastSeen = ts
	}
	if ts.Before(f.FirstSeen) {
		f.FirstSeen = ts
	}
	switch dir {
	case C2S:
		f.BytesC2S += len(payload)
		f.clientStream = append(f.clientStream, payload...)
	case S2C:
		f.BytesS2C += len(payload)
		f.serverStream = append(f.serverStream, payload...)
	}
	f.reclassify()

	rec := Record{
		Protocol:  f.Protocol,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Direction: string(dir),
		Length:    len(payload),
		SNI:       f.SNI,
		Payload:   payload,
	}
	return rec, f
}

func (f *Flow) reclassify() {
	proto := Classify(f.clientStream, f.Key.Transport)
	if proto == ProtoUnknown {
		proto = Classify(f.serverStream, f.Key.Transport)
	}
	if proto != ProtoUnknown {
		f.Protocol = proto
	}
	if f.Protocol == ProtoTLS && f.SNI == "" {
		f.SNI = TLSSNI(f.clientStream)
	}
}

// Len reports the number of distinct flows tracked.
func (t *FlowTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.flows)
}

// Flows returns all tracked flows, sorted by first-seen time then key, so the
// output is deterministic.
func (t *FlowTable) Flows() []*Flow {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*Flow, 0, len(t.flows))
	for _, f := range t.flows {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FirstSeen.Equal(out[j].FirstSeen) {
			return out[i].FirstSeen.Before(out[j].FirstSeen)
		}
		return out[i].Key.String() < out[j].Key.String()
	})
	return out
}

// Select returns the flows whose Record matches the compiled filter.
func (t *FlowTable) Select(f *Filter) []*Flow {
	var out []*Flow
	for _, flow := range t.Flows() {
		if f.Match(flow.Record()) {
			out = append(out, flow)
		}
	}
	return out
}
