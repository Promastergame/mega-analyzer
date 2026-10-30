package netproxy

import "time"

// MITMEvent представляет событие MITM.
type MITMEvent struct {
	Type      string // "tls_handshake", "tls_fingerprint", "protocol_inferred", "secret_found", "anomaly"
	Timestamp time.Time
	Data      map[string]interface{}
}

// GetEventChannel возвращает канал событий.
func (proxy *AdvancedMITMProxy) GetEventChannel() <-chan MITMEvent {
	return proxy.eventChan
}

func (proxy *AdvancedMITMProxy) sendEvent(e MITMEvent) {
	// Check eventsDone first and only: once closed, a combined select would
	// otherwise pick pseudo-randomly between the closed-done case and a
	// still-ready eventChan send, letting events leak out after Close().
	select {
	case <-proxy.eventsDone:
		return
	default:
	}
	select {
	case proxy.eventChan <- e:
	default:
		// Do not let telemetry backpressure block TLS handshakes.
	}
}
