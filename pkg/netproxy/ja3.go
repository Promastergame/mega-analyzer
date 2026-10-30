package netproxy

import (
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// JA3Analyzer анализирует TLS ClientHello.
//
// NOTE: despite the historical name, Go's crypto/tls does not expose raw
// extension ordering, so this does NOT compute a canonical JA3/JA4 string. It
// records ClientHello metadata only. For a true JA3 you need to parse the raw
// ClientHello (e.g. via a peeked first record or a library like utls).
type JA3Analyzer struct {
	records map[string]*JA3Record
	order   []string      // insertion order, for FIFO eviction
	seq     atomic.Uint64 // monotonic tiebreaker for record keys
	mu      sync.RWMutex
}

// JA3Record хранит метаданные ClientHello (не канонический JA3).
//
// Fingerprint and Extensions are intentionally left unpopulated: crypto/tls
// does not surface enough to fill them honestly. They remain for wire/format
// compatibility with downstream consumers.
type JA3Record struct {
	Fingerprint    string // always empty; see type doc
	ClientIP       string
	Timestamp      time.Time
	CipherSuites   []uint16
	Extensions     []uint16 // always empty; see type doc
	EllipticCurves []string
	SignatureAlgs  []string
}

// analyzeClientHello records TLS ClientHello metadata and emits an event.
func (proxy *AdvancedMITMProxy) analyzeClientHello(hello *tls.ClientHelloInfo, conn *tls.Conn) {
	state := conn.ConnectionState()
	record := &JA3Record{
		Timestamp:    time.Now(),
		CipherSuites: []uint16{state.CipherSuite},
	}
	data := map[string]interface{}{
		"cipher_suite": state.CipherSuite,
		"version":      state.Version,
		"note":         "tls_client_hello_metadata_not_canonical_ja3",
	}
	if hello != nil {
		record.CipherSuites = append([]uint16(nil), hello.CipherSuites...)
		if hello.Conn != nil {
			record.ClientIP = hello.Conn.RemoteAddr().String()
		}
		record.EllipticCurves = make([]string, 0, len(hello.SupportedCurves))
		for _, c := range hello.SupportedCurves {
			record.EllipticCurves = append(record.EllipticCurves, fmt.Sprintf("%d", c))
		}
		record.SignatureAlgs = make([]string, 0, len(hello.SignatureSchemes))
		for _, alg := range hello.SignatureSchemes {
			record.SignatureAlgs = append(record.SignatureAlgs, fmt.Sprintf("%d", alg))
		}
		data["sni"] = hello.ServerName
		data["offered_cipher_suites"] = hello.CipherSuites
		data["supported_protos"] = hello.SupportedProtos
	}

	proxy.ja3Analyzer.mu.Lock()
	// UnixNano alone collides when two handshakes land in the same tick (the
	// exact bug fixed for cert serials). A per-analyzer atomic counter makes
	// the key unique regardless of clock resolution.
	key := fmt.Sprintf("%d-%d", time.Now().UnixNano(), proxy.ja3Analyzer.seq.Add(1))
	proxy.ja3Analyzer.records[key] = record
	proxy.ja3Analyzer.order = append(proxy.ja3Analyzer.order, key)
	for len(proxy.ja3Analyzer.order) > maxJA3Records {
		oldest := proxy.ja3Analyzer.order[0]
		proxy.ja3Analyzer.order = proxy.ja3Analyzer.order[1:]
		delete(proxy.ja3Analyzer.records, oldest)
	}
	proxy.ja3Analyzer.mu.Unlock()

	proxy.sendEvent(MITMEvent{
		Type:      "tls_fingerprint",
		Timestamp: time.Now(),
		Data:      data,
	})
}
