package netproxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
)

// maxCertCacheEntries bounds AdvancedMITMProxy.certCache so a long-running proxy
// visiting many distinct hosts does not grow the cache unbounded.
const maxCertCacheEntries = 500

// maxJA3Records bounds JA3Analyzer.records so a long-running proxy does not
// accumulate fingerprint history unbounded.
const maxJA3Records = 2000

// AdvancedMITMProxy is the advanced lab MITM proxy. Its behaviour is split
// across several files (see doc.go); this file owns the struct, construction
// and lifecycle (connection tracking + Close).
type AdvancedMITMProxy struct {
	config *AdvancedMITMConfig
	ca     *CertificateAuthority

	// Leaf-certificate cache with FIFO eviction and single-flight generation.
	certCache    map[string]*tls.Certificate
	certOrder    []string            // insertion order, for FIFO eviction
	certInflight map[string]*certReq // in-progress generations, for single-flight
	cacheMu      sync.RWMutex

	tlsListener  net.Listener
	udpConn      *net.UDPConn
	quicListener net.Listener

	ja3Analyzer      *JA3Analyzer
	protocolInferrer *ProtocolInferrer
	replayEngine     *ReplayEngine
	fuzzingEngine    *FuzzingEngine
	secretScanner    *SecretScanner

	eventChan  chan MITMEvent
	eventsDone chan struct{}

	// sem, when non-nil, bounds the number of concurrently intercepted
	// connections (config.MaxActiveConns).
	sem chan struct{}

	// activeConns tracks every live connection so Close can force them shut and
	// unblock any relay stuck in a Read; without this, Close's wg.Wait could
	// hang forever on a connection that never sees EOF. connMu guards closed +
	// wg.Add + activeConns together, so Close cannot race a fresh connection
	// past the closed check (which would be undefined per the WaitGroup docs).
	activeConns map[net.Conn]struct{}
	connMu      sync.Mutex
	closed      bool
	closeOnce   sync.Once
	wg          sync.WaitGroup
}

// NewAdvancedMITMProxy creates a new advanced MITM proxy from config. It
// validates config up front and initialises only the subsystems that are
// enabled.
func NewAdvancedMITMProxy(config *AdvancedMITMConfig) (*AdvancedMITMProxy, error) {
	if config == nil {
		config = &AdvancedMITMConfig{}
	}
	if err := config.validate(); err != nil {
		return nil, err
	}

	proxy := &AdvancedMITMProxy{
		config:       config,
		certCache:    make(map[string]*tls.Certificate),
		certInflight: make(map[string]*certReq),
		activeConns:  make(map[net.Conn]struct{}),
		eventChan:    make(chan MITMEvent, 1000),
		eventsDone:   make(chan struct{}),
	}
	if config.MaxActiveConns > 0 {
		proxy.sem = make(chan struct{}, config.MaxActiveConns)
	}

	// Initialise the CA if requested. PermittedDNSDomains (if set) is embedded
	// as X.509 Name Constraints for a freshly generated CA.
	if config.EnableTLS && config.GenerateLabCA {
		ca, err := NewCertificateAuthorityConstrained(
			config.CAKeyPath, config.CACertPath, config.CertCachePath, config.PermittedDNSDomains,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize CA: %w", err)
		}
		proxy.ca = ca
	}

	if config.EnableJA3Analysis {
		proxy.ja3Analyzer = &JA3Analyzer{records: make(map[string]*JA3Record)}
	}
	if config.EnableProtocolInference {
		proxy.protocolInferrer = &ProtocolInferrer{captures: make(map[string]*ProtocolCapture)}
	}
	if config.EnableReplay {
		proxy.replayEngine = &ReplayEngine{captures: make(map[string]*ReplayCapture)}
	}
	if config.EnableFuzzing {
		proxy.fuzzingEngine = &FuzzingEngine{
			mutationRate: config.FuzzingMutationRate,
			results:      make(map[string]*FuzzingResult),
		}
	}
	if config.EnableRedaction && config.SecretScannerEnabled {
		scanner, err := newSecretScanner()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize secret scanner: %w", err)
		}
		proxy.secretScanner = scanner
	}

	return proxy, nil
}

// trackConn registers c as a live connection and returns a release func. It
// returns ok=false if the proxy is already closed, in which case the caller
// must not proceed (and should close c itself). The closed-check, wg.Add and
// registration happen atomically under connMu so they cannot race Close.
func (proxy *AdvancedMITMProxy) trackConn(c net.Conn) (release func(), ok bool) {
	proxy.connMu.Lock()
	if proxy.closed {
		proxy.connMu.Unlock()
		return nil, false
	}
	proxy.wg.Add(1)
	proxy.activeConns[c] = struct{}{}
	proxy.connMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			proxy.connMu.Lock()
			delete(proxy.activeConns, c)
			proxy.connMu.Unlock()
			proxy.wg.Done()
		})
	}, true
}

// GetCA returns the proxy's certificate authority (nil if TLS/CA is disabled),
// so callers can install CACertPEM() into a client trust store.
func (proxy *AdvancedMITMProxy) GetCA() *CertificateAuthority { return proxy.ca }

// Close shuts the proxy down. It is idempotent. It closes the listeners, then
// force-closes every still-live connection so any relay blocked in a Read
// unblocks, and only then waits for all connection goroutines to finish.
func (proxy *AdvancedMITMProxy) Close() error {
	proxy.closeOnce.Do(func() {
		proxy.connMu.Lock()
		proxy.closed = true
		if proxy.tlsListener != nil {
			_ = proxy.tlsListener.Close()
		}
		if proxy.udpConn != nil {
			_ = proxy.udpConn.Close()
		}
		if proxy.quicListener != nil {
			_ = proxy.quicListener.Close()
		}
		// Force every live connection shut so a relay parked in Read returns and
		// its release() runs, letting wg.Wait() below actually complete.
		for c := range proxy.activeConns {
			_ = c.Close()
		}
		proxy.connMu.Unlock()

		close(proxy.eventsDone)
		proxy.wg.Wait()
		// Do not close eventChan: external callers may still hold a proxy
		// reference and an accidental late send must not panic the process.
	})
	return nil
}
