package netproxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"mega-analyzer/pkg/logger"
)

// InterceptTLSConnection перехватывает TLS соединение.
func (proxy *AdvancedMITMProxy) InterceptTLSConnection(clientConn net.Conn, serverAddr string) error {
	release, ok := proxy.trackConn(clientConn)
	if !ok {
		clientConn.Close()
		return fmt.Errorf("MITM proxy is closed")
	}
	defer release()
	defer clientConn.Close()

	// Optional concurrency limit.
	if proxy.sem != nil {
		select {
		case proxy.sem <- struct{}{}:
			defer func() { <-proxy.sem }()
		case <-proxy.eventsDone:
			return fmt.Errorf("MITM proxy is closed")
		}
	}

	// Enforce the allowlist/offline policy BEFORE forging a certificate or
	// completing a handshake that impersonates serverAddr.
	if !proxy.isAllowedServerAddr(serverAddr) {
		return fmt.Errorf("upstream %s is not allowed by MITM allowlist/offline policy", serverAddr)
	}

	cert, err := proxy.getOrGenerateCertificate(serverAddr)
	if err != nil {
		logger.Error("failed to get certificate", "server", serverAddr, "error", err)
		return err
	}

	// Capture ClientHello metadata before crypto/tls consumes it, and mirror
	// the client's ALPN offer so an h2-only client can complete the handshake.
	baseTLSConfig := &tls.Config{
		// Match the upstream side (MinVersion TLS12) so we don't accept a
		// downgraded client that the real server would refuse.
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
	}
	var clientHello *tls.ClientHelloInfo
	tlsConfig := baseTLSConfig.Clone()
	tlsConfig.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		copyInfo := *chi
		copyInfo.CipherSuites = append([]uint16(nil), chi.CipherSuites...)
		copyInfo.SupportedCurves = append([]tls.CurveID(nil), chi.SupportedCurves...)
		copyInfo.SupportedPoints = append([]uint8(nil), chi.SupportedPoints...)
		copyInfo.SignatureSchemes = append([]tls.SignatureScheme(nil), chi.SignatureSchemes...)
		copyInfo.SupportedProtos = append([]string(nil), chi.SupportedProtos...)
		clientHello = &copyInfo

		// Offer the client's own ALPN list back; the negotiated protocol is
		// propagated to the upstream dial after the handshake.
		cfg := baseTLSConfig.Clone()
		cfg.NextProtos = append([]string(nil), chi.SupportedProtos...)
		return cfg, nil
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

	// Bound the handshake so a stalled client cannot pin a goroutine forever.
	_ = clientConn.SetDeadline(time.Now().Add(proxy.config.handshakeTimeout()))
	if err := tlsConn.Handshake(); err != nil {
		logger.Error("TLS handshake failed", "error", err)
		return err
	}
	_ = clientConn.SetDeadline(time.Time{}) // clear the handshake deadline

	negotiatedProto := tlsConn.ConnectionState().NegotiatedProtocol

	// Анализируем TLS ClientHello metadata (not a canonical JA3 string).
	if proxy.config.EnableJA3Analysis && proxy.ja3Analyzer != nil {
		proxy.analyzeClientHello(clientHello, tlsConn)
	}

	proxy.sendEvent(MITMEvent{
		Type:      "tls_handshake",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"server": serverAddr,
			"cipher": tlsConn.ConnectionState().CipherSuite,
			"alpn":   negotiatedProto,
		},
	})

	return proxy.proxyConnection(tlsConn, serverAddr, negotiatedProto, true)
}

// proxyConnection проксирует соединение между клиентом и сервером.
func (proxy *AdvancedMITMProxy) proxyConnection(clientConn net.Conn, serverAddr, alpn string, useTLS bool) error {
	if !proxy.isAllowedServerAddr(serverAddr) {
		return fmt.Errorf("upstream %s is not allowed by MITM allowlist/offline policy", serverAddr)
	}

	host, _, _ := net.SplitHostPort(serverAddr)
	if host == "" {
		host = serverAddr
	}
	host = strings.Trim(host, "[]")

	dialer := &net.Dialer{Timeout: proxy.config.dialTimeout()}
	var serverConn net.Conn
	var err error
	if useTLS {
		upstreamCfg := &tls.Config{
			ServerName:         host,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: proxy.config.InsecureUpstreamTLS, //nolint:gosec // opt-in for lab targets with invalid certs
		}
		// Propagate the ALPN we negotiated with the client so h2 is not silently
		// downgraded to http/1.1 on the upstream leg.
		if alpn != "" {
			upstreamCfg.NextProtos = []string{alpn}
		}
		serverConn, err = tls.DialWithDialer(dialer, "tcp", serverAddr, upstreamCfg)
	} else {
		serverConn, err = dialer.Dial("tcp", serverAddr)
	}
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer serverConn.Close()

	// Track the upstream conn too so Close() can tear it down.
	if rel, ok := proxy.trackConn(serverConn); ok {
		defer rel()
	}

	relayBidirectional(clientConn, serverConn, proxy.config.maxBytesPerConn(), proxy.config.relayIdleTimeout())
	return nil
}

// relayBidirectional copies data in both directions with proper half-close
// support: when one direction reaches EOF, only THAT direction's write side is
// closed (CloseWrite), leaving the peer free to keep sending on the still-open
// half. The previous code forced a deadline on BOTH sides as soon as either
// finished — even on a clean EOF — which truncated data in the live direction
// of a half-duplex exchange. A bounded grace period is the only remaining
// hard cutoff, for a genuinely stuck half.
func relayBidirectional(a, b net.Conn, maxBytes int64, idle time.Duration) {
	const grace = 30 * time.Second
	done := make(chan struct{}, 2)
	relay := func(dst, src net.Conn) {
		// copyWithLimits (not io.Copy) bounds each direction with a byte cap, a
		// per-read idle timeout, and a fixed 32 KiB buffer, so a large or hostile
		// stream can neither run forever nor force an unbounded allocation.
		_, _ = copyWithLimits(dst, src, maxBytes, idle)
		closeWrite(dst) // signal EOF to dst's peer without killing the reverse dir
		done <- struct{}{}
	}
	go relay(b, a)
	go relay(a, b)

	<-done // one direction half-closed
	select {
	case <-done: // the other direction finished on its own
	case <-time.After(grace):
		// Reverse half is stuck; force both closed as a last resort.
		_ = a.SetDeadline(time.Now())
		_ = b.SetDeadline(time.Now())
		<-done
	}
}

// errRelayLimit is returned internally by copyWithLimits when a direction hits
// its MaxBytesPerConn cap. The relay treats it as a normal stop and half-closes
// that direction.
var errRelayLimit = errors.New("relay byte limit reached")

// copyWithLimits copies src->dst with the safeguards a bare io.Copy lacks:
//   - maxBytes: hard cap on bytes copied in this direction (<=0 = unlimited),
//     bounding memory/capture for very large or malicious streams;
//   - idle: per-read deadline (<=0 = disabled) so a stalled peer cannot pin the
//     goroutine and its buffer open forever;
//   - a fixed 32 KiB buffer, so a single Read can never force a huge allocation.
func copyWithLimits(dst, src net.Conn, maxBytes int64, idle time.Duration) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		if idle > 0 {
			_ = src.SetReadDeadline(time.Now().Add(idle))
		}
		nr, rerr := src.Read(buf)
		if nr > 0 {
			chunk := buf[:nr]
			if maxBytes > 0 && total+int64(nr) > maxBytes {
				chunk = buf[:maxBytes-total]
			}
			nw, werr := dst.Write(chunk)
			total += int64(nw)
			if werr != nil {
				return total, werr
			}
			if nw < len(chunk) {
				return total, io.ErrShortWrite
			}
			if maxBytes > 0 && total >= maxBytes {
				return total, errRelayLimit
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return total, nil
			}
			return total, rerr
		}
	}
}

func closeWrite(conn net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}
