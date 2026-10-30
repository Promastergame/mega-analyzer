package netproxy

import (
	"crypto/tls"
	"fmt"
)

// certReq coordinates a single in-progress leaf-certificate generation so
// concurrent connections to the same new host share one RSA keygen instead of
// each doing their own (a cache stampede). The first caller becomes the leader
// and generates; every other caller waits on done and reads the leader's
// result.
type certReq struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

// getOrGenerateCertificate получает или генерирует сертификат, coalescing
// concurrent requests for the same host via single-flight.
//
// Named returns are used so the deferred cleanup can run even on panic: if
// GenerateLeafCertificate ever panicked, the old code left the certInflight
// entry in place and every waiter blocked on <-req.done forever. The defer now
// always deletes the inflight entry, publishes a result, caches on success,
// and wakes waiters.
func (proxy *AdvancedMITMProxy) getOrGenerateCertificate(host string) (cert *tls.Certificate, err error) {
	if proxy.ca == nil {
		return nil, fmt.Errorf("CA not initialized")
	}
	certHost, _ := certificateHost(host)
	if certHost == "" {
		return nil, fmt.Errorf("empty certificate host")
	}

	// Fast path: already cached.
	proxy.cacheMu.RLock()
	if c, ok := proxy.certCache[certHost]; ok {
		proxy.cacheMu.RUnlock()
		return c, nil
	}
	proxy.cacheMu.RUnlock()

	// Slow path: decide leader vs. waiter under the write lock.
	proxy.cacheMu.Lock()
	if c, ok := proxy.certCache[certHost]; ok {
		proxy.cacheMu.Unlock()
		return c, nil
	}
	if req, ok := proxy.certInflight[certHost]; ok {
		proxy.cacheMu.Unlock()
		<-req.done
		return req.cert, req.err
	}
	req := &certReq{done: make(chan struct{})}
	proxy.certInflight[certHost] = req
	proxy.cacheMu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during certificate generation for %s: %v", certHost, r)
			cert = nil
		}
		req.cert, req.err = cert, err

		proxy.cacheMu.Lock()
		delete(proxy.certInflight, certHost)
		if err == nil && cert != nil {
			if _, exists := proxy.certCache[certHost]; !exists {
				proxy.certOrder = append(proxy.certOrder, certHost)
			}
			proxy.certCache[certHost] = cert
			for len(proxy.certOrder) > maxCertCacheEntries {
				oldest := proxy.certOrder[0]
				proxy.certOrder = proxy.certOrder[1:]
				delete(proxy.certCache, oldest)
			}
		}
		proxy.cacheMu.Unlock()

		close(req.done) // wake any waiters
	}()

	// Generate outside the lock (RSA keygen is slow; holding cacheMu would
	// serialise every other host's lookups behind it).
	cert, err = proxy.ca.GenerateLeafCertificate(certHost)
	return cert, err
}
