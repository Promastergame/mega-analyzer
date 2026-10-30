package netproxy

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func leafParsed(t *testing.T, ca *CertificateAuthority, host string) *x509.Certificate {
	t.Helper()
	cert, err := ca.GenerateLeafCertificate(host)
	if err != nil {
		t.Fatalf("GenerateLeafCertificate(%q): %v", host, err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatalf("empty certificate chain for %q", host)
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return parsed
}

func newTestCA(t *testing.T, permitted []string) *CertificateAuthority {
	t.Helper()
	dir := t.TempDir()
	ca, err := NewCertificateAuthorityConstrained(
		filepath.Join(dir, "ca.key"),
		filepath.Join(dir, "ca.crt"),
		filepath.Join(dir, "cache"),
		permitted,
	)
	if err != nil {
		t.Fatalf("NewCertificateAuthorityConstrained: %v", err)
	}
	return ca
}

func TestLeafCert_SerialsAreRandomAndUnique(t *testing.T) {
	ca := newTestCA(t, nil)

	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		leaf := leafParsed(t, ca, "test.example.com")
		s := leaf.SerialNumber.String()
		if seen[s] {
			t.Fatalf("duplicate leaf serial number %s (collision)", s)
		}
		seen[s] = true
		// A 128-bit random serial must be far larger than the old UnixNano
		// values; require at least a big magnitude to catch a regression to a
		// small/predictable serial.
		if leaf.SerialNumber.BitLen() < 32 {
			t.Errorf("serial number too small (%d bits); expected ~128-bit random", leaf.SerialNumber.BitLen())
		}
	}
}

func TestLeafCert_NotBeforeIsBackdated(t *testing.T) {
	ca := newTestCA(t, nil)
	leaf := leafParsed(t, ca, "test.example.com")
	if !leaf.NotBefore.Before(time.Now()) {
		t.Errorf("NotBefore %v is not before now; backdating for clock skew is missing", leaf.NotBefore)
	}
	// Should be roughly an hour back, not e.g. a year.
	if time.Since(leaf.NotBefore) > 2*time.Hour {
		t.Errorf("NotBefore backdated too far: %v", leaf.NotBefore)
	}
}

func TestCA_NameConstraintsWhenConfigured(t *testing.T) {
	ca := newTestCA(t, []string{"test", "example.com"})
	ca.mu.RLock()
	caCert := ca.caCert
	ca.mu.RUnlock()
	if len(caCert.PermittedDNSDomains) == 0 {
		t.Fatalf("expected CA to carry permitted DNS domains, got none")
	}

	// A leaf inside the permitted set must verify against the CA as root; one
	// outside must be rejected by the constraint-aware verifier.
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	good := leafParsed(t, ca, "svc.example.com")
	if _, err := good.Verify(x509.VerifyOptions{DNSName: "svc.example.com", Roots: roots}); err != nil {
		t.Errorf("permitted-domain leaf failed verification: %v", err)
	}

	bad := leafParsed(t, ca, "www.google.com")
	if _, err := bad.Verify(x509.VerifyOptions{DNSName: "www.google.com", Roots: roots}); err == nil {
		t.Errorf("out-of-constraint leaf (www.google.com) verified but should be rejected by name constraints")
	}
}

func TestCA_UnconstrainedByDefault(t *testing.T) {
	ca := newTestCA(t, nil)
	ca.mu.RLock()
	caCert := ca.caCert
	ca.mu.RUnlock()
	if len(caCert.PermittedDNSDomains) != 0 {
		t.Errorf("default CA should be unconstrained, got permitted domains %v", caCert.PermittedDNSDomains)
	}
}

func TestGetOrGenerateCertificate_SingleFlight(t *testing.T) {
	dir := t.TempDir()
	cfg := &AdvancedMITMConfig{
		EnableTLS:     true,
		GenerateLabCA: true,
		CAKeyPath:     filepath.Join(dir, "ca.key"),
		CACertPath:    filepath.Join(dir, "ca.crt"),
		CertCachePath: filepath.Join(dir, "cache"),
	}
	proxy, err := NewAdvancedMITMProxy(cfg)
	if err != nil {
		t.Fatalf("NewAdvancedMITMProxy: %v", err)
	}
	defer proxy.Close()

	const goroutines = 32
	results := make([]*tls.Certificate, goroutines)
	errs := make([]error, goroutines)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release all at once to maximise the stampede
			results[i], errs[i] = proxy.getOrGenerateCertificate("stampede.example.com:443")
		}()
	}
	close(start)
	wg.Wait()

	// All must succeed and return the SAME cached certificate pointer, proving
	// exactly one generation was shared (no stampede).
	var first *tls.Certificate
	for i := 0; i < goroutines; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if first == nil {
			first = results[i]
		} else if results[i] != first {
			t.Fatalf("goroutine %d got a different cert pointer; single-flight failed", i)
		}
	}
}
