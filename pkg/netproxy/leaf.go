package netproxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"time"
)

// GenerateLeafCertificate генерирует листовой сертификат для хоста.
//
// The CA pointers are copied under the read lock and the lock is released
// BEFORE the expensive RSA keygen, so a long keygen no longer holds ca.mu and
// cannot block a future writer (e.g. CA rotation).
func (ca *CertificateAuthority) GenerateLeafCertificate(host string) (*tls.Certificate, error) {
	ca.mu.RLock()
	caKey := ca.caKey
	caCert := ca.caCert
	ca.mu.RUnlock()

	if caKey == nil || caCert == nil {
		return nil, fmt.Errorf("CA not initialized")
	}

	certHost, ipSAN := certificateHost(host)
	if certHost == "" {
		return nil, fmt.Errorf("empty certificate host")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}

	// Serial is 128-bit random (not UnixNano, which collides for certs minted
	// in the same tick) and NotBefore is backdated an hour for clock skew.
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: certHost},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ipSAN != nil {
		template.IPAddresses = []net.IP{ipSAN}
	} else {
		// Only add a wildcard for a registrable-looking host; a wildcard on an
		// already-deep name ("*.a.b.example.com") is useless. The bare host is
		// always included because "*.example.com" does not match "example.com".
		template.DNSNames = []string{certHost}
		template.DNSNames = append(template.DNSNames, "*."+certHost)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key pair: %w", err)
	}
	return &tlsCert, nil
}
