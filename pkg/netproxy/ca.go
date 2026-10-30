package netproxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"mega-analyzer/pkg/logger"
)

// CertificateAuthority управляет генерацией сертификатов.
type CertificateAuthority struct {
	caKey  *rsa.PrivateKey
	caCert *x509.Certificate
	// caCertDER is the DER encoding of caCert. It was previously named
	// "caCertPEM" but actually held DER, which would produce a broken file if
	// handed to a client as PEM. Use CACertPEM() for a real PEM blob.
	caCertDER []byte

	keyPath   string
	certPath  string
	cachePath string

	// permittedDNSDomains only takes effect for a freshly generated CA. For a
	// loaded CA this is repopulated from the certificate's actual constraints
	// so the field never lies about what the on-disk CA enforces.
	permittedDNSDomains []string
	mu                  sync.RWMutex
}

// NewCertificateAuthority создает новый CA (без ограничений имён).
func NewCertificateAuthority(keyPath, certPath, cachePath string) (*CertificateAuthority, error) {
	return NewCertificateAuthorityConstrained(keyPath, certPath, cachePath, nil)
}

// NewCertificateAuthorityConstrained is like NewCertificateAuthority but, for a
// newly generated CA, embeds X.509 Name Constraints permitting only the given
// DNS domain suffixes. Passing nil/empty leaves the CA unconstrained.
// Constraints only apply to a freshly generated CA; loading an existing CA
// keeps whatever constraints it was created with (and reflects them back into
// permittedDNSDomains).
func NewCertificateAuthorityConstrained(keyPath, certPath, cachePath string, permittedDNSDomains []string) (*CertificateAuthority, error) {
	ca := &CertificateAuthority{
		keyPath:             keyPath,
		certPath:            certPath,
		cachePath:           cachePath,
		permittedDNSDomains: append([]string(nil), permittedDNSDomains...),
	}

	// Проверяем наличие существующего CA.
	if _, err := os.Stat(keyPath); err == nil {
		if _, err := os.Stat(certPath); err == nil {
			if err := ca.loadCA(); err != nil {
				return nil, fmt.Errorf("failed to load CA: %w", err)
			}
			return ca, nil
		}
	}

	if err := ca.generateCA(); err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}
	return ca, nil
}

// CACertPEM returns a PEM-encoded copy of the CA certificate, suitable for
// installing into a client trust store. Returns nil if the CA is not loaded.
func (ca *CertificateAuthority) CACertPEM() []byte {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	if ca.caCertDER == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.caCertDER})
}

// PermittedDNSDomains returns the DNS name constraints this CA actually
// enforces (empty means unconstrained). For a loaded CA this reflects the
// on-disk certificate, not whatever was passed to the constructor.
func (ca *CertificateAuthority) PermittedDNSDomains() []string {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return append([]string(nil), ca.permittedDNSDomains...)
}

// randomSerialNumber returns a cryptographically-random 128-bit positive serial
// number (RFC 5280 / CA-Browser Forum). The old big.NewInt(1) / UnixNano scheme
// was predictable and could collide for two leaves minted in the same tick,
// producing two different certs with the same issuer+serial.
func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128) // 2^128
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	if serial.Sign() == 0 { // 0 is valid rand output but not a valid serial
		serial.SetInt64(1)
	}
	return serial, nil
}

// parseCAPrivateKey accepts both PKCS#1 and PKCS#8 RSA keys so a CA generated
// by other tooling still loads.
func parseCAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	keyIface, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key (tried PKCS1 and PKCS8): %w", err)
	}
	rsaKey, ok := keyIface.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA private key is not RSA (%T)", keyIface)
	}
	return rsaKey, nil
}

func (ca *CertificateAuthority) generateCA() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return err
	}

	// MaxPathLenZero prevents this lab CA from signing intermediate CAs; it can
	// only mint leaves. NotBefore is backdated an hour to tolerate clock skew.
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Mega-Analyzer Lab CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	if len(ca.permittedDNSDomains) > 0 {
		template.PermittedDNSDomainsCritical = true
		template.PermittedDNSDomains = append([]string(nil), ca.permittedDNSDomains...)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	if err := writePEMFile(ca.keyPath, 0o600, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}
	if err := writePEMFile(ca.certPath, 0o644, "CERTIFICATE", certBytes); err != nil {
		return fmt.Errorf("failed to write cert file: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	ca.mu.Lock()
	ca.caKey = key
	ca.caCert = cert
	ca.caCertDER = certBytes
	ca.mu.Unlock()

	logger.Info("Generated new Lab CA", "path", ca.certPath)
	return nil
}

// loadCA загружает существующий CA.
func (ca *CertificateAuthority) loadCA() error {
	keyData, err := os.ReadFile(ca.keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("failed to decode PEM key")
	}
	key, err := parseCAPrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	certData, err := os.ReadFile(ca.certPath)
	if err != nil {
		return fmt.Errorf("failed to read cert file: %w", err)
	}
	block, _ = pem.Decode(certData)
	if block == nil {
		return fmt.Errorf("failed to decode PEM cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}
	if !cert.IsCA {
		return fmt.Errorf("loaded certificate at %s is not a CA", ca.certPath)
	}

	ca.mu.Lock()
	ca.caKey = key
	ca.caCert = cert
	ca.caCertDER = block.Bytes
	// Reflect the real on-disk constraints instead of leaving whatever was
	// passed to the constructor, so the field never lies after a load.
	ca.permittedDNSDomains = append([]string(nil), cert.PermittedDNSDomains...)
	ca.mu.Unlock()

	logger.Info("Loaded existing Lab CA", "path", ca.certPath)
	return nil
}

func writePEMFile(path string, perm os.FileMode, blockType string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return err
	}
	return f.Sync()
}
