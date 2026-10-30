package peinspect

// Offline Authenticode tests build a REAL self-signed PKCS#7 with the stdlib
// (RSA-2048 + x509.CreateCertificate) over a fixture PE, then verify it with
// VerifyEmbeddedSignature / Inspect. Tamper cases prove the check is not a
// rubber stamp.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"
	"time"
)

var (
	acOIDBytesSHA256  = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}
	acOIDBytesSHA256R = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B}
	acOIDBytesSPC     = []byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04}
	acOIDBytesPEImage = []byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0F}
	acOIDBytesSD      = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02}
	acOIDBytesCT      = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03}
	acOIDBytesMD      = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04}
	acOIDBytesST      = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05}
)

type acTestKey struct {
	key      *rsa.PrivateKey
	certDER  []byte
	serial   *big.Int
	issuer   []byte // DER of cert.RawIssuer (Name)
	cn       string
	certHash string
}

func makeACTestKey(t *testing.T, cn string) *acTestKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x12345678),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	sum := sha256.Sum256(der)
	return &acTestKey{key: key, certDER: der, serial: tmpl.SerialNumber, issuer: cert.RawIssuer, cn: cn, certHash: hexOf(sum[:])}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

// buildACTestPKCS7 signs imageDigest with key and returns ContentInfo DER.
func buildACTestPKCS7(t *testing.T, k *acTestKey, imageDigest []byte) []byte {
	t.Helper()
	oid := func(body []byte) []byte { return derTLV(0x06, body) }
	seq := func(parts ...[]byte) []byte { return derTLV(0x30, concat(parts...)) }
	intVal := func(b []byte) []byte { return derTLV(0x02, b) }

	digestAlgo := seq(oid(acOIDBytesSHA256), derTLV(0x05, nil)) // SEQ{ OID, NULL }
	digestInfo := seq(digestAlgo, derTLV(0x04, imageDigest))
	peImageData := seq(oid(acOIDBytesPEImage), seq(intVal([]byte{0})))
	spc := seq(peImageData, digestInfo)
	eContent := derTLV(0xA0, derTLV(0x04, spc))
	encap := seq(oid(acOIDBytesSPC), eContent)
	digests := derTLV(0x31, digestAlgo)
	certs := derTLV(0xA0, append([]byte(nil), k.certDER...))

	attr := func(oidBody, value []byte) []byte {
		return seq(oid(oidBody), derTLV(0x31, value))
	}
	signedAttrs := concat(
		attr(acOIDBytesCT, oid(acOIDBytesSPC)),
		attr(acOIDBytesMD, derTLV(0x04, imageDigest)),
		attr(acOIDBytesST, derTLV(0x17, []byte("250101000000Z"))),
	)
	sigAlgo := seq(oid(acOIDBytesSHA256R), derTLV(0x05, nil))
	// Signature input: DER SET OF over the attribute encodings.
	setDER := append([]byte{0x31}, derLen(len(signedAttrs))...)
	setDER = append(setDER, signedAttrs...)
	h := sha256.Sum256(setDER)
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}
	sid := seq(append([]byte(nil), k.issuer...), intVal([]byte{0x12, 0x34, 0x56, 0x78}))
	signer := seq(intVal([]byte{1}), sid, digestAlgo, derTLV(0xA0, signedAttrs), sigAlgo, derTLV(0x04, sig))
	signers := derTLV(0x31, signer)
	signedData := seq(intVal([]byte{1}), digests, encap, certs, signers)
	return seq(oid(acOIDBytesSD), derTLV(0xA0, signedData))
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// signFixturePE builds an x86 fixture PE, computes the Authenticode image
// digest over it, and appends a real self-signed PKCS#7. Returns the final
// file, the offsets needed for direct VerifyEmbeddedSignature calls, and the
// PKCS#7 DER length (the RSA signature occupies its tail).
func signFixturePE(t *testing.T, k *acTestKey) (file []byte, checksumOff, certEntryOff, certOff, certSize uint64, pkcs7Len int) {
	t.Helper()
	base := buildFixturePE(t, peFixtureOpts{machine: 0x14c, ndirs: true})
	const optBase = 88
	const fixed = 96
	checksumOff, certEntryOff = optBase+64, optBase+fixed+32
	certOff = uint64(len(base)) // 1024, already 8-aligned
	h := sha256.New()
	h.Write(base[:checksumOff])
	h.Write(base[checksumOff+4 : certEntryOff])
	h.Write(base[certEntryOff+8 : certOff])
	pkcs7 := buildACTestPKCS7(t, k, h.Sum(nil))

	wincert := make([]byte, 8+len(pkcs7))
	binary.LittleEndian.PutUint32(wincert[0:], uint32(8+len(pkcs7)))
	binary.LittleEndian.PutUint16(wincert[4:], 0x0200)
	binary.LittleEndian.PutUint16(wincert[6:], 0x0002)
	copy(wincert[8:], pkcs7)
	for len(wincert)%8 != 0 {
		wincert = append(wincert, 0)
	}
	certSize = uint64(len(wincert))
	file = append(append([]byte(nil), base...), wincert...)
	// Back-patch the certificate directory (excluded from the digest, so no
	// re-sign is needed after this write).
	binary.LittleEndian.PutUint32(file[optBase+fixed+32:], uint32(certOff))
	binary.LittleEndian.PutUint32(file[optBase+fixed+32+4:], uint32(certSize))
	return file, checksumOff, certEntryOff, certOff, certSize, len(pkcs7)
}

func TestAuthenticodeValidSelfSigned(t *testing.T) {
	k := makeACTestKey(t, "Test Signer")
	file, checksumOff, certEntryOff, certOff, certSize, _ := signFixturePE(t, k)

	m, err := Inspect(file)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if m.Signature.Status != "present" {
		t.Fatalf("Status = %q, want present", m.Signature.Status)
	}
	if m.Signature.Integrity != "valid" {
		t.Fatalf("Integrity = %q (%s), want valid", m.Signature.Integrity, m.Signature.Verification)
	}
	if m.Signature.Trust != "unknown" {
		t.Errorf("Trust = %q, want unknown (no chain validation offline)", m.Signature.Trust)
	}
	if m.Signature.Signer != "Test Signer" {
		t.Errorf("Signer = %q, want Test Signer", m.Signature.Signer)
	}
	if m.Signature.CertSHA256 != k.certHash {
		t.Errorf("CertSHA256 mismatch")
	}
	if !strings.Contains(m.Signature.Verification, "Test Signer") {
		t.Errorf("Verification %q does not name the signer", m.Signature.Verification)
	}
	if !strings.Contains(m.Signature.Verification, "NOT validated") {
		t.Errorf("Verification %q must state the chain was not validated", m.Signature.Verification)
	}
	if m.Signature.ClaimedTime == "" {
		t.Error("ClaimedTime should carry the signingTime attribute")
	}

	// Direct call agrees with Inspect.
	ar := VerifyEmbeddedSignature(file, checksumOff, certEntryOff, certOff, certSize)
	if ar.Integrity != "valid" || ar.Signer != "Test Signer" || ar.CertSHA256 != k.certHash {
		t.Errorf("direct verify = %+v, want valid/Test Signer", ar)
	}
}

func TestAuthenticodeTamperedImage(t *testing.T) {
	k := makeACTestKey(t, "Test Signer")
	file, _, _, _, _, _ := signFixturePE(t, k)
	file[512] ^= 0xFF // flip a byte inside .text raw
	m, err := Inspect(file)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if m.Signature.Status != "present" {
		t.Fatalf("Status = %q, want present (structure intact)", m.Signature.Status)
	}
	if m.Signature.Integrity != "invalid" {
		t.Fatalf("Integrity = %q, want invalid after image tamper", m.Signature.Integrity)
	}
}

func TestAuthenticodeTamperedSignature(t *testing.T) {
	k := makeACTestKey(t, "Test Signer")
	file, _, _, certOff, _, pkcs7Len := signFixturePE(t, k)
	file[certOff+8+uint64(pkcs7Len)-1] ^= 0xFF // flip last byte of the RSA signature
	m, err := Inspect(file)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if m.Signature.Integrity != "invalid" {
		t.Fatalf("Integrity = %q, want invalid after signature tamper", m.Signature.Integrity)
	}
}

func TestAuthenticodeGarbageCertIsUnverifiable(t *testing.T) {
	data := buildFixturePE(t, peFixtureOpts{machine: 0x14c, ndirs: true, certDER: testSignedDataDER()})
	m, err := Inspect(data)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if m.Signature.Status != "present" {
		t.Fatalf("Status = %q, want present", m.Signature.Status)
	}
	if m.Signature.Integrity != "unverifiable" {
		t.Fatalf("Integrity = %q, want unverifiable for a non-signature blob", m.Signature.Integrity)
	}
	if m.Signature.Verification == "" {
		t.Error("Verification must explain why the check could not complete")
	}
}

func TestAuthenticodeBoundsNeverPanic(t *testing.T) {
	for _, data := range [][]byte{nil, {}, {0x4d, 0x5a}, make([]byte, 2048)} {
		ar := VerifyEmbeddedSignature(data, 152, 216, 1024, 64)
		if ar.Integrity != "unverifiable" {
			t.Errorf("len=%d: Integrity = %q, want unverifiable", len(data), ar.Integrity)
		}
	}
}

func TestAuthenticodeDERReader(t *testing.T) {
	if _, _, err := readTLV([]byte{0x30, 0x80, 0x00}); err == nil {
		t.Error("indefinite length must be rejected")
	}
	if _, _, err := readTLV([]byte{0x30}); err == nil {
		t.Error("truncated TLV must be rejected")
	}
	if _, _, err := readTLV([]byte{0x30, 0x05, 0x01, 0x02}); err == nil {
		t.Error("overrunning length must be rejected")
	}
	name, err := oidName(adTLV{class: 0, constructed: false, tag: 6, content: acOIDBytesSHA256R})
	if err != nil || name != "1.2.840.113549.1.1.11" {
		t.Errorf("oidName = %q, %v", name, err)
	}
	if got := parseDERTime(adTLV{class: 0, tag: 23, content: []byte("250101000000Z")}); got == "" {
		t.Error("UTCTime should parse")
	}
	if got := parseDERTime(adTLV{class: 0, tag: 24, content: []byte("20250101000000Z")}); got == "" {
		t.Error("GeneralizedTime should parse")
	}
	if got := parseDERTime(adTLV{class: 0, tag: 4, content: []byte("x")}); got != "" {
		t.Error("non-time TLV must yield empty string, not fail the caller")
	}
}
