package certaudit

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// CertInfo holds parsed certificate details.
type CertInfo struct {
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	SerialNumber       string   `json:"serial_number"`
	ValidFrom          string   `json:"valid_from"`
	ValidTo            string   `json:"valid_to"`
	Expired            bool     `json:"expired"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	HashAlgorithm      string   `json:"hash_algorithm"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm"`
	KeySize            int      `json:"key_size,omitempty"`
	MD5                string   `json:"md5"`
	SHA1               string   `json:"sha1"`
	SHA256             string   `json:"sha256"`
	SHA512             string   `json:"sha512"`
	IsDebug            bool     `json:"is_debug"`
	IsGoogleDebug      bool     `json:"is_google_debug"`
	Issues             []string `json:"issues,omitempty"`
}

// Report holds the certificate audit result for an APK.
type Report struct {
	GeneratedAt     string     `json:"generated_at"`
	Target          string     `json:"target"`
	V1Signed        bool       `json:"v1_signed"`
	V2Signed        bool       `json:"v2_signed"`
	V3Signed        bool       `json:"v3_signed"`
	JanusVulnerable bool       `json:"janus_vulnerable"`
	Certs           []CertInfo `json:"certificates"`
	Score           int        `json:"score"`
	Verdict         string     `json:"verdict"`
}

const (
	maxAPKBytes       int64 = 256 << 20
	maxSignatureBytes int64 = 8 << 20
)

// AnalyzeAPK parses signing certificates from an APK file.
func AnalyzeAPK(apkPath string) (*Report, error) {
	info, err := os.Stat(apkPath)
	if err != nil {
		return nil, fmt.Errorf("stat apk: %w", err)
	}
	if info.Size() > maxAPKBytes {
		return nil, fmt.Errorf("apk exceeds certificate-audit limit of %d bytes", maxAPKBytes)
	}
	data, err := os.ReadFile(apkPath)
	if err != nil {
		return nil, fmt.Errorf("read apk: %w", err)
	}

	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open apk: %w", err)
	}

	rep := &Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Target:      apkPath,
	}

	// V1 (JAR) signing detection
	for _, f := range z.File {
		name := strings.ToUpper(f.Name)
		if strings.HasPrefix(name, "META-INF/") {
			if strings.HasSuffix(name, ".RSA") || strings.HasSuffix(name, ".DSA") || strings.HasSuffix(name, ".EC") {
				rep.V1Signed = true
				certs, err := parseCertsFromPKCS7(f)
				if err == nil {
					for _, c := range certs {
						rep.Certs = append(rep.Certs, *c)
					}
				}
			}
			if name == "META-INF/MANIFEST.MF" {
				rep.V1Signed = true
			}
		}
	}

	// V2/V3 signing scheme blocks live in the APK Signing Block, which sits
	// immediately before the ZIP Central Directory. Parse it for real instead
	// of guessing from the absence of a v1 signature.
	rep.V2Signed, rep.V3Signed = detectSigningBlock(data)

	// Janus (CVE-2017-13156): a DEX payload prepended before a ZIP local file
	// header is only exploitable when v2/v3 signing (which covers the whole
	// file as a single blob) is absent.
	rep.JanusVulnerable = rep.V1Signed && !rep.V2Signed && !rep.V3Signed && detectPrependedDex(data)

	rep.Score = scoreReport(rep)
	rep.Verdict = verdictFromScore(rep.Score)
	return rep, nil
}

// parseCertsFromPKCS7 reads a PKCS#7 SignedData wrapper and extracts X.509 certs.
// Most Android v1 signatures are PKCS#7/CMS containers.
func parseCertsFromPKCS7(zf *zip.File) ([]*CertInfo, error) {
	rc, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxSignatureBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSignatureBytes {
		return nil, fmt.Errorf("signature entry exceeds %d bytes", maxSignatureBytes)
	}
	return extractCerts(data)
}

// extractCerts tries to parse raw DER certificates from a PKCS#7 blob.
func extractCerts(data []byte) ([]*CertInfo, error) {
	var certs []*CertInfo
	// Walk the ASN.1 structure looking for X.509 certificates.
	// A simple heuristic: look for the X.509 certificate tag sequence 0x30 0x82
	for i := 0; i < len(data)-4; i++ {
		if data[i] == 0x30 && data[i+1] == 0x82 {
			// Try parsing a certificate starting here with various lengths
			for length := 256; length <= 8192 && i+length <= len(data); length += 256 {
				candidate := data[i : i+length]
				cert, err := x509.ParseCertificate(candidate)
				if err == nil {
					certs = append(certs, certToInfo(cert))
					i += length - 1
					break
				}
			}
		}
	}
	// Fallback: if no certs found via heuristic, try parsing the whole blob as a single cert
	if len(certs) == 0 {
		cert, err := x509.ParseCertificate(data)
		if err == nil {
			certs = append(certs, certToInfo(cert))
		}
	}
	return certs, nil
}

func certToInfo(cert *x509.Certificate) *CertInfo {
	now := time.Now()
	expired := now.After(cert.NotAfter)
	info := &CertInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.Text(16),
		ValidFrom:          cert.NotBefore.Format(time.RFC3339),
		ValidTo:            cert.NotAfter.Format(time.RFC3339),
		Expired:            expired,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		HashAlgorithm:      hashAlgoFromSig(cert.SignatureAlgorithm),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		SHA1:               fmt.Sprintf("%x", sha1.Sum(cert.Raw)),
		SHA256:             fmt.Sprintf("%x", sha256.Sum256(cert.Raw)),
		MD5:                fmt.Sprintf("%x", md5Hash(cert.Raw)),
		SHA512:             fmt.Sprintf("%x", sha512Hash(cert.Raw)),
		IsDebug:            isDebugCert(cert),
		IsGoogleDebug:      isGoogleDebugCert(cert),
	}
	// KeySize extraction would need crypto/rsa type assertion; skip for brevity.
	_ = cert.PublicKey
	// Populate issues
	if expired {
		info.Issues = append(info.Issues, "Certificate has expired")
	}
	if info.IsDebug {
		info.Issues = append(info.Issues, "Debug certificate detected (androiddebugkey)")
	}
	if info.SignatureAlgorithm == x509.MD2WithRSA.String() ||
		info.SignatureAlgorithm == x509.MD5WithRSA.String() ||
		strings.Contains(info.SignatureAlgorithm, "SHA1") {
		info.Issues = append(info.Issues, "Weak signature algorithm")
	}
	if cert.NotAfter.Sub(cert.NotBefore) > 365*30*24*time.Hour {
		info.Issues = append(info.Issues, "Very long validity period (>30 years)")
	}
	return info
}

func isDebugCert(cert *x509.Certificate) bool {
	sub := strings.ToLower(cert.Subject.String())
	return strings.Contains(sub, "android debug") || strings.Contains(sub, "cn=androiddebugkey")
}

func isGoogleDebugCert(cert *x509.Certificate) bool {
	sub := strings.ToLower(cert.Subject.String())
	return strings.Contains(sub, "android") && strings.Contains(sub, "debug")
}

func hashAlgoFromSig(sig x509.SignatureAlgorithm) string {
	s := sig.String()
	if strings.Contains(s, "SHA256") {
		return "SHA-256"
	}
	if strings.Contains(s, "SHA384") {
		return "SHA-384"
	}
	if strings.Contains(s, "SHA512") {
		return "SHA-512"
	}
	if strings.Contains(s, "SHA1") {
		return "SHA-1"
	}
	if strings.Contains(s, "MD5") {
		return "MD5"
	}
	return "unknown"
}

func md5Hash(data []byte) []byte {
	h := md5.Sum(data)
	return h[:]
}

func sha512Hash(data []byte) []byte {
	h := sha512.Sum512(data)
	return h[:]
}

const (
	eocdMagic          = 0x06054b50
	eocdRecordSize     = 22
	eocdMaxCommentSize = 65535
	signingBlockMagic  = "APK Sig Block 42"
	sigSchemeV2ID      = 0x7109871a
	sigSchemeV3ID      = 0xf05368c0
)

// detectSigningBlock locates the APK Signing Block (if any) relative to the
// ZIP End Of Central Directory record and reports which signature schemes
// (v2/v3) are present in it.
func detectSigningBlock(data []byte) (v2, v3 bool) {
	cdOffset, ok := findCentralDirectoryOffset(data)
	if !ok {
		return false, false
	}
	pairs, ok := readSigningBlock(data, cdOffset)
	if !ok {
		return false, false
	}
	return scanSigningBlockIDs(pairs)
}

// findCentralDirectoryOffset scans backward from the end of the file for the
// ZIP End Of Central Directory record and returns the actual offset of the
// Central Directory that precedes it.
//
// The CD offset field recorded inside the EOCD record is relative to the
// start of the original archive and becomes stale when extra bytes are
// prepended to the file (e.g. a Janus-style prepended DEX payload). Instead
// of trusting that field, the Central Directory start is derived from the
// EOCD's "size of central directory" field and the actual (scanned) position
// of the EOCD magic, which is skew-resistant.
func findCentralDirectoryOffset(data []byte) (int64, bool) {
	maxScan := eocdRecordSize + eocdMaxCommentSize
	start := len(data) - maxScan
	if start < 0 {
		start = 0
	}
	for i := len(data) - eocdRecordSize; i >= start; i-- {
		if le32(data[i:]) == eocdMagic {
			cdSize := int64(le32(data[i+12:]))
			cdOffset := int64(i) - cdSize
			if cdOffset >= 0 && cdSize >= 0 {
				return cdOffset, true
			}
		}
	}
	return 0, false
}

// readSigningBlock validates and extracts the ID-value pair section of the
// APK Signing Block that immediately precedes the Central Directory.
func readSigningBlock(data []byte, cdOffset int64) ([]byte, bool) {
	magicLen := int64(len(signingBlockMagic))
	if cdOffset-magicLen < 0 {
		return nil, false
	}
	if string(data[cdOffset-magicLen:cdOffset]) != signingBlockMagic {
		return nil, false
	}
	if cdOffset-magicLen-8 < 0 {
		return nil, false
	}
	trailingSize := le64(data[cdOffset-magicLen-8:])
	blockStart := cdOffset - 8 - int64(trailingSize)
	if blockStart < 0 || blockStart+8 > int64(len(data)) {
		return nil, false
	}
	leadingSize := le64(data[blockStart:])
	if leadingSize != trailingSize {
		return nil, false
	}
	pairsStart := blockStart + 8
	pairsEnd := cdOffset - magicLen - 8
	if pairsStart < 0 || pairsEnd > int64(len(data)) || pairsStart > pairsEnd {
		return nil, false
	}
	return data[pairsStart:pairsEnd], true
}

// scanSigningBlockIDs walks the length-prefixed ID-value pairs of an APK
// Signing Block looking for the v2/v3 signature scheme block IDs.
func scanSigningBlockIDs(pairs []byte) (v2, v3 bool) {
	off := int64(0)
	for off+12 <= int64(len(pairs)) {
		pairLen := le64(pairs[off:])
		id := le32(pairs[off+8:])
		switch id {
		case sigSchemeV2ID:
			v2 = true
		case sigSchemeV3ID:
			v3 = true
		}
		next := off + 8 + int64(pairLen)
		if pairLen < 4 || next <= off || next > int64(len(pairs)) {
			break
		}
		off = next
	}
	return v2, v3
}

// detectPrependedDex reports whether the file begins with a DEX header
// followed later by a ZIP local file header — the byte pattern exploited by
// Janus (CVE-2017-13156) to smuggle an extra DEX into a v1-only signed APK.
func detectPrependedDex(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	if !bytes.Equal(data[:4], []byte{'d', 'e', 'x', '\n'}) {
		return false
	}
	return bytes.Contains(data[4:], []byte{'P', 'K', 0x03, 0x04})
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func le64(b []byte) uint64 {
	return uint64(le32(b)) | uint64(le32(b[4:]))<<32
}

func scoreReport(rep *Report) int {
	score := 0
	if rep.V1Signed && !rep.V2Signed {
		score += 20 // v1-only is less secure
	}
	if rep.V2Signed {
		score -= 10
	}
	if rep.JanusVulnerable {
		score += 25
	}
	for _, c := range rep.Certs {
		if c.Expired {
			score += 30
		}
		if c.IsDebug || c.IsGoogleDebug {
			score += 40
		}
		if c.SignatureAlgorithm == x509.MD5WithRSA.String() ||
			c.SignatureAlgorithm == x509.SHA1WithRSA.String() {
			score += 20
		}
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

func verdictFromScore(score int) string {
	if score >= 60 {
		return "critical"
	}
	if score >= 40 {
		return "high"
	}
	if score >= 20 {
		return "medium"
	}
	if score > 0 {
		return "low"
	}
	return "secure"
}

// For ASN.1 parsing we need to avoid unused import; use it in extractCerts.
var _ = asn1.RawContent{}
