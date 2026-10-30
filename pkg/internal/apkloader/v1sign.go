package apkloader

// Offline v1 (JAR-scheme) signing support: a minimal PKCS#7 SignedData
// builder/parser/verifier on top of the standard library only.
//
// Why hand-rolled DER instead of encoding/asn1: the structures we need
// ([0] IMPLICIT certificates, signedAttrs whose exact TLV bytes are the
// RSA input) are awkward to express with encoding/asn1 struct tags, while
// a tiny explicit writer/reader leaves zero ambiguity about the bytes
// that get signed and verified.

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------------------
// Minimal DER writer (definite lengths only)
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

func derLength(n int) []byte {
	if n < 0 {
		return []byte{0}
	}
	if n < 128 {
		return []byte{byte(n)}
	}
	var tmp [8]byte
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte(n)
		n >>= 8
	}
	body := tmp[i:]
	out := make([]byte, 0, 1+len(body))
	out = append(out, byte(0x80|len(body)))
	return append(out, body...)
}

// derTLV wraps concatenated contents in tag+length.
func derTLV(tag byte, contents ...[]byte) []byte {
	total := 0
	for _, c := range contents {
		total += len(c)
	}
	out := make([]byte, 0, 2+total)
	out = append(out, tag)
	out = append(out, derLength(total)...)
	for _, c := range contents {
		out = append(out, c...)
	}
	return out
}

func derIntegerFromBig(v *big.Int) []byte {
	if v == nil {
		return derTLV(0x02, []byte{0x00})
	}
	b := v.Bytes()
	if len(b) == 0 {
		b = []byte{0x00}
	} else if b[0]&0x80 != 0 {
		b = append([]byte{0x00}, b...)
	}
	return derTLV(0x02, b)
}

func derNull() []byte { return []byte{0x05, 0x00} }

// Raw OID bodies (tag+length added by caller).
var (
	oidDataBody          = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01}
	oidSignedDataBody    = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02}
	oidSHA256Body        = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}
	oidSHA256WithRSAbody = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B}
	oidContentTypeBody   = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03}
	oidMessageDigestBody = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04}
)

// ---------------------------------------------------------------------------
// PKCS#7 SignedData builder (detached, like jarsigner -signedjar output)
// ---------------------------------------------------------------------------

// buildPKCS7SignatureBlock creates a real DER PKCS#7 SignedData block over
// sfBytes (the CERT.SF content): SignedData{ sha256, encap=data(detached),
// certs=[signer cert], signerInfos=[{ sha256, signedAttrs{contentType,
// messageDigest=SHA256(sf)}, sha256WithRSA }] }.
func buildPKCS7SignatureBlock(sfBytes []byte, key *rsa.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	if key == nil || cert == nil {
		return nil, fmt.Errorf("pkcs7: need both private key and certificate")
	}
	if len(cert.RawIssuer) == 0 {
		return nil, fmt.Errorf("pkcs7: certificate has no issuer encoding")
	}

	sfDigest := sha256.Sum256(sfBytes)

	attrContentType := derTLV(0x30,
		derTLV(0x06, oidContentTypeBody),
		derTLV(0x31, derTLV(0x06, oidDataBody)),
	)
	attrMessageDigest := derTLV(0x30,
		derTLV(0x06, oidMessageDigestBody),
		derTLV(0x31, derTLV(0x04, sfDigest[:])),
	)
	// These DER attribute encodings sort contentType before messageDigest.
	attrsInner := append(append([]byte(nil), attrContentType...), attrMessageDigest...)
	// RFC 5652 section 5.4: signedAttrs is stored with [0] IMPLICIT, but
	// the signature covers its DER SET OF encoding (universal tag 0x31).
	signedAttrs := derTLV(0xA0, attrsInner)
	toBeSigned := derTLV(0x31, attrsInner)

	h := sha256.Sum256(toBeSigned)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		return nil, fmt.Errorf("pkcs7: rsa sign: %w", err)
	}

	signerInfo := derTLV(0x30,
		derTLV(0x02, []byte{0x01}),
		derTLV(0x30, cert.RawIssuer, derIntegerFromBig(cert.SerialNumber)),
		derTLV(0x30, derTLV(0x06, oidSHA256Body)),
		signedAttrs,
		derTLV(0x30, derTLV(0x06, oidSHA256WithRSAbody), derNull()),
		derTLV(0x04, sig),
	)
	signedData := derTLV(0x30,
		derTLV(0x02, []byte{0x01}),
		derTLV(0x31, derTLV(0x30, derTLV(0x06, oidSHA256Body))),
		derTLV(0x30, derTLV(0x06, oidDataBody)),
		derTLV(0xA0, cert.Raw),
		derTLV(0x31, signerInfo),
	)
	return derTLV(0x30,
		derTLV(0x06, oidSignedDataBody),
		derTLV(0xA0, signedData),
	), nil
}

// ---------------------------------------------------------------------------
// Minimal DER reader (definite lengths only, no indefinite/Ber cruft)
// ---------------------------------------------------------------------------

type derNode struct {
	Tag     byte
	Content []byte
	Full    []byte // exact TLV bytes as found in the input
}

func derRead(buf []byte) (derNode, int, error) {
	if len(buf) < 2 {
		return derNode{}, 0, fmt.Errorf("pkcs7: truncated header")
	}
	tag := buf[0]
	first := buf[1]
	pos := 2
	var length int
	if first&0x80 == 0 {
		length = int(first)
	} else {
		nb := int(first & 0x7F)
		if nb == 0 || nb > 4 || len(buf) < 2+nb {
			return derNode{}, 0, fmt.Errorf("pkcs7: bad length encoding")
		}
		for _, b := range buf[2 : 2+nb] {
			length = length<<8 | int(b)
		}
		pos = 2 + nb
	}
	if length < 0 || len(buf) < pos+length {
		return derNode{}, 0, fmt.Errorf("pkcs7: truncated content")
	}
	return derNode{Tag: tag, Content: buf[pos : pos+length], Full: buf[:pos+length]}, pos + length, nil
}

func derChildren(content []byte) ([]derNode, error) {
	var out []derNode
	for len(content) > 0 {
		n, consumed, err := derRead(content)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
		content = content[consumed:]
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// PKCS#7 parser + verifier
// ---------------------------------------------------------------------------

type pkcs7Parsed struct {
	CertDERs      [][]byte // raw certificate encodings from [0]
	AuthAttrsFull []byte   // DER SET OF encoding covered by the RSA signature
	MessageDigest []byte   // messageDigest attribute value
	Signature     []byte
}

func parsePKCS7SignatureBlock(block []byte) (*pkcs7Parsed, error) {
	ci, consumed, err := derRead(block)
	if err != nil {
		return nil, err
	}
	if ci.Tag != 0x30 || consumed != len(block) {
		return nil, fmt.Errorf("pkcs7: not a DER SEQUENCE block")
	}
	ciKids, err := derChildren(ci.Content)
	if err != nil || len(ciKids) != 2 {
		return nil, fmt.Errorf("pkcs7: bad ContentInfo")
	}
	if ciKids[0].Tag != 0x06 || !bytes.Equal(ciKids[0].Content, oidSignedDataBody) {
		return nil, fmt.Errorf("pkcs7: not SignedData")
	}
	if ciKids[1].Tag != 0xA0 {
		return nil, fmt.Errorf("pkcs7: SignedData not [0]-wrapped")
	}
	sd, _, err := derRead(ciKids[1].Content)
	if err != nil || sd.Tag != 0x30 {
		return nil, fmt.Errorf("pkcs7: bad SignedData")
	}
	sdKids, err := derChildren(sd.Content)
	if err != nil || len(sdKids) != 5 {
		return nil, fmt.Errorf("pkcs7: bad SignedData fields")
	}
	// [version, digestAlgorithms, encapContentInfo, certificates[0], signerInfos]
	if sdKids[3].Tag != 0xA0 {
		return nil, fmt.Errorf("pkcs7: missing certificates [0]")
	}
	certKids, err := derChildren(sdKids[3].Content)
	if err != nil || len(certKids) == 0 {
		return nil, fmt.Errorf("pkcs7: empty certificates")
	}
	p := &pkcs7Parsed{}
	for _, c := range certKids {
		if c.Tag != 0x30 {
			return nil, fmt.Errorf("pkcs7: certificate is not a SEQUENCE")
		}
		p.CertDERs = append(p.CertDERs, c.Full)
	}
	siKids, err := derChildren(sdKids[4].Content)
	if err != nil || len(siKids) == 0 {
		return nil, fmt.Errorf("pkcs7: empty signerInfos")
	}
	// First signer only: multi-signer chains (e.g. TSA countersignatures)
	// are out of scope for the offline path.
	fields, err := derChildren(siKids[0].Content)
	if err != nil || len(fields) != 6 {
		return nil, fmt.Errorf("pkcs7: bad SignerInfo")
	}
	algKids, err := derChildren(fields[2].Content)
	if err != nil || len(algKids) == 0 || algKids[0].Tag != 0x06 ||
		!bytes.Equal(algKids[0].Content, oidSHA256Body) {
		return nil, fmt.Errorf("pkcs7: digest algorithm is not SHA-256")
	}
	if fields[3].Tag != 0xA0 {
		return nil, fmt.Errorf("pkcs7: missing signedAttrs [0]")
	}
	// Reconstruct the signature input's universal SET tag; [0] only belongs
	// to the SignerInfo field encoding, never to the signed digest input.
	p.AuthAttrsFull = derTLV(0x31, fields[3].Content)
	attrs, err := derChildren(fields[3].Content)
	if err != nil {
		return nil, err
	}
	for _, a := range attrs {
		parts, err := derChildren(a.Content)
		if err != nil || len(parts) != 2 {
			continue
		}
		if parts[0].Tag == 0x06 && bytes.Equal(parts[0].Content, oidMessageDigestBody) {
			vals, err := derChildren(parts[1].Content)
			if err != nil || len(vals) == 0 || vals[0].Tag != 0x04 {
				return nil, fmt.Errorf("pkcs7: bad messageDigest attribute")
			}
			p.MessageDigest = vals[0].Content
		}
	}
	if len(p.MessageDigest) == 0 {
		return nil, fmt.Errorf("pkcs7: no messageDigest attribute")
	}
	sigAlgKids, err := derChildren(fields[4].Content)
	if err != nil || len(sigAlgKids) == 0 || sigAlgKids[0].Tag != 0x06 ||
		!bytes.Equal(sigAlgKids[0].Content, oidSHA256WithRSAbody) {
		return nil, fmt.Errorf("pkcs7: signature algorithm is not SHA-256 with RSA")
	}
	if fields[5].Tag != 0x04 {
		return nil, fmt.Errorf("pkcs7: signature is not an OCTET STRING")
	}
	p.Signature = fields[5].Content
	return p, nil
}

// verifyPKCS7SignatureBlock checks the RSA signature over the signedAttrs
// and that the messageDigest attribute matches sfBytes. It returns the
// hex SHA-256 fingerprint of the signer certificate.
func verifyPKCS7SignatureBlock(block, sfBytes []byte) (string, error) {
	p, err := parsePKCS7SignatureBlock(block)
	if err != nil {
		return "", err
	}
	if len(p.CertDERs) == 0 {
		return "", fmt.Errorf("pkcs7: no signer certificate")
	}
	cert, err := x509.ParseCertificate(p.CertsDER())
	if err != nil {
		return "", fmt.Errorf("pkcs7: bad signer certificate: %w", err)
	}
	rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("pkcs7: signer key is not RSA (offline path supports RSA only)")
	}
	want := sha256.Sum256(sfBytes)
	if subtle.ConstantTimeCompare(want[:], p.MessageDigest) != 1 {
		return "", fmt.Errorf("pkcs7: CERT.SF digest mismatch (block does not cover this .SF)")
	}
	h := sha256.Sum256(p.AuthAttrsFull)
	if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, h[:], p.Signature); err != nil {
		return "", fmt.Errorf("pkcs7: RSA signature invalid: %w", err)
	}
	fp := sha256.Sum256(p.CertsDER())
	return hex.EncodeToString(fp[:]), nil
}

func (p *pkcs7Parsed) CertsDER() []byte { return p.CertDERs[0] }

// pkcs7CertFingerprints extracts SHA-256 fingerprints of every certificate
// embedded in a v1 signature block. Unknown layouts yield an error, never
// an empty silent success.
func pkcs7CertFingerprints(block []byte) ([]string, error) {
	p, err := parsePKCS7SignatureBlock(block)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, raw := range p.CertDERs {
		if _, err := x509.ParseCertificate(raw); err != nil {
			return nil, fmt.Errorf("pkcs7: bad embedded certificate: %w", err)
		}
		fp := sha256.Sum256(raw)
		hexFP := hex.EncodeToString(fp[:])
		if !seen[hexFP] {
			seen[hexFP] = true
			out = append(out, hexFP)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Signer fingerprints of an APK (v1 blocks on disk)
// ---------------------------------------------------------------------------

func isV1SigBlockName(name string) bool {
	upper := strings.ToUpper(name)
	if !strings.HasPrefix(upper, "META-INF/") {
		return false
	}
	return strings.HasSuffix(upper, ".RSA") || strings.HasSuffix(upper, ".DSA") || strings.HasSuffix(upper, ".EC")
}

// v1BlockFingerprints returns signer cert fingerprints from every v1
// signature block inside the APK, or an error when there is nothing to
// read. It performs no signature math: pair it with VerifyV1SignatureOffline.
func v1BlockFingerprints(apkPath string) ([]string, error) {
	reader, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("open APK: %w", err)
	}
	defer reader.Close()
	seen := map[string]bool{}
	var out []string
	found := false
	for _, f := range reader.File {
		if f.FileInfo().IsDir() {
			continue
		}
		found = true
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f.Name, err)
		}
		raw, err := readAllLimit(rc, 8<<20)
		_ = rc.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f.Name, err)
		}
		fps, err := pkcs7CertFingerprints(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		for _, fp := range fps {
			if !seen[fp] {
				seen[fp] = true
				out = append(out, fp)
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("no v1 signature block (META-INF/*.RSA|*.DSA|*.EC)")
	}
	return out, nil
}

// originalSignerFingerprints reads v1 blocks from an unpacked source tree
// (e.g. a decoded APK dir that still carries META-INF). It returns nil when
// the tree carries no signature material: unknown, not unsigned.
func originalSignerFingerprints(sourceDir string) []string {
	entries, err := os.ReadDir(filepath.Join(sourceDir, "META-INF"))
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !isV1SigBlockName("META-INF/"+e.Name()) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(sourceDir, "META-INF", e.Name()))
		if err != nil {
			continue
		}
		fps, err := pkcs7CertFingerprints(raw)
		if err != nil {
			continue
		}
		for _, fp := range fps {
			if !seen[fp] {
				seen[fp] = true
				out = append(out, fp)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Offline v1 chain verification (no Java required)
// ---------------------------------------------------------------------------

// VerifyV1SignatureOffline performs real cryptography on the v1 JAR scheme
// without external tools: entry digests vs MANIFEST.MF, manifest digest vs
// CERT.SF, .SF digest vs the PKCS#7 messageDigest, RSA over signedAttrs.
// It returns the signer certificate fingerprint on success.
//
// Only SHA-256 digest lines are accepted: that is what our signer writes,
// and SHA-1-only archives belong to the apksigner path.
func VerifyV1SignatureOffline(apkPath string) (string, error) {
	reader, err := zip.OpenReader(apkPath)
	if err != nil {
		return "", fmt.Errorf("open APK: %w", err)
	}
	defer reader.Close()

	files := map[string]*zip.File{}
	for _, f := range reader.File {
		if f.FileInfo().IsDir() {
			continue
		}
		files[f.Name] = f
	}
	manifestFile, ok := files["META-INF/MANIFEST.MF"]
	if !ok {
		return "", fmt.Errorf("META-INF/MANIFEST.MF missing")
	}
	manifestBytes, err := readZipBytes(manifestFile)
	if err != nil {
		return "", fmt.Errorf("read MANIFEST.MF: %w", err)
	}

	// Locate a *.SF + same-basename block pair (any alias, not just CERT.*).
	var sfName, blockName string
	for name := range files {
		upper := strings.ToUpper(name)
		if !strings.HasPrefix(upper, "META-INF/") || !strings.HasSuffix(upper, ".SF") {
			continue
		}
		base := strings.TrimSuffix(name, filepath.Ext(name))
		for _, ext := range []string{".RSA", ".DSA", ".EC", ".rsa", ".dsa", ".ec"} {
			if _, ok := files[base+ext]; ok {
				sfName, blockName = name, base+ext
				break
			}
		}
		if sfName != "" {
			break
		}
	}
	if sfName == "" {
		return "", fmt.Errorf("no v1 signature pair (*.SF + block)")
	}
	sfBytes, err := readZipBytes(files[sfName])
	if err != nil {
		return "", fmt.Errorf("read %s: %w", sfName, err)
	}
	blockBytes, err := readZipBytes(files[blockName])
	if err != nil {
		return "", fmt.Errorf("read %s: %w", blockName, err)
	}

	// 1. Entry digests vs MANIFEST.MF.
	for _, section := range splitManifestSections(manifestBytes) {
		name, want, ok := manifestSectionDigest(section)
		if !ok {
			continue // main section
		}
		target, ok := files[name]
		if !ok {
			return "", fmt.Errorf("MANIFEST.MF lists missing entry %q", name)
		}
		raw, err := readZipBytes(target)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", name, err)
		}
		got := sha256.Sum256(raw)
		if base64.StdEncoding.EncodeToString(got[:]) != want {
			return "", fmt.Errorf("digest mismatch for entry %q", name)
		}
	}

	// 2. Full-manifest digest vs .SF header.
	sfHeaderDigest := sfHeaderManifestDigest(sfBytes)
	fullHash := sha256.Sum256(manifestBytes)
	if sfHeaderDigest == "" {
		return "", fmt.Errorf("%s has no SHA-256-Digest-Manifest (unsupported .SF layout)", sfName)
	}
	if base64.StdEncoding.EncodeToString(fullHash[:]) != sfHeaderDigest {
		return "", fmt.Errorf("%s does not cover MANIFEST.MF", sfName)
	}

	// 3. Per-section .SF digests vs manifest sections.
	manifestSections := map[string][]byte{}
	for _, section := range splitManifestSections(manifestBytes) {
		if name, _, ok := manifestSectionDigest(section); ok {
			manifestSections[name] = section
		}
	}
	for _, section := range splitManifestSections(sfBytes) {
		name, want, ok := sfSectionDigest(section)
		if !ok {
			continue // header
		}
		msec, ok := manifestSections[name]
		if !ok {
			return "", fmt.Errorf("%s lists unknown manifest entry %q", sfName, name)
		}
		candidate := append(append([]byte(nil), msec...), []byte("\r\n\r\n")...)
		got := sha256.Sum256(candidate)
		if base64.StdEncoding.EncodeToString(got[:]) != want {
			return "", fmt.Errorf("%s section digest mismatch for %q", sfName, name)
		}
	}

	// 4. PKCS#7 over the .SF bytes.
	return verifyPKCS7SignatureBlock(blockBytes, sfBytes)
}

func readZipBytes(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return readAllLimit(rc, 512<<20)
}

// readAllLimit reads r with a hard cap so a corrupt length prefix cannot
// exhaust memory.
func readAllLimit(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("entry exceeds %d bytes", limit)
	}
	return b, nil
}

// splitManifestSections splits manifest-style bytes on blank CRLF lines,
// mirroring how generateManifest/generateSignatureFile delimit sections.
func splitManifestSections(data []byte) [][]byte {
	parts := bytes.Split(data, []byte("\r\n\r\n"))
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		if len(bytes.TrimSpace(p)) == 0 {
			continue
		}
		out = append(out, p)
	}
	return out
}

// manifestSectionDigest extracts (Name, SHA-256-Digest) from a MANIFEST.MF
// section. ok=false for the main section.
func manifestSectionDigest(section []byte) (name, digest string, ok bool) {
	for _, line := range bytes.Split(section, []byte("\r\n")) {
		if bytes.HasPrefix(line, []byte("Name: ")) {
			name = string(line[len("Name: "):])
		} else if bytes.HasPrefix(line, []byte("SHA-256-Digest: ")) {
			digest = string(line[len("SHA-256-Digest: "):])
		}
	}
	if name == "" || digest == "" {
		return "", "", false
	}
	return name, digest, true
}

// sfSectionDigest extracts (Name, SHA-256-Digest) from a CERT.SF section.
func sfSectionDigest(section []byte) (name, digest string, ok bool) {
	for _, line := range bytes.Split(section, []byte("\r\n")) {
		if bytes.HasPrefix(line, []byte("Name: ")) {
			name = string(line[len("Name: "):])
		} else if bytes.HasPrefix(line, []byte("SHA-256-Digest: ")) {
			digest = string(line[len("SHA-256-Digest: "):])
		}
	}
	if name == "" || digest == "" {
		return "", "", false
	}
	return name, digest, true
}

func sfHeaderManifestDigest(sfBytes []byte) string {
	for _, section := range splitManifestSections(sfBytes) {
		if _, _, ok := sfSectionDigest(section); ok {
			continue
		}
		for _, line := range bytes.Split(section, []byte("\r\n")) {
			if bytes.HasPrefix(line, []byte("SHA-256-Digest-Manifest: ")) {
				return string(line[len("SHA-256-Digest-Manifest: "):])
			}
		}
	}
	return ""
}
