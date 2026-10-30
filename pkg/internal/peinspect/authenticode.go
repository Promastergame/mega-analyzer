package peinspect

// Offline Authenticode verification.
//
// What this does: recompute the Authenticode PE image digest (checksum field,
// certificate-directory entry and the certificate table through end-of-file
// excluded — the same exclusion Windows uses, which is why trailing overlays
// do not break real signatures) and verify the embedded PKCS#7 SignedData
// self-consistency: messageDigest attribute vs image digest, RSA signature
// over the DER SET OF signedAttrs with the embedded signer certificate.
//
// What this explicitly does NOT do: chain building, revocation checks and
// catalog-signing lookups all require the Windows trust store or network
// access. Trust and Revocation therefore always stay "unknown" and the
// Verification string says so. A "valid" Integrity means "the file matches
// what the embedded signer signed", not "the signer is trusted".

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // needed to verify legacy SHA-1 Authenticode signatures
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"
)

// AuthenticodeResult is the outcome of offline verification of one embedded
// PKCS#7 signature. Integrity is "valid", "invalid" or "unverifiable" (the
// latter with a Note explaining why — unsupported algorithm, missing
// attributes, unparseable structure — never a silent pass).
type AuthenticodeResult struct {
	Integrity    string // valid | invalid | unverifiable
	Verification string // human-readable summary of what was checked
	Note         string // extra context (multi-signer, countersignature, time, ...)
	Signer       string // signer certificate subject CN ("" when unknown)
	CertSHA256   string // hex SHA-256 of the embedded signer certificate ("" when unknown)
	ClaimedTime  string // signingTime attribute in RFC3339 ("" when absent/unparseable)
}

// digest algorithms usable for the Authenticode image hash.
var authenticodeHashes = map[string]func() hash.Hash{
	"1.3.14.3.2.26":          sha1.New,      // SHA-1 (legacy, verification only)
	"2.16.840.1.101.3.4.2.1": sha256.New,    // SHA-256
	"2.16.840.1.101.3.4.2.2": sha512.New384, // SHA-384
	"2.16.840.1.101.3.4.2.3": sha512.New,    // SHA-512
}

// RSA signature algorithms accepted on SignerInfo (PKCS#1 v1.5 only;
// Authenticode does not use PSS in practice).
var authenticodeSigHashes = map[string]crypto.Hash{
	"1.2.840.113549.1.1.5":  crypto.SHA1,   // sha1RSA
	"1.2.840.113549.1.1.11": crypto.SHA256, // sha256RSA
	"1.2.840.113549.1.1.12": crypto.SHA384, // sha384RSA
	"1.2.840.113549.1.1.13": crypto.SHA512, // sha512RSA
}

const (
	acOidSignedData  = "1.2.840.113549.1.7.2"
	acOidSpcIndirect = "1.3.6.1.4.1.311.2.1.4"
	acOidContentType = "1.2.840.113549.1.9.3"
	acOidMsgDigest   = "1.2.840.113549.1.9.4"
	acOidSigningTime = "1.2.840.113549.1.9.5"
)

// VerifyEmbeddedSignature verifies the first embedded PKCS#7 signature.
// checksumOff is the file offset of the CheckSum field (opt+64), certEntryOff
// the file offset of the certificate directory entry (8 bytes), certOff the
// file offset of the WIN_CERTIFICATE table and certSize its directory size.
func VerifyEmbeddedSignature(data []byte, checksumOff, certEntryOff, certOff, certSize uint64) AuthenticodeResult {
	fail := func(note string) AuthenticodeResult {
		return AuthenticodeResult{Integrity: "unverifiable", Verification: "offline self-consistency check could not be completed; chain and revocation require OS trust store", Note: note}
	}
	if checksumOff+4 > uint64(len(data)) || certEntryOff+8 > uint64(len(data)) ||
		certOff+8 > uint64(len(data)) || certOff+certSize > uint64(len(data)) {
		return fail("certificate table or excluded ranges out of file bounds")
	}
	dwLength := uint64(u32le(data[certOff:]))
	if dwLength < 8 || dwLength > certSize {
		return fail("WIN_CERTIFICATE length out of bounds")
	}
	if u16le(data[certOff+4:]) != 0x0200 {
		return fail("unsupported WIN_CERTIFICATE revision (not PKCS#7)")
	}
	if u16le(data[certOff+6:]) != 0x0002 {
		return fail("certificate entry is not PKCS#7 SignedData")
	}
	aligned := (dwLength + 7) &^ 7
	if certOff+aligned > uint64(len(data)) {
		return fail("WIN_CERTIFICATE overruns file")
	}
	blob := data[certOff+8 : certOff+dwLength]
	if certSize > aligned {
		// Multiple WIN_CERTIFICATE entries; only the first is checked.
		return withNote(verifySignedData(data, checksumOff, certEntryOff, certOff, blob), "certificate table holds multiple entries; only the first was verified")
	}
	return verifySignedData(data, checksumOff, certEntryOff, certOff, blob)
}

func withNote(r AuthenticodeResult, note string) AuthenticodeResult {
	if r.Note == "" {
		r.Note = note
	} else {
		r.Note += "; " + note
	}
	return r
}

func verifySignedData(data []byte, checksumOff, certEntryOff, certOff uint64, blob []byte) AuthenticodeResult {
	fail := func(note string) AuthenticodeResult {
		return AuthenticodeResult{Integrity: "unverifiable", Verification: "offline self-consistency check could not be completed; chain and revocation require OS trust store", Note: note}
	}
	top, rest, err := readTLV(blob)
	if err != nil || top.class != 0 || !top.constructed || top.tag != 16 || len(rest) != 0 {
		return fail("PKCS#7 ContentInfo is not a single DER SEQUENCE")
	}
	items, err := tlvChildren(top.content)
	if err != nil || len(items) != 2 {
		return fail("ContentInfo must hold contentType + [0] content")
	}
	ct, err := oidName(items[0])
	if err != nil || ct != acOidSignedData {
		return fail("ContentInfo contentType is not signedData")
	}
	if items[1].class != 2 || !items[1].constructed || items[1].tag != 0 {
		return fail("ContentInfo content is not [0] EXPLICIT")
	}
	// [0] EXPLICIT wraps a single SignedData SEQUENCE.
	sdTLV, rest, err := readTLV(items[1].content)
	if err != nil || len(rest) != 0 || sdTLV.class != 0 || !sdTLV.constructed || sdTLV.tag != 16 {
		return fail("SignedData is not a single DER SEQUENCE")
	}
	sdItems, err := tlvChildren(sdTLV.content)
	if err != nil || len(sdItems) < 5 {
		return fail("SignedData has fewer fields than required")
	}
	pos := 1 // skip version INTEGER
	// digestAlgorithms: SET or SEQUENCE OF AlgorithmIdentifier.
	if !sdItems[pos].constructed || (sdItems[pos].tag != 16 && sdItems[pos].tag != 17) {
		return fail("SignedData digestAlgorithms malformed")
	}
	pos++
	// encapContentInfo.
	if sdItems[pos].class != 0 || !sdItems[pos].constructed || sdItems[pos].tag != 16 {
		return fail("encapContentInfo malformed")
	}
	msgAlgo, msgDigest, err := parseSpcIndirect(sdItems[pos].content)
	if err != nil {
		return fail("SpcIndirectDataContent: " + err.Error())
	}
	pos++
	// Optional certificates [0] / CRLs [1].
	var certDERs [][]byte
	for pos < len(sdItems) && sdItems[pos].class == 2 && (sdItems[pos].tag == 0 || sdItems[pos].tag == 1) {
		if sdItems[pos].tag == 0 {
			certs, err := tlvChildren(sdItems[pos].content)
			if err != nil {
				return fail("SignedData certificates malformed")
			}
			for _, c := range certs {
				if c.class == 0 && c.constructed && c.tag == 16 {
					certDERs = append(certDERs, c.raw)
				}
			}
		}
		pos++
	}
	if pos >= len(sdItems) || !sdItems[pos].constructed || (sdItems[pos].tag != 16 && sdItems[pos].tag != 17) {
		return fail("SignedData signerInfos missing")
	}
	signerTLVs, err := tlvChildren(sdItems[pos].content)
	if err != nil || len(signerTLVs) == 0 {
		return fail("SignedData signerInfos malformed")
	}
	notes := []string{}
	if len(signerTLVs) > 1 {
		notes = append(notes, fmt.Sprintf("%d signerInfos present; only the first was verified", len(signerTLVs)))
	}
	si, err := parseSignerInfo(signerTLVs[0])
	if err != nil {
		return fail("SignerInfo: " + err.Error())
	}
	if si.unauthPresent {
		notes = append(notes, "unsignedAttributes/countersignature present; not verified offline")
	}
	if si.digestAlgo != msgAlgo {
		return AuthenticodeResult{Integrity: "invalid",
			Verification: "SignerInfo digest algorithm differs from SpcIndirectDataContent digest algorithm",
			Note:         strings.Join(notes, "; ")}
	}
	newHash, ok := authenticodeHashes[msgAlgo]
	if !ok {
		return fail("image digest algorithm " + msgAlgo + " not supported offline")
	}
	h := newHash()
	h.Write(data[:checksumOff])
	h.Write(data[checksumOff+4 : certEntryOff])
	h.Write(data[certEntryOff+8 : certOff])
	// Per Authenticode hashing rules everything from the certificate table
	// to end-of-file is excluded, so trailing overlays do not break the hash.
	imageDigest := h.Sum(nil)
	if !equalBytes(imageDigest, msgDigest) {
		return AuthenticodeResult{Integrity: "invalid",
			Verification: "PE image digest does not match the digest signed in SpcIndirectDataContent (file modified after signing or corrupt)",
			Note:         strings.Join(notes, "; ")}
	}
	// signedAttrs checks: contentType + messageDigest attributes required.
	attrCT, attrDigest, claimedTime, err := parseSignedAttrs(si.signedAttrs)
	if err != nil {
		return fail("signedAttrs: " + err.Error())
	}
	if attrCT != acOidSpcIndirect {
		return AuthenticodeResult{Integrity: "invalid", Verification: "signedAttrs contentType is not spcIndirectDataContent",
			Note: strings.Join(notes, "; ")}
	}
	if !equalBytes(attrDigest, msgDigest) {
		return AuthenticodeResult{Integrity: "invalid", Verification: "signedAttrs messageDigest differs from SpcIndirectDataContent digest",
			Note: strings.Join(notes, "; ")}
	}
	sigHash, ok := authenticodeSigHashes[si.sigAlgo]
	if !ok {
		return fail("signer signature algorithm " + si.sigAlgo + " is not RSA PKCS#1 v1.5")
	}
	cert, issuerMatch := findSignerCert(certDERs, si.issuerRaw, si.serial)
	if !issuerMatch {
		return fail("signer certificate (issuer+serial) not found among embedded certificates")
	}
	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fail("signer public key is not RSA; only RSA verified offline")
	}
	// The signature input is the DER SET OF encoding of signedAttrs.
	msg := append([]byte{0x31}, derLength(len(si.signedAttrs))...)
	msg = append(msg, si.signedAttrs...)
	digestOfAttrs := hashByCrypto(sigHash)
	digestOfAttrs.Write(msg)
	if err := rsa.VerifyPKCS1v15(rsaPub, sigHash, digestOfAttrs.Sum(nil), si.signature); err != nil {
		return AuthenticodeResult{Integrity: "invalid",
			Verification: "RSA signature over signedAttrs failed verification with the embedded signer certificate",
			Note:         strings.Join(notes, "; ")}
	}
	res := AuthenticodeResult{
		Integrity:    "valid",
		Verification: fmt.Sprintf("RSA-%s self-consistent signature by CN=%q (cert SHA-256 %s); certificate chain and revocation NOT validated — offline check only", hashName(sigHash), cert.Subject.CommonName, hex.EncodeToString(sha256Of(cert.Raw))),
		Signer:       cert.Subject.CommonName,
		CertSHA256:   hex.EncodeToString(sha256Of(cert.Raw)),
	}
	if claimedTime != "" {
		res.ClaimedTime = claimedTime
		notes = append(notes, "claimed signing time "+claimedTime+" (attribute, not a trusted timestamp)")
	}
	if len(notes) > 0 {
		res.Note = strings.Join(notes, "; ")
	}
	return res
}

// ─── SpcIndirectDataContent ──────────────────────────────────────────────────

// parseSpcIndirect extracts (digestAlgorithm OID, messageDigest) from an
// encapContentInfo SEQUENCE. It locates the DigestInfo-shaped child
// (SEQUENCE{ SEQUENCE{ OID ... }, OCTET STRING }) without assuming the exact
// shape of the sibling SpcAttributeTypeAndOptionalValue value.
func parseSpcIndirect(encap []byte) (algo string, digest []byte, err error) {
	items, err := tlvChildren(encap)
	if err != nil || len(items) != 2 {
		return "", nil, fmt.Errorf("encapContentInfo must hold contentType + [0] eContent")
	}
	ct, err := oidName(items[0])
	if err != nil || ct != acOidSpcIndirect {
		return "", nil, fmt.Errorf("eContent type is not spcIndirectDataContent")
	}
	if items[1].class != 2 || !items[1].constructed || items[1].tag != 0 {
		return "", nil, fmt.Errorf("eContent is not [0] EXPLICIT")
	}
	inner := items[1].content
	// eContent holds an OCTET STRING wrapping SpcIndirectDataContent.
	if t, rest, err := readTLV(inner); err == nil && len(rest) == 0 && t.class == 0 && !t.constructed && t.tag == 4 {
		inner = t.content
	}
	spcTLV, rest, err := readTLV(inner)
	if err != nil || len(rest) != 0 || spcTLV.class != 0 || !spcTLV.constructed || spcTLV.tag != 16 {
		return "", nil, fmt.Errorf("SpcIndirectDataContent not a SEQUENCE")
	}
	spc, err := tlvChildren(spcTLV.content)
	if err != nil || len(spc) != 2 {
		return "", nil, fmt.Errorf("SpcIndirectDataContent must hold data + messageDigest")
	}
	// messageDigest is the child shaped SEQUENCE{ SEQUENCE{ OID }, OCTET }.
	for _, child := range spc {
		if child.class != 0 || !child.constructed || child.tag != 16 {
			continue
		}
		parts, err := tlvChildren(child.content)
		if err != nil || len(parts) != 2 {
			continue
		}
		if parts[0].class != 0 || !parts[0].constructed || parts[0].tag != 16 {
			continue
		}
		algItems, err := tlvChildren(parts[0].content)
		if err != nil || len(algItems) == 0 {
			continue
		}
		oidStr, err := oidName(algItems[0])
		if err != nil {
			continue
		}
		if parts[1].class != 0 || parts[1].constructed || parts[1].tag != 4 {
			continue
		}
		return oidStr, append([]byte(nil), parts[1].content...), nil
	}
	return "", nil, fmt.Errorf("DigestInfo not found in SpcIndirectDataContent")
}

// ─── SignerInfo ──────────────────────────────────────────────────────────────

type signerInfo struct {
	issuerRaw     []byte // DER of sid issuer Name
	serial        *big.Int
	digestAlgo    string
	signedAttrs   []byte // raw SET OF content bytes (without tag/length)
	sigAlgo       string
	signature     []byte
	unauthPresent bool
}

func parseSignerInfo(t adTLV) (*signerInfo, error) {
	if t.class != 0 || !t.constructed || t.tag != 16 {
		return nil, fmt.Errorf("SignerInfo not a SEQUENCE")
	}
	items, err := tlvChildren(t.content)
	if err != nil || len(items) < 5 {
		return nil, fmt.Errorf("SignerInfo has fewer fields than required")
	}
	pos := 1 // skip version
	// sid: IssuerAndSerialNumber SEQUENCE{ Name, INTEGER }.
	if items[pos].class != 0 || !items[pos].constructed || items[pos].tag != 16 {
		return nil, fmt.Errorf("non-issuerSerial SignerInfo sid not supported offline")
	}
	sidParts, err := tlvChildren(items[pos].content)
	if err != nil || len(sidParts) != 2 {
		return nil, fmt.Errorf("sid malformed")
	}
	if sidParts[0].class != 0 || !sidParts[0].constructed || sidParts[0].tag != 16 {
		return nil, fmt.Errorf("sid issuer not a Name")
	}
	if sidParts[1].class != 0 || sidParts[1].constructed || sidParts[1].tag != 2 {
		return nil, fmt.Errorf("sid serial not an INTEGER")
	}
	si := &signerInfo{issuerRaw: sidParts[0].raw, serial: new(big.Int).SetBytes(sidParts[1].content)}
	pos++
	// digestAlgorithm.
	algItems, err := tlvChildren(items[pos].content)
	if err != nil || len(algItems) == 0 || items[pos].class != 0 || !items[pos].constructed || items[pos].tag != 16 {
		return nil, fmt.Errorf("digestAlgorithm malformed")
	}
	si.digestAlgo, err = oidName(algItems[0])
	if err != nil {
		return nil, fmt.Errorf("digestAlgorithm OID malformed")
	}
	pos++
	// signedAttrs [0] IMPLICIT — required by Authenticode.
	if pos >= len(items) || items[pos].class != 2 || !items[pos].constructed || items[pos].tag != 0 {
		return nil, fmt.Errorf("signedAttrs absent (required by Authenticode)")
	}
	si.signedAttrs = items[pos].content
	pos++
	// signatureAlgorithm.
	if pos >= len(items) {
		return nil, fmt.Errorf("signatureAlgorithm absent")
	}
	sigItems, err := tlvChildren(items[pos].content)
	if err != nil || len(sigItems) == 0 {
		return nil, fmt.Errorf("signatureAlgorithm malformed")
	}
	si.sigAlgo, err = oidName(sigItems[0])
	if err != nil {
		return nil, fmt.Errorf("signatureAlgorithm OID malformed")
	}
	pos++
	// signature OCTET STRING.
	if pos >= len(items) || items[pos].class != 0 || items[pos].constructed || items[pos].tag != 4 {
		return nil, fmt.Errorf("signature not an OCTET STRING")
	}
	si.signature = items[pos].content
	pos++
	si.unauthPresent = pos < len(items)
	return si, nil
}

// parseSignedAttrs returns the contentType attribute value OID, the
// messageDigest attribute value bytes and the claimed signingTime (""
// when absent).
func parseSignedAttrs(setContent []byte) (contentType string, msgDigest []byte, claimedTime string, err error) {
	attrs, err := tlvChildren(setContent)
	if err != nil {
		return "", nil, "", fmt.Errorf("signedAttrs not a SET OF Attribute: %v", err)
	}
	var ct string
	var md []byte
	for _, a := range attrs {
		if a.class != 0 || !a.constructed || a.tag != 16 {
			return "", nil, "", fmt.Errorf("signedAttrs element not an Attribute SEQUENCE")
		}
		parts, err := tlvChildren(a.content)
		if err != nil || len(parts) != 2 {
			return "", nil, "", fmt.Errorf("Attribute must hold type + values")
		}
		oidStr, err := oidName(parts[0])
		if err != nil {
			return "", nil, "", fmt.Errorf("Attribute type not an OID")
		}
		// Attribute values: SET (or SEQUENCE, accepted defensively) of ANY.
		vals, err := tlvChildren(parts[1].content)
		if err != nil || len(vals) == 0 {
			return "", nil, "", fmt.Errorf("Attribute %s has no values", oidStr)
		}
		switch oidStr {
		case acOidContentType:
			o, err := oidName(vals[0])
			if err != nil {
				return "", nil, "", fmt.Errorf("contentType value not an OID")
			}
			ct = o
		case acOidMsgDigest:
			if vals[0].class != 0 || vals[0].constructed || vals[0].tag != 4 {
				return "", nil, "", fmt.Errorf("messageDigest value not an OCTET STRING")
			}
			md = vals[0].content
		case acOidSigningTime:
			claimedTime = parseDERTime(vals[0])
		}
	}
	if ct == "" {
		return "", nil, "", fmt.Errorf("contentType attribute missing")
	}
	if md == nil {
		return "", nil, "", fmt.Errorf("messageDigest attribute missing")
	}
	return ct, md, claimedTime, nil
}

// parseDERTime renders UTCTime/GeneralizedTime TLVs as RFC3339 ("" when the
// value is not a recognized time; time parse failures never fail the crypto).
func parseDERTime(t adTLV) string {
	if t.class != 0 || t.constructed || (t.tag != 23 && t.tag != 24) {
		return ""
	}
	s := string(t.content)
	var tm time.Time
	var err error
	if t.tag == 23 {
		tm, err = parseUTCTime(s)
	} else {
		tm, err = parseGeneralizedTime(s)
	}
	if err != nil {
		return ""
	}
	return tm.UTC().Format(time.RFC3339)
}

func parseUTCTime(s string) (time.Time, error) {
	s = strings.TrimSuffix(s, "Z")
	if i := strings.IndexAny(s, "+-"); i >= 0 && len(s) > 12 {
		s = s[:i] // ignore numeric timezone offsets for display purposes
	}
	return time.ParseInLocation("060102150405", s, time.UTC)
}

func parseGeneralizedTime(s string) (time.Time, error) {
	s = strings.TrimSuffix(s, "Z")
	if i := strings.Index(s, "."); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexAny(s, "+-"); i >= 0 && len(s) > 14 {
		s = s[:i]
	}
	return time.ParseInLocation("20060102150405", s, time.UTC)
}

func findSignerCert(derCerts [][]byte, issuerRaw []byte, serial *big.Int) (*x509.Certificate, bool) {
	for _, der := range derCerts {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		if cert.SerialNumber.Cmp(serial) == 0 && equalBytes(cert.RawIssuer, issuerRaw) {
			return cert, true
		}
	}
	return nil, false
}

// ─── minimal DER reader ──────────────────────────────────────────────────────

type adTLV struct {
	class       int
	constructed bool
	tag         uint64
	raw         []byte // full TLV (tag+length+content)
	content     []byte
}

func readTLV(b []byte) (adTLV, []byte, error) {
	var t adTLV
	if len(b) < 2 {
		return t, nil, fmt.Errorf("truncated TLV")
	}
	first := b[0]
	t.class = int(first >> 6)
	t.constructed = first&0x20 != 0
	tag := uint64(first & 0x1f)
	pos := 1
	if tag == 0x1f {
		tag = 0
		for {
			if pos >= len(b) {
				return t, nil, fmt.Errorf("truncated high-tag form")
			}
			c := b[pos]
			pos++
			tag = tag<<7 | uint64(c&0x7f)
			if tag > 1<<32 {
				return t, nil, fmt.Errorf("tag number too large")
			}
			if c&0x80 == 0 {
				break
			}
		}
	}
	t.tag = tag
	if pos >= len(b) {
		return t, nil, fmt.Errorf("missing length")
	}
	lb := b[pos]
	pos++
	var length uint64
	if lb&0x80 == 0 {
		length = uint64(lb)
	} else {
		n := int(lb & 0x7f)
		if n == 0 {
			return t, nil, fmt.Errorf("indefinite length rejected")
		}
		if n > 4 || pos+n > len(b) {
			return t, nil, fmt.Errorf("length field out of bounds")
		}
		for i := 0; i < n; i++ {
			length = length<<8 | uint64(b[pos+i])
		}
		pos += n
	}
	if length > uint64(len(b)-pos) {
		return t, nil, fmt.Errorf("content overruns input")
	}
	t.content = b[pos : pos+int(length)]
	t.raw = b[:pos+int(length)]
	return t, b[pos+int(length):], nil
}

func tlvChildren(content []byte) ([]adTLV, error) {
	var out []adTLV
	rest := content
	for len(rest) > 0 {
		t, next, err := readTLV(rest)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		rest = next
	}
	return out, nil
}

// oidName renders a primitive OBJECT IDENTIFIER TLV in dotted form.
func oidName(t adTLV) (string, error) {
	if t.class != 0 || t.constructed || t.tag != 6 || len(t.content) == 0 {
		return "", fmt.Errorf("not an OBJECT IDENTIFIER")
	}
	b := t.content
	arcs := []uint64{uint64(b[0]) / 40, uint64(b[0]) % 40}
	var v uint64
	cont := false
	for _, c := range b[1:] {
		v = v<<7 | uint64(c&0x7f)
		cont = c&0x80 != 0
		if !cont {
			arcs = append(arcs, v)
			v = 0
		}
	}
	if cont {
		return "", fmt.Errorf("truncated OID")
	}
	var sb strings.Builder
	for i, a := range arcs {
		if i > 0 {
			sb.WriteByte('.')
		}
		fmt.Fprintf(&sb, "%d", a)
	}
	return sb.String(), nil
}

func derLength(n int) []byte {
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
	out := []byte{byte(0x80 | (len(tmp) - i))}
	return append(out, tmp[i:]...)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sha256Of(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func hashByCrypto(h crypto.Hash) hash.Hash {
	switch h {
	case crypto.SHA1:
		return sha1.New()
	case crypto.SHA384:
		return sha512.New384()
	case crypto.SHA512:
		return sha512.New()
	default:
		return sha256.New()
	}
}

func hashName(h crypto.Hash) string {
	switch h {
	case crypto.SHA1:
		return "SHA1"
	case crypto.SHA384:
		return "SHA384"
	case crypto.SHA512:
		return "SHA512"
	default:
		return "SHA256"
	}
}

func u32le(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func u16le(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}
