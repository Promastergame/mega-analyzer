package apkloader

// Offline APK Signature Scheme v2/v3 verifier (pure Go).
//
// Recomputes chunked content digests, checks them against the block, and
// verifies the RSA signatures over signed-data. Used fail-closed after
// signing: an APK we cannot prove is never shipped as "signed".

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// V2VerifyOutcome describes a verified v2/v3 block.
type V2VerifyOutcome struct {
	V2           bool   // a valid v2 signer block is present
	V3           bool   // a valid v3 signer block is present
	SignerSHA256 string // hex SHA-256 of the signer certificate
	MinSDK       uint32 // v3 minSdkVersion (0 when no v3 block)
}

// VerifyV2V3Offline verifies the v2/v3 signing block of apkPath.
func VerifyV2V3Offline(apkPath string) (*V2VerifyOutcome, error) {
	l, err := parseAPKLayout(apkPath)
	if err != nil {
		return nil, err
	}
	bs, blen, ok := l.signingBlockRange()
	if !ok {
		return nil, fmt.Errorf("apksig: no APK Signing Block")
	}
	// Sections for digest: head, cd, eocd-with-cdOff-at-block-start.
	head := l.data[:bs]
	cd := l.data[l.cdOff : l.cdOff+l.cdSize]
	eocd := l.data[l.eocdOff:]
	eocdDigest := append([]byte(nil), eocd...)
	binary.LittleEndian.PutUint32(eocdDigest[16:], bs)
	_, want := contentDigestV2(head, cd, eocdDigest)
	out := &V2VerifyOutcome{}
	// Walk pairs: [u64 size][u32 id][value] ... [u64 size][magic].
	pos := uint64(bs) + 8
	endPairs := uint64(bs) + uint64(blen) - 24
	for pos < endPairs {
		if endPairs-pos < 12 {
			return nil, fmt.Errorf("apksig: truncated signing-block pair")
		}
		size := binary.LittleEndian.Uint64(l.data[pos : pos+8])
		id := binary.LittleEndian.Uint32(l.data[pos+8 : pos+12])
		if size < 4 || size > endPairs-pos-8 {
			return nil, fmt.Errorf("apksig: corrupt signing-block pair")
		}
		val := l.data[pos+12 : pos+8+size]
		switch id {
		case apkSigV2ID, apkSigV3ID:
			if id == apkSigV2ID && out.V2 || id == apkSigV3ID && out.V3 {
				return nil, fmt.Errorf("apksig: duplicate %s signer block", schemeName(id))
			}
			fp, minSdk, err := verifySignerBlock(val, id == apkSigV3ID, want)
			if err != nil {
				return nil, fmt.Errorf("apksig: scheme %s invalid: %w", schemeName(id), err)
			}
			if out.SignerSHA256 == "" {
				out.SignerSHA256 = fp
			} else if out.SignerSHA256 != fp {
				return nil, fmt.Errorf("apksig: v2/v3 signers differ")
			}
			if id == apkSigV2ID {
				out.V2 = true
			} else {
				out.V3 = true
				out.MinSDK = minSdk
			}
		}
		pos += 8 + size
	}
	if !out.V2 && !out.V3 {
		return nil, fmt.Errorf("apksig: no v2/v3 signer block present")
	}
	return out, nil
}

func schemeName(id uint32) string {
	if id == apkSigV3ID {
		return "v3"
	}
	return "v2"
}

// verifySignerBlock checks one signer pair value against the content digest.
func verifySignerBlock(val []byte, isV3 bool, want [32]byte) (fp string, minSdk uint32, err error) {
	if len(val) < 8 {
		return "", 0, fmt.Errorf("truncated signer value")
	}
	total := binary.LittleEndian.Uint32(val[0:4])
	signerLen := binary.LittleEndian.Uint32(val[4:8])
	if uint64(total)+4 != uint64(len(val)) || uint64(signerLen)+4 != uint64(total) {
		return "", 0, fmt.Errorf("bad signer framing")
	}
	signer := val[8 : 8+signerLen]
	p := 0
	rd := func(n int) ([]byte, error) {
		if n < 0 || n > len(signer)-p {
			return nil, fmt.Errorf("truncated signer")
		}
		b := signer[p : p+n]
		p += n
		return b, nil
	}
	sdLenBytes, err := rd(4)
	if err != nil {
		return "", 0, err
	}
	sdLen := binary.LittleEndian.Uint32(sdLenBytes)
	sd, err := rd(int(sdLen))
	if err != nil {
		return "", 0, fmt.Errorf("signed-data: %w", err)
	}
	var outerMinSDK, outerMaxSDK uint32
	if isV3 {
		sdkRange, err := rd(8)
		if err != nil {
			return "", 0, fmt.Errorf("v3 SDK range: %w", err)
		}
		outerMinSDK = binary.LittleEndian.Uint32(sdkRange[:4])
		outerMaxSDK = binary.LittleEndian.Uint32(sdkRange[4:])
		if outerMinSDK > outerMaxSDK || outerMaxSDK > v3MaxSDK {
			return "", 0, fmt.Errorf("invalid v3 SDK range")
		}
	}
	sigsLenBytes, err := rd(4)
	if err != nil {
		return "", 0, err
	}
	sigsLen := binary.LittleEndian.Uint32(sigsLenBytes)
	sigs, err := rd(int(sigsLen))
	if err != nil {
		return "", 0, fmt.Errorf("signatures: %w", err)
	}
	pubLenBytes, err := rd(4)
	if err != nil {
		return "", 0, err
	}
	pubLen := binary.LittleEndian.Uint32(pubLenBytes)
	pubDER, err := rd(int(pubLen))
	if err != nil {
		return "", 0, fmt.Errorf("public key: %w", err)
	}
	if p != len(signer) {
		return "", 0, fmt.Errorf("trailing signer data")
	}
	// Parse signed-data.
	q := 0
	qu32 := func() (uint32, error) {
		if q+4 > len(sd) {
			return 0, fmt.Errorf("truncated signed-data")
		}
		v := binary.LittleEndian.Uint32(sd[q : q+4])
		q += 4
		return v, nil
	}
	digestsLen, err := qu32()
	if err != nil {
		return "", 0, err
	}
	if uint64(digestsLen) > uint64(len(sd)-q) {
		return "", 0, fmt.Errorf("digests overrun")
	}
	digests := sd[q : q+int(digestsLen)]
	q += int(digestsLen)
	matched := false
	for r := 0; r < len(digests); {
		if len(digests)-r < 4 {
			return "", 0, fmt.Errorf("truncated digest record")
		}
		recLen := binary.LittleEndian.Uint32(digests[r : r+4])
		if uint64(recLen) > uint64(len(digests)-r-4) || recLen < 8 {
			return "", 0, fmt.Errorf("bad digest record")
		}
		alg := binary.LittleEndian.Uint32(digests[r+4 : r+8])
		body := digests[r+8 : r+4+int(recLen)]
		if alg == sigAlgRSA256 && len(body) >= 4 {
			dlen := binary.LittleEndian.Uint32(body[0:4])
			if int(dlen)+4 == len(body) && bytesEqual32(body[4:], want) {
				matched = true
			}
		}
		r += 4 + int(recLen)
	}
	if !matched {
		return "", 0, fmt.Errorf("content digest mismatch")
	}
	certsLen, err := qu32()
	if err != nil {
		return "", 0, err
	}
	if uint64(certsLen) > uint64(len(sd)-q) {
		return "", 0, fmt.Errorf("certs overrun")
	}
	certs := sd[q : q+int(certsLen)]
	q += int(certsLen)
	if len(certs) < 4 {
		return "", 0, fmt.Errorf("no certificates")
	}
	certLen := binary.LittleEndian.Uint32(certs[0:4])
	if uint64(certLen) > uint64(len(certs)-4) {
		return "", 0, fmt.Errorf("certificate overrun")
	}
	certDER := certs[4 : 4+int(certLen)]
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", 0, fmt.Errorf("bad certificate: %w", err)
	}
	if isV3 {
		minSdk, err = qu32()
		if err != nil {
			return "", 0, fmt.Errorf("v3 minSdk: %w", err)
		}
		maxSDK, err := qu32()
		if err != nil {
			return "", 0, fmt.Errorf("v3 maxSdk: %w", err)
		}
		if minSdk != outerMinSDK || maxSDK != outerMaxSDK {
			return "", 0, fmt.Errorf("v3 SDK range differs from signed-data")
		}
	}
	attrsLen, err := qu32()
	if err != nil {
		return "", 0, fmt.Errorf("additional attributes: %w", err)
	}
	if uint64(attrsLen) != uint64(len(sd)-q) {
		return "", 0, fmt.Errorf("bad additional attributes framing")
	}
	// Public key must match the certificate.
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return "", 0, fmt.Errorf("bad public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", 0, fmt.Errorf("public key is not RSA")
	}
	certRSA, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || certRSA.N.Cmp(rsaPub.N) != 0 || certRSA.E != rsaPub.E {
		return "", 0, fmt.Errorf("public key does not match certificate")
	}
	// Verify at least one RSA-SHA256 signature over signed-data.
	sdSum := sha256.Sum256(sd)
	verified := false
	for r := 0; r < len(sigs); {
		if len(sigs)-r < 4 {
			return "", 0, fmt.Errorf("truncated signature record")
		}
		recLen := binary.LittleEndian.Uint32(sigs[r : r+4])
		if uint64(recLen) > uint64(len(sigs)-r-4) || recLen < 8 {
			return "", 0, fmt.Errorf("bad signature record")
		}
		alg := binary.LittleEndian.Uint32(sigs[r+4 : r+8])
		body := sigs[r+8 : r+4+int(recLen)]
		if alg == sigAlgRSA256 && len(body) >= 4 {
			slen := binary.LittleEndian.Uint32(body[0:4])
			if int(slen)+4 == len(body) {
				if rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, sdSum[:], body[4:]) == nil {
					verified = true
				}
			}
		}
		r += 4 + int(recLen)
	}
	if !verified {
		return "", 0, fmt.Errorf("no valid RSA-SHA256 signature over signed-data")
	}
	sum := sha256.Sum256(certDER)
	return hex.EncodeToString(sum[:]), minSdk, nil
}

func bytesEqual32(a []byte, b [32]byte) bool {
	if len(a) != 32 {
		return false
	}
	for i := range b {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
