package apkloader

// APK Signature Schemes v2 and v3, pure Go (no apksigner/Java).
//
// Layout mirrors the platform spec: the APK Signing Block sits immediately
// before the central directory; digests cover (before-CD, central directory,
// EOCD-with-CD-offset-pointing-at-the-block) in 1 MiB chunks. Crypto is the
// standard library (RSA-2048 PKCS#1 v1.5 + SHA-256, self-signed debug cert).
//
// v3 adds matching minSdkVersion/maxSdkVersion ranges inside and outside
// signed-data (no key rotation: rotation attributes are out of scope).
//
// References (format only, clean-room code):
//   - Android source docs "APK Signature Scheme v2/v3"
//   - AOSP ApkSignerBlockUtils / ApkSignatureSchemeV2Verifier behavior

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"os"
)

const (
	apkSigV2ID   uint32 = 0x7109871a
	apkSigV3ID   uint32 = 0xf05368c0
	apkSigPadID  uint32 = 0x42726577
	apkSigMagic         = "APK Sig Block 42"
	sigAlgRSA256 uint32 = 0x0103

	v2ChunkSize = 1 << 20
	v3MinSDK    = 28 // Android P introduced APK Signature Scheme v3.
	v3MaxSDK    = 0x7fffffff
	// soPageAlign is the 16 KiB page alignment Android 15 requires for
	// uncompressed native libraries. The signing block is padded so its
	// total size is a multiple of this and insertion preserves alignment.
	soPageAlign = 16384
)

// ── ZIP/ EOCD parsing ────────────────────────────────────────────────────────

type zipLayout struct {
	data    []byte
	cdOff   uint32
	cdSize  uint32
	eocdOff uint32
}

func parseAPKLayout(path string) (*zipLayout, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseAPKLayoutBytes(data)
}

func parseAPKLayoutBytes(data []byte) (*zipLayout, error) {
	if len(data) < 22 {
		return nil, fmt.Errorf("apksig: not a zip archive")
	}
	// EOCD: search backwards for PK\x05\x06 within the last 64K+22 bytes.
	start := 0
	if len(data) > 65557+22 {
		start = len(data) - (65557 + 22)
	}
	eocd := -1
	for i := len(data) - 22; i >= start; i-- {
		if data[i] == 0x50 && data[i+1] == 0x4B && data[i+2] == 0x05 && data[i+3] == 0x06 {
			eocd = i
			break
		}
	}
	if eocd < 0 {
		return nil, fmt.Errorf("apksig: end-of-central-directory not found")
	}
	diskEntries := binary.LittleEndian.Uint16(data[eocd+8:])
	totalEntries := binary.LittleEndian.Uint16(data[eocd+10:])
	cdSize := binary.LittleEndian.Uint32(data[eocd+12:])
	cdOff := binary.LittleEndian.Uint32(data[eocd+16:])
	commentLen := binary.LittleEndian.Uint16(data[eocd+20:])
	if diskEntries == 0xFFFF || totalEntries == 0xFFFF || cdSize == 0xFFFFFFFF || cdOff == 0xFFFFFFFF {
		return nil, fmt.Errorf("apksig: zip64 archives need apksigner")
	}
	if eocd+22+int(commentLen) != len(data) {
		return nil, fmt.Errorf("apksig: trailing data after end-of-central-directory")
	}
	if uint64(cdOff)+uint64(cdSize) > uint64(eocd) {
		return nil, fmt.Errorf("apksig: central directory overruns its container")
	}
	return &zipLayout{data: data, cdOff: cdOff, cdSize: cdSize, eocdOff: uint32(eocd)}, nil
}

// signingBlockRange locates an existing APK Signing Block (if any).
// Footer layout immediately before the central directory:
// [u64 block-size-excluding-header][16-byte magic]. Returns blockStart and
// total block length. Both size fields include the 24-byte footer.
func (l *zipLayout) signingBlockRange() (uint32, uint32, bool) {
	if l.cdOff < 32 || uint64(l.cdOff) > uint64(len(l.data)) {
		return 0, 0, false
	}
	if string(l.data[l.cdOff-16:l.cdOff]) != apkSigMagic {
		return 0, 0, false
	}
	size := binary.LittleEndian.Uint64(l.data[l.cdOff-24 : l.cdOff-16])
	if size < 24 || size > uint64(l.cdOff)-8 {
		return 0, 0, false
	}
	blockStart := uint32(uint64(l.cdOff) - 8 - size)
	if binary.LittleEndian.Uint64(l.data[blockStart:blockStart+8]) != size {
		return 0, 0, false
	}
	return blockStart, uint32(8 + size), true
}

// ── Content digests ──────────────────────────────────────────────────────────

// contentDigestV2 computes the top-level SHA-256 over the three protected
// sections. eocdForDigest is the EOCD with the CD-offset field pointing at
// blockStart (pre-insertion CD offset), exactly as the verifier rebuilds it.
func contentDigestV2(beforeCD, centralDir, eocdForDigest []byte) (uint32, [32]byte) {
	chunks := uint32(0)
	for _, s := range [][]byte{beforeCD, centralDir, eocdForDigest} {
		chunks += uint32((len(s) + v2ChunkSize - 1) / v2ChunkSize)
	}
	top := sha256.New()
	top.Write([]byte{0x5A})
	var cnt [4]byte
	binary.LittleEndian.PutUint32(cnt[:], chunks)
	top.Write(cnt[:])
	for _, s := range [][]byte{beforeCD, centralDir, eocdForDigest} {
		for pos := 0; pos < len(s); {
			n := len(s) - pos
			if n > v2ChunkSize {
				n = v2ChunkSize
			}
			part := sha256.New()
			part.Write([]byte{0xA5})
			var lb [4]byte
			binary.LittleEndian.PutUint32(lb[:], uint32(n))
			part.Write(lb[:])
			part.Write(s[pos : pos+n])
			sum := part.Sum(nil)
			top.Write(sum)
			pos += n
		}
	}
	var digest [32]byte
	copy(digest[:], top.Sum(nil))
	return chunks, digest
}

// ── Signer block encoding ────────────────────────────────────────────────────

type signerInput struct {
	schemeID uint32
	digest   [32]byte
	key      *rsa.PrivateKey
	certDER  []byte
	pubDER   []byte
	minSdk   uint32 // v3 only
	isV3     bool
}

// buildSignedData assembles signed-data bytes (the RSA input is its SHA-256).
func buildSignedData(in *signerInput) []byte {
	var digests bytes.Buffer
	putU32le(&digests, 4+4+32) // digest record len
	putU32le(&digests, sigAlgRSA256)
	putU32le(&digests, 32)
	digests.Write(in.digest[:])
	var digestsSeq bytes.Buffer
	putU32le(&digestsSeq, uint32(digests.Len()))
	digestsSeq.Write(digests.Bytes())
	var certs bytes.Buffer
	putU32le(&certs, uint32(len(in.certDER)))
	certs.Write(in.certDER)
	var certsSeq bytes.Buffer
	putU32le(&certsSeq, uint32(certs.Len()))
	certsSeq.Write(certs.Bytes())
	var sd bytes.Buffer
	// digestsSeq/certsSeq already carry their own length prefixes.
	sd.Write(digestsSeq.Bytes())
	sd.Write(certsSeq.Bytes())
	if in.isV3 {
		putU32le(&sd, in.minSdk)
		putU32le(&sd, v3MaxSDK)
	}
	putU32le(&sd, 0) // additional attributes: none
	return sd.Bytes()
}

func putU32le(b *bytes.Buffer, v uint32) {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	b.Write(tmp[:])
}

// buildSignerPair builds one (id, value) pair plus its 8-byte size prefix
// content (caller adds pair framing): returns the full pair bytes
// (u64 size, u32 id, value) for the signing block body.
func buildSignerPair(in *signerInput) ([]byte, error) {
	sd := buildSignedData(in)
	sum := sha256.Sum256(sd)
	sig, err := rsa.SignPKCS1v15(rand.Reader, in.key, crypto.SHA256, sum[:])
	if err != nil {
		return nil, fmt.Errorf("apksig: RSA sign: %w", err)
	}
	var sigs bytes.Buffer
	putU32le(&sigs, 4+4+uint32(len(sig)))
	putU32le(&sigs, sigAlgRSA256)
	putU32le(&sigs, uint32(len(sig)))
	sigs.Write(sig)
	var signer bytes.Buffer
	putU32le(&signer, uint32(len(sd)))
	signer.Write(sd)
	if in.isV3 {
		putU32le(&signer, in.minSdk)
		putU32le(&signer, v3MaxSDK)
	}
	putU32le(&signer, uint32(sigs.Len()))
	signer.Write(sigs.Bytes())
	putU32le(&signer, uint32(len(in.pubDER)))
	signer.Write(in.pubDER)
	var value bytes.Buffer
	putU32le(&value, uint32(4+signer.Len()))
	putU32le(&value, uint32(signer.Len()))
	value.Write(signer.Bytes())
	var pair bytes.Buffer
	putU64le(&pair, uint64(4+value.Len()))
	putU32le(&pair, in.schemeID)
	pair.Write(value.Bytes())
	return pair.Bytes(), nil
}

func putU64le(b *bytes.Buffer, v uint64) {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], v)
	b.Write(tmp[:])
}

// ── Sign ─────────────────────────────────────────────────────────────────────

// SignV2V3 inserts v2 (+v3) APK Signing Blocks with the debug key material.
// The file must already be aligned and v1-signed; v1 covers entry data only
// and survives block insertion, matching apksigner ordering.
func SignV2V3(apkPath string, key *rsa.PrivateKey, cert *x509.Certificate, minSdk uint32) error {
	if minSdk < v3MinSDK {
		minSdk = v3MinSDK
	}
	if minSdk > v3MaxSDK {
		return fmt.Errorf("apksig: v3 minimum SDK exceeds Android's maximum SDK value")
	}
	l, err := parseAPKLayout(apkPath)
	if err != nil {
		return err
	}
	// Strip a previous signing block so re-signing is idempotent.
	head := l.data[:l.cdOff]
	if bs, _, ok := l.signingBlockRange(); ok {
		head = l.data[:bs]
	}
	// Re-derive section bounds on the stripped image.
	cd := l.data[l.cdOff : l.cdOff+l.cdSize]
	eocd := l.data[l.eocdOff:]
	blockStart := uint32(len(head)) // == pre-insertion CD offset
	// EOCD-for-digest: CD offset field points at the block start.
	eocdDigest := append([]byte(nil), eocd...)
	binary.LittleEndian.PutUint32(eocdDigest[16:], blockStart)
	_, digest := contentDigestV2(head, cd, eocdDigest)
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("apksig: marshal public key: %w", err)
	}
	v2pair, err := buildSignerPair(&signerInput{schemeID: apkSigV2ID, digest: digest, key: key, certDER: cert.Raw, pubDER: pubDER})
	if err != nil {
		return err
	}
	v3pair, err := buildSignerPair(&signerInput{schemeID: apkSigV3ID, digest: digest, key: key, certDER: cert.Raw, pubDER: pubDER, minSdk: minSdk, isV3: true})
	if err != nil {
		return err
	}
	// Pad so the whole block is a multiple of the page alignment: insertion
	// then preserves 16 KiB alignment of everything after it.
	units := uint32(32 + len(v2pair) + len(v3pair) + 12)
	pad := (soPageAlign - units%soPageAlign) % soPageAlign
	var pairs bytes.Buffer
	pairs.Write(v2pair)
	pairs.Write(v3pair)
	putU64le(&pairs, uint64(4+pad))
	putU32le(&pairs, apkSigPadID)
	if pad > 0 {
		pairs.Write(make([]byte, pad))
	}
	blockLen := 8 + pairs.Len() + 24
	var block bytes.Buffer
	putU64le(&block, uint64(blockLen-8))
	block.Write(pairs.Bytes())
	putU64le(&block, uint64(blockLen-8))
	block.WriteString(apkSigMagic)
	if block.Len() != blockLen {
		return fmt.Errorf("apksig: internal block size mismatch")
	}
	// Rewrite: head + block + cd + eocd(with updated CD offset).
	out := make([]byte, 0, len(head)+block.Len()+len(cd)+len(eocd))
	out = append(out, head...)
	out = append(out, block.Bytes()...)
	newCDOff := uint32(len(out))
	out = append(out, cd...)
	eocdNew := append([]byte(nil), eocd...)
	binary.LittleEndian.PutUint32(eocdNew[16:], newCDOff)
	out = append(out, eocdNew...)
	tmp := apkPath + ".v2signed"
	if err := os.WriteFile(tmp, out, 0644); err != nil {
		return err
	}
	if err := os.Remove(apkPath); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, apkPath)
}
