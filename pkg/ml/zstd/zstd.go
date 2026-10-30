// Package zstd decompresses Zstandard streams.
//
// ═══════════════════════════════════════════════════════════════════════════
//
// Why this exists: the Go standard library ships gzip, zlib, flate, bzip2 and
// lzw, but not zstd. Modern game assets use zstd constantly. A .sctx texture is
// a small FlatBuffers head followed by one zstd frame; KTX2 supercompression is
// zstd; plenty of shipped bundles are just zstd around a PNG. Until now this
// project could recognise those files and print their headers, and nothing
// more, which is a fairly useless place to stop.
//
// Scope: decompression only. Nothing here compresses, and dictionaries are
// rejected rather than half-supported. That is the whole surface an asset
// inspector needs, and it keeps the package small enough to audit.
//
// Portability: pure Go, no cgo, no build tags, no assembly, no dependency, and
// no arithmetic that assumes a 64-bit int. Every size and offset that the
// format allows to exceed 2^31 is carried in uint64, so an Android or Raspberry
// Pi build behaves exactly like a Windows or Linux amd64 one. Correctness was
// checked against real output from the reference zstd tool; see
// fixtures_test.go.
//
// Safety: a frame header is a few bytes and can claim a sixteen exabyte
// content size. Every entry point therefore works against an output limit and
// treats the header's numbers as hints. Use DecompressLimit, or a Decoder with
// MaxOutput set, whenever the input is untrusted, which for this project it
// always is.
//
// The implementation follows RFC 8878 and was written against zstd 1.5.7.
package zstd

import (
	"errors"
	"fmt"
)

// DefaultMaxOutput caps Decompress at one gibibyte. It is a guard against a
// forged header, not a statement about real assets, which are far smaller.
const DefaultMaxOutput = 1 << 30

// Errors returned by this package. Every failure wraps exactly one of these,
// so callers can branch with errors.Is without matching on message text.
var (
	// ErrMagic means the bytes are not a zstd stream at all.
	ErrMagic = errors.New("zstd: not a zstd stream")
	// ErrCorrupt means the stream is malformed: a field is impossible, a
	// table does not add up, or a match points outside the window.
	ErrCorrupt = errors.New("zstd: corrupt stream")
	// ErrTruncated means the stream is well formed as far as it goes but ends
	// early. Worth distinguishing, because a truncated asset is usually a
	// packing bug rather than tampering.
	ErrTruncated = errors.New("zstd: truncated stream")
	// ErrDictionary means the frame was compressed against a dictionary this
	// decoder cannot supply.
	ErrDictionary = errors.New("zstd: frame needs a dictionary")
	// ErrChecksum means the content decoded but does not match the checksum
	// the frame carries. The bytes have changed since they were compressed.
	ErrChecksum = errors.New("zstd: content checksum mismatch")
	// ErrTooLarge means decoding stopped because the output limit was reached.
	ErrTooLarge = errors.New("zstd: output limit exceeded")
)

func errf(format string, args ...any) error {
	return fmt.Errorf("zstd: %s: %w", fmt.Sprintf(format, args...), ErrCorrupt)
}

func trunc(format string, args ...any) error {
	return fmt.Errorf("zstd: %s: %w", fmt.Sprintf(format, args...), ErrTruncated)
}

func tooLarge(format string, args ...any) error {
	return fmt.Errorf("zstd: %s: %w", fmt.Sprintf(format, args...), ErrTooLarge)
}

func dictErr(id uint32) error {
	return fmt.Errorf("zstd: frame was compressed with dictionary %d, which this decoder cannot load: %w", id, ErrDictionary)
}

func checksumErr(got, want uint32) error {
	return fmt.Errorf("zstd: content checksum is %08x but the frame trailer says %08x: %w", got, want, ErrChecksum)
}

// IsFrame reports whether src begins with a zstd frame whose header parses.
// It is stricter than a magic-number test, so it can be used to tell a real
// frame from four coincidental bytes inside an image.
func IsFrame(src []byte) bool {
	h, err := readHeaderAt(src, 0)
	return err == nil && !h.Skippable
}

// HasMagic reports only whether the first four bytes are the frame magic.
func HasMagic(src []byte) bool {
	if len(src) < 4 {
		return false
	}
	magic := uint32(src[0]) | uint32(src[1])<<8 | uint32(src[2])<<16 | uint32(src[3])<<24
	return magic == FrameMagic
}

// FindFrame returns the offset of the first byte sequence that both matches the
// frame magic and parses as a frame header, or -1. This is how an embedded
// frame is located inside a wrapper format such as .sctx, where the frame does
// not start at byte zero and the offset is not recorded anywhere useful.
func FindFrame(src []byte) int {
	for i := 0; i+4 <= len(src); i++ {
		if src[i] != 0x28 || src[i+1] != 0xB5 || src[i+2] != 0x2F || src[i+3] != 0xFD {
			continue
		}
		if h, err := readHeaderAt(src, i); err == nil && !h.Skippable {
			return i
		}
	}
	return -1
}

// ReadHeader parses the frame header at the start of src without decoding
// anything.
func ReadHeader(src []byte) (Header, error) {
	return readHeaderAt(src, 0)
}

// DecodedSize reports the content size declared by the first real frame in
// src, skipping any leading skippable frames. ok is false when the frame omits
// it, which is normal for anything a streaming compressor produced.
//
// This is a sizing hint only. It is never trusted as a promise; Decompress
// checks the frame against what it actually produced.
func DecodedSize(src []byte) (size uint64, ok bool) {
	p := 0
	for p+4 <= len(src) {
		h, err := readHeaderAt(src, p)
		if err != nil {
			return 0, false
		}
		if h.Skippable {
			next := uint64(p) + h.TotalSize()
			if next > uint64(len(src)) {
				return 0, false
			}
			p = int(next)
			continue
		}
		if !h.ContentSizeKnown {
			return 0, false
		}
		return h.ContentSize, true
	}
	return 0, false
}

// Decompress decodes every frame in src and returns the concatenated content,
// capped at DefaultMaxOutput.
func Decompress(src []byte) ([]byte, error) {
	return DecompressLimit(src, DefaultMaxOutput)
}

// DecompressLimit decodes src, refusing to produce more than maxOut bytes. A
// maxOut of zero or less means DefaultMaxOutput. Use this for untrusted input.
func DecompressLimit(src []byte, maxOut int) ([]byte, error) {
	dec := Decoder{MaxOutput: maxOut}
	return dec.Decompress(src)
}

// Decoder decodes zstd streams, keeping its scratch buffers between calls.
// Reuse one per goroutine when walking many files: an asset scan can hit
// thousands of textures, and this avoids re-allocating the literals buffer for
// every one. A Decoder must not be shared across goroutines; the zero value is
// ready to use.
type Decoder struct {
	// MaxOutput caps the total decoded size. Zero means DefaultMaxOutput.
	MaxOutput int

	fd frameDecoder
}

// NewDecoder returns a Decoder with the default output limit.
func NewDecoder() *Decoder {
	return &Decoder{}
}

// Decompress decodes every frame in src and returns the concatenated content.
//
// Trailing bytes after the last complete frame are ignored, because embedded
// frames are routinely followed by padding or an unrelated tail. Bytes before
// the first frame are not: use FindFrame if the frame does not start at zero.
func (dec *Decoder) Decompress(src []byte) ([]byte, error) {
	limit := dec.MaxOutput
	if limit <= 0 {
		limit = DefaultMaxOutput
	}

	d := &dec.fd
	d.maxOut = limit
	d.out = nil
	d.frameStart = 0

	// Size the buffer from the declared content size when it is both known and
	// sane. Capping the hint at 64 MiB means a forged header costs one wasted
	// allocation at worst, never an out-of-memory kill.
	if n, ok := DecodedSize(src); ok && n > 0 && n <= uint64(limit) && n <= 64<<20 {
		d.out = make([]byte, 0, int(n))
	}

	p := 0
	real := 0
	for p+4 <= len(src) {
		magic := uint32(src[p]) | uint32(src[p+1])<<8 | uint32(src[p+2])<<16 | uint32(src[p+3])<<24
		if magic != FrameMagic && magic&skippableMask != skippableLow {
			if real == 0 {
				return nil, ErrMagic
			}
			break
		}
		next, err := d.decodeFrame(src, p)
		if err != nil {
			return d.out, err
		}
		if next <= p {
			// Cannot happen with the parser above, but a zero-length step would
			// spin forever, so it is checked rather than assumed.
			return d.out, errf("frame at offset %d made no progress", p)
		}
		if magic == FrameMagic {
			real++
		}
		p = next
	}
	if real == 0 {
		return nil, ErrMagic
	}
	out := d.out
	d.out = nil // do not hand the caller a buffer the next call would reuse
	return out, nil
}

// DecompressAt decodes the single frame starting at off and returns the content
// along with the offset just past the frame. Useful when a container records
// where its frame begins and what follows it.
func (dec *Decoder) DecompressAt(src []byte, off int) ([]byte, int, error) {
	limit := dec.MaxOutput
	if limit <= 0 {
		limit = DefaultMaxOutput
	}
	d := &dec.fd
	d.maxOut = limit
	d.out = nil
	d.frameStart = 0
	next, err := d.decodeFrame(src, off)
	out := d.out
	d.out = nil
	if err != nil {
		return out, next, err
	}
	return out, next, nil
}
