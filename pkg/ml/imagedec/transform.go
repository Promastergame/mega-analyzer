package imagedec

import (
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// REVERSIBLE BYTE TRANSFORMS
//
// A Transform is always the RECOVERY direction: applying it to the bytes on
// disk is meant to produce the plaintext. That convention removes the constant
// sign confusion of "was it +7 or -7" - the solver derives whatever value makes
// the known plaintext come out right, and the caller just applies it.
//
// The set here is not arbitrary. It is what asset obfuscation in shipped mobile
// games actually uses: a fixed XOR key, a rolling XOR key, a byte-wise add, a
// bit rotate, a complement, and endian or nibble shuffles. All are involutive
// or trivially invertible, all are O(n), and none need a key schedule - which
// is precisely why they get chosen, and precisely why they fall to a
// known-plaintext attack on a file header.
// ═══════════════════════════════════════════════════════════════════════════════

// Kind enumerates the transform families.
type Kind uint8

const (
	// KindIdentity means the bytes on disk are already the plaintext.
	KindIdentity Kind = iota
	// KindXOR is a repeating-key XOR. A key of length 1 is the classic
	// single-byte case.
	KindXOR
	// KindAdd adds N to every byte, modulo 256.
	KindAdd
	// KindRotate rotates every byte left by N bits.
	KindRotate
	// KindNot complements every byte.
	KindNot
	// KindReverse reverses the whole buffer, so the header lives at the tail.
	KindReverse
	// KindNibble swaps the high and low nibble of every byte.
	KindNibble
	// KindSwap16 swaps adjacent byte pairs: an endian flip on 16-bit words.
	KindSwap16
	// KindSwap32 reverses each aligned 4-byte group.
	KindSwap32
)

// Transform is a concrete recovery operation.
type Transform struct {
	Kind Kind
	// Key is the repeating XOR key. Only meaningful for KindXOR.
	Key []byte
	// N is the addend for KindAdd or the bit count for KindRotate.
	N uint8
}

// Identity is the no-op transform.
func Identity() Transform { return Transform{Kind: KindIdentity} }

// IsIdentity reports whether the transform changes nothing. A recovered XOR
// key of all zeroes is identity in disguise and must not be reported as a
// discovery.
func (t Transform) IsIdentity() bool {
	switch t.Kind {
	case KindIdentity:
		return true
	case KindXOR:
		for _, b := range t.Key {
			if b != 0 {
				return false
			}
		}
		return true
	case KindAdd:
		return t.N == 0
	case KindRotate:
		return t.N%8 == 0
	default:
		return false
	}
}

// Canonical collapses transforms that are literally the same operation under
// two different names, so the solver reports one answer per distinct behaviour
// instead of several spellings of it.
//
// Two exact equivalences exist in this set, and without this both would be
// found, both would score identically, and which one surfaced would depend on
// the order the solver happened to try them in:
//
//	rotl4         is nibble swap
//	xor with 0xFF is complement
//
// The more descriptive name wins in each pair.
func (t Transform) Canonical() Transform {
	switch t.Kind {
	case KindRotate:
		if t.N%8 == 4 {
			return Transform{Kind: KindNibble}
		}
	case KindXOR:
		if len(t.Key) == 1 && t.Key[0] == 0xFF {
			return Transform{Kind: KindNot}
		}
	}
	return t
}

func rotl8(b byte, n uint8) byte {
	n &= 7
	if n == 0 {
		return b
	}
	return b<<n | b>>(8-n)
}

// ByteAt returns the recovered plaintext byte for position i of a buffer of
// length total, given the ciphertext byte src.
//
// Position matters for KindXOR (key phase) and is why the solver can work on a
// window without materialising the whole file.
func (t Transform) ByteAt(src byte, i, total int) byte {
	switch t.Kind {
	case KindXOR:
		if len(t.Key) == 0 {
			return src
		}
		return src ^ t.Key[i%len(t.Key)]
	case KindAdd:
		return src + t.N
	case KindRotate:
		return rotl8(src, t.N)
	case KindNot:
		return ^src
	case KindNibble:
		return src<<4 | src>>4
	default:
		_ = total
		return src
	}
}

// positional reports whether the transform moves bytes rather than only
// rewriting them in place. Positional transforms cannot be evaluated one byte
// at a time and are handled by Apply on a whole window.
func (t Transform) positional() bool {
	switch t.Kind {
	case KindReverse, KindSwap16, KindSwap32:
		return true
	default:
		return false
	}
}

// Apply returns the recovered plaintext for src. The input is never modified.
func (t Transform) Apply(src []byte) []byte {
	out := make([]byte, len(src))

	switch t.Kind {
	case KindReverse:
		for i := range src {
			out[i] = src[len(src)-1-i]
		}
	case KindSwap16:
		copy(out, src)
		for i := 0; i+1 < len(out); i += 2 {
			out[i], out[i+1] = out[i+1], out[i]
		}
	case KindSwap32:
		copy(out, src)
		for i := 0; i+3 < len(out); i += 4 {
			out[i], out[i+3] = out[i+3], out[i]
			out[i+1], out[i+2] = out[i+2], out[i+1]
		}
	default:
		for i := range src {
			out[i] = t.ByteAt(src[i], i, len(src))
		}
	}
	return out
}

// String renders the transform for a report line.
func (t Transform) String() string {
	switch t.Kind {
	case KindIdentity:
		return "identity"
	case KindXOR:
		var sb strings.Builder
		fmt.Fprintf(&sb, "xor[%d]=", len(t.Key))
		for i, b := range t.Key {
			if i > 0 {
				sb.WriteByte(' ')
			}
			fmt.Fprintf(&sb, "%02x", b)
		}
		return sb.String()
	case KindAdd:
		return fmt.Sprintf("add+%d", t.N)
	case KindRotate:
		return fmt.Sprintf("rotl%d", t.N%8)
	case KindNot:
		return "not"
	case KindReverse:
		return "reverse"
	case KindNibble:
		return "nibble-swap"
	case KindSwap16:
		return "swap16"
	case KindSwap32:
		return "swap32"
	default:
		return "?"
	}
}
