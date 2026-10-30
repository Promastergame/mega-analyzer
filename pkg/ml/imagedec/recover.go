package imagedec

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// ═══════════════════════════════════════════════════════════════════════════════
// RECOVERY
//
// Given an arbitrary blob, decide what it really is. Three passes, cheapest
// first:
//
//	1. Direct  - does a known magic sit at offset 0.
//	2. Solve   - assume the payload IS one of the known formats and solve for
//	             the byte transform that would turn these bytes into that
//	             header. This is a known-plaintext attack, and file formats
//	             hand us the plaintext for free.
//	3. Scan    - look for a known magic at any offset, which catches the
//	             wrapper shape: small proprietary head, real payload behind it.
//
// A solved transform is never trusted on the magic alone. The magic proves the
// key is consistent; the structural checks below prove the result is a real
// file. Recovering a 1-byte XOR key from a 2-byte BMP magic is not a finding,
// it is arithmetic - so a signature must leave verification bytes over, and the
// decoded header must survive a size and field sanity pass.
// ═══════════════════════════════════════════════════════════════════════════════

// Options tunes the search. The zero value is usable; Normalize fills defaults.
type Options struct {
	// MaxKeyLen bounds the repeating-XOR key length that will be attempted.
	MaxKeyLen int
	// MaxCandidates bounds the returned list.
	MaxCandidates int
	// ScanWindow is how far into the buffer the embedded-magic scan looks.
	ScanWindow int
	// SkipScan disables pass 3.
	SkipScan bool
	// SkipSolve disables pass 2.
	SkipSolve bool
}

// Normalize returns o with zero fields replaced by defaults.
func (o Options) Normalize() Options {
	if o.MaxKeyLen <= 0 {
		o.MaxKeyLen = 16
	}
	if o.MaxCandidates <= 0 {
		o.MaxCandidates = 8
	}
	if o.ScanWindow <= 0 {
		o.ScanWindow = 4096
	}
	return o
}

// Candidate is one hypothesis about what the blob is.
type Candidate struct {
	Signature string
	Ext       string
	Family    Family
	Transform Transform
	// Base is where the payload starts in the original buffer.
	Base int
	// Score is a 0..100 confidence. Anything below 50 is a lead, not a result.
	Score    int
	Evidence []string
}

// Result is the full picture.
type Result struct {
	// Direct is true when the blob is simply a known format, unobfuscated.
	Direct bool
	// Candidates are ranked best first.
	Candidates []Candidate
	// Frames are compression streams found anywhere in the scan window.
	Frames []Frame
	Notes  []string
}

// Best returns the highest-scoring candidate.
func (r Result) Best() (Candidate, bool) {
	if len(r.Candidates) == 0 {
		return Candidate{}, false
	}
	return r.Candidates[0], true
}

// probeLen is how many bytes the solver decodes to run structural checks. It
// must comfortably exceed the longest header any check reads (KTX2 reaches
// offset 24) while staying small enough that the work is free.
const probeLen = 64

// Analyze runs the three passes and returns ranked hypotheses.
func Analyze(data []byte, opts Options) Result {
	opts = opts.Normalize()
	var res Result

	if len(data) < 4 {
		res.Notes = append(res.Notes, "buffer too short to carry any known signature")
		return res
	}

	// ── pass 1: direct ─────────────────────────────────────────────────
	if sig, ok := Identify(data, 0); ok {
		res.Direct = true
		score, ev := structuralScore(sig, data)
		res.Candidates = append(res.Candidates, Candidate{
			Signature: sig.Name,
			Ext:       sig.Ext,
			Family:    sig.Family,
			Transform: Identity(),
			Base:      0,
			Score:     clampScore(60 + 4*len(sig.Magic) + score),
			Evidence:  append([]string{"magic matches at offset 0 with no transform"}, ev...),
		})
	}

	// ── pass 2: solve for a transform ───────────────────────────────────
	if !opts.SkipSolve && !res.Direct {
		res.Candidates = append(res.Candidates, solve(data, opts)...)
	}

	// ── pass 3: scan for embedded magics ───────────────────────────────
	if !opts.SkipScan {
		embedded, frames := scanEmbedded(data, opts)
		res.Candidates = append(res.Candidates, embedded...)
		res.Frames = frames
	}

	sort.SliceStable(res.Candidates, func(i, j int) bool {
		if res.Candidates[i].Score != res.Candidates[j].Score {
			return res.Candidates[i].Score > res.Candidates[j].Score
		}
		return res.Candidates[i].Base < res.Candidates[j].Base
	})
	if len(res.Candidates) > opts.MaxCandidates {
		res.Candidates = res.Candidates[:opts.MaxCandidates]
	}

	if len(res.Candidates) == 0 {
		res.Notes = append(res.Notes,
			"no known signature, no solvable byte transform and no embedded stream")
	}
	return res
}

func clampScore(n int) int {
	if n < 0 {
		return 0
	}
	if n > 100 {
		return 100
	}
	return n
}

// window materialises up to probeLen recovered bytes starting at the payload
// base, so structural checks can read a decoded header cheaply.
func window(data []byte, base int, t Transform) []byte {
	if t.positional() {
		// A positional transform rearranges the whole buffer, so the plaintext
		// head is not a function of the ciphertext head alone. Reverse is the
		// only one where a bounded slice suffices, and it comes from the tail.
		if t.Kind == KindReverse {
			n := probeLen
			if n > len(data) {
				n = len(data)
			}
			return t.Apply(data[len(data)-n:])
		}
		n := probeLen
		if n > len(data)-base {
			n = len(data) - base
		}
		return t.Apply(data[base : base+n])
	}

	n := probeLen
	if n > len(data)-base {
		n = len(data) - base
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = t.ByteAt(data[base+i], base+i, len(data))
	}
	return out
}

// solve attempts every transform family against every signature.
func solve(data []byte, opts Options) []Candidate {
	var out []Candidate

	for _, sig := range signatures {
		anchors := sig.Anchors()
		if len(anchors) < 3 {
			// Two fixed bytes cannot both derive and verify a key. Skipping
			// these is what keeps BMP and the zlib variants from producing a
			// "recovered" key for literally any input.
			continue
		}
		if sig.Span() > len(data) {
			continue
		}

		for _, t := range candidateTransforms(data, sig, anchors, opts) {
			if t.IsIdentity() {
				continue
			}
			plain := window(data, 0, t)
			if !sig.MatchesAt(plain, 0) {
				continue
			}
			score, ev := structuralScore(sig, plain)
			// The base score rewards how much plaintext the match had to
			// explain, and penalises long keys, which explain more by fitting
			// more rather than by being right.
			base := 20 + 4*len(anchors)
			if t.Kind == KindXOR {
				base -= 2 * (len(t.Key) - 1)
			}
			out = append(out, Candidate{
				Signature: sig.Name,
				Ext:       sig.Ext,
				Family:    sig.Family,
				Transform: t,
				Base:      0,
				Score:     clampScore(base + score),
				Evidence: append([]string{
					fmt.Sprintf("%s recovers the %d-byte %s signature", t, len(anchors), sig.Name),
				}, ev...),
			})
		}
	}
	return out
}

// candidateTransforms derives, per family, the transform that WOULD map the
// bytes on disk onto this signature. Derivation is exact, not searched: for
// every family except rotate there is at most one answer, and rotate has seven.
func candidateTransforms(data []byte, sig Signature, anchors []Anchor, opts Options) []Transform {
	var out []Transform

	// Repeating XOR. Key length L is derived from the first L anchors and then
	// verified against the rest, so L must leave at least one anchor over.
	contiguous := contiguousAnchors(anchors)
	for L := 1; L <= opts.MaxKeyLen && 2*L <= len(contiguous); L++ {
		key := make([]byte, L)
		for i := 0; i < L; i++ {
			key[i] = data[contiguous[i].Offset] ^ contiguous[i].Want
		}
		ok := true
		for j := L; j < len(contiguous); j++ {
			a := contiguous[j]
			if data[a.Offset]^key[a.Offset%L] != a.Want {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, Transform{Kind: KindXOR, Key: key})
		}
	}

	// Byte-wise add: one unknown, derived from the first anchor.
	delta := anchors[0].Want - data[anchors[0].Offset]
	addOK := true
	for _, a := range anchors {
		if data[a.Offset]+delta != a.Want {
			addOK = false
			break
		}
	}
	if addOK {
		out = append(out, Transform{Kind: KindAdd, N: delta})
	}

	// Bit rotate: seven possibilities, all cheap to test outright.
	for n := uint8(1); n < 8; n++ {
		ok := true
		for _, a := range anchors {
			if rotl8(data[a.Offset], n) != a.Want {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, Transform{Kind: KindRotate, N: n})
		}
	}

	// Fixed-shape families: no unknown to derive, just test.
	for _, t := range []Transform{
		{Kind: KindNot},
		{Kind: KindNibble},
		{Kind: KindSwap16},
		{Kind: KindSwap32},
		{Kind: KindReverse},
	} {
		plain := window(data, 0, t)
		if sig.MatchesAt(plain, 0) {
			out = append(out, t)
		}
	}

	// Collapse equivalent spellings and drop the duplicates they create, so a
	// nibble swap is reported once rather than as both rotl4 and nibble-swap
	// with identical scores and an arbitrary winner.
	seen := make(map[string]bool, len(out))
	uniq := out[:0]
	for _, t := range out {
		c := t.Canonical()
		key := c.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		uniq = append(uniq, c)
	}
	return uniq
}

// contiguousAnchors keeps the run starting at offset 0, because a repeating key
// can only be phase-solved across a gap if the gap length is known. Signatures
// with a split magic (RIFF/WEBP) contribute their first run here and their
// second run to verification via MatchesAt.
func contiguousAnchors(anchors []Anchor) []Anchor {
	out := make([]Anchor, 0, len(anchors))
	next := 0
	for _, a := range anchors {
		if a.Offset != next {
			break
		}
		out = append(out, a)
		next++
	}
	return out
}

// scanEmbedded looks for known magics at every offset in the scan window. This
// is the generic form of "find the compressed body inside a proprietary
// wrapper", and it needs no knowledge of the wrapper at all.
func scanEmbedded(data []byte, opts Options) ([]Candidate, []Frame) {
	var cands []Candidate
	var frames []Frame

	limit := opts.ScanWindow
	if limit > len(data) {
		limit = len(data)
	}

	seen := make(map[string]bool)
	for off := 1; off < limit; off++ {
		sig, ok := Identify(data, off)
		if !ok {
			continue
		}
		if f, ok := parseFrameAt(sig.Name, data, off); ok {
			frames = append(frames, f)
		}

		// One candidate per format, at its first occurrence.
		if seen[sig.Name] {
			continue
		}
		seen[sig.Name] = true

		score, ev := structuralScore(sig, data[off:])
		// An embedded find is weaker than a header find: a 4-byte magic will
		// appear by chance roughly once per 4 GB, but proprietary heads are
		// short, so a hit deep into the file deserves less weight.
		penalty := off / 256
		cands = append(cands, Candidate{
			Signature: sig.Name,
			Ext:       sig.Ext,
			Family:    sig.Family,
			Transform: Identity(),
			Base:      off,
			Score:     clampScore(30 + 3*len(sig.Magic) + score - penalty),
			Evidence: append([]string{
				fmt.Sprintf("%s magic found at offset %d, behind a %d-byte head", sig.Name, off, off),
			}, ev...),
		})
	}
	return cands, frames
}

// structuralScore validates fields past the magic. This is what separates a
// real recovery from an arithmetic coincidence.
func structuralScore(sig Signature, plain []byte) (int, []string) {
	var ev []string
	score := 0

	add := func(points int, format string, args ...any) {
		score += points
		ev = append(ev, fmt.Sprintf(format, args...))
	}

	switch sig.Name {
	case "png":
		if len(plain) >= 24 {
			if binary.BigEndian.Uint32(plain[8:12]) == 13 && string(plain[12:16]) == "IHDR" {
				w := binary.BigEndian.Uint32(plain[16:20])
				h := binary.BigEndian.Uint32(plain[20:24])
				if w > 0 && h > 0 && w <= 1<<16 && h <= 1<<16 {
					add(25, "IHDR is well formed and the image is %dx%d", w, h)
				} else {
					add(-15, "IHDR present but the dimensions %dx%d are implausible", w, h)
				}
			} else {
				add(-25, "the chunk after the signature is not a 13-byte IHDR")
			}
		}
	case "ktx2":
		if len(plain) >= 24 {
			w := binary.LittleEndian.Uint32(plain[20:24])
			if w > 0 && w <= 1<<16 {
				add(20, "pixelWidth is %d", w)
			} else {
				add(-15, "pixelWidth %d is implausible", w)
			}
		}
	case "ktx1":
		if len(plain) >= 16 {
			if binary.LittleEndian.Uint32(plain[12:16]) == 0x04030201 {
				add(20, "the endianness field reads 0x04030201 as written")
			} else {
				add(-15, "the endianness field is neither byte order")
			}
		}
	case "dds":
		if len(plain) >= 8 {
			if sz := binary.LittleEndian.Uint32(plain[4:8]); sz == 124 {
				add(20, "dwSize is 124, as the header requires")
			} else {
				add(-20, "dwSize is %d, not 124", sz)
			}
		}
	case "astc":
		if len(plain) >= 7 {
			x, y, z := plain[4], plain[5], plain[6]
			if validASTCDim(x) && validASTCDim(y) && z >= 1 && z <= 6 {
				add(20, "block footprint %dx%dx%d is a legal ASTC size", x, y, z)
			} else {
				add(-20, "block footprint %dx%dx%d is not a legal ASTC size", x, y, z)
			}
		}
	case "jpeg":
		if len(plain) >= 4 {
			if plain[3] >= 0xC0 {
				add(12, "the byte after SOI is marker FF%02X", plain[3])
			} else {
				add(-15, "FF%02X is not a valid JPEG marker", plain[3])
			}
		}
	case "gif87a", "gif89a":
		if len(plain) >= 10 {
			w := binary.LittleEndian.Uint16(plain[6:8])
			h := binary.LittleEndian.Uint16(plain[8:10])
			if w > 0 && h > 0 {
				add(15, "logical screen is %dx%d", w, h)
			} else {
				add(-15, "logical screen is %dx%d", w, h)
			}
		}
	case "qoi":
		if len(plain) >= 14 {
			w := binary.BigEndian.Uint32(plain[4:8])
			h := binary.BigEndian.Uint32(plain[8:12])
			ch := plain[12]
			if w > 0 && h > 0 && (ch == 3 || ch == 4) {
				add(20, "%dx%d with %d channels", w, h, ch)
			} else {
				add(-15, "header fields are out of range")
			}
		}
	case "webp":
		if len(plain) >= 12 {
			add(10, "RIFF and WEBP tags both present")
		}
	case "zstd":
		if f, ok := parseZstdFrame(plain, 0); ok {
			if f.DeclaredSize >= 0 {
				add(18, "frame header is coherent and declares %d bytes decompressed", f.DeclaredSize)
			} else {
				add(12, "frame header is coherent; it carries no content size")
			}
		} else {
			add(-20, "the bytes after the magic are not a valid zstd frame header")
		}
	case "gzip":
		if len(plain) >= 3 && plain[2] == 8 {
			add(12, "compression method is deflate")
		} else {
			add(-20, "compression method is not deflate")
		}
	case "zlib-default", "zlib-best", "zlib-none":
		if _, ok := parseZlibFrame(plain, 0); ok {
			add(10, "the CMF/FLG pair is a multiple of 31")
		} else {
			add(-20, "the CMF/FLG pair fails its check value")
		}
	case "glb":
		if len(plain) >= 12 {
			if v := binary.LittleEndian.Uint32(plain[4:8]); v == 1 || v == 2 {
				add(18, "GLB container version %d", v)
			} else {
				add(-15, "GLB container version %d is undefined", v)
			}
		}
	}
	return score, ev
}

// validASTCDim reports whether n is a footprint dimension ASTC actually defines.
func validASTCDim(n byte) bool {
	switch n {
	case 3, 4, 5, 6, 8, 10, 12:
		return true
	default:
		return false
	}
}
