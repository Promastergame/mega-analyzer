package zstd

// ═══════════════════════════════════════════════════════════════════════════
// Format constants and the static tables
// ═══════════════════════════════════════════════════════════════════════════
//
// Transcribed from zstd 1.5.7 (lib/common/zstd_internal.h and
// lib/decompress/zstd_decompress_internal.h) and cross-checked line by line
// against the baseline tables in doc/zstd_compression_format.md, the normative
// text behind RFC 8878. Both sources agree.
//
// Everything here is a package-level literal rather than something computed in
// init(), so there is no dependency on the order Go runs init functions in.

const (
	// FrameMagic is the value of the first four bytes of a zstd frame, read
	// little-endian.
	FrameMagic uint32 = 0xFD2FB528

	skippableLow  uint32 = 0x184D2A50
	skippableMask uint32 = 0xFFFFFFF0

	// BlockSizeMax is the most content a single block may expand to.
	BlockSizeMax = 128 * 1024

	// MaxWindowLog is the largest window exponent the format allows. A frame
	// header can claim a 2 GiB window in a handful of bytes, which is why the
	// public API always works against an output limit rather than trusting it.
	MaxWindowLog = 31

	maxLL    = 35
	maxML    = 52
	maxOff   = 31
	llFSELog = 9
	mlFSELog = 9
	ofFSELog = 8

	fseMinTableLog  = 5
	hufTableLogMax  = 12
	longNbSeq       = 0x7F00
	blockHeaderSize = 3
	frameHeaderMin  = 5
)

// Literal length codes. Codes 0..15 are the length itself; above that a
// baseline plus extra bits taken from the sequence bitstream.
var llBits = [maxLL + 1]uint8{
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 2, 2, 3, 3,
	4, 6, 7, 8, 9, 10, 11, 12,
	13, 14, 15, 16,
}

var llBase = [maxLL + 1]uint32{
	0, 1, 2, 3, 4, 5, 6, 7,
	8, 9, 10, 11, 12, 13, 14, 15,
	16, 18, 20, 22, 24, 28, 32, 40,
	48, 64, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000,
	0x2000, 0x4000, 0x8000, 0x10000,
}

var llDefaultNorm = [maxLL + 1]int16{
	4, 3, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 1, 1, 1,
	2, 2, 2, 2, 2, 2, 2, 2,
	2, 3, 2, 1, 1, 1, 1, 1,
	-1, -1, -1, -1,
}

const llDefaultLog = 6

// Match length codes. Codes 0..31 mean 3..34 literally, because 3 is the
// shortest match zstd will emit.
var mlBits = [maxML + 1]uint8{
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 2, 2, 3, 3,
	4, 4, 5, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16,
}

var mlBase = [maxML + 1]uint32{
	3, 4, 5, 6, 7, 8, 9, 10,
	11, 12, 13, 14, 15, 16, 17, 18,
	19, 20, 21, 22, 23, 24, 25, 26,
	27, 28, 29, 30, 31, 32, 33, 34,
	35, 37, 39, 41, 43, 47, 51, 59,
	67, 83, 99, 0x83, 0x103, 0x203, 0x403, 0x803,
	0x1003, 0x2003, 0x4003, 0x8003, 0x10003,
}

var mlDefaultNorm = [maxML + 1]int16{
	1, 4, 3, 2, 2, 2, 2, 2,
	2, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, -1, -1,
	-1, -1, -1, -1, -1,
}

const mlDefaultLog = 6

// An offset code carries exactly as many extra bits as the code number.
var ofBits = [maxOff + 1]uint8{
	0, 1, 2, 3, 4, 5, 6, 7,
	8, 9, 10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23,
	24, 25, 26, 27, 28, 29, 30, 31,
}

// Offset baselines are pre-reduced by 3 so codes above 3 yield the real
// distance with no further arithmetic, while codes 0..3 select a repeat
// offset. That is why entries 0 and 1 break the (1<<n)-3 pattern.
var ofBase = [maxOff + 1]uint32{
	0, 1, 1, 5, 0xD, 0x1D, 0x3D, 0x7D,
	0xFD, 0x1FD, 0x3FD, 0x7FD, 0xFFD, 0x1FFD, 0x3FFD, 0x7FFD,
	0xFFFD, 0x1FFFD, 0x3FFFD, 0x7FFFD, 0xFFFFD, 0x1FFFFD, 0x3FFFFD, 0x7FFFFD,
	0xFFFFFD, 0x1FFFFFD, 0x3FFFFFD, 0x7FFFFFD, 0xFFFFFFD, 0x1FFFFFFD, 0x3FFFFFFD, 0x7FFFFFFD,
}

var ofDefaultNorm = [ofDefaultMax + 1]int16{
	1, 1, 1, 1, 1, 1, 2, 2,
	2, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	-1, -1, -1, -1, -1,
}

const (
	ofDefaultLog = 5
	ofDefaultMax = 28
)

// The three predefined sequence distributions, built once. They are read-only
// afterwards, so a single copy is safe to share across concurrent decodes.
var (
	predefLL  *seqTable
	predefML  *seqTable
	predefOF  *seqTable
	predefErr error
)

func init() {
	var err error
	if predefLL, err = buildSeqTable(llDefaultNorm[:], maxLL, llDefaultLog, llBase[:], llBits[:]); err != nil && predefErr == nil {
		predefErr = err
	}
	if predefML, err = buildSeqTable(mlDefaultNorm[:], maxML, mlDefaultLog, mlBase[:], mlBits[:]); err != nil && predefErr == nil {
		predefErr = err
	}
	if predefOF, err = buildSeqTable(ofDefaultNorm[:], ofDefaultMax, ofDefaultLog, ofBase[:], ofBits[:]); err != nil && predefErr == nil {
		predefErr = err
	}
}
