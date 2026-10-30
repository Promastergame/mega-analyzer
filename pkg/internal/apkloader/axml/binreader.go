package axml

import "encoding/binary"

// binreader is the shared bounds-checked cursor for the binary resource
// formats. Historically every parser hand-cut slices (buf[8:12] and
// friends), which is where the recurring out-of-range panics on crafted
// input came from (audit improvement #2). New parsing code should read
// through this helper: a failed read returns an error instead of panicking,
// and the guard in panicguard.go stays as the last line of defense.
type binreader struct {
	buf []byte
	off int
	err error
}

func newBinreader(buf []byte) *binreader { return &binreader{buf: buf} }

// fail marks the reader as poisoned; every subsequent read becomes a no-op
// so one error check per parse covers a whole block of reads.
func (r *binreader) fail() { r.err = errReaderBounds }

func (r *binreader) Err() error { return r.err }

// need reports whether n bytes remain, poisoning the reader otherwise.
func (r *binreader) need(n int) bool {
	if r.err != nil {
		return false
	}
	if r.off+n > len(r.buf) || r.off+n < 0 {
		r.fail()
		return false
	}
	return true
}

// U16 reads a little-endian uint16.
func (r *binreader) U16() uint16 {
	if !r.need(2) {
		return 0
	}
	v := binary.LittleEndian.Uint16(r.buf[r.off : r.off+2])
	r.off += 2
	return v
}

// U8At reads a byte at an absolute offset without moving the cursor.
func (r *binreader) U8At(off int) uint8 {
	if off < 0 || off+1 > len(r.buf) {
		r.fail()
		return 0
	}
	return r.buf[off]
}

// U32 reads a little-endian uint32.
func (r *binreader) U32() uint32 {
	if !r.need(4) {
		return 0
	}
	v := binary.LittleEndian.Uint32(r.buf[r.off : r.off+4])
	r.off += 4
	return v
}

// Bytes returns the next n bytes (zero-copy view) or nil on bounds failure.
func (r *binreader) Bytes(n int) []byte {
	if n < 0 || !r.need(n) {
		return nil
	}
	out := r.buf[r.off : r.off+n]
	r.off += n
	return out
}

// Skip advances n bytes, bounds-checked.
func (r *binreader) Skip(n int) {
	if !r.need(n) {
		return
	}
	r.off += n
}

// U16At / U32At read at an absolute offset without moving the cursor.
func (r *binreader) U16At(off int) uint16 {
	if off < 0 || off+2 > len(r.buf) {
		r.fail()
		return 0
	}
	return binary.LittleEndian.Uint16(r.buf[off : off+2])
}

func (r *binreader) U32At(off int) uint32 {
	if off < 0 || off+4 > len(r.buf) {
		r.fail()
		return 0
	}
	return binary.LittleEndian.Uint32(r.buf[off : off+4])
}

var errReaderBounds = &boundsError{}

type boundsError struct{}

func (*boundsError) Error() string { return "axml: read past end of buffer" }
