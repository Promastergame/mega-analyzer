package artifacts

import (
	"math"
	"sync"
)

// EMBED BUDGET TRACKER
//
// Plan par.4 + par.10:
//   - per-file cap (--artifacts-max-mb) decides "embed inline" vs "external_path"
//   - total cap (--artifacts-budget) flips ALL further items to external_path

// Budget tracks total embedded bytes against a cap. Items are built on
// parallel workers, so every mutation goes through mu.
type Budget struct {
	mu           sync.Mutex
	maxFileBytes int64
	totalBytes   int64
	used         int64
}

// NewBudget initialises a budget with per-file and total caps in MB. A
// non-positive value means "unlimited" for that dimension.
func NewBudget(perFileMB, totalMB int) *Budget {
	return &Budget{
		maxFileBytes: mbToBytes(perFileMB),
		totalBytes:   mbToBytes(totalMB),
	}
}

// mbToBytes converts an MB count to bytes, clamping instead of overflowing
// int64 for absurdly large inputs (the old multiply could wrap negative,
// which silently meant "unlimited"). R11.
func mbToBytes(v int) int64 {
	const mb = int64(1024 * 1024)
	if v <= 0 {
		return 0
	}
	if int64(v) > math.MaxInt64/mb {
		return math.MaxInt64
	}
	return int64(v) * mb
}

// CanEmbed reports whether a file of the given size may still be embedded
// inline. Returns false when:
//   - per-file cap is set and size > cap
//   - total cap is set and embedding would push us over
func (b *Budget) CanEmbed(size int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.canEmbedLocked(size)
}

func (b *Budget) canEmbedLocked(size int64) bool {
	if size <= 0 {
		return true
	}
	if b.maxFileBytes > 0 && size > b.maxFileBytes {
		return false
	}
	if b.totalBytes > 0 && size > b.totalBytes-b.used {
		return false
	}
	return true
}

// Charge updates usage after CanEmbed. Concurrent callers should use
// ReserveForData for an atomic check and reservation.
func (b *Budget) Charge(size int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if size > 0 {
		if size > math.MaxInt64-b.used {
			b.used = math.MaxInt64
		} else {
			b.used += size
		}
	}
}

// ReserveForData atomically checks and reserves the embedded size of a data
// payload, including base64 expansion and the data URI prefix. The per-file
// cap applies to raw bytes; the total cap applies to the complete URI.
func (b *Budget) ReserveForData(dataLen, prefixLen int) bool {
	if dataLen < 0 || prefixLen < 0 {
		return false
	}
	groups := int64(dataLen) / 3
	if dataLen%3 != 0 {
		groups++
	}
	if groups > (math.MaxInt64-int64(prefixLen))/4 {
		return false
	}
	uriLen := int64(prefixLen) + 4*groups
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.maxFileBytes > 0 && int64(dataLen) > b.maxFileBytes {
		return false
	}
	if uriLen > math.MaxInt64-b.used || (b.totalBytes > 0 && uriLen > b.totalBytes-b.used) {
		return false
	}
	b.used += uriLen
	return true
}

// Used returns the total embedded bytes so far.
func (b *Budget) Used() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}
