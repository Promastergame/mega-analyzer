package artifacts

import "math"

// EMBED BUDGET TRACKER
//
// Plan par.4 + par.10:
//   - per-file cap (--artifacts-max-mb) decides "embed inline" vs "external_path"
//   - total cap (--artifacts-budget) flips ALL further items to external_path

// Budget tracks total embedded bytes against a cap.
type Budget struct {
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
	if size <= 0 {
		return true
	}
	if b.maxFileBytes > 0 && size > b.maxFileBytes {
		return false
	}
	if b.totalBytes > 0 && b.used+size > b.totalBytes {
		return false
	}
	return true
}

// Charge reserves the given size against the total budget. Should only
// be called after CanEmbed returned true.
func (b *Budget) Charge(size int64) {
	if size > 0 {
		b.used += size
	}
}

// Used returns the total embedded bytes so far.
func (b *Budget) Used() int64 { return b.used }
