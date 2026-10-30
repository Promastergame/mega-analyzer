package apkloader

// ═══════════════════════════════════════════════════════════════════════════════
// HYPERION ENGINE v3.0 — StringTable
// ═══════════════════════════════════════════════════════════════════════════════
//
// Zero-allocation string access for DEX parsing.
// Stores only (offset, length) pairs — 8 bytes per entry instead of full strings.
// Three access levels:
//   - GetView(idx)   → []byte   — zero alloc, pointer into mmap
//   - GetCached(idx) → string   — one alloc, cached for repeated access
//   - GetCloned(idx) → string   — always fresh copy, safe for long-lived storage

import (
	"sync"
	"unsafe"
)

// StringEntry stores the location of a string in the raw DEX data.
// 8 bytes per entry vs ~40+ bytes for a Go string + header.
type StringEntry struct {
	Offset uint32 // byte offset of the decoded string data in DEX
	Length uint32 // byte length of the decoded ASCII portion
}

// StringTable is a zero-allocation string index over memory-mapped DEX data.
// It defers actual string decoding until access time and caches results.
type StringTable struct {
	entries []StringEntry
	data    []byte // raw DEX bytes (mmap or heap)

	// Lazy string cache — populated on first GetCached() call per index.
	cache []string
	once  []uint32 // bitfield: 1 bit per index, marks if cache[i] is populated
	mu    sync.RWMutex
}

// NewStringTable creates a StringTable with pre-allocated entry slots.
func NewStringTable(count uint32, data []byte) *StringTable {
	// Each uint32 in the bitfield covers 32 indices
	bitfieldSize := (count + 31) / 32
	return &StringTable{
		entries: make([]StringEntry, count),
		data:    data,
		cache:   make([]string, count),
		once:    make([]uint32, bitfieldSize),
	}
}

// SetEntry records the location of string[idx] in the DEX data.
// Called during initial header parsing — no allocation.
func (st *StringTable) SetEntry(idx uint32, offset, length uint32) {
	if idx < uint32(len(st.entries)) {
		st.entries[idx] = StringEntry{Offset: offset, Length: length}
	}
}

// Count returns the number of string entries.
func (st *StringTable) Count() int {
	return len(st.entries)
}

// GetView returns a direct byte slice into the underlying data.
// Zero allocation. The returned slice is valid as long as the mmap is alive.
// WARNING: Do not store the result past the lifetime of the parser.
func (st *StringTable) GetView(idx uint32) []byte {
	if idx >= uint32(len(st.entries)) {
		return nil
	}
	e := st.entries[idx]
	if e.Length == 0 {
		return nil
	}
	end := e.Offset + e.Length
	if end > uint32(len(st.data)) {
		return nil
	}
	return st.data[e.Offset:end]
}

// GetCached returns a Go string, cached after first access.
// One allocation on first call, zero on subsequent calls.
func (st *StringTable) GetCached(idx uint32) string {
	if idx >= uint32(len(st.entries)) {
		return ""
	}

	// Fast path: check bitfield without lock
	wordIdx := idx / 32
	bitMask := uint32(1) << (idx % 32)

	st.mu.RLock()
	if st.once[wordIdx]&bitMask != 0 {
		s := st.cache[idx]
		st.mu.RUnlock()
		return s
	}
	st.mu.RUnlock()

	// Slow path: decode and cache
	st.mu.Lock()
	defer st.mu.Unlock()

	// Double-check under write lock
	if st.once[wordIdx]&bitMask != 0 {
		return st.cache[idx]
	}

	view := st.GetView(idx)
	if view == nil {
		st.once[wordIdx] |= bitMask
		return ""
	}

	s := string(view) // single allocation
	st.cache[idx] = s
	st.once[wordIdx] |= bitMask
	return s
}

// GetUnsafe returns a string that points directly into the mmap data.
// ZERO allocation. The string is valid ONLY while the mmap is alive.
// Use only for short-lived comparisons within a single analysis pass.
func (st *StringTable) GetUnsafe(idx uint32) string {
	view := st.GetView(idx)
	if view == nil {
		return ""
	}
	// unsafe.String creates a string header pointing to the existing bytes.
	// No copy. No allocation. The caller must not retain this string.
	return unsafe.String(&view[0], len(view))
}

// GetCloned returns a freshly allocated copy of the string.
// Safe for long-lived storage (struct fields, maps, etc).
func (st *StringTable) GetCloned(idx uint32) string {
	view := st.GetView(idx)
	if view == nil {
		return ""
	}
	// Explicit copy via append to ensure independent backing array.
	clone := make([]byte, len(view))
	copy(clone, view)
	return string(clone)
}

// PrewarmRange decodes and caches strings in [start, end).
// Useful for warming up hot sections (e.g., type names).
func (st *StringTable) PrewarmRange(start, end uint32) {
	if end > uint32(len(st.entries)) {
		end = uint32(len(st.entries))
	}
	for i := start; i < end; i++ {
		_ = st.GetCached(i)
	}
}
