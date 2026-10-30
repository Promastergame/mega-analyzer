package apkloader

// ═══════════════════════════════════════════════════════════════════════════════
// HYPERION ENGINE v3.0 — Arena Allocator
// ═══════════════════════════════════════════════════════════════════════════════
//
// Bump-allocator for short-lived IR objects (instructions, basic blocks).
// Allocates from a contiguous byte slab. When analysis of a method is done,
// call Reset() to free everything in one shot — no GC pressure.
//
// This is dramatically faster than individual heap allocations for IR construction:
//   - No per-object GC tracking
//   - Cache-friendly: objects are contiguous in memory
//   - O(1) cleanup via Reset()

import (
	"sync"
	"unsafe"
)

const (
	defaultArenaSize = 1 << 20 // 1MB — fits ~65k RawInsn structs
	maxArenaSize     = 1 << 26 // 64MB hard cap per arena
)

// Arena is a bump allocator for transient IR objects.
// Not thread-safe — each goroutine should have its own arena.
type Arena struct {
	slab   []byte
	offset int
}

// NewArena creates a new arena with the given capacity.
func NewArena(capacity int) *Arena {
	if capacity <= 0 {
		capacity = defaultArenaSize
	}
	if capacity > maxArenaSize {
		capacity = maxArenaSize
	}
	return &Arena{
		slab: make([]byte, capacity),
	}
}

// Alloc reserves n bytes from the arena and returns a pointer.
// Returns nil if the arena is exhausted.
// The pointer is valid until Reset() is called.
func (a *Arena) Alloc(n int) unsafe.Pointer {
	// Align to 8 bytes for struct field alignment
	aligned := (a.offset + 7) &^ 7
	if aligned+n > len(a.slab) {
		return nil // arena exhausted
	}
	ptr := unsafe.Pointer(&a.slab[aligned])
	a.offset = aligned + n
	return ptr
}

// AllocRawInsn allocates a single RawInsn from the arena.
// Returns nil if the arena is exhausted.
func (a *Arena) AllocRawInsn() *RawInsn {
	ptr := a.Alloc(int(unsafe.Sizeof(RawInsn{})))
	if ptr == nil {
		return nil
	}
	insn := (*RawInsn)(ptr)
	*insn = RawInsn{} // zero-initialize
	return insn
}

// AllocRawInsnSlice allocates a slice of RawInsn from the arena.
// Falls back to heap if the arena is exhausted.
func (a *Arena) AllocRawInsnSlice(count int) []RawInsn {
	size := count * int(unsafe.Sizeof(RawInsn{}))
	ptr := a.Alloc(size)
	if ptr == nil {
		// Fallback to heap — better than panicking
		return make([]RawInsn, count)
	}
	return unsafe.Slice((*RawInsn)(ptr), count)
}

// Used returns the number of bytes currently allocated.
func (a *Arena) Used() int {
	return a.offset
}

// Cap returns the total capacity of the arena.
func (a *Arena) Cap() int {
	return len(a.slab)
}

// Reset reclaims all arena memory in O(1).
// All pointers previously returned by Alloc become invalid.
func (a *Arena) Reset() {
	a.offset = 0
}

// ═══════════════════════════════════════════════════════════════════════════════
// ARENA POOL — recycles arenas across method analyses
// ═══════════════════════════════════════════════════════════════════════════════

var arenaPool = sync.Pool{
	New: func() interface{} {
		return NewArena(defaultArenaSize)
	},
}

// GetArena acquires an arena from the pool (or creates a new one).
func GetArena() *Arena {
	a := arenaPool.Get().(*Arena)
	a.Reset()
	return a
}

// PutArena returns an arena to the pool.
// Do NOT use any pointers from this arena after calling PutArena.
func PutArena(a *Arena) {
	if a.Cap() > maxArenaSize {
		return // don't recycle oversized arenas
	}
	arenaPool.Put(a)
}
