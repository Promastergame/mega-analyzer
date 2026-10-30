package apkloader

// ═══════════════════════════════════════════════════════════════════════════════
// HYPERION ENGINE v3.0 — Phase 4.3: Linear Scan Register Allocator
// ═══════════════════════════════════════════════════════════════════════════════
//
// Re-allocates registers after transformations. Optimizes for:
//   - Minimal register count
//   - Long-lived values don't overlap with temporaries

import (
	"sort"
)

// Interval represents a live range for a variable.
type Interval struct {
	Reg       uint16 // original register (virtual)
	Start     int    // instruction index where defined
	End       int    // last instruction index where used
	Spill     bool   // spilled to stack
	SpillSlot int    // stack slot if spilled
}

// RegAlloc performs linear scan register allocation.
type RegAlloc struct {
	Intervals  []Interval
	FreeRegs   []uint16       // available physical registers
	UsedRegs   map[uint16]int // reg -> end of interval
	SpillCount int
	MaxRegUsed uint16
}

// NewRegAlloc creates a register allocator with given register pool.
// Dalvik: v0..vn = locals, vn+1.. = temporaries. Total usually v0..v15 for small methods.
func NewRegAlloc(maxReg uint16) *RegAlloc {
	// Reserve v0..v15 as general purpose
	free := make([]uint16, 0, 16)
	for i := uint16(0); i < 16 && i <= maxReg+4; i++ {
		free = append(free, i)
	}

	return &RegAlloc{
		Intervals:  nil,
		FreeRegs:   free,
		UsedRegs:   make(map[uint16]int),
		SpillCount: 0,
		MaxRegUsed: 0,
	}
}

// BuildIntervals computes live intervals from def-use chains.
func (ra *RegAlloc) BuildIntervals(ssa *SSAFunction, du *DefUseGraph) {
	intervalMap := make(map[uint16]*Interval)

	// For each block
	for _, sb := range ssa.Blocks {
		// Process phis (they define registers at block start)
		for _, phi := range sb.Phis {
			reg := phi.Dst.Reg
			if iv, ok := intervalMap[reg]; ok {
				if sb.ID < iv.Start {
					iv.Start = sb.ID
				}
			} else {
				intervalMap[reg] = &Interval{
					Reg:   reg,
					Start: sb.ID,
					End:   sb.ID,
				}
			}
		}

		// Process instructions
		for insnIdx, insn := range sb.Insns {
			pos := sb.ID*1000 + insnIdx // simple ordering

			// Definition extends interval start
			if insn.Dst.Reg != 0 || insn.Dst.Version != 0 {
				reg := insn.Dst.Reg
				if iv, ok := intervalMap[reg]; ok {
					if pos < iv.Start {
						iv.Start = pos
					}
				} else {
					intervalMap[reg] = &Interval{
						Reg:   reg,
						Start: pos,
						End:   pos,
					}
				}
			}

			// Uses extend interval end
			for _, src := range insn.Srcs {
				reg := src.Reg
				if iv, ok := intervalMap[reg]; ok {
					if pos > iv.End {
						iv.End = pos
					}
				}
			}
		}
	}

	// Convert to slice
	ra.Intervals = make([]Interval, 0, len(intervalMap))
	for _, iv := range intervalMap {
		ra.Intervals = append(ra.Intervals, *iv)
	}

	// Sort by start position
	sort.Slice(ra.Intervals, func(i, j int) bool {
		return ra.Intervals[i].Start < ra.Intervals[j].Start
	})
}

// Allocate performs linear scan register allocation.
func (ra *RegAlloc) Allocate() map[uint16]uint16 {
	// virtual reg -> physical reg
	mapping := make(map[uint16]uint16)

	// Active intervals (sorted by end)
	active := make([]Interval, 0)

	for _, current := range ra.Intervals {
		// Expire old intervals
		newActive := active[:0]
		for _, iv := range active {
			if iv.End >= current.Start {
				newActive = append(newActive, iv)
			} else {
				// Free the register
				if phys, ok := mapping[iv.Reg]; ok {
					ra.FreeRegs = append(ra.FreeRegs, phys)
					delete(ra.UsedRegs, phys)
				}
			}
		}
		active = newActive

		// Try to allocate a register
		if len(ra.FreeRegs) > 0 {
			// Take first free register
			phys := ra.FreeRegs[0]
			ra.FreeRegs = ra.FreeRegs[1:]
			mapping[current.Reg] = phys
			ra.UsedRegs[phys] = current.End
			if phys > ra.MaxRegUsed {
				ra.MaxRegUsed = phys
			}
		} else {
			// Spill: find interval with furthest end
			spillIdx := -1
			furthestEnd := -1
			for i, iv := range active {
				if iv.End > furthestEnd {
					furthestEnd = iv.End
					spillIdx = i
				}
			}

			if spillIdx >= 0 && furthestEnd > current.End {
				// Spill the furthest interval, allocate to current
				spilled := active[spillIdx]
				phys := mapping[spilled.Reg]
				delete(mapping, spilled.Reg)
				spilled.Spill = true
				spilled.SpillSlot = ra.SpillCount
				ra.SpillCount++

				mapping[current.Reg] = phys
				ra.UsedRegs[phys] = current.End

				// Update active
				active[spillIdx] = current
			} else {
				// Spill current
				current.Spill = true
				current.SpillSlot = ra.SpillCount
				ra.SpillCount++
			}
		}

		// Add to active (sorted by end)
		active = append(active, current)
		sort.Slice(active, func(i, j int) bool {
			return active[i].End < active[j].End
		})
	}

	return mapping
}

// RewriteInsns applies register mapping to instructions.
// Note: RawInsn uses Regs array; MIRInsn uses Dst/Src1/Src2.
// This version handles RawInsn.Reg remapping.
func (ra *RegAlloc) RewriteInsns(insns []RawInsn, mapping map[uint16]uint16) []RawInsn {
	newInsns := make([]RawInsn, len(insns))
	copy(newInsns, insns)

	for i := range newInsns {
		insn := &newInsns[i]

		// Remap all registers in the Regs array
		for j := range insn.Regs {
			if newReg, ok := mapping[insn.Regs[j]]; ok {
				insn.Regs[j] = newReg
			}
		}
	}

	return newInsns
}

// ═══════════════════════════════════════════════════════════════════════════════
// SIMPLE ALLOCATION FOR PATCHING
// ═══════════════════════════════════════════════════════════════════════════════

// SimpleRegAlloc is a simpler allocator for quick patching.
type SimpleRegAlloc struct {
	NextReg uint16
	MaxRegs uint16
}

// NewSimpleRegAlloc creates a simple bump allocator.
func NewSimpleRegAlloc(startReg uint16) *SimpleRegAlloc {
	return &SimpleRegAlloc{
		NextReg: startReg,
		MaxRegs: 255,
	}
}

// Alloc allocates a single register.
func (sra *SimpleRegAlloc) Alloc() uint16 {
	reg := sra.NextReg
	sra.NextReg++
	return reg
}

// AllocRange allocates a range of consecutive registers.
func (sra *SimpleRegAlloc) AllocRange(count int) uint16 {
	start := sra.NextReg
	sra.NextReg += uint16(count)
	return start
}

// GetMaxReg returns the highest allocated register.
func (sra *SimpleRegAlloc) GetMaxReg() uint16 {
	if sra.NextReg == 0 {
		return 0
	}
	return sra.NextReg - 1
}
