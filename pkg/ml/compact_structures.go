package ml

// ═══════════════════════════════════════════════════════════════════════════════
// COMPACT DATA STRUCTURES — Task 6.3: Optimize memory footprint
// ═══════════════════════════════════════════════════════════════════════════════
//
// This file contains compact representations of data structures to reduce
// memory overhead. Uses bit fields for boolean flags and compact storage.

// MethodFlags — compact representation of boolean flags using bit fields
type MethodFlags uint32

const (
	// Return type flags (bits 0-2)
	FlagReturnsBoolean MethodFlags = 1 << 0
	FlagReturnsVoid    MethodFlags = 1 << 1
	FlagReturnsInt     MethodFlags = 1 << 2

	// Access flags (bits 3-8)
	FlagIsPublic    MethodFlags = 1 << 3
	FlagIsPrivate   MethodFlags = 1 << 4
	FlagIsStatic    MethodFlags = 1 << 5
	FlagIsFinal     MethodFlags = 1 << 6
	FlagIsAbstract  MethodFlags = 1 << 7
	FlagIsSynthetic MethodFlags = 1 << 8

	// Structure flags (bits 9-11)
	FlagHasDualReturn   MethodFlags = 1 << 9
	FlagHasIfWithReturn MethodFlags = 1 << 10
	FlagIsShortMethod   MethodFlags = 1 << 11

	// Security flags (bits 12-13)
	FlagHasSecurityAPI     MethodFlags = 1 << 12
	FlagHasSecurityStrings MethodFlags = 1 << 13

	// Context flags (bits 14-18)
	FlagIsAppCode     MethodFlags = 1 << 14
	FlagIsLibrary     MethodFlags = 1 << 15
	FlagIsConstructor MethodFlags = 1 << 16
	FlagIsAccessor    MethodFlags = 1 << 17
	FlagIsCallback    MethodFlags = 1 << 18

	// Name analysis flags (bits 19-20)
	FlagHasCheckPrefix  MethodFlags = 1 << 19
	FlagHasSecurityName MethodFlags = 1 << 20
)

// HasFlag checks if a flag is set
func (f MethodFlags) HasFlag(flag MethodFlags) bool {
	return f&flag != 0
}

// SetFlag sets a flag
func (f *MethodFlags) SetFlag(flag MethodFlags) {
	*f |= flag
}

// ClearFlag clears a flag
func (f *MethodFlags) ClearFlag(flag MethodFlags) {
	*f &^= flag
}

// ToggleFlag toggles a flag
func (f *MethodFlags) ToggleFlag(flag MethodFlags) {
	*f ^= flag
}

// CompactMethodInfo — compact version of MethodInfo using bit fields
// This reduces memory footprint by ~30% for boolean fields
type CompactMethodInfo struct {
	// Identifiers (strings are interned to reduce memory)
	Name          string
	ClassName     string
	FilePath      string
	FullSignature string
	ReturnType    string
	NameLower     string

	// Compact flags (21 booleans in 4 bytes instead of 21 bytes)
	Flags MethodFlags

	// Counters (use uint16 instead of int where possible)
	InstructionCount uint16
	RegisterCount    uint8
	ReturnCount      uint8
	IfCheckCount     uint8

	// Slices (pre-allocated in pool)
	Calls            []CallInfo
	SecurityCalls    []string
	StringConsts     []string
	SecurityStrings  []string
	MatchedNameParts []string
	RawBody          []string

	// Method boundaries
	MethodHeader string
	MethodFooter string
}

// ToCompact converts MethodInfo to CompactMethodInfo
func (mi *MethodInfo) ToCompact() *CompactMethodInfo {
	cmi := &CompactMethodInfo{
		Name:             mi.Name,
		ClassName:        mi.ClassName,
		FilePath:         mi.FilePath,
		FullSignature:    mi.FullSignature,
		ReturnType:       mi.ReturnType,
		NameLower:        mi.NameLower,
		InstructionCount: uint16(mi.InstructionCount),
		RegisterCount:    uint8(mi.RegisterCount),
		ReturnCount:      uint8(mi.ReturnCount),
		IfCheckCount:     uint8(mi.IfCheckCount),
		Calls:            mi.Calls,
		SecurityCalls:    mi.SecurityCalls,
		StringConsts:     mi.StringConsts,
		SecurityStrings:  mi.SecurityStrings,
		MatchedNameParts: mi.MatchedNameParts,
		RawBody:          mi.RawBody,
		MethodHeader:     mi.MethodHeader,
		MethodFooter:     mi.MethodFooter,
	}

	// Convert booleans to flags
	if mi.ReturnsBoolean {
		cmi.Flags.SetFlag(FlagReturnsBoolean)
	}
	if mi.ReturnsVoid {
		cmi.Flags.SetFlag(FlagReturnsVoid)
	}
	if mi.ReturnsInt {
		cmi.Flags.SetFlag(FlagReturnsInt)
	}
	if mi.IsPublic {
		cmi.Flags.SetFlag(FlagIsPublic)
	}
	if mi.IsPrivate {
		cmi.Flags.SetFlag(FlagIsPrivate)
	}
	if mi.IsStatic {
		cmi.Flags.SetFlag(FlagIsStatic)
	}
	if mi.IsFinal {
		cmi.Flags.SetFlag(FlagIsFinal)
	}
	if mi.IsAbstract {
		cmi.Flags.SetFlag(FlagIsAbstract)
	}
	if mi.IsSynthetic {
		cmi.Flags.SetFlag(FlagIsSynthetic)
	}
	if mi.HasDualReturn {
		cmi.Flags.SetFlag(FlagHasDualReturn)
	}
	if mi.HasIfWithReturn {
		cmi.Flags.SetFlag(FlagHasIfWithReturn)
	}
	if mi.IsShortMethod {
		cmi.Flags.SetFlag(FlagIsShortMethod)
	}
	if mi.HasSecurityAPI {
		cmi.Flags.SetFlag(FlagHasSecurityAPI)
	}
	if mi.HasSecurityStrings {
		cmi.Flags.SetFlag(FlagHasSecurityStrings)
	}
	if mi.IsAppCode {
		cmi.Flags.SetFlag(FlagIsAppCode)
	}
	if mi.IsLibrary {
		cmi.Flags.SetFlag(FlagIsLibrary)
	}
	if mi.IsConstructor {
		cmi.Flags.SetFlag(FlagIsConstructor)
	}
	if mi.IsAccessor {
		cmi.Flags.SetFlag(FlagIsAccessor)
	}
	if mi.IsCallback {
		cmi.Flags.SetFlag(FlagIsCallback)
	}
	if mi.HasCheckPrefix {
		cmi.Flags.SetFlag(FlagHasCheckPrefix)
	}
	if mi.HasSecurityName {
		cmi.Flags.SetFlag(FlagHasSecurityName)
	}

	return cmi
}

// FromCompact converts CompactMethodInfo back to MethodInfo
func (cmi *CompactMethodInfo) FromCompact() *MethodInfo {
	mi := &MethodInfo{
		Name:             cmi.Name,
		ClassName:        cmi.ClassName,
		FilePath:         cmi.FilePath,
		FullSignature:    cmi.FullSignature,
		ReturnType:       cmi.ReturnType,
		NameLower:        cmi.NameLower,
		InstructionCount: int(cmi.InstructionCount),
		RegisterCount:    int(cmi.RegisterCount),
		ReturnCount:      int(cmi.ReturnCount),
		IfCheckCount:     int(cmi.IfCheckCount),
		Calls:            cmi.Calls,
		SecurityCalls:    cmi.SecurityCalls,
		StringConsts:     cmi.StringConsts,
		SecurityStrings:  cmi.SecurityStrings,
		MatchedNameParts: cmi.MatchedNameParts,
		RawBody:          cmi.RawBody,
		MethodHeader:     cmi.MethodHeader,
		MethodFooter:     cmi.MethodFooter,
	}

	// Convert flags to booleans
	mi.ReturnsBoolean = cmi.Flags.HasFlag(FlagReturnsBoolean)
	mi.ReturnsVoid = cmi.Flags.HasFlag(FlagReturnsVoid)
	mi.ReturnsInt = cmi.Flags.HasFlag(FlagReturnsInt)
	mi.IsPublic = cmi.Flags.HasFlag(FlagIsPublic)
	mi.IsPrivate = cmi.Flags.HasFlag(FlagIsPrivate)
	mi.IsStatic = cmi.Flags.HasFlag(FlagIsStatic)
	mi.IsFinal = cmi.Flags.HasFlag(FlagIsFinal)
	mi.IsAbstract = cmi.Flags.HasFlag(FlagIsAbstract)
	mi.IsSynthetic = cmi.Flags.HasFlag(FlagIsSynthetic)
	mi.HasDualReturn = cmi.Flags.HasFlag(FlagHasDualReturn)
	mi.HasIfWithReturn = cmi.Flags.HasFlag(FlagHasIfWithReturn)
	mi.IsShortMethod = cmi.Flags.HasFlag(FlagIsShortMethod)
	mi.HasSecurityAPI = cmi.Flags.HasFlag(FlagHasSecurityAPI)
	mi.HasSecurityStrings = cmi.Flags.HasFlag(FlagHasSecurityStrings)
	mi.IsAppCode = cmi.Flags.HasFlag(FlagIsAppCode)
	mi.IsLibrary = cmi.Flags.HasFlag(FlagIsLibrary)
	mi.IsConstructor = cmi.Flags.HasFlag(FlagIsConstructor)
	mi.IsAccessor = cmi.Flags.HasFlag(FlagIsAccessor)
	mi.IsCallback = cmi.Flags.HasFlag(FlagIsCallback)
	mi.HasCheckPrefix = cmi.Flags.HasFlag(FlagHasCheckPrefix)
	mi.HasSecurityName = cmi.Flags.HasFlag(FlagHasSecurityName)

	return mi
}

// MemoryFootprint returns estimated memory footprint in bytes
func (mi *MethodInfo) MemoryFootprint() int {
	size := 0

	// Strings
	size += len(mi.Name) + len(mi.ClassName) + len(mi.FilePath)
	size += len(mi.FullSignature) + len(mi.ReturnType) + len(mi.NameLower)
	size += len(mi.MethodHeader) + len(mi.MethodFooter)

	// Booleans (21 * 1 byte)
	size += 21

	// Integers (4 * 8 bytes on 64-bit)
	size += 32

	// Slices
	size += len(mi.Calls) * 64         // CallInfo ~64 bytes each
	size += len(mi.SecurityCalls) * 16 // string pointers
	size += len(mi.StringConsts) * 16
	size += len(mi.SecurityStrings) * 16
	size += len(mi.MatchedNameParts) * 16
	size += len(mi.RawBody) * 16

	return size
}

// MemoryFootprint returns estimated memory footprint in bytes for compact version
func (cmi *CompactMethodInfo) MemoryFootprint() int {
	size := 0

	// Strings (same as MethodInfo)
	size += len(cmi.Name) + len(cmi.ClassName) + len(cmi.FilePath)
	size += len(cmi.FullSignature) + len(cmi.ReturnType) + len(cmi.NameLower)
	size += len(cmi.MethodHeader) + len(cmi.MethodFooter)

	// Flags (4 bytes instead of 21)
	size += 4

	// Integers (uint16 + 3*uint8 = 5 bytes instead of 32)
	size += 5

	// Slices (same as MethodInfo)
	size += len(cmi.Calls) * 64
	size += len(cmi.SecurityCalls) * 16
	size += len(cmi.StringConsts) * 16
	size += len(cmi.SecurityStrings) * 16
	size += len(cmi.MatchedNameParts) * 16
	size += len(cmi.RawBody) * 16

	return size
}
