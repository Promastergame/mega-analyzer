package apkloader

import "mega-analyzer/pkg/internal/peinspect"

// DeobfuscationResult matches the JSON returned by Rust.
type DeobfuscationResult struct {
	DebugMirLen             uint64  `json:"debug_mir_len"`
	DebugInsnCount          int     `json:"debug_insn_count"`
	Converged               bool    `json:"converged"`
	Iterations              int     `json:"iterations"`
	InstructionsBefore      int     `json:"instructions_before"`
	InstructionsAfter       int     `json:"instructions_after"`
	BlocksBefore            int     `json:"blocks_before"`
	BlocksAfter             int     `json:"blocks_after"`
	ConstantsResolved       int     `json:"constants_resolved"`
	OpaquePredicatesRemoved int     `json:"opaque_predicates_removed"`
	PatternsApplied         int     `json:"patterns_applied"`
	StringsDecrypted        int     `json:"strings_decrypted"`
	MbaSimplified           int     `json:"mba_simplified"`
	ReductionPercent        float64 `json:"reduction_percent"`
	DurationMs              int64   `json:"duration_ms"`
}

// NativeScanReport matches ScanReport from omnisec-scan-native.
// PE and DotNet carry the structured Go-side analysis (sections, entry
// point, TLS, overlay, signature, CLI metadata); they are omitempty so the
// Rust JSON contract is unaffected when the Go fallback produced them.
type NativeScanReport struct {
	TargetFormat   string                `json:"target_format"`
	TargetArch     string                `json:"target_arch"`
	TargetSize     int                   `json:"target_size"`
	Hardening      HardeningReport       `json:"hardening"`
	Findings       []NativeFinding       `json:"findings"`
	Score          uint32                `json:"score"`
	Verdict        string                `json:"verdict"`
	ScannerVersion string                `json:"scanner_version"`
	PE             *peinspect.Metadata   `json:"pe,omitempty"`
	DotNet         *peinspect.DotNetInfo `json:"dotnet,omitempty"`
}

type HardeningReport struct {
	NX            *bool   `json:"nx"`
	PIE           *bool   `json:"pie"`
	Relro         string  `json:"relro"`
	StackCanary   *bool   `json:"stack_canary"`
	FortifySource *bool   `json:"fortify_source"`
	Stripped      *bool   `json:"stripped"`
	Rpath         *string `json:"rpath,omitempty"`
	Runpath       *string `json:"runpath,omitempty"`
	WxSections    int     `json:"wx_sections"`
}

type NativeFinding struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Assessment  string   `json:"assessment,omitempty"` // hardening | capability | behavior | inventory
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence"`
	CWE         *string  `json:"cwe,omitempty"`
	Remediation *string  `json:"remediation,omitempty"`
	FileOffset  *uint64  `json:"file_offset,omitempty"`
	Payload     *string  `json:"ml_apli_ex_payload,omitempty"`
	Stages      []string `json:"stages,omitempty"`
}

// Block and instruction types for the FFI bridge
type FfiMirInsn struct {
	Kind   uint8
	Cond   uint8
	Dst    int16
	Src1   int16
	Src2   int16
	Imm    int64
	RefIdx uint32
}

type FfiBlock struct {
	ID    uint32
	Insns []FfiMirInsn
	Succs []uint32
}

type FfiVirtInsn struct {
	Kind   uint8
	Dst    int16
	Src1   int16
	Src2   int16
	Imm    int64
	RefIdx uint32
}

type FfiVirtBlock struct {
	ID    uint32
	Insns []FfiVirtInsn
	Succs []uint32
}
