//! Pre-generated codebook of atomic hypervectors for IR concepts.
//!
//! A [`CodeBook`] maps every distinct "atom" in the OmniIR world (opcodes,
//! operand types, register classes, value types, control-flow roles, and
//! memory-access patterns) to a unique sparse [`HyperVector`].
//!
//! All HVs are deterministically derived from a master seed, so the same
//! codebook is reproduced on every run and every machine.

use crate::HyperVector;
use crate::permutation::PermutationTable;
use std::collections::HashMap as FxHashMap;

/// Seed offsets for different atom namespaces.
/// Keeps different categories in non-overlapping seed space.
const NS_OPCODE: u64 = 0x0100_0000;
const NS_OPERAND_TYPE: u64 = 0x0200_0000;
const NS_REGISTER_CLASS: u64 = 0x0300_0000;
const NS_VALUE_TYPE: u64 = 0x0400_0000;
const NS_CONTROL_FLOW: u64 = 0x0500_0000;
const NS_MEMORY_ACCESS: u64 = 0x0600_0000;
const NS_PERMUTATION: u64 = 0x0700_0000;
const NS_LIFECYCLE: u64 = 0x0800_0000;
const NS_SYSCALL_PROX: u64 = 0x0900_0000;

/// Control-flow role tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlFlowTag {
    /// Entry point of a function.
    Entry,
    /// Normal (non-branching) block.
    Sequential,
    /// Conditional branch point.
    ConditionalBranch,
    /// Unconditional jump.
    UnconditionalJump,
    /// Function call site.
    CallSite,
    /// Indirect call site (vtable / function pointer).
    IndirectCallSite,
    /// Return point.
    ReturnSite,
    /// Loop header.
    LoopHeader,
    /// Loop body.
    LoopBody,
    /// System call.
    SystemCall,
}

/// Memory access pattern tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryAccessTag {
    /// Stack read (e.g., `[rbp - 8]`).
    StackRead,
    /// Stack write.
    StackWrite,
    /// Heap read (generic memory load).
    HeapRead,
    /// Heap write (generic memory store).
    HeapWrite,
    /// Atomic operation (CAS, fence).
    Atomic,
    /// No memory access.
    None,
}

/// Allocation lifecycle stage — **critical for UAF detection**.
///
/// UAF = a `Use` that occurs after a `Free` on the same object.
/// By encoding the lifecycle stage into the instruction HV, two identical
/// `Load` instructions can produce *different* HVs depending on whether
/// the target pointer is in the `Allocated` or `Freed` stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LifecycleStage {
    /// Before allocation (unknown / uninitialized pointer).
    Uninitialized,
    /// Pointer comes from malloc/new/alloc.
    Allocated,
    /// Object is actively being used (between alloc and free).
    InUse,
    /// Object has been freed / deallocated.
    Freed,
    /// Post-free use — **the bug itself**.
    PostFreeUse,
    /// Re-allocation (new object at same address).
    Reallocated,
    /// Unknown lifecycle (conservative default).
    Unknown,
}

/// Proximity to a system call — encodes execution context.
///
/// Instructions near a syscall carry different risk profiles than
/// instructions deep in computational loops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyscallProximity {
    /// This IS the syscall.
    IsSyscall,
    /// Directly before a syscall (argument setup).
    PreSyscall,
    /// Directly after a syscall (return value check).
    PostSyscall,
    /// Within a few instructions of a syscall.
    NearSyscall,
    /// Far from any syscall.
    FarFromSyscall,
}

/// A codebook mapping IR atoms → sparse HyperVectors.
///
/// Built once at pipeline startup; all subsequent encodings look up
/// pre-generated vectors from here.
pub struct CodeBook {
    master_seed: u64,

    /// Opcode → HV (keyed by opcode discriminant as u32).
    opcodes: FxHashMap<u32, HyperVector>,

    /// Operand type → HV.
    operand_types: FxHashMap<u8, HyperVector>,

    /// Register class → HV.
    register_classes: FxHashMap<u8, HyperVector>,

    /// Value type → HV.
    value_types: FxHashMap<u8, HyperVector>,

    /// Control-flow tags → HV.
    control_flow: FxHashMap<ControlFlowTag, HyperVector>,

    /// Memory access tags → HV.
    memory_access: FxHashMap<MemoryAccessTag, HyperVector>,

    /// Lifecycle stage → HV.
    lifecycle: FxHashMap<LifecycleStage, HyperVector>,

    /// Syscall proximity → HV.
    syscall_proximity: FxHashMap<SyscallProximity, HyperVector>,

    /// Positional permutation tables (one per slot index).
    /// `perms[0]` = "position 0", `perms[1]` = "position 1", etc.
    /// Slots 12 and 13 are reserved for lifecycle and syscall proximity.
    perms: Vec<PermutationTable>,
}

impl CodeBook {
    /// Maximum number of positional permutations we pre-generate.
    const MAX_POSITIONS: usize = 16;

    /// Create a new codebook from a master seed.
    ///
    /// This is deterministic: same seed → same codebook, always.
    #[must_use]
    pub fn new(master_seed: u64) -> Self {
        let mut cb = Self {
            master_seed,
            opcodes: FxHashMap::default(),
            operand_types: FxHashMap::default(),
            register_classes: FxHashMap::default(),
            value_types: FxHashMap::default(),
            control_flow: FxHashMap::default(),
            memory_access: FxHashMap::default(),
            lifecycle: FxHashMap::default(),
            syscall_proximity: FxHashMap::default(),
            perms: Vec::with_capacity(Self::MAX_POSITIONS),
        };

        cb.init_operand_types();
        cb.init_register_classes();
        cb.init_value_types();
        cb.init_control_flow();
        cb.init_memory_access();
        cb.init_lifecycle();
        cb.init_syscall_proximity();
        cb.init_permutations();

        cb
    }

    // ── Lookup ────────────────────────────────────────────────────────────

    /// Get HV for an opcode (lazy-init: created on first access, cached).
    pub fn opcode(&mut self, opcode_id: u32) -> HyperVector {
        let seed = self.master_seed ^ NS_OPCODE ^ (opcode_id as u64);
        *self
            .opcodes
            .entry(opcode_id)
            .or_insert_with(|| HyperVector::sparse(seed))
    }

    /// Get HV for an operand type.
    ///
    /// Encoding: 0 = Register, 1 = Immediate, 2 = Memory, 3 = Label, 4 = Symbol, 5 = Type.
    #[must_use]
    pub fn operand_type(&self, type_id: u8) -> HyperVector {
        self.operand_types
            .get(&type_id)
            .copied()
            .unwrap_or_else(HyperVector::zero)
    }

    /// Get HV for a register class.
    #[must_use]
    pub fn register_class(&self, class_id: u8) -> HyperVector {
        self.register_classes
            .get(&class_id)
            .copied()
            .unwrap_or_else(HyperVector::zero)
    }

    /// Get HV for a value type.
    #[must_use]
    pub fn value_type(&self, type_id: u8) -> HyperVector {
        self.value_types
            .get(&type_id)
            .copied()
            .unwrap_or_else(HyperVector::zero)
    }

    /// Get HV for a control-flow tag.
    #[must_use]
    pub fn control_flow_tag(&self, tag: ControlFlowTag) -> HyperVector {
        self.control_flow
            .get(&tag)
            .copied()
            .unwrap_or_else(HyperVector::zero)
    }

    /// Get HV for a memory access tag.
    #[must_use]
    pub fn memory_access_tag(&self, tag: MemoryAccessTag) -> HyperVector {
        self.memory_access
            .get(&tag)
            .copied()
            .unwrap_or_else(HyperVector::zero)
    }

    /// Get HV for a lifecycle stage.
    #[must_use]
    pub fn lifecycle_stage(&self, stage: LifecycleStage) -> HyperVector {
        self.lifecycle
            .get(&stage)
            .copied()
            .unwrap_or_else(HyperVector::zero)
    }

    /// Get HV for syscall proximity.
    #[must_use]
    pub fn syscall_prox(&self, prox: SyscallProximity) -> HyperVector {
        self.syscall_proximity
            .get(&prox)
            .copied()
            .unwrap_or_else(HyperVector::zero)
    }

    /// Get the permutation table for positional slot `pos`.
    ///
    /// Slots 0..15 are pre-generated; anything beyond panics.
    #[must_use]
    pub fn permutation(&self, pos: usize) -> &PermutationTable {
        &self.perms[pos.min(Self::MAX_POSITIONS - 1)]
    }

    // ── Composite encoding helpers ───────────────────────────────────────

    /// Encode an instruction-level HV from its components.
    ///
    /// `HV_inst = OpHV ⊕ ρ₁(DstTypeHV) ⊕ ρ₂(SrcTypeHV) ⊕ ρ₃(RegClassHV) ⊕ ρ₄(MemHV) ⊕ ρ₅(CfHV)`
    ///
    /// Each component is permuted by a different positional table to avoid
    /// collisions, then bound (XOR'd) together.
    pub fn encode_instruction(
        &mut self,
        opcode_id: u32,
        dst_types: &[u8],
        src_types: &[u8],
        reg_classes: &[u8],
        mem_tag: MemoryAccessTag,
        cf_tag: ControlFlowTag,
        lifecycle: LifecycleStage,
        syscall_prox: SyscallProximity,
    ) -> HyperVector {
        let mut hv = self.opcode(opcode_id);

        // Destination operand types (slots 1-4).
        for (i, &ty) in dst_types.iter().enumerate() {
            let op_hv = self.operand_type(ty);
            let permuted = self.perms[1 + i].apply(&op_hv);
            hv = hv.bind(permuted);
        }

        // Source operand types (slots 5-8).
        for (i, &ty) in src_types.iter().enumerate() {
            let op_hv = self.operand_type(ty);
            let permuted = self.perms[5 + i].apply(&op_hv);
            hv = hv.bind(permuted);
        }

        // Register classes involved (slot 9).
        if !reg_classes.is_empty() {
            let reg_hvs: Vec<HyperVector> = reg_classes
                .iter()
                .map(|&c| self.register_class(c))
                .collect();
            let bundled = HyperVector::bundle(&reg_hvs);
            let permuted = self.perms[9].apply(&bundled);
            hv = hv.bind(permuted);
        }

        // Memory access pattern (slot 10).
        let mem_hv = self.memory_access_tag(mem_tag);
        let mem_permuted = self.perms[10].apply(&mem_hv);
        hv = hv.bind(mem_permuted);

        // Control-flow role (slot 11).
        let cf_hv = self.control_flow_tag(cf_tag);
        let cf_permuted = self.perms[11].apply(&cf_hv);
        hv = hv.bind(cf_permuted);

        // Allocation lifecycle stage (slot 12) — critical for UAF.
        let lc_hv = self.lifecycle_stage(lifecycle);
        let lc_permuted = self.perms[12].apply(&lc_hv);
        hv = hv.bind(lc_permuted);

        // Syscall proximity (slot 13).
        let sp_hv = self.syscall_prox(syscall_prox);
        let sp_permuted = self.perms[13].apply(&sp_hv);
        hv = hv.bind(sp_permuted);

        // Context-aware lifecycle boost: if we have a specific lifecycle stage,
        // bind its permutation to the result to force divergence between stages.
        if lifecycle != LifecycleStage::Unknown && lifecycle != LifecycleStage::InUse {
            let context_boost = self.perms[14].apply(&self.lifecycle_stage(lifecycle));
            hv = hv.bind(context_boost);
        }

        hv
    }

    // ── Init helpers ─────────────────────────────────────────────────────

    fn init_operand_types(&mut self) {
        for i in 0u8..6 {
            let seed = self.master_seed ^ NS_OPERAND_TYPE ^ (i as u64);
            self.operand_types.insert(i, HyperVector::sparse(seed));
        }
    }

    fn init_register_classes(&mut self) {
        for i in 0u8..10 {
            let seed = self.master_seed ^ NS_REGISTER_CLASS ^ (i as u64);
            self.register_classes.insert(i, HyperVector::sparse(seed));
        }
    }

    fn init_value_types(&mut self) {
        for i in 0u8..12 {
            let seed = self.master_seed ^ NS_VALUE_TYPE ^ (i as u64);
            self.value_types.insert(i, HyperVector::sparse(seed));
        }
    }

    fn init_control_flow(&mut self) {
        use ControlFlowTag::{
            CallSite, ConditionalBranch, Entry, IndirectCallSite, LoopBody, LoopHeader, ReturnSite,
            Sequential, SystemCall, UnconditionalJump,
        };
        let tags = [
            Entry,
            Sequential,
            ConditionalBranch,
            UnconditionalJump,
            CallSite,
            IndirectCallSite,
            ReturnSite,
            LoopHeader,
            LoopBody,
            SystemCall,
        ];
        for (i, tag) in tags.iter().enumerate() {
            let seed = self.master_seed ^ NS_CONTROL_FLOW ^ (i as u64);
            self.control_flow.insert(*tag, HyperVector::sparse(seed));
        }
    }

    fn init_memory_access(&mut self) {
        use MemoryAccessTag::{Atomic, HeapRead, HeapWrite, None, StackRead, StackWrite};
        let tags = [StackRead, StackWrite, HeapRead, HeapWrite, Atomic, None];
        for (i, tag) in tags.iter().enumerate() {
            let seed = self.master_seed ^ NS_MEMORY_ACCESS ^ (i as u64);
            self.memory_access.insert(*tag, HyperVector::sparse(seed));
        }
    }

    fn init_lifecycle(&mut self) {
        use LifecycleStage::{
            Allocated, Freed, InUse, PostFreeUse, Reallocated, Uninitialized, Unknown,
        };
        let stages = [
            Uninitialized,
            Allocated,
            InUse,
            Freed,
            PostFreeUse,
            Reallocated,
            Unknown,
        ];
        for (i, stage) in stages.iter().enumerate() {
            let seed = self.master_seed ^ NS_LIFECYCLE ^ (i as u64);
            self.lifecycle.insert(*stage, HyperVector::sparse(seed));
        }
    }

    fn init_syscall_proximity(&mut self) {
        use SyscallProximity::{FarFromSyscall, IsSyscall, NearSyscall, PostSyscall, PreSyscall};
        let proxs = [
            IsSyscall,
            PreSyscall,
            PostSyscall,
            NearSyscall,
            FarFromSyscall,
        ];
        for (i, prox) in proxs.iter().enumerate() {
            let seed = self.master_seed ^ NS_SYSCALL_PROX ^ (i as u64);
            self.syscall_proximity
                .insert(*prox, HyperVector::sparse(seed));
        }
    }

    fn init_permutations(&mut self) {
        for i in 0..Self::MAX_POSITIONS {
            let seed = self.master_seed ^ NS_PERMUTATION ^ (i as u64);
            self.perms.push(PermutationTable::from_seed(seed));
        }
    }
}

impl std::fmt::Debug for CodeBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CodeBook(seed={:#x}, opcodes={}, perms={})",
            self.master_seed,
            self.opcodes.len(),
            self.perms.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codebook_is_deterministic() {
        let mut cb1 = CodeBook::new(0xDEAD_BEEF);
        let mut cb2 = CodeBook::new(0xDEAD_BEEF);

        let hv1 = cb1.opcode(42);
        let hv2 = cb2.opcode(42);
        assert_eq!(hv1, hv2);

        assert_eq!(
            cb1.control_flow_tag(ControlFlowTag::Entry),
            cb2.control_flow_tag(ControlFlowTag::Entry),
        );
    }

    #[test]
    fn different_opcodes_produce_dissimilar_hvs() {
        let mut cb = CodeBook::new(42);
        let add = cb.opcode(3); // OpCode::Add discriminant
        let sub = cb.opcode(4); // OpCode::Sub discriminant
        let j = add.jaccard(sub);
        assert!(j < 0.15, "opcodes too similar: jaccard = {j}");
    }

    #[test]
    fn encode_instruction_is_deterministic() {
        let mut cb = CodeBook::new(42);
        let hv1 = cb.encode_instruction(
            3,
            &[0],
            &[0, 1],
            &[0],
            MemoryAccessTag::None,
            ControlFlowTag::Sequential,
            LifecycleStage::Unknown,
            SyscallProximity::FarFromSyscall,
        );
        let mut cb2 = CodeBook::new(42);
        let hv2 = cb2.encode_instruction(
            3,
            &[0],
            &[0, 1],
            &[0],
            MemoryAccessTag::None,
            ControlFlowTag::Sequential,
            LifecycleStage::Unknown,
            SyscallProximity::FarFromSyscall,
        );
        assert_eq!(hv1, hv2);
    }

    #[test]
    fn different_instructions_differ() {
        let mut cb = CodeBook::new(42);
        let add_rr = cb.encode_instruction(
            3,
            &[0],
            &[0, 0],
            &[0],
            MemoryAccessTag::None,
            ControlFlowTag::Sequential,
            LifecycleStage::Unknown,
            SyscallProximity::FarFromSyscall,
        );
        let load_mem = cb.encode_instruction(
            20,
            &[0],
            &[2],
            &[0],
            MemoryAccessTag::HeapRead,
            ControlFlowTag::Sequential,
            LifecycleStage::InUse,
            SyscallProximity::FarFromSyscall,
        );
        let j = add_rr.jaccard(load_mem);
        assert!(j < 0.40, "instructions too similar: jaccard = {j}");
    }

    #[test]
    fn control_flow_tags_are_distinct() {
        let cb = CodeBook::new(42);
        let entry = cb.control_flow_tag(ControlFlowTag::Entry);
        let call = cb.control_flow_tag(ControlFlowTag::CallSite);
        let ret = cb.control_flow_tag(ControlFlowTag::ReturnSite);
        assert!(entry.jaccard(call) < 0.15);
        assert!(entry.jaccard(ret) < 0.15);
        assert!(call.jaccard(ret) < 0.15);
    }

    #[test]
    fn memory_tags_are_distinct() {
        let cb = CodeBook::new(42);
        let sr = cb.memory_access_tag(MemoryAccessTag::StackRead);
        let hw = cb.memory_access_tag(MemoryAccessTag::HeapWrite);
        let at = cb.memory_access_tag(MemoryAccessTag::Atomic);
        assert!(sr.jaccard(hw) < 0.15);
        assert!(sr.jaccard(at) < 0.15);
    }

    #[test]
    fn lifecycle_stages_are_distinct() {
        let cb = CodeBook::new(42);
        let alloc = cb.lifecycle_stage(LifecycleStage::Allocated);
        let freed = cb.lifecycle_stage(LifecycleStage::Freed);
        let post_free = cb.lifecycle_stage(LifecycleStage::PostFreeUse);
        assert!(alloc.jaccard(freed) < 0.15);
        assert!(alloc.jaccard(post_free) < 0.15);
        assert!(freed.jaccard(post_free) < 0.15);
    }

    /// **The critical UAF test**: same Load instruction, but one is on a
    /// live object (InUse) and one is on a freed object (PostFreeUse).
    /// They MUST produce different HVs.
    #[test]
    fn same_load_different_lifecycle_produces_different_hvs() {
        let mut cb = CodeBook::new(42);
        let load_live = cb.encode_instruction(
            22,
            &[0],
            &[2],
            &[0],
            MemoryAccessTag::HeapRead,
            ControlFlowTag::Sequential,
            LifecycleStage::InUse,
            SyscallProximity::FarFromSyscall,
        );
        let mut cb2 = CodeBook::new(42);
        let load_freed = cb2.encode_instruction(
            22,
            &[0],
            &[2],
            &[0],
            MemoryAccessTag::HeapRead,
            ControlFlowTag::Sequential,
            LifecycleStage::PostFreeUse,
            SyscallProximity::FarFromSyscall,
        );
        assert_ne!(load_live, load_freed, "lifecycle must differentiate UAF");
    }

    #[test]
    fn syscall_proximity_affects_encoding() {
        let mut cb = CodeBook::new(42);
        let far = cb.encode_instruction(
            23,
            &[2],
            &[0],
            &[0],
            MemoryAccessTag::HeapWrite,
            ControlFlowTag::Sequential,
            LifecycleStage::InUse,
            SyscallProximity::FarFromSyscall,
        );
        let mut cb2 = CodeBook::new(42);
        let near = cb2.encode_instruction(
            23,
            &[2],
            &[0],
            &[0],
            MemoryAccessTag::HeapWrite,
            ControlFlowTag::Sequential,
            LifecycleStage::InUse,
            SyscallProximity::PreSyscall,
        );
        assert_ne!(far, near, "syscall proximity must affect encoding");
    }
}
