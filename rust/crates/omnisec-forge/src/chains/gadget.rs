//! Gadget representations.
//!
//! A gadget is the smallest reusable instruction sequence the chain
//! assembler can splice together. We model each gadget as:
//!
//! - a concrete `address` in the target image (or `0` for synthetic /
//!   abstract gadgets emitted by mitigation bypasses),
//! - a list of [`RegisterEffect`]s describing what registers it reads /
//!   writes / sets to a constant,
//! - a [`Terminator`] (how control flow leaves the gadget),
//! - a [`GadgetCategory`] tag for fast filtering.
//!
//! `RegisterEffect` is intentionally low-level: each effect is a 64-bit
//! affine transformation `dst = a*src + b`, which is exactly what the
//! linear-arithmetic propagator in `omnisec-smt` can solve directly.

use omnisec_json::{FromJson, ToJson};

/// Coarse classification used by mitigation bypasses and chain builders
/// to filter candidate gadgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum GadgetCategory {
    /// `pop reg ; ret` style — load a register from the stack.
    PopReg,
    /// `mov reg, reg ; ret` — copy a register.
    MovReg,
    /// `add reg, imm ; ret` etc. — arithmetic on a register.
    Arith,
    /// `mov [reg], reg ; ret` — write to memory.
    MemWrite,
    /// `mov reg, [reg] ; ret` — read from memory.
    MemRead,
    /// Stack pivot: alters `sp` from a controlled register.
    StackPivot,
    /// Direct system-call invocation (`syscall`/`svc`/`ecall`).
    SyscallStub,
    /// Indirect call through a CFI-valid target.
    CfiCompliant,
    /// PAC sign / authenticate gadget (`paciasp`, `xpaclri`, …).
    PacForge,
    /// Privilege-escalation gadget (e.g. RISC-V `csrrw mepc`).
    PrivEscalation,
    /// Hardware-fault stub (e.g. GhostWrite vector store).
    HardwareFault,
    /// Anything that doesn't fit the above.
    Other,
}

impl std::fmt::Display for GadgetCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::PopReg => "pop_reg",
            Self::MovReg => "mov_reg",
            Self::Arith => "arith",
            Self::MemWrite => "mem_write",
            Self::MemRead => "mem_read",
            Self::StackPivot => "stack_pivot",
            Self::SyscallStub => "syscall_stub",
            Self::CfiCompliant => "cfi_compliant",
            Self::PacForge => "pac_forge",
            Self::PrivEscalation => "priv_escalation",
            Self::HardwareFault => "hardware_fault",
            Self::Other => "other",
        };
        f.write_str(name)
    }
}

impl std::str::FromStr for GadgetCategory {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "pop_reg" => Self::PopReg,
            "mov_reg" => Self::MovReg,
            "arith" => Self::Arith,
            "mem_write" => Self::MemWrite,
            "mem_read" => Self::MemRead,
            "stack_pivot" => Self::StackPivot,
            "syscall_stub" => Self::SyscallStub,
            "cfi_compliant" => Self::CfiCompliant,
            "pac_forge" => Self::PacForge,
            "priv_escalation" => Self::PrivEscalation,
            "hardware_fault" => Self::HardwareFault,
            "other" => Self::Other,
            other => return Err(format!("unknown gadget category: {other}")),
        })
    }
}

/// What `dst = factor * src + offset`-style effect a gadget has on a
/// specific register.
///
/// `src == "*"` means "the gadget writes a fresh constant `offset`".
/// `dst == src` with `factor == 1, offset == 0` is a no-op (allowed,
/// useful as padding).
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToJson, FromJson)]
pub struct RegisterEffect {
    /// Destination register name (arch-specific, e.g. "rdi", "x0", "a0").
    pub dst: String,
    /// Source register name. `"*"` ⇒ no source, gadget loads a constant.
    pub src: String,
    /// Linear factor applied to `src`.
    pub factor: i64,
    /// Constant added after the multiplication.
    pub offset: i64,
}

impl RegisterEffect {
    /// `dst = constant`.
    #[must_use]
    pub fn load_const(dst: impl Into<String>, constant: i64) -> Self {
        Self {
            dst: dst.into(),
            src: "*".into(),
            factor: 0,
            offset: constant,
        }
    }

    /// `dst = src`.
    #[must_use]
    pub fn copy(dst: impl Into<String>, src: impl Into<String>) -> Self {
        Self {
            dst: dst.into(),
            src: src.into(),
            factor: 1,
            offset: 0,
        }
    }

    /// `dst = src + offset`.
    #[must_use]
    pub fn add_const(dst: impl Into<String>, src: impl Into<String>, offset: i64) -> Self {
        Self {
            dst: dst.into(),
            src: src.into(),
            factor: 1,
            offset,
        }
    }
}

/// How control leaves a gadget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum Terminator {
    /// Plain `ret`.
    Ret,
    /// Indirect jump (JOP).
    JumpReg,
    /// Indirect call (COP).
    CallReg,
    /// System-call (`syscall`/`svc`).
    Syscall,
    /// Privileged return (`mret`/`eret`).
    PrivilegedReturn,
}

/// A concrete gadget — a real instruction sequence at a known address.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct Gadget {
    /// Address in the target image (0 for synthetic / abstract).
    pub address: u64,
    /// Symbolic CPU-state transition.
    pub effects: Vec<RegisterEffect>,
    /// How control leaves the gadget.
    pub terminator: Terminator,
    /// Category tag.
    pub category: GadgetCategory,
    /// Human-readable label (mnemonic-ish).
    pub label: String,
    /// Original raw bytes (empty for synthetic gadgets).
    pub raw: Vec<u8>,
    /// Registers this gadget *clobbers as a side-effect* — i.e. writes
    /// values that cannot be predicted from its effects.
    ///
    /// Used by the BGAT assembler to reject chains where gadget B
    /// clobbers a register that a later goal assumes gadget A already
    /// pinned. On MIPS this also captures delay-slot side-effects: if
    /// the delay slot executes `addiu $t9, $t9, 0x18` the scanner
    /// records `$t9` as clobbered.
    #[json(default)]
    pub clobbers: Vec<String>,
}

impl Gadget {
    /// Convenience constructor for a concrete `pop reg ; ret`-style gadget.
    #[must_use]
    pub fn pop_reg(address: u64, reg: impl Into<String>, raw: Vec<u8>) -> Self {
        let reg = reg.into();
        let mut effects: Vec<RegisterEffect> = Vec::new();
        effects.push(RegisterEffect::load_const(reg.clone(), 0));
        Self {
            address,
            effects,
            terminator: Terminator::Ret,
            category: GadgetCategory::PopReg,
            label: format!("pop {reg} ; ret"),
            raw,
            clobbers: Vec::new(),
        }
    }

    /// Convenience: `syscall ; ret` style (Linux x86_64).
    #[must_use]
    pub fn syscall(address: u64, raw: Vec<u8>) -> Self {
        Self {
            address,
            effects: Vec::new(),
            terminator: Terminator::Syscall,
            category: GadgetCategory::SyscallStub,
            label: "syscall ; ret".into(),
            raw,
            clobbers: Vec::new(),
        }
    }

    /// `true` if this gadget writes `reg` either through an effect or
    /// as a declared side-effect clobber.
    #[must_use]
    pub fn clobbers(&self, reg: &str) -> bool {
        self.clobbers.iter().any(|c| c == reg)
    }

    /// `true` if this gadget's [`CpuStateTransition`] writes `reg`.
    #[must_use]
    pub fn writes(&self, reg: &str) -> bool {
        self.effects.iter().any(|e| e.dst == reg)
    }
}

/// "Abstract" placeholder for a gadget that hasn't been resolved to a real
/// address yet. Mitigation bypasses produce these; the chain assembler
/// replaces them with concrete [`Gadget`]s by querying the [`super::finder`].
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct GadgetSpec {
    /// Required category.
    pub category: GadgetCategory,
    /// Human-readable label (used to find the right gadget).
    pub label: String,
    /// Optional concrete address pinning.
    pub fixed_address: Option<u64>,
}

impl GadgetSpec {
    /// Build an abstract spec — no concrete address yet.
    #[must_use]
    pub fn abstract_(category: GadgetCategory, label: impl Into<String>) -> Self {
        Self {
            category,
            label: label.into(),
            fixed_address: None,
        }
    }

    /// Pin to a concrete address.
    #[must_use]
    pub fn at(category: GadgetCategory, label: impl Into<String>, address: u64) -> Self {
        Self {
            category,
            label: label.into(),
            fixed_address: Some(address),
        }
    }
}

/// One entry in an assembled chain — what gets serialised into the final
/// [`crate::SynthesizedPayload`].
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct GadgetEntry {
    /// Address of the gadget.
    pub address: u64,
    /// Human-readable label.
    pub label: String,
    /// Category (echoed for forensic reports).
    pub category: GadgetCategory,
    /// Stack-frame data this entry pushes after the address (e.g.
    /// "pop rdi ; ret" pushes its rdi value here). For abstract / pre-arch
    /// gadgets this is always empty.
    pub stack_data: Vec<u8>,
}

impl GadgetEntry {
    /// Build from a concrete gadget.
    #[must_use]
    pub fn from_gadget(g: &Gadget) -> Self {
        Self {
            address: g.address,
            label: g.label.clone(),
            category: g.category,
            stack_data: Vec::new(),
        }
    }
}

/// What the SMT assembler reasons about: a sequence of [`RegisterEffect`]s
/// for one gadget, expressed as a pure data type so we can `Hash + Eq`
/// it for the BGAT cache.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToJson, FromJson)]
pub struct CpuStateTransition {
    /// The effects to apply, in order.
    pub effects: Vec<RegisterEffect>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pop_reg_gadget_writes_target_register() {
        let g = Gadget::pop_reg(0x0040_1400, "rdi", vec![0x5F, 0xC3]);
        assert!(g.writes("rdi"));
        assert!(!g.writes("rsi"));
        assert_eq!(g.terminator, Terminator::Ret);
        assert_eq!(g.category, GadgetCategory::PopReg);
    }

    #[test]
    fn abstract_spec_has_no_address() {
        let s = GadgetSpec::abstract_(GadgetCategory::PacForge, "paciasp");
        assert!(s.fixed_address.is_none());
        let s = GadgetSpec::at(GadgetCategory::PopReg, "pop rdi", 0x0040_1100);
        assert_eq!(s.fixed_address, Some(0x0040_1100));
    }
}
