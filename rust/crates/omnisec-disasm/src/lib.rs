//! Multi-arch disassembly & lifting into OmniIR.
//!
//! Phase 1 ships only `x86` / `x86_64` (via `iced-x86`). ARM64 and MIPS
//! lifters live behind the same [`Disassembler`] trait and will arrive
//! when the corresponding loaders need them.
//!
//! ## What this crate is and isn't
//!
//! - **Is**: a *linear-sweep* decoder + a coarse opcode mapper. Given a byte
//!   slice and a base virtual address, it emits a stream of OmniIR
//!   [`Instruction`]s.
//! - **Is not** (yet): a recursive-traversal disassembler, an SSA former, or
//!   a register-aware data-flow lifter. Those are downstream, in
//!   `omnisec-cfg` / `omnisec-analysis`.
//!
//! ### Mapping fidelity
//!
//! For Phase 1 we map only the "data path" instructions every analysis
//! needs (mov / add / sub / xor / and / or / cmp / test / push / pop /
//! call / jmp / jcc / ret). Everything else lands as
//! [`OpCode::Custom`] with the iced mnemonic preserved in
//! [`Instruction::mnemonic`]. Coverage will tighten as we move into
//! Phase 2 (SSA, taint).

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod traits;
pub mod x86;

pub use traits::Disassembler;
pub use x86::X86Disassembler;

use omnisec_core::Arch;
use omnisec_ir::Instruction;

/// Pick a default disassembler for an architecture, if we ship one.
///
/// Returns `None` for archs we don't yet support; callers should treat that
/// as "skip lifting, keep raw bytes".
#[must_use]
pub fn default_for(arch: Arch) -> Option<Box<dyn Disassembler>> {
    match arch {
        Arch::X86 => Some(Box::new(X86Disassembler::new_32())),
        Arch::X86_64 => Some(Box::new(X86Disassembler::new_64())),
        _ => None,
    }
}

/// Convenience: linear-sweep `bytes` at `base_addr` using the default
/// disassembler for `arch`. Returns an empty `Vec` for unsupported arches.
#[must_use]
pub fn linear_sweep(arch: Arch, bytes: &[u8], base_addr: u64) -> Vec<Instruction> {
    default_for(arch)
        .map(|d| d.disassemble(bytes, base_addr))
        .unwrap_or_default()
}
