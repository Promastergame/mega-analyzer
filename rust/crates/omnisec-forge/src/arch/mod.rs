//! Per-architecture emitters.
//!
//! Each architecture implements [`ArchEmitter`] which lowers a
//! [`crate::primitive::ChainGoal`] into concrete [`RegisterGoal`]s using
//! the arch's calling convention, plus any arch-specific quirks
//! (MIPS delay slots, MIPS `$gp` re-init, RISC-V compressed-instruction
//! gadgets, ARM64 PAC requirements).

use omnisec_core::{Arch, Endian};

use crate::chains::assembler::RegisterGoal;
use crate::error::{ForgeError, Result};
use crate::primitive::ChainGoal;

pub mod arm64;
pub mod mips;
pub mod riscv;
pub mod x86_64;

pub use arm64::Arm64Emitter;
pub use mips::MipsEmitter;
pub use riscv::RiscVEmitter;
pub use x86_64::X86_64Emitter;

/// Common per-arch description used by the chain assembler and the
/// encoding stage.
pub trait ArchEmitter {
    /// Architecture this emitter targets.
    fn arch(&self) -> Arch;

    /// Pointer width in bits (32 / 64).
    fn pointer_width_bits(&self) -> u32;

    /// Endianness of the target.
    fn endian(&self) -> Endian;

    /// Argument registers, in calling-convention order.
    fn arg_registers(&self) -> &'static [&'static str];

    /// Register holding the syscall number.
    fn syscall_nr_register(&self) -> &'static str;

    /// Lower an abstract chain goal to a list of register goals.
    fn lower(&self, goal: &ChainGoal) -> Result<Vec<RegisterGoal>>;

    /// Encode an absolute pointer for inlining into the payload — handles
    /// per-arch endianness and pointer width.
    fn encode_pointer(&self, address: u64) -> Vec<u8> {
        let bytes = match self.endian() {
            Endian::Little => address.to_le_bytes(),
            Endian::Big => address.to_be_bytes(),
        };
        let cut = (self.pointer_width_bits() as usize) / 8;
        match self.endian() {
            Endian::Little => bytes[..cut].to_vec(),
            Endian::Big => bytes[(8 - cut)..].to_vec(),
        }
    }
}

/// Get the right emitter for `arch`. Errors with [`ForgeError::ArchMismatch`]
/// when we don't have a backend for the requested arch.
pub fn emitter_for(arch: Arch) -> Result<Box<dyn ArchEmitter + Send + Sync>> {
    match arch {
        Arch::X86_64 => Ok(Box::new(X86_64Emitter)),
        Arch::Arm64 => Ok(Box::new(Arm64Emitter)),
        Arch::Mips | Arch::Mips64 => Ok(Box::new(MipsEmitter::for_arch(arch))),
        Arch::RiscV32 | Arch::RiscV64 => Ok(Box::new(RiscVEmitter::for_arch(arch))),
        other => Err(ForgeError::ArchMismatch {
            expected: Arch::X86_64,
            actual: other,
        }),
    }
}
