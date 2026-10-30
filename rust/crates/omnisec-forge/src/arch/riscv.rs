//! RISC-V emitter (RV32 / RV64).
//!
//! RISC-V quirks the Forge accounts for:
//!
//! - **Compressed instructions (RVC)**: 16-bit aligned gadgets can be
//!   located by scanning the binary at every 2-byte offset, not 4. The
//!   gadget finder handles this automatically; here we just expose the
//!   right register names for both `a*` (integer args) and `c.*`
//!   compressed-form-friendly aliases.
//! - **PMP**: handled by [`crate::mitigation::pmp::PmpBypass`].
//! - **GhostWrite**: when a primitive is tagged
//!   [`crate::primitive::PrimitiveKind::HardwareFault`] on RISC-V we
//!   accept goals that target physically-mapped pages even when PMP
//!   would normally block them; the bypass plan attaches the
//!   `ghostwrite_stub`.
//!
//! Linux RISC-V uses a unified syscall numbering very similar to
//! ARM64's. We hard-code the small set we need.

use omnisec_core::{Arch, Endian};

use crate::chains::assembler::RegisterGoal;
use crate::error::Result;
use crate::primitive::ChainGoal;

use super::ArchEmitter;

/// RISC-V emitter (32 / 64-bit).
#[derive(Debug, Clone, Copy)]
pub struct RiscVEmitter {
    arch: Arch,
}

impl RiscVEmitter {
    /// Build for a specific RISC-V variant.
    #[must_use]
    pub const fn for_arch(arch: Arch) -> Self {
        Self { arch }
    }
}

impl ArchEmitter for RiscVEmitter {
    fn arch(&self) -> Arch {
        self.arch
    }

    fn pointer_width_bits(&self) -> u32 {
        match self.arch {
            Arch::RiscV32 => 32,
            _ => 64,
        }
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn arg_registers(&self) -> &'static [&'static str] {
        // a0..a7 are the integer arg regs.
        &["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
    }

    fn syscall_nr_register(&self) -> &'static str {
        "a7"
    }

    fn lower(&self, goal: &ChainGoal) -> Result<Vec<RegisterGoal>> {
        const SYS_EXECVE: i64 = 221;
        const SYS_MPROTECT: i64 = 226;
        const PROT_RWX: i64 = 0x7;

        match goal {
            ChainGoal::SpawnShell | ChainGoal::SpawnCommand { .. } => Ok(vec![
                RegisterGoal {
                    register: "a0".into(),
                    value: 0,
                },
                RegisterGoal {
                    register: "a1".into(),
                    value: 0,
                },
                RegisterGoal {
                    register: "a2".into(),
                    value: 0,
                },
                RegisterGoal {
                    register: "a7".into(),
                    value: SYS_EXECVE,
                },
            ]),
            ChainGoal::MakeRwxAndJump { addr, len } => Ok(vec![
                RegisterGoal {
                    register: "a0".into(),
                    value: *addr as i64,
                },
                RegisterGoal {
                    register: "a1".into(),
                    value: *len as i64,
                },
                RegisterGoal {
                    register: "a2".into(),
                    value: PROT_RWX,
                },
                RegisterGoal {
                    register: "a7".into(),
                    value: SYS_MPROTECT,
                },
            ]),
            ChainGoal::StackPivot { .. } => Ok(vec![RegisterGoal {
                register: "sp".into(),
                value: 0,
            }]),
            ChainGoal::DataMutation { addr, .. } => Ok(vec![RegisterGoal {
                register: "a0".into(),
                value: *addr as i64,
            }]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn riscv_arg_regs_start_at_a0() {
        let regs = RiscVEmitter::for_arch(Arch::RiscV64).arg_registers();
        assert_eq!(regs[0], "a0");
        assert_eq!(regs.len(), 8);
    }

    #[test]
    fn riscv_syscall_nr_lives_in_a7() {
        assert_eq!(
            RiscVEmitter::for_arch(Arch::RiscV64).syscall_nr_register(),
            "a7"
        );
    }
}
