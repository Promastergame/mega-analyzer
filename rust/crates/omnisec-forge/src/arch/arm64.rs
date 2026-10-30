//! ARM64 (AArch64) emitter.
//!
//! AAPCS calling convention: x0..x7 carry the first 8 integer arguments.
//! Syscall number lives in `x8`.
//!
//! Notes specific to this emitter:
//!
//! - PAC: when [`crate::config::ForgeConfig::mitigation`] expands to a
//!   profile that includes [`crate::mitigation::MitigationKind::Pac`],
//!   the chain assembler is also fed the `paciasp`/`autiasp` abstract
//!   gadgets and has to splice them around the chain entry/exit. We do
//!   *not* compute MAC values here — that's the oracle stage's job.
//! - Branch-target identification (BTI): all chain entry points are
//!   assumed to land on a `bti c`-tagged instruction; if the gadget pool
//!   contains BTI-untagged candidates the emitter still produces
//!   register goals — the chain assembler will simply not pick them up.

use omnisec_core::{Arch, Endian};

use crate::chains::assembler::RegisterGoal;
use crate::error::Result;
use crate::primitive::ChainGoal;

use super::ArchEmitter;

/// ARM64 emitter.
#[derive(Debug, Default, Clone, Copy)]
pub struct Arm64Emitter;

impl ArchEmitter for Arm64Emitter {
    fn arch(&self) -> Arch {
        Arch::Arm64
    }

    fn pointer_width_bits(&self) -> u32 {
        64
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn arg_registers(&self) -> &'static [&'static str] {
        &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
    }

    fn syscall_nr_register(&self) -> &'static str {
        "x8"
    }

    fn lower(&self, goal: &ChainGoal) -> Result<Vec<RegisterGoal>> {
        const SYS_EXECVE: i64 = 221;
        const SYS_MPROTECT: i64 = 226;
        const PROT_RWX: i64 = 0x7;
        match goal {
            ChainGoal::SpawnShell | ChainGoal::SpawnCommand { .. } => Ok(vec![
                RegisterGoal {
                    register: "x0".into(),
                    value: 0,
                },
                RegisterGoal {
                    register: "x1".into(),
                    value: 0,
                },
                RegisterGoal {
                    register: "x2".into(),
                    value: 0,
                },
                RegisterGoal {
                    register: "x8".into(),
                    value: SYS_EXECVE,
                },
            ]),
            ChainGoal::MakeRwxAndJump { addr, len } => Ok(vec![
                RegisterGoal {
                    register: "x0".into(),
                    value: *addr as i64,
                },
                RegisterGoal {
                    register: "x1".into(),
                    value: *len as i64,
                },
                RegisterGoal {
                    register: "x2".into(),
                    value: PROT_RWX,
                },
                RegisterGoal {
                    register: "x8".into(),
                    value: SYS_MPROTECT,
                },
            ]),
            ChainGoal::StackPivot { .. } => Ok(vec![RegisterGoal {
                register: "sp".into(),
                value: 0,
            }]),
            ChainGoal::DataMutation { addr, .. } => Ok(vec![RegisterGoal {
                register: "x0".into(),
                value: *addr as i64,
            }]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm64_uses_x8_for_syscall_nr() {
        assert_eq!(Arm64Emitter.syscall_nr_register(), "x8");
    }

    #[test]
    fn arm64_arg_regs_are_x0_through_x7() {
        assert_eq!(Arm64Emitter.arg_registers().len(), 8);
        assert_eq!(Arm64Emitter.arg_registers()[0], "x0");
    }
}
