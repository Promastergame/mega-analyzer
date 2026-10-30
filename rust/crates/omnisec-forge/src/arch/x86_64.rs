//! x86_64 / AMD64 emitter.
//!
//! System V AMD64 calling convention: rdi, rsi, rdx, rcx, r8, r9. Syscall
//! number lives in rax.

use omnisec_core::{Arch, Endian};

use crate::chains::assembler::RegisterGoal;
use crate::error::Result;
use crate::primitive::ChainGoal;

use super::ArchEmitter;

/// x86_64 emitter.
#[derive(Debug, Default, Clone, Copy)]
pub struct X86_64Emitter;

impl ArchEmitter for X86_64Emitter {
    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn pointer_width_bits(&self) -> u32 {
        64
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn arg_registers(&self) -> &'static [&'static str] {
        &["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    }

    fn syscall_nr_register(&self) -> &'static str {
        "rax"
    }

    fn lower(&self, goal: &ChainGoal) -> Result<Vec<RegisterGoal>> {
        // Syscall numbers (Linux x86_64).
        const SYS_EXECVE: i64 = 59;
        const SYS_MPROTECT: i64 = 10;
        const PROT_READ_WRITE_EXEC: i64 = 0x7;

        match goal {
            ChainGoal::SpawnShell | ChainGoal::SpawnCommand { .. } => Ok(vec![
                RegisterGoal {
                    register: "rdi".into(),
                    value: 0, // placeholder for /bin/sh address
                },
                RegisterGoal {
                    register: "rsi".into(),
                    value: 0,
                },
                RegisterGoal {
                    register: "rdx".into(),
                    value: 0,
                },
                RegisterGoal {
                    register: "rax".into(),
                    value: SYS_EXECVE,
                },
            ]),
            ChainGoal::MakeRwxAndJump { addr, len } => Ok(vec![
                RegisterGoal {
                    register: "rdi".into(),
                    value: *addr as i64,
                },
                RegisterGoal {
                    register: "rsi".into(),
                    value: *len as i64,
                },
                RegisterGoal {
                    register: "rdx".into(),
                    value: PROT_READ_WRITE_EXEC,
                },
                RegisterGoal {
                    register: "rax".into(),
                    value: SYS_MPROTECT,
                },
            ]),
            ChainGoal::StackPivot { .. } => Ok(vec![RegisterGoal {
                register: "rsp".into(),
                value: 0,
            }]),
            ChainGoal::DataMutation { addr, .. } => Ok(vec![RegisterGoal {
                register: "rdi".into(),
                value: *addr as i64,
            }]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execve_lowering_yields_four_register_goals() {
        let goals = X86_64Emitter.lower(&ChainGoal::SpawnShell).unwrap();
        assert_eq!(goals.len(), 4);
        assert_eq!(goals[3].register, "rax");
        assert_eq!(goals[3].value, 59);
    }

    #[test]
    fn pointer_encoding_is_little_endian_8_bytes() {
        let bytes = X86_64Emitter.encode_pointer(0xDEAD_BEEF);
        assert_eq!(bytes, vec![0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0]);
    }
}
