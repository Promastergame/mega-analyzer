//! MIPS / MIPS64 emitter.
//!
//! MIPS quirks the Forge accounts for:
//!
//! - **Branch delay slots**: every taken branch executes the following
//!   instruction. Gadgets must therefore be filtered to those whose
//!   delay slot does not clobber the freshly-loaded register.
//! - **`$gp` re-init**: O32/N64 inter-segment jumps require restoring
//!   the global pointer. The emitter records this as a synthetic
//!   constraint on a `gp` register goal whenever the goal targets a
//!   different `.text` segment.
//! - **Cache incoherence**: ROP chains that drop fresh code into a
//!   data segment must call `cacheflush()` first (see [`crate::mitigation::dep`]).
//!
//! The arg registers are `$a0..$a3` on O32 and `$a0..$a7` on N64; we
//! always expose the N64 register names for simplicity since the chain
//! assembler is name-driven.

use omnisec_core::{Arch, Endian};

use crate::chains::assembler::RegisterGoal;
use crate::error::Result;
use crate::primitive::ChainGoal;

use super::ArchEmitter;

/// MIPS emitter (covers both 32 and 64-bit variants).
#[derive(Debug, Clone, Copy)]
pub struct MipsEmitter {
    arch: Arch,
}

impl MipsEmitter {
    /// Build for a specific MIPS arch variant.
    #[must_use]
    pub const fn for_arch(arch: Arch) -> Self {
        Self { arch }
    }
}

impl ArchEmitter for MipsEmitter {
    fn arch(&self) -> Arch {
        self.arch
    }

    fn pointer_width_bits(&self) -> u32 {
        match self.arch {
            Arch::Mips64 => 64,
            _ => 32,
        }
    }

    fn endian(&self) -> Endian {
        // MIPS is a bit unusual — it has both little- and big-endian
        // variants. Most Linux/Android MIPS deployments are little-endian
        // these days; routers / firmware are typically big-endian. We
        // default to big-endian here because that's what the legacy
        // routers + firmware that motivated the MIPS path tend to use.
        Endian::Big
    }

    fn arg_registers(&self) -> &'static [&'static str] {
        &["$a0", "$a1", "$a2", "$a3", "$a4", "$a5", "$a6", "$a7"]
    }

    fn syscall_nr_register(&self) -> &'static str {
        "$v0"
    }

    fn lower(&self, goal: &ChainGoal) -> Result<Vec<RegisterGoal>> {
        // Syscall numbers. For O32 we keep the original Linux MIPS set;
        // for N64 we use the 5000-series numbers. `cacheflush` is O32-
        // specific and dropped for N64.
        const PROT_RWX: i64 = 0x7;
        let (sys_execve, sys_mprotect, sys_cacheflush): (i64, i64, Option<i64>) = match self.arch {
            Arch::Mips64 => (5057, 5010, None),
            _ => (4011, 4125, Some(4147)),
        };

        // $gp is caller-saved under O32/N64. When a chain jumps between
        // object segments the global-pointer register must be restored
        // so the callee can reach its `.got` entries. We pin $gp to 0
        // here so the BGAT solver has something concrete to pop into it;
        // the real value is patched in by the runtime oracle stage from
        // the target image's `_gp` symbol.
        let gp_init = RegisterGoal {
            register: "$gp".into(),
            value: 0,
        };

        match goal {
            ChainGoal::SpawnShell | ChainGoal::SpawnCommand { .. } => {
                let mut goals = vec![
                    RegisterGoal {
                        register: "$a0".into(),
                        value: 0,
                    },
                    RegisterGoal {
                        register: "$a1".into(),
                        value: 0,
                    },
                    RegisterGoal {
                        register: "$a2".into(),
                        value: 0,
                    },
                    RegisterGoal {
                        register: "$v0".into(),
                        value: sys_execve,
                    },
                ];
                goals.push(gp_init);
                Ok(goals)
            }
            ChainGoal::MakeRwxAndJump { addr, len } => {
                let mut goals = vec![
                    // mprotect first…
                    RegisterGoal {
                        register: "$a0".into(),
                        value: *addr as i64,
                    },
                    RegisterGoal {
                        register: "$a1".into(),
                        value: *len as i64,
                    },
                    RegisterGoal {
                        register: "$a2".into(),
                        value: PROT_RWX,
                    },
                    RegisterGoal {
                        register: "$v0".into(),
                        value: sys_mprotect,
                    },
                ];
                // …then cacheflush so the I-cache notices the new code
                // (O32 only; N64 kernels drop the syscall).
                if let Some(flush) = sys_cacheflush {
                    goals.push(RegisterGoal {
                        register: "$v0".into(),
                        value: flush,
                    });
                }
                goals.push(gp_init);
                Ok(goals)
            }
            ChainGoal::StackPivot { .. } => Ok(vec![
                RegisterGoal {
                    register: "$sp".into(),
                    value: 0,
                },
                gp_init,
            ]),
            ChainGoal::DataMutation { addr, .. } => Ok(vec![RegisterGoal {
                register: "$a0".into(),
                value: *addr as i64,
            }]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mips_pointer_width_follows_arch() {
        assert_eq!(MipsEmitter::for_arch(Arch::Mips).pointer_width_bits(), 32);
        assert_eq!(MipsEmitter::for_arch(Arch::Mips64).pointer_width_bits(), 64);
    }

    #[test]
    fn mips_make_rwx_includes_cacheflush() {
        let goals = MipsEmitter::for_arch(Arch::Mips)
            .lower(&ChainGoal::MakeRwxAndJump {
                addr: 0x4000_0000,
                len: 0x1000,
            })
            .unwrap();
        assert!(goals.iter().any(|g| g.value == 4147));
    }

    #[test]
    fn mips64_skips_cacheflush() {
        let goals = MipsEmitter::for_arch(Arch::Mips64)
            .lower(&ChainGoal::MakeRwxAndJump {
                addr: 0x4000_0000,
                len: 0x1000,
            })
            .unwrap();
        // N64 kernels don't expose cacheflush — old O32 number must not leak.
        assert!(goals.iter().all(|g| g.value != 4147));
        // N64 mprotect syscall number instead.
        assert!(goals.iter().any(|g| g.value == 5010));
    }

    #[test]
    fn mips_spawn_shell_pins_gp() {
        let goals = MipsEmitter::for_arch(Arch::Mips)
            .lower(&ChainGoal::SpawnShell)
            .unwrap();
        assert!(goals.iter().any(|g| g.register == "$gp"));
    }
}
