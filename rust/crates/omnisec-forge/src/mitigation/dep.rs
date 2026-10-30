//! DEP / NX (no-execute) bypass strategy.
//!
//! With DEP enabled, the synthesised payload cannot live on the stack —
//! we have to either:
//!
//! 1. ROP/JOP entirely in `.text`, or
//! 2. call `mprotect`/`VirtualProtect`/`mmap(PROT_EXEC)` to flip the page
//!    permissions of a controlled region, then jump to it.
//!
//! Strategy 2 is what most modern primitives end up using because it
//! short-circuits the rest of the gadget search. This module
//! pre-allocates a `make_rwx_and_jump` auxiliary gadget spec that
//! [`crate::chains::SmtAssembler`] will resolve concretely on the
//! target arch.

use omnisec_core::Arch;

use crate::chains::{GadgetCategory, GadgetSpec};
use crate::error::Result;
use crate::primitive::{ChainGoal, VulnerabilityPrimitive};
use crate::util::Prng;

use super::{Bypass, BypassPlan, MitigationKind};

/// DEP / NX bypass.
#[derive(Debug, Default, Clone, Copy)]
pub struct DepNxBypass;

impl Bypass for DepNxBypass {
    fn kind(&self) -> MitigationKind {
        MitigationKind::DepNx
    }

    fn applies_to(&self, arch: Arch) -> bool {
        arch.is_native()
    }

    fn plan(&self, primitive: &VulnerabilityPrimitive, _prng: &mut Prng) -> Result<BypassPlan> {
        let mut plan = BypassPlan {
            kind: Some(MitigationKind::DepNx),
            ..Default::default()
        };

        match &primitive.goal {
            ChainGoal::MakeRwxAndJump { addr, len } => {
                plan.notes.push(format!(
                    "Goal already calls mprotect-equivalent on {addr:#x}+{len:#x}"
                ));
                plan.auxiliary_gadgets.push(GadgetSpec::abstract_(
                    GadgetCategory::SyscallStub,
                    "mprotect",
                ));
            }
            ChainGoal::SpawnShell | ChainGoal::SpawnCommand { .. } => {
                plan.notes.push(
                    "DEP bypass: chain calls libc directly (system / execve), no shellcode page needed".into(),
                );
            }
            ChainGoal::StackPivot { .. } => {
                plan.notes
                    .push("DEP bypass: pivot first, then ROP through libc gadgets".into());
                plan.auxiliary_gadgets.push(GadgetSpec::abstract_(
                    GadgetCategory::StackPivot,
                    "stack_pivot",
                ));
            }
            ChainGoal::DataMutation { .. } => {
                plan.notes
                    .push("DEP bypass irrelevant for data-only primitives".into());
            }
        }

        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitive::PrimitiveKind;

    #[test]
    fn rwx_goal_emits_syscall_stub() {
        let p = VulnerabilityPrimitive::new(
            "rwx",
            Arch::X86_64,
            PrimitiveKind::StackBufferOverflow,
            ChainGoal::MakeRwxAndJump {
                addr: 0x0040_1400,
                len: 0x1000,
            },
        );
        let plan = DepNxBypass.plan(&p, &mut Prng::new(0)).unwrap();
        assert!(
            plan.auxiliary_gadgets
                .iter()
                .any(|g| g.category == GadgetCategory::SyscallStub)
        );
    }

    #[test]
    fn data_mutation_goal_is_noop() {
        let p = VulnerabilityPrimitive::new(
            "dop",
            Arch::X86_64,
            PrimitiveKind::LogicFlaw,
            ChainGoal::DataMutation {
                addr: 0x0060_1020,
                write: vec![1],
            },
        );
        let plan = DepNxBypass.plan(&p, &mut Prng::new(0)).unwrap();
        assert!(plan.auxiliary_gadgets.is_empty());
    }
}
