//! Mitigation bypass strategies.
//!
//! Each mitigation kind has a corresponding [`Bypass`] implementation that
//! turns the abstract "we need to defeat ASLR / DEP / PAC / MTE / CFI / PMP"
//! intent into a concrete [`BypassPlan`]: extra gadgets to splice into the
//! chain, additional bad-byte constraints, witness overrides, and free-form
//! notes the per-stage report can render.
//!
//! Everything here is pure CPU-side logic. There is no random search and
//! no model inference — the strategies are deterministic functions of
//! `(VulnerabilityPrimitive, ForgeConfig::seed)`.

use omnisec_core::Arch;
use omnisec_json::{FromJson, ToJson};

use crate::chains::GadgetSpec;
use crate::error::Result;
use crate::primitive::VulnerabilityPrimitive;
use crate::util::Prng;

pub mod aslr;
pub mod canary;
pub mod cfi;
pub mod dep;
pub mod mte;
pub mod pac;
pub mod pmp;

pub use aslr::AslrBypass;
pub use canary::StackCanaryBypass;
pub use cfi::CfiBypass;
pub use dep::DepNxBypass;
pub use mte::MteBypass;
pub use pac::PacBypass;
pub use pmp::PmpBypass;

/// Every mitigation the Forge knows how to plan around.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum MitigationKind {
    /// Address-space layout randomisation.
    Aslr,
    /// Data-Execution Prevention / NX bit.
    DepNx,
    /// Stack canary / `__stack_chk_guard`.
    StackCanary,
    /// Control-Flow Integrity (LLVM CFI, Clang shadow-call-stack, …).
    Cfi,
    /// ARM64 Pointer Authentication.
    Pac,
    /// ARM64 Memory Tagging Extension.
    Mte,
    /// RISC-V Physical Memory Protection.
    Pmp,
}

impl MitigationKind {
    /// Short canonical name used in reports / tests.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aslr => "aslr",
            Self::DepNx => "dep_nx",
            Self::StackCanary => "stack_canary",
            Self::Cfi => "cfi",
            Self::Pac => "pac",
            Self::Mte => "mte",
            Self::Pmp => "pmp",
        }
    }
}

impl std::fmt::Display for MitigationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Concrete bypass plan produced by a [`Bypass`].
///
/// We intentionally make this a plain data struct rather than a `dyn` trait
/// object: the engine merges plans from multiple bypasses and the merge
/// is just `Vec::extend` over each field.
#[derive(Debug, Clone, Default, PartialEq, Eq, ToJson, FromJson)]
pub struct BypassPlan {
    /// Which mitigation this plan addresses.
    pub kind: Option<MitigationKind>,
    /// Free-form notes recorded on the per-stage report.
    pub notes: Vec<String>,
    /// Auxiliary gadgets the chain assembler must splice in *before* the
    /// main goal gadgets (e.g. a `paciasp` / `xpaclri` pair on ARM64).
    pub auxiliary_gadgets: Vec<GadgetSpec>,
    /// Extra bytes the encoder must avoid in the final payload.
    pub bad_bytes: Vec<u8>,
    /// Hard-pin a Phase-3 witness variable to a specific value (e.g. a
    /// canary leak the bypass discovered).
    pub witness_overrides: Vec<(String, i128, u32)>,
}

impl BypassPlan {
    /// Empty plan — used when a bypass deems no action necessary.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Merge another plan into this one in-place.
    pub fn merge(&mut self, other: BypassPlan) {
        if self.kind.is_none() {
            self.kind = other.kind;
        }
        self.notes.extend(other.notes);
        self.auxiliary_gadgets.extend(other.auxiliary_gadgets);
        self.bad_bytes.extend(other.bad_bytes);
        self.bad_bytes.sort_unstable();
        self.bad_bytes.dedup();
        self.witness_overrides.extend(other.witness_overrides);
    }
}

/// A bypass strategy — one per [`MitigationKind`].
pub trait Bypass {
    /// Mitigation this strategy addresses.
    fn kind(&self) -> MitigationKind;

    /// `true` if this bypass strategy applies to `arch`.
    fn applies_to(&self, arch: Arch) -> bool;

    /// Synthesize a deterministic plan for the given primitive.
    fn plan(&self, primitive: &VulnerabilityPrimitive, prng: &mut Prng) -> Result<BypassPlan>;
}

/// Construct the right [`Bypass`] for a given mitigation, or `None` if we
/// don't have a strategy for it on this arch.
#[must_use]
pub fn bypass_for(kind: MitigationKind) -> Box<dyn Bypass + Send + Sync> {
    match kind {
        MitigationKind::Aslr => Box::new(AslrBypass),
        MitigationKind::DepNx => Box::new(DepNxBypass),
        MitigationKind::StackCanary => Box::new(StackCanaryBypass),
        MitigationKind::Cfi => Box::new(CfiBypass),
        MitigationKind::Pac => Box::new(PacBypass),
        MitigationKind::Mte => Box::new(MteBypass),
        MitigationKind::Pmp => Box::new(PmpBypass),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_merge_is_dedup_sorted() {
        let mut a = BypassPlan {
            kind: Some(MitigationKind::Aslr),
            notes: vec!["a".into()],
            bad_bytes: vec![0x0a, 0x00],
            ..Default::default()
        };
        let b = BypassPlan {
            notes: vec!["b".into()],
            bad_bytes: vec![0x00, 0x0d],
            ..Default::default()
        };
        a.merge(b);
        assert_eq!(a.notes, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(a.bad_bytes, vec![0x00, 0x0a, 0x0d]);
    }
}
