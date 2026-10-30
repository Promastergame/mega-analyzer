//! [`ForgeEngine`] — the Phase-4 orchestrator.
//!
//! Walks every primitive through the same five-stage pipeline:
//!
//! 1. **Validate** — config / primitive arch must agree.
//! 2. **MitigationPlanning** — every active mitigation contributes its
//!    [`crate::mitigation::BypassPlan`].
//! 3. **GoalLowering** — arch-specific [`crate::arch::ArchEmitter`]
//!    converts the abstract [`crate::primitive::ChainGoal`] into
//!    register goals.
//! 4. **ChainAssembly** — either [`crate::chains::SmtAssembler`] (when
//!    the primitive needs a control-flow chain) or
//!    [`crate::dop::DopCfiPlanner`] (when DOP is preferred).
//! 5. **PayloadEncoding** — bad-byte avoidance via
//!    [`crate::encoding::PolymorphicEncoder`].
//! 6. **OracleVerification** — optional, only runs when
//!    [`crate::ForgeConfig::run_oracle`] is true.

pub mod engine;

pub use engine::{ForgeEngine, ForgeStage, ForgeStageReport};
