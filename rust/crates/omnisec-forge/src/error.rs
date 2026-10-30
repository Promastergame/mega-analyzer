//! Crate-level error and result types.

/// Forge result alias.
pub type Result<T> = std::result::Result<T, ForgeError>;

/// Every error a Forge stage can emit.
#[derive(Debug)]
pub enum ForgeError {
    /// The vulnerability primitive's required architecture does not match the
    /// architecture configured on the Forge.
    ArchMismatch {
        /// Architecture configured on the Forge.
        expected: omnisec_core::Arch,
        /// Architecture the primitive needs.
        actual: omnisec_core::Arch,
    },

    /// We could not satisfy the SMT constraints required to assemble a chain
    /// or a polymorphic encoder.
    Unsat(String),

    /// SMT solver returned `Unknown` (theory incomplete on this constraint).
    SmtUnknown(String),

    /// We exhausted the gadget search budget without finding a chain.
    BudgetExhausted(String),

    /// The requested mitigation bypass is not implemented for this arch.
    UnsupportedMitigation {
        /// Mitigation name (e.g. "PAC", "MTE").
        bypass: &'static str,
        /// Target architecture.
        arch: omnisec_core::Arch,
    },

    /// A required input field was missing on the primitive.
    MissingInput(&'static str),

    /// Generic invariant violation — should never happen if the Forge code is
    /// correct.
    Invariant(&'static str),
}

impl std::fmt::Display for ForgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ArchMismatch { expected, actual } => {
                write!(
                    f,
                    "architecture mismatch: forge targets {expected}, primitive requires {actual}"
                )
            }
            Self::Unsat(msg) => write!(f, "SMT constraint set is unsatisfiable: {msg}"),
            Self::SmtUnknown(msg) => write!(f, "SMT solver could not decide: {msg}"),
            Self::BudgetExhausted(msg) => write!(f, "BGAT search budget exhausted: {msg}"),
            Self::UnsupportedMitigation { bypass, arch } => {
                write!(f, "mitigation bypass {bypass} is not supported on {arch}")
            }
            Self::MissingInput(what) => write!(f, "missing primitive input: {what}"),
            Self::Invariant(what) => write!(f, "forge invariant violated: {what}"),
        }
    }
}

impl std::error::Error for ForgeError {}
