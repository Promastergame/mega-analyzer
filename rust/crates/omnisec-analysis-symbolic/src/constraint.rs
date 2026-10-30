//! Constraint types for symbolic execution.

use omnisec_json::ToJson;

/// A constraint on a symbolic variable.
#[derive(Debug, Clone, ToJson)]
pub struct Constraint {
    /// Constraint type: "eq", "ne", "lt", "le", "gt", "ge", "range".
    pub kind: String,
    /// Symbolic variable name.
    pub variable: String,
    /// Constraint value.
    pub value: i64,
    /// Confidence in this constraint (0-100).
    pub confidence: u8,
}

impl Constraint {
    /// Create an equality constraint.
    pub fn eq(variable: &str, value: i64, confidence: u8) -> Self {
        Self {
            kind: "eq".into(),
            variable: variable.into(),
            value,
            confidence,
        }
    }

    /// Create an inequality constraint.
    pub fn ne(variable: &str, value: i64, confidence: u8) -> Self {
        Self {
            kind: "ne".into(),
            variable: variable.into(),
            value,
            confidence,
        }
    }

    /// Create a less-than constraint.
    pub fn lt(variable: &str, value: i64, confidence: u8) -> Self {
        Self {
            kind: "lt".into(),
            variable: variable.into(),
            value,
            confidence,
        }
    }

    /// Check if this constraint can be solved concretely.
    pub fn is_solvable(&self) -> bool {
        matches!(
            self.kind.as_str(),
            "eq" | "ne" | "lt" | "le" | "gt" | "ge" | "range"
        )
    }
}
