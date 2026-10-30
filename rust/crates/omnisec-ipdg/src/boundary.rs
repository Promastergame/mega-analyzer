//! Representation of process boundaries and IPC mechanisms.

use crate::component::ComponentId;
use omnisec_json::{FromJson, ToJson};

/// Type of process boundary or IPC mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
pub enum BoundaryKind {
    /// Java Native Interface (Java/Kotlin <-> C/C++)
    Jni,
    /// System call (User <-> Kernel)
    Syscall,
    /// I/O Control (User <-> Driver)
    Ioctl,
    /// Android Binder IPC
    Binder,
    /// Network or Unix domain socket
    Socket,
    /// Named or anonymous pipe
    Pipe,
    /// Shared memory region
    SharedMemory,
    /// Message queue
    MessageQueue,
    /// POSIX signal
    Signal,
    /// Hardware interrupt
    HardwareInterrupt,
    /// Remote Procedure Call
    Rpc,
    /// FastCGI interface
    FastCgi,
    /// HTTP/HTTPS request
    Http,
    /// File system interaction
    FileSystem,
    /// Android Intent
    Intent,
    /// Android Content Provider
    ContentProvider,
}

/// A boundary between two components in the IPDG.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct Boundary {
    /// Type of boundary
    pub kind: BoundaryKind,
    /// Source component ID
    pub source: ComponentId,
    /// Destination component ID
    pub dest: ComponentId,
    /// Specific function or interface name
    pub function: Option<String>,
    /// Trust level of this boundary (0.0 = untrusted, 1.0 = fully trusted)
    pub trust_level: f32,
    /// Whether input validation is performed at this boundary
    pub has_validation: bool,
}

impl Boundary {
    /// Create a new boundary.
    pub fn new(kind: BoundaryKind, source: ComponentId, dest: ComponentId) -> Self {
        Self {
            kind,
            source,
            dest,
            function: None,
            trust_level: 0.5,
            has_validation: false,
        }
    }

    /// Set the function name.
    #[must_use]
    pub fn with_function(mut self, function: String) -> Self {
        self.function = Some(function);
        self
    }

    /// Set the trust level.
    #[must_use]
    pub fn with_trust_level(mut self, level: f32) -> Self {
        self.trust_level = level;
        self
    }

    /// Set whether validation is performed.
    #[must_use]
    pub fn with_validation(mut self, validation: bool) -> Self {
        self.has_validation = validation;
        self
    }

    /// Compute a risk score for this boundary.
    pub fn risk_score(&self) -> f32 {
        let base_risk = match self.kind {
            BoundaryKind::Syscall | BoundaryKind::Ioctl => 0.8,
            BoundaryKind::Jni | BoundaryKind::Binder => 0.6,
            BoundaryKind::Socket | BoundaryKind::Http => 0.7,
            _ => 0.4,
        };

        let mut score = base_risk * (1.0 - self.trust_level);
        if !self.has_validation {
            score += 0.2;
        }

        score.clamp(0.0, 1.0)
    }
}

/// Metadata about a specific edge crossing a boundary.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct BoundaryEdge {
    /// The boundary being crossed
    pub boundary: Boundary,
    /// Whether taint is known to flow through this specific crossing
    pub is_tainted: bool,
    /// Confidence in the cross-boundary analysis
    pub confidence: f32,
}

impl BoundaryEdge {
    /// Create a new boundary edge.
    pub fn new(boundary: Boundary) -> Self {
        Self {
            boundary,
            is_tainted: false,
            confidence: 1.0,
        }
    }

    /// Set whether the edge is tainted.
    #[must_use]
    pub fn with_taint(mut self, tainted: bool) -> Self {
        self.is_tainted = tainted;
        self
    }

    /// Set the confidence level.
    #[must_use]
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence;
        self
    }
}
