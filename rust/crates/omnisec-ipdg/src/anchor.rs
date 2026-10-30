//! Global anchor system for cross-boundary vulnerability detection.

use omnisec_hdc::{Anchor, HyperVector, MatchResult};
use omnisec_json::{FromJson, ToJson};
use std::collections::HashMap as FxHashMap;

use crate::Result as IpdgResult;
use crate::component::ComponentId;
use crate::graph::Ipdg;
use crate::taint::TaintPath;

/// A vulnerability pattern that spans multiple components.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct GlobalAnchor {
    /// Pattern name
    pub name: String,

    /// Description
    pub description: String,

    /// Components involved (in order)
    pub component_sequence: Vec<ComponentId>,

    /// Minimum number of boundary crossings
    pub min_boundary_crossings: usize,

    /// HDC anchor for structural matching
    pub anchor: Anchor,

    /// Required taint flow characteristics
    pub taint_requirements: TaintRequirements,

    /// Severity (0.0 = low, 1.0 = critical)
    pub severity: f32,
}

/// Requirements for taint flow in a cross-boundary pattern.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct TaintRequirements {
    /// Must cross privilege boundary
    pub requires_privilege_escalation: bool,

    /// Minimum confidence threshold
    pub min_confidence: f32,

    /// Minimum risk score
    pub min_risk_score: f32,

    /// Required source types
    pub required_sources: Vec<String>,

    /// Required sink types
    pub required_sinks: Vec<String>,
}

impl Default for TaintRequirements {
    fn default() -> Self {
        Self {
            requires_privilege_escalation: false,
            min_confidence: 0.5,
            min_risk_score: 0.5,
            required_sources: Vec::new(),
            required_sinks: Vec::new(),
        }
    }
}

/// A match of a global anchor against the IPDG.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct GlobalAnchorMatch {
    /// The pattern that matched
    pub pattern: String,

    /// Taint path that triggered the match
    pub taint_path: TaintPath,

    /// HDC match result
    pub hdc_match: MatchResult,

    /// Overall confidence (combines HDC and taint confidence)
    pub confidence: f32,

    /// Severity score
    pub severity: f32,

    /// Detailed explanation
    pub explanation: String,
}

impl GlobalAnchorMatch {
    /// Check if this is a critical finding.
    pub fn is_critical(&self) -> bool {
        self.severity > 0.8 && self.confidence > 0.7
    }
}

/// JSON-friendly wrapper for a map keyed by component sequences (JSON object
/// keys must be strings, so keys are stored as comma-joined component ids).
#[derive(Debug, Clone, Default)]
pub struct ComponentIndex(FxHashMap<Vec<ComponentId>, Vec<usize>>);

impl omnisec_json::ToJson for ComponentIndex {
    fn to_json(&self) -> omnisec_json::JsonValue {
        let entries: Vec<(String, omnisec_json::JsonValue)> = self
            .0
            .iter()
            .map(|(k, v)| {
                let key = k
                    .iter()
                    .map(|c| c.0.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                (key, v.to_json())
            })
            .collect();
        omnisec_json::JsonValue::Object(entries)
    }
}

impl omnisec_json::FromJson for ComponentIndex {
    fn from_json(v: &omnisec_json::JsonValue) -> Result<Self, omnisec_json::JsonError> {
        let mut m = FxHashMap::new();
        if let omnisec_json::JsonValue::Object(entries) = v {
            for (k, val) in entries {
                let ids: Result<Vec<ComponentId>, _> = k
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::parse)
                    .collect();
                m.insert(ids?, Vec::<usize>::from_json(val)?);
            }
        }
        Ok(Self(m))
    }
}

/// Store for global anchors (cross-boundary vulnerability patterns).
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct GlobalAnchorStore {
    /// All registered patterns
    patterns: Vec<GlobalAnchor>,

    /// Index by component sequence for fast lookup
    component_index: ComponentIndex,
}

impl GlobalAnchorStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
            component_index: ComponentIndex::default(),
        }
    }

    /// Add a pattern to the store.
    pub fn add_pattern(&mut self, pattern: GlobalAnchor) {
        let idx = self.patterns.len();
        let seq = pattern.component_sequence.clone();

        self.patterns.push(pattern);
        self.component_index.0.entry(seq).or_default().push(idx);
    }

    /// Load patterns from a JSON file.
    pub fn load_from_json(path: &std::path::Path) -> IpdgResult<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            crate::IpdgError::AnchorMatchingError(format!("Failed to read file: {}", e))
        })?;

        omnisec_json::from_json_str(&content).map_err(|e| {
            crate::IpdgError::AnchorMatchingError(format!("Failed to parse JSON: {}", e))
        })
    }

    /// Save patterns to a JSON file.
    pub fn save_to_json(&self, path: &std::path::Path) -> IpdgResult<()> {
        let content = omnisec_json::to_json_pretty(self);

        std::fs::write(path, content).map_err(|e| {
            crate::IpdgError::AnchorMatchingError(format!("Failed to write file: {}", e))
        })
    }

    /// Match all patterns against an IPDG.
    pub fn match_all(&self, ipdg: &Ipdg, taint_paths: &[TaintPath]) -> Vec<GlobalAnchorMatch> {
        let mut matches = Vec::new();

        for path in taint_paths {
            for pattern in &self.patterns {
                if let Some(m) = self.match_pattern(pattern, path, ipdg) {
                    matches.push(m);
                }
            }
        }

        // Sort by severity and confidence
        matches.sort_by(|a, b| {
            let score_a = a.severity * a.confidence;
            let score_b = b.severity * b.confidence;
            score_b
                .partial_cmp(&score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        matches
    }

    /// Match a single pattern against a taint path.
    fn match_pattern(
        &self,
        pattern: &GlobalAnchor,
        path: &TaintPath,
        _ipdg: &Ipdg,
    ) -> Option<GlobalAnchorMatch> {
        // Check basic requirements
        if path.boundary_crossings < pattern.min_boundary_crossings {
            return None;
        }

        // Check taint requirements
        if !self.check_taint_requirements(&pattern.taint_requirements, path) {
            return None;
        }

        // Check component sequence
        if !self.check_component_sequence(&pattern.component_sequence, &path.components) {
            return None;
        }

        // Perform HDC matching on the subgraph
        // For now, we'll use a simplified match
        let hdc_confidence = 0.85f32;

        let hdc_match = MatchResult {
            anchor_name: pattern.name.clone(),
            jaccard: hdc_confidence as f64,
            hamming_sim: hdc_confidence as f64,
            is_match: true,
            severity: pattern.severity as f64,
            matched_motifs: vec![pattern.description.clone()],
        };

        // Combine HDC confidence with taint path confidence
        let combined_confidence = f32::midpoint(hdc_confidence, path.confidence);

        let explanation = format!(
            "Cross-boundary vulnerability detected: {}\n\
             Components: {:?}\n\
             Boundary crossings: {}\n\
             Taint flow: {:?} → {:?}\n\
             Risk score: {:.2}\n\
             Confidence: {:.2}",
            pattern.description,
            path.components,
            path.boundary_crossings,
            path.source,
            path.sink,
            path.risk_score,
            combined_confidence
        );

        Some(GlobalAnchorMatch {
            pattern: pattern.name.clone(),
            taint_path: path.clone(),
            hdc_match,
            confidence: combined_confidence,
            severity: pattern.severity,
            explanation,
        })
    }

    fn check_taint_requirements(&self, req: &TaintRequirements, path: &TaintPath) -> bool {
        if req.requires_privilege_escalation && !path.crosses_privilege_boundary {
            return false;
        }

        if path.confidence < req.min_confidence {
            return false;
        }

        if path.risk_score < req.min_risk_score {
            return false;
        }

        // Check source types
        if !req.required_sources.is_empty() {
            let source_str = format!("{:?}", path.source);
            if !req.required_sources.iter().any(|s| source_str.contains(s)) {
                return false;
            }
        }

        // Check sink types
        if !req.required_sinks.is_empty() {
            let sink_str = format!("{:?}", path.sink);
            if !req.required_sinks.iter().any(|s| sink_str.contains(s)) {
                return false;
            }
        }

        true
    }

    fn check_component_sequence(&self, required: &[ComponentId], actual: &[ComponentId]) -> bool {
        if required.is_empty() {
            return true;
        }

        // Check if all required components appear in order
        let mut req_idx = 0;
        for &comp in actual {
            if req_idx < required.len() && comp == required[req_idx] {
                req_idx += 1;
            }
        }

        req_idx == required.len()
    }

    /// Get all patterns.
    pub fn patterns(&self) -> &[GlobalAnchor] {
        &self.patterns
    }

    /// Create a default store with common cross-boundary patterns.
    pub fn with_defaults() -> Self {
        let mut store = Self::new();

        // Pattern 1: JNI UAF (Java → Native)
        store.add_pattern(GlobalAnchor {
            name: "jni_use_after_free".to_string(),
            description: "Use-after-free through JNI boundary".to_string(),
            component_sequence: vec![],
            min_boundary_crossings: 1,
            anchor: Anchor {
                name: "jni_uaf".to_string(),
                description: "JNI UAF pattern".to_string(),
                signature: HyperVector::sparse(100),
                threshold: 0.15,
                severity: 0.9,
                example_count: 1,
                motifs: vec!["JNI UAF pattern".to_string()],
                bit_counts: None,
            },
            taint_requirements: TaintRequirements {
                requires_privilege_escalation: false,
                min_confidence: 0.5,
                min_risk_score: 0.7,
                required_sources: vec!["UserInput".to_string()],
                required_sinks: vec!["Memory".to_string()],
            },
            severity: 0.9,
        });

        // Pattern 2: Syscall injection (User → Kernel)
        store.add_pattern(GlobalAnchor {
            name: "syscall_injection".to_string(),
            description: "Command injection through syscall boundary".to_string(),
            component_sequence: vec![],
            min_boundary_crossings: 1,
            anchor: Anchor {
                name: "syscall_injection".to_string(),
                description: "Syscall injection pattern".to_string(),
                signature: HyperVector::sparse(200),
                threshold: 0.15,
                severity: 0.95,
                example_count: 1,
                motifs: vec!["Syscall injection pattern".to_string()],
                bit_counts: None,
            },
            taint_requirements: TaintRequirements {
                requires_privilege_escalation: true,
                min_confidence: 0.5,
                min_risk_score: 0.8,
                required_sources: vec!["Network".to_string(), "UserInput".to_string()],
                required_sinks: vec!["Syscall".to_string(), "CommandExecution".to_string()],
            },
            severity: 0.95,
        });

        // Pattern 3: IOCTL buffer overflow (User → Kernel Driver)
        store.add_pattern(GlobalAnchor {
            name: "ioctl_buffer_overflow".to_string(),
            description: "Buffer overflow through IOCTL interface".to_string(),
            component_sequence: vec![],
            min_boundary_crossings: 1,
            anchor: Anchor {
                name: "ioctl_overflow".to_string(),
                description: "IOCTL overflow pattern".to_string(),
                signature: HyperVector::sparse(300),
                threshold: 0.15,
                severity: 0.92,
                example_count: 1,
                motifs: vec!["IOCTL overflow pattern".to_string()],
                bit_counts: None,
            },
            taint_requirements: TaintRequirements {
                requires_privilege_escalation: true,
                min_confidence: 0.5,
                min_risk_score: 0.75,
                required_sources: vec!["UserInput".to_string()],
                required_sinks: vec!["Memory".to_string(), "Syscall".to_string()],
            },
            severity: 0.92,
        });

        store
    }
}

impl Default for GlobalAnchorStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TaintSink, TaintSource};

    #[test]
    fn test_global_anchor_store() {
        let store = GlobalAnchorStore::with_defaults();
        assert_eq!(store.patterns().len(), 3);
    }

    #[test]
    fn test_taint_requirements() {
        let req = TaintRequirements {
            requires_privilege_escalation: true,
            min_confidence: 0.7,
            min_risk_score: 0.8,
            required_sources: vec!["Network".to_string()],
            required_sinks: vec!["Syscall".to_string()],
        };

        let path = TaintPath {
            source: TaintSource::Network,
            sink: TaintSink::Syscall,
            nodes: vec![],
            components: vec![],
            boundary_crossings: 1,
            crosses_privilege_boundary: true,
            confidence: 0.75,
            risk_score: 0.85,
        };

        let store = GlobalAnchorStore::new();
        assert!(store.check_taint_requirements(&req, &path));
    }

    #[test]
    fn test_component_sequence() {
        let store = GlobalAnchorStore::new();

        let required = vec![ComponentId(1), ComponentId(2)];
        let actual = vec![ComponentId(1), ComponentId(3), ComponentId(2)];

        assert!(store.check_component_sequence(&required, &actual));

        let actual_wrong = vec![ComponentId(2), ComponentId(1)];
        assert!(!store.check_component_sequence(&required, &actual_wrong));
    }
}
