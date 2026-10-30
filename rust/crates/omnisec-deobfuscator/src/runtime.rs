//! Runtime mutation analysis for unpacked or generated native code.
//!
//! This module is intentionally snapshot-based: an external sandbox,
//! debugger, hypervisor, or instrumentation layer captures memory regions,
//! and OmniSec compares those read-only snapshots. It does not patch a
//! process, disable checks, or generate payloads.

use omnisec_json::{FromJson, ToJson};

/// Access permissions for a captured memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToJson, FromJson)]
pub struct MemoryPermissions {
    /// Region can be read.
    pub read: bool,
    /// Region can be written.
    pub write: bool,
    /// Region can be executed.
    pub execute: bool,
}

impl MemoryPermissions {
    /// Read-only memory.
    pub const READ: Self = Self {
        read: true,
        write: false,
        execute: false,
    };

    /// Read/write memory.
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
    };

    /// Read/execute memory.
    pub const READ_EXECUTE: Self = Self {
        read: true,
        write: false,
        execute: true,
    };

    /// Read/write/execute memory.
    pub const READ_WRITE_EXECUTE: Self = Self {
        read: true,
        write: true,
        execute: true,
    };

    /// Whether the region can execute code.
    #[must_use]
    pub const fn is_executable(self) -> bool {
        self.execute
    }

    /// Whether the region can be written.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        self.write
    }
}

/// A captured memory region.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct MemoryRegion {
    /// Base virtual address.
    pub base: u64,
    /// Captured bytes.
    pub bytes: Vec<u8>,
    /// Region permissions at capture time.
    pub permissions: MemoryPermissions,
    /// Optional module/mapping name.
    pub name: Option<String>,
}

impl MemoryRegion {
    /// Create a captured region.
    #[must_use]
    pub fn new(base: u64, bytes: impl Into<Vec<u8>>, permissions: MemoryPermissions) -> Self {
        Self {
            base,
            bytes: bytes.into(),
            permissions,
            name: None,
        }
    }

    /// Attach a human-readable mapping name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Address just after the captured region.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.bytes.len() as u64)
    }

    /// Region size in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the region has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// A memory snapshot from one point in execution.
#[derive(Debug, Clone, Default, PartialEq, Eq, ToJson, FromJson)]
pub struct RuntimeSnapshot {
    /// Snapshot label, for example `before_entry` or `after_unpack`.
    pub label: String,
    /// Captured memory regions.
    pub regions: Vec<MemoryRegion>,
}

impl RuntimeSnapshot {
    /// Create an empty snapshot.
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            regions: Vec::new(),
        }
    }

    /// Add one captured region.
    pub fn push_region(&mut self, region: MemoryRegion) {
        self.regions.push(region);
    }

    /// Find the region with the same base address.
    #[must_use]
    pub fn region_at(&self, base: u64) -> Option<&MemoryRegion> {
        self.regions.iter().find(|region| region.base == base)
    }
}

/// Runtime mutation analyzer configuration.
#[derive(Debug, Clone, Copy, ToJson, FromJson)]
pub struct RuntimeMutationConfig {
    /// Ignore regions smaller than this.
    pub min_region_size: usize,
    /// Minimum changed byte ratio for `ModifiedExecutableRegion`.
    pub min_changed_ratio: f64,
    /// Entropy drop threshold for likely unpacking.
    pub entropy_drop_threshold: f64,
    /// Minimum bytes needed to report an XOR transform.
    pub min_xor_bytes: usize,
}

impl Default for RuntimeMutationConfig {
    fn default() -> Self {
        Self {
            min_region_size: 4,
            min_changed_ratio: 0.05,
            entropy_drop_threshold: 1.0,
            min_xor_bytes: 8,
        }
    }
}

/// Runtime mutation finding kind.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub enum RuntimeMutationKind {
    /// A previously unseen executable mapping appeared.
    NewExecutableRegion,
    /// An executable mapping changed bytes between snapshots.
    ModifiedExecutableRegion,
    /// A writable mapping became executable.
    WriteThenExecuteTransition,
    /// A mapping is writable and executable at the same time.
    RwxRegion,
    /// Entropy dropped, often indicating unpacking/decryption.
    EntropyDropUnpacked,
    /// A stable XOR key maps old bytes to new bytes.
    XorDecoded {
        /// Single-byte XOR key.
        key: u8,
    },
}

/// One runtime mutation finding.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct RuntimeMutationFinding {
    /// Finding kind.
    pub kind: RuntimeMutationKind,
    /// Region base address.
    pub base: u64,
    /// Region size.
    pub size: usize,
    /// Confidence from 0 to 100.
    pub confidence: u8,
    /// Human-readable summary.
    pub description: String,
    /// Entropy before mutation, when available.
    pub before_entropy: Option<f64>,
    /// Entropy after mutation, when available.
    pub after_entropy: Option<f64>,
    /// Number of bytes that changed, when available.
    pub changed_bytes: Option<usize>,
}

/// Dump of bytes worth feeding to disassembly / CFG / SSA.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct RuntimeCodeDump {
    /// Dump base virtual address.
    pub base: u64,
    /// Captured executable bytes.
    pub bytes: Vec<u8>,
    /// Permissions at dump time.
    pub permissions: MemoryPermissions,
    /// Reason this dump was selected.
    pub reason: RuntimeMutationKind,
}

/// Complete runtime mutation report.
#[derive(Debug, Clone, Default, ToJson, FromJson)]
pub struct RuntimeMutationReport {
    /// All findings.
    pub findings: Vec<RuntimeMutationFinding>,
    /// Executable dumps to pass into lifters/scanners.
    pub dumps: Vec<RuntimeCodeDump>,
}

/// Analyzer for runtime-unpacked or generated code snapshots.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeMutationAnalyzer {
    config: RuntimeMutationConfig,
}

impl RuntimeMutationAnalyzer {
    /// Create an analyzer.
    #[must_use]
    pub const fn new(config: RuntimeMutationConfig) -> Self {
        Self { config }
    }

    /// Create an analyzer with default settings.
    #[must_use]
    pub const fn with_defaults() -> Self {
        Self::new(RuntimeMutationConfig {
            min_region_size: 4,
            min_changed_ratio: 0.05,
            entropy_drop_threshold: 1.0,
            min_xor_bytes: 8,
        })
    }

    /// Compare two snapshots and report runtime code mutations.
    #[must_use]
    pub fn analyze(
        &self,
        before: &RuntimeSnapshot,
        after: &RuntimeSnapshot,
    ) -> RuntimeMutationReport {
        let mut report = RuntimeMutationReport::default();

        for after_region in &after.regions {
            if after_region.len() < self.config.min_region_size {
                continue;
            }

            let before_region = before.region_at(after_region.base);
            Self::detect_permission_findings(after_region, before_region, &mut report);

            if !after_region.permissions.is_executable() {
                continue;
            }

            if let Some(before_region) = before_region {
                self.compare_executable_region(before_region, after_region, &mut report);
            } else {
                report.push_finding(RuntimeMutationFinding {
                    kind: RuntimeMutationKind::NewExecutableRegion,
                    base: after_region.base,
                    size: after_region.len(),
                    confidence: 95,
                    description: "new executable memory region appeared".into(),
                    before_entropy: None,
                    after_entropy: Some(shannon_entropy(&after_region.bytes)),
                    changed_bytes: None,
                });
                report.push_dump(after_region, RuntimeMutationKind::NewExecutableRegion);
            }
        }

        report
    }

    fn detect_permission_findings(
        after_region: &MemoryRegion,
        before_region: Option<&MemoryRegion>,
        report: &mut RuntimeMutationReport,
    ) {
        if after_region.permissions.is_writable() && after_region.permissions.is_executable() {
            report.push_finding(RuntimeMutationFinding {
                kind: RuntimeMutationKind::RwxRegion,
                base: after_region.base,
                size: after_region.len(),
                confidence: 80,
                description: "memory region is writable and executable".into(),
                before_entropy: before_region.map(|region| shannon_entropy(&region.bytes)),
                after_entropy: Some(shannon_entropy(&after_region.bytes)),
                changed_bytes: before_region.map(|region| changed_byte_count(region, after_region)),
            });
        }

        if let Some(before_region) = before_region
            && before_region.permissions.is_writable()
            && !before_region.permissions.is_executable()
            && after_region.permissions.is_executable()
        {
            report.push_finding(RuntimeMutationFinding {
                kind: RuntimeMutationKind::WriteThenExecuteTransition,
                base: after_region.base,
                size: after_region.len(),
                confidence: 90,
                description: "writable memory became executable".into(),
                before_entropy: Some(shannon_entropy(&before_region.bytes)),
                after_entropy: Some(shannon_entropy(&after_region.bytes)),
                changed_bytes: Some(changed_byte_count(before_region, after_region)),
            });
            report.push_dump(
                after_region,
                RuntimeMutationKind::WriteThenExecuteTransition,
            );
        }
    }

    fn compare_executable_region(
        &self,
        before_region: &MemoryRegion,
        after_region: &MemoryRegion,
        report: &mut RuntimeMutationReport,
    ) {
        let changed = changed_byte_count(before_region, after_region);
        let max_len = before_region.len().max(after_region.len());
        let changed_ratio = usize_to_f64(changed) / usize_to_f64(max_len.max(1));
        let before_entropy = shannon_entropy(&before_region.bytes);
        let after_entropy = shannon_entropy(&after_region.bytes);

        if changed_ratio >= self.config.min_changed_ratio {
            report.push_finding(RuntimeMutationFinding {
                kind: RuntimeMutationKind::ModifiedExecutableRegion,
                base: after_region.base,
                size: after_region.len(),
                confidence: confidence_from_ratio(changed_ratio),
                description: "executable memory bytes changed".into(),
                before_entropy: Some(before_entropy),
                after_entropy: Some(after_entropy),
                changed_bytes: Some(changed),
            });
            report.push_dump(after_region, RuntimeMutationKind::ModifiedExecutableRegion);
        }

        if before_entropy - after_entropy >= self.config.entropy_drop_threshold {
            report.push_finding(RuntimeMutationFinding {
                kind: RuntimeMutationKind::EntropyDropUnpacked,
                base: after_region.base,
                size: after_region.len(),
                confidence: 85,
                description: "entropy dropped after execution, likely unpacked/decrypted code"
                    .into(),
                before_entropy: Some(before_entropy),
                after_entropy: Some(after_entropy),
                changed_bytes: Some(changed),
            });
            report.push_dump(after_region, RuntimeMutationKind::EntropyDropUnpacked);
        }

        if let Some(key) = detect_single_byte_xor(
            &before_region.bytes,
            &after_region.bytes,
            self.config.min_xor_bytes,
        ) {
            report.push_finding(RuntimeMutationFinding {
                kind: RuntimeMutationKind::XorDecoded { key },
                base: after_region.base,
                size: after_region.len(),
                confidence: 90,
                description: format!(
                    "region bytes match single-byte XOR transform with key 0x{key:02x}"
                ),
                before_entropy: Some(before_entropy),
                after_entropy: Some(after_entropy),
                changed_bytes: Some(changed),
            });
            report.push_dump(after_region, RuntimeMutationKind::XorDecoded { key });
        }
    }
}

impl RuntimeMutationReport {
    fn push_finding(&mut self, finding: RuntimeMutationFinding) {
        self.findings.push(finding);
    }

    fn push_dump(&mut self, region: &MemoryRegion, reason: RuntimeMutationKind) {
        if self
            .dumps
            .iter()
            .any(|dump| dump.base == region.base && dump.reason == reason)
        {
            return;
        }
        self.dumps.push(RuntimeCodeDump {
            base: region.base,
            bytes: region.bytes.clone(),
            permissions: region.permissions,
            reason,
        });
    }
}

/// Compute Shannon entropy in bits per byte.
#[must_use]
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &byte in bytes {
        counts[usize::from(byte)] += 1;
    }

    let len = usize_to_f64(bytes.len());
    counts
        .into_iter()
        .filter(|&count| count > 0)
        .map(|count| {
            let p = usize_to_f64(count) / len;
            -p * p.log2()
        })
        .sum()
}

fn changed_byte_count(before: &MemoryRegion, after: &MemoryRegion) -> usize {
    let common = before.bytes.len().min(after.bytes.len());
    let changed_common = before
        .bytes
        .iter()
        .zip(&after.bytes)
        .filter(|(left, right)| left != right)
        .count();
    changed_common + before.bytes.len().max(after.bytes.len()) - common
}

fn confidence_from_ratio(ratio: f64) -> u8 {
    if ratio >= 0.80 {
        95
    } else if ratio >= 0.50 {
        90
    } else if ratio >= 0.20 {
        80
    } else {
        65
    }
}

fn usize_to_f64(value: usize) -> f64 {
    u32::try_from(value).map_or(f64::from(u32::MAX), f64::from)
}

fn detect_single_byte_xor(before: &[u8], after: &[u8], min_xor_bytes: usize) -> Option<u8> {
    let mut key = None;
    let mut transformed = 0usize;

    for (&left, &right) in before.iter().zip(after) {
        if left == right {
            continue;
        }

        let candidate = left ^ right;
        if candidate == 0 {
            continue;
        }

        match key {
            Some(existing) if existing != candidate => return None,
            Some(_) => {}
            None => key = Some(candidate),
        }
        transformed += 1;
    }

    (transformed >= min_xor_bytes)
        .then_some(key?)
        .filter(|&key| key != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(label: &str, regions: Vec<MemoryRegion>) -> RuntimeSnapshot {
        RuntimeSnapshot {
            label: label.into(),
            regions,
        }
    }

    #[test]
    fn detects_new_executable_region() {
        let before = snapshot("before", vec![]);
        let after = snapshot(
            "after",
            vec![MemoryRegion::new(
                0x1000,
                [0x55, 0x48, 0x89, 0xe5, 0xc3],
                MemoryPermissions::READ_EXECUTE,
            )],
        );

        let report = RuntimeMutationAnalyzer::with_defaults().analyze(&before, &after);

        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == RuntimeMutationKind::NewExecutableRegion)
        );
        assert_eq!(report.dumps.len(), 1);
    }

    #[test]
    fn detects_write_then_execute_transition() {
        let before = snapshot(
            "before",
            vec![MemoryRegion::new(
                0x2000,
                [0x90; 16],
                MemoryPermissions::READ_WRITE,
            )],
        );
        let after = snapshot(
            "after",
            vec![MemoryRegion::new(
                0x2000,
                [0x90; 16],
                MemoryPermissions::READ_EXECUTE,
            )],
        );

        let report = RuntimeMutationAnalyzer::with_defaults().analyze(&before, &after);

        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == RuntimeMutationKind::WriteThenExecuteTransition)
        );
    }

    #[test]
    fn detects_modified_executable_region_and_xor_key() {
        let plain = [
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0xc3, 0x90, 0x90, 0x90,
        ];
        let encrypted: Vec<u8> = plain.iter().map(|byte| byte ^ 0xaa).collect();
        let before = snapshot(
            "before",
            vec![MemoryRegion::new(
                0x3000,
                encrypted,
                MemoryPermissions::READ_EXECUTE,
            )],
        );
        let after = snapshot(
            "after",
            vec![MemoryRegion::new(
                0x3000,
                plain,
                MemoryPermissions::READ_EXECUTE,
            )],
        );

        let report = RuntimeMutationAnalyzer::with_defaults().analyze(&before, &after);

        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == RuntimeMutationKind::ModifiedExecutableRegion)
        );
        assert!(report.findings.iter().any(|finding| {
            matches!(finding.kind, RuntimeMutationKind::XorDecoded { key: 0xaa })
        }));
    }

    #[test]
    fn detects_entropy_drop_unpacking() {
        let before = snapshot(
            "before",
            vec![MemoryRegion::new(
                0x4000,
                (0u8..=255).collect::<Vec<_>>(),
                MemoryPermissions::READ_EXECUTE,
            )],
        );
        let after = snapshot(
            "after",
            vec![MemoryRegion::new(
                0x4000,
                vec![0x90; 256],
                MemoryPermissions::READ_EXECUTE,
            )],
        );

        let report = RuntimeMutationAnalyzer::with_defaults().analyze(&before, &after);

        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == RuntimeMutationKind::EntropyDropUnpacked)
        );
    }
}
