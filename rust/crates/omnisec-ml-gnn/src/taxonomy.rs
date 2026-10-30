//! Canonical DEX license/piracy taxonomy — the SINGLE source of truth shared by
//! the dataset loader, the trainer, the weight files (`class_names` metadata)
//! and — by index — the Go `VulnClass` enum (`pkg/ml/gnn/model_types.go`).
//!
//! Index alignment is a hard ABI contract. The Go side can (and should) verify
//! it at start-up via `gnn_num_classes()` / `gnn_class_name(i)`.

#[cfg(test)]
use std::ffi::CStr;

use omnisec_json::{FromJson, ToJson};

use crate::error::GnnError;

/// Number of classes. Wire-locked to the FFI/Go contract.
pub const NUM_CLASSES: usize = 8;

/// Strongly-typed class index.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "kebab-case")]
pub enum VulnClass {
    /// No license/piracy signal (negative / skip class).
    Benign = 0,
    /// Legitimate LVL / Play licensing verification.
    LicenseCheck = 1,
    /// License check neutralised / always-licensed.
    LicenseBypass = 2,
    /// Fake signature / PackageManager proxy.
    SignatureSpoof = 3,
    /// Checksum / anti-tamper hooked or removed.
    IntegrityTamper = 4,
    /// Re-sign / store attribution / injected loader.
    RepackMarker = 5,
    /// JNI / native licensing or .so protection bridge.
    NativeBridge = 6,
    /// DexClassLoader / reflection-driven payload.
    DynamicLoad = 7,
}

impl VulnClass {
    pub const ALL: [VulnClass; NUM_CLASSES] = [
        Self::Benign,
        Self::LicenseCheck,
        Self::LicenseBypass,
        Self::SignatureSpoof,
        Self::IntegrityTamper,
        Self::RepackMarker,
        Self::NativeBridge,
        Self::DynamicLoad,
    ];

    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        CLASS_NAMES[self as usize]
    }
}

impl TryFrom<usize> for VulnClass {
    type Error = GnnError;
    fn try_from(idx: usize) -> Result<Self, Self::Error> {
        Self::ALL.get(idx).copied().ok_or_else(|| {
            GnnError::Dataset(format!("class index {idx} out of range 0..{NUM_CLASSES}"))
        })
    }
}

/// Human-readable names, index-aligned with [`VulnClass`] and the Go enum.
pub const CLASS_NAMES: [&str; NUM_CLASSES] = [
    "benign",           // 0 — no license/piracy signal (negative / skip class)
    "license-check",    // 1 — legitimate LVL / Play licensing verification
    "license-bypass",   // 2 — license check neutralised / always-licensed
    "signature-spoof",  // 3 — fake signature / PackageManager proxy
    "integrity-tamper", // 4 — checksum / anti-tamper hooked or removed
    "repack-marker",    // 5 — re-sign / store attribution / injected loader
    "native-bridge",    // 6 — JNI / native licensing or .so protection bridge
    "dynamic-load",     // 7 — DexClassLoader / reflection-driven payload
];

/// NUL-terminated mirror of [`CLASS_NAMES`], used by the test that pins the
/// C-string form a `gnn_class_name` export must return.
#[cfg(test)]
pub(crate) const CLASS_CNAMES: [&CStr; NUM_CLASSES] = [
    c"benign",
    c"license-check",
    c"license-bypass",
    c"signature-spoof",
    c"integrity-tamper",
    c"repack-marker",
    c"native-bridge",
    c"dynamic-load",
];

/// Index of the negative class that the scanner's quality gate skips.
pub const BENIGN: usize = VulnClass::Benign as usize;

/// Map a class index to its name (`"unknown"` when out of range).
#[must_use]
pub fn class_name(idx: usize) -> &'static str {
    CLASS_NAMES.get(idx).copied().unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_names_and_cstrs_are_aligned() {
        for (i, class) in VulnClass::ALL.iter().enumerate() {
            assert_eq!(class.index(), i);
            assert_eq!(class.name(), CLASS_NAMES[i]);
            assert_eq!(CLASS_CNAMES[i].to_str().unwrap(), CLASS_NAMES[i]);
            assert_eq!(VulnClass::try_from(i).unwrap(), *class);
        }
        assert!(VulnClass::try_from(NUM_CLASSES).is_err());
        assert_eq!(BENIGN, 0);
        let mut uniq = CLASS_NAMES.to_vec();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), NUM_CLASSES, "class names must be unique");
    }
}
