//! Component representation — individual executable units in the IPDG.

use omnisec_collections::IndexMap;
use omnisec_json::{FromJson, ToJson};
use std::fmt;
use std::path::PathBuf;

/// Unique identifier for a component in the IPDG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
pub struct ComponentId(pub u32);

impl fmt::Display for ComponentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "C{}", self.0)
    }
}

impl std::str::FromStr for ComponentId {
    type Err = std::num::ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let digits = s.trim().trim_start_matches('C').trim_start_matches('c');
        digits.parse::<u32>().map(Self)
    }
}

/// Type of executable component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
pub enum ComponentKind {
    /// Android application (APK/DEX)
    AndroidApp,
    /// Native shared library (.so, .dll, .dylib)
    NativeLibrary,
    /// Native executable (ELF, PE, Mach-O)
    NativeExecutable,
    /// Kernel module or driver
    KernelModule,
    /// Java/JVM bytecode (JAR, CLASS)
    JvmBytecode,
    /// .NET assembly (EXE, DLL)
    DotNetAssembly,
    /// WebAssembly module
    WasmModule,
    /// Script or interpreted code
    Script,
}

impl fmt::Display for ComponentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AndroidApp => write!(f, "Android App"),
            Self::NativeLibrary => write!(f, "Native Library"),
            Self::NativeExecutable => write!(f, "Native Executable"),
            Self::KernelModule => write!(f, "Kernel Module"),
            Self::JvmBytecode => write!(f, "JVM Bytecode"),
            Self::DotNetAssembly => write!(f, ".NET Assembly"),
            Self::WasmModule => write!(f, "WASM Module"),
            Self::Script => write!(f, "Script"),
        }
    }
}

/// A component in the inter-process dependency graph.
///
/// Represents a single executable unit (binary, library, module) that can
/// communicate with other components through well-defined boundaries.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct Component {
    /// Unique identifier
    pub id: ComponentId,

    /// Component type
    pub kind: ComponentKind,

    /// Human-readable name
    pub name: String,

    /// File path (if available)
    pub path: Option<PathBuf>,

    /// Architecture (x86_64, ARM64, etc.)
    pub arch: Option<String>,

    /// Entry points (function addresses or method names)
    pub entry_points: Vec<String>,

    /// Exported symbols/functions
    pub exports: Vec<String>,

    /// Imported symbols/functions
    pub imports: Vec<String>,

    /// Additional metadata
    pub metadata: ComponentMetadata,
}

/// Additional metadata for a component.
#[derive(Debug, Clone, Default, ToJson, FromJson)]
pub struct ComponentMetadata {
    /// Package name (for Android/Java)
    pub package: Option<String>,

    /// Version string
    pub version: Option<String>,

    /// Build ID or hash
    pub build_id: Option<String>,

    /// Whether the component is stripped
    pub is_stripped: bool,

    /// Whether the component is obfuscated
    pub is_obfuscated: bool,

    /// Security features (PIE, RELRO, Stack Canary, etc.)
    pub security_features: Vec<String>,

    /// Custom key-value pairs
    pub custom: IndexMap<String, String>,
}

impl Component {
    /// Create a new component.
    pub fn new(id: ComponentId, kind: ComponentKind, name: String) -> Self {
        Self {
            id,
            kind,
            name,
            path: None,
            arch: None,
            entry_points: Vec::new(),
            exports: Vec::new(),
            imports: Vec::new(),
            metadata: ComponentMetadata::default(),
        }
    }

    /// Set the file path.
    #[must_use]
    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.path = Some(path);
        self
    }

    /// Set the architecture.
    #[must_use]
    pub fn with_arch(mut self, arch: String) -> Self {
        self.arch = Some(arch);
        self
    }

    /// Add an entry point.
    pub fn add_entry_point(&mut self, entry: String) {
        self.entry_points.push(entry);
    }

    /// Add an exported symbol.
    pub fn add_export(&mut self, export: String) {
        self.exports.push(export);
    }

    /// Add an imported symbol.
    pub fn add_import(&mut self, import: String) {
        self.imports.push(import);
    }

    /// Check if this component exports a given symbol.
    pub fn exports_symbol(&self, symbol: &str) -> bool {
        self.exports.iter().any(|s| s == symbol)
    }

    /// Check if this component imports a given symbol.
    pub fn imports_symbol(&self, symbol: &str) -> bool {
        self.imports.iter().any(|s| s == symbol)
    }
}

impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}] ({})", self.name, self.id, self.kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_creation() {
        let comp = Component::new(
            ComponentId(1),
            ComponentKind::NativeLibrary,
            "libvulnerable.so".to_string(),
        )
        .with_arch("x86_64".to_string());

        assert_eq!(comp.id, ComponentId(1));
        assert_eq!(comp.kind, ComponentKind::NativeLibrary);
        assert_eq!(comp.name, "libvulnerable.so");
        assert_eq!(comp.arch, Some("x86_64".to_string()));
    }

    #[test]
    fn test_symbol_tracking() {
        let mut comp = Component::new(
            ComponentId(2),
            ComponentKind::NativeExecutable,
            "app".to_string(),
        );

        comp.add_export("vulnerable_function".to_string());
        comp.add_import("malloc".to_string());

        assert!(comp.exports_symbol("vulnerable_function"));
        assert!(comp.imports_symbol("malloc"));
        assert!(!comp.exports_symbol("malloc"));
    }
}
