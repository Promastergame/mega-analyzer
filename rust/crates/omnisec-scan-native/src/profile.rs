//! Target profiling for Android-native ELF scans.

use omnisec_core::Arch;
use omnisec_json::{FromJson, ToJson};
use omnisec_loader::LoadedBinary;
use omnisec_loader_elf::elfparse::{ET_CORE, ET_DYN, ET_EXEC, ET_REL, ElfFile};
use omnisec_loader_pe::peparse::PeFile;

/// ELF role of the scanned target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToJson, FromJson)]
#[allow(non_camel_case_types)]
#[json(rename_all = "snake_case")]
pub enum ElfKind {
    /// `ET_DYN`, used by Android `.so` files and PIE executables.
    SharedObject,
    /// `ET_EXEC`, a fixed-address executable.
    Executable,
    /// `ET_REL`, a relocatable object file.
    Relocatable,
    /// `ET_CORE`, a core dump.
    Core,
    /// Missing or unknown ELF type.
    Unknown,
}

/// PE object kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum PeKind {
    /// Standard executable (.exe).
    Executable,
    /// Dynamic Link Library (.dll).
    Dll,
    /// Kernel driver (.sys).
    Driver,
    /// Missing or unknown PE type.
    Unknown,
}

impl ElfKind {
    /// Stable display name for CLI output.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SharedObject => "shared_object",
            Self::Executable => "executable",
            Self::Relocatable => "relocatable",
            Self::Core => "core",
            Self::Unknown => "unknown",
        }
    }
}

/// Android ABI inferred from the ELF machine architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToJson, FromJson)]
pub enum AndroidAbi {
    /// 32-bit ARM Android ABI.
    #[json(rename = "armeabi-v7a")]
    ArmeabiV7a,
    /// 64-bit ARM Android ABI.
    #[json(rename = "arm64-v8a")]
    Arm64V8a,
    /// 32-bit x86 Android ABI.
    #[json(rename = "x86")]
    X86,
    /// 64-bit x86 Android ABI.
    #[json(rename = "x86_64")]
    X86_64,
    /// Legacy 32-bit MIPS Android ABI.
    #[json(rename = "mips")]
    Mips,
    /// Legacy 64-bit MIPS Android ABI.
    #[json(rename = "mips64")]
    Mips64,
}

impl AndroidAbi {
    /// Android directory / ABI name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ArmeabiV7a => "armeabi-v7a",
            Self::Arm64V8a => "arm64-v8a",
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Mips => "mips",
            Self::Mips64 => "mips64",
        }
    }
}

/// High-level profile of the native target being scanned.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct TargetProfile {
    /// Container format (ELF, PE).
    pub format: omnisec_core::Format,
    /// ELF object kind, if format is ELF.
    #[json(default, skip_serializing_if = "Option::is_none")]
    pub elf_kind: Option<ElfKind>,
    /// PE object kind, if format is PE.
    #[json(default, skip_serializing_if = "Option::is_none")]
    pub pe_kind: Option<PeKind>,
    /// Android ABI inferred from architecture, when it maps to one.
    #[json(default, skip_serializing_if = "Option::is_none")]
    pub android_abi: Option<AndroidAbi>,
    /// Dynamic `DT_SONAME` (ELF) or internal name (PE).
    #[json(default, skip_serializing_if = "Option::is_none")]
    pub internal_name: Option<String>,
    /// Dynamic `DT_NEEDED` dependencies (ELF) or Import DLLs (PE).
    #[json(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
    /// Number of exported `Java_*` JNI entry points.
    pub jni_exports: usize,
    /// Whether `JNI_OnLoad` is exported or present in symbols.
    pub has_jni_onload: bool,
}

impl TargetProfile {
    pub(crate) fn from_elf(bin: &LoadedBinary, elf: Option<&ElfFile<'_>>) -> Self {
        let elf_kind = elf.map_or(ElfKind::Unknown, |e| match e.header.e_type {
            ET_DYN => ElfKind::SharedObject,
            ET_EXEC => ElfKind::Executable,
            ET_REL => ElfKind::Relocatable,
            ET_CORE => ElfKind::Core,
            _ => ElfKind::Unknown,
        });
        let soname = elf.and_then(|e| e.soname.map(ToOwned::to_owned));
        let needed_libraries = elf
            .map(|e| e.libraries.iter().map(|lib| (*lib).to_owned()).collect())
            .unwrap_or_default();
        let jni_exports = bin
            .exports
            .iter()
            .filter(|export| export.name.starts_with("Java_"))
            .count();
        let has_jni_onload = bin.exports.iter().any(|export| export.name == "JNI_OnLoad")
            || bin.symbols.iter().any(|symbol| symbol.name == "JNI_OnLoad");

        Self {
            format: bin.format,
            elf_kind: Some(elf_kind),
            pe_kind: None,
            android_abi: android_abi_for(bin.arch),
            internal_name: soname,
            dependencies: needed_libraries,
            jni_exports,
            has_jni_onload,
        }
    }

    pub(crate) fn from_pe(bin: &LoadedBinary, pe: Option<&PeFile>) -> Self {
        let pe_kind = pe.map_or(PeKind::Unknown, |p| {
            if p.is_64 {
                // Check characteristics or subsystem.
                if p.header.coff_header.characteristics & 0x2000 != 0 {
                    PeKind::Dll
                } else if p
                    .header
                    .optional_header
                    .is_some_and(|oh| oh.windows_fields.subsystem == 1)
                {
                    PeKind::Driver
                } else {
                    PeKind::Executable
                }
            } else {
                PeKind::Unknown
            }
        });

        let dependencies = pe
            .map(|p| p.libraries.iter().map(|lib| (*lib).to_owned()).collect())
            .unwrap_or_default();

        Self {
            format: bin.format,
            elf_kind: None,
            pe_kind: Some(pe_kind),
            android_abi: None, // Android ABIs are for ELF/Linux usually.
            internal_name: None,
            dependencies,
            jni_exports: 0,
            has_jni_onload: false,
        }
    }
}

fn android_abi_for(arch: Arch) -> Option<AndroidAbi> {
    match arch {
        Arch::Arm => Some(AndroidAbi::ArmeabiV7a),
        Arch::Arm64 => Some(AndroidAbi::Arm64V8a),
        Arch::X86 => Some(AndroidAbi::X86),
        Arch::X86_64 => Some(AndroidAbi::X86_64),
        Arch::Mips => Some(AndroidAbi::Mips),
        Arch::Mips64 => Some(AndroidAbi::Mips64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use omnisec_core::{Endian, Format};
    use omnisec_loader::{Export, LoadedBinary};

    use super::*;

    #[test]
    fn profile_infers_android_abi_and_jni_exports() {
        let mut bin = LoadedBinary::new(Format::Elf, Arch::Arm64, Endian::Little, 0);
        bin.exports.push(Export {
            name: "JNI_OnLoad".into(),
            address: 0x1000,
            ordinal: None,
            is_forwarder: false,
            forward_target: None,
        });
        bin.exports.push(Export {
            name: "Java_com_example_App_nativeMain".into(),
            address: 0x1100,
            ordinal: None,
            is_forwarder: false,
            forward_target: None,
        });

        let profile = TargetProfile::from_elf(&bin, None);

        assert_eq!(profile.elf_kind, Some(ElfKind::Unknown));
        assert_eq!(profile.android_abi, Some(AndroidAbi::Arm64V8a));
        assert_eq!(profile.jni_exports, 1);
        assert!(profile.has_jni_onload);
    }
}
