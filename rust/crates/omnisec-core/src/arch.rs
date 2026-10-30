//! Architecture and target descriptors.

use omnisec_json::{FromJson, ToJson};

/// An instruction-set architecture / virtual machine target.
///
/// Native architectures (`X86`, `X86_64`, `Arm`, ...) map to real ISAs.
/// Virtual architectures (`Dalvik`, `Jvm`, `Cil`, `Wasm32/64`) map to
/// managed bytecode VMs. They live in the same enum because the OmniIR
/// lifter treats them uniformly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
#[allow(non_camel_case_types)]
pub enum Arch {
    /// 32-bit Intel.
    X86,
    /// 64-bit Intel / AMD64.
    X86_64,
    /// 32-bit ARM (ARMv7-ish).
    Arm,
    /// 64-bit ARM (AArch64).
    Arm64,
    /// 32-bit MIPS.
    Mips,
    /// 64-bit MIPS.
    Mips64,
    /// 32-bit RISC-V.
    RiscV32,
    /// 64-bit RISC-V.
    RiscV64,
    /// PowerPC 32-bit.
    Ppc,
    /// PowerPC 64-bit.
    Ppc64,
    /// SPARC.
    Sparc,
    /// Android Dalvik bytecode.
    Dalvik,
    /// JVM bytecode.
    Jvm,
    /// .NET Common Intermediate Language.
    Cil,
    /// WebAssembly 32-bit.
    Wasm32,
    /// WebAssembly 64-bit.
    Wasm64,
    /// Unknown / undetected.
    Unknown,
}

impl Arch {
    /// Short canonical name (lower-case, no underscores where avoidable).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "arm",
            Self::Arm64 => "arm64",
            Self::Mips => "mips",
            Self::Mips64 => "mips64",
            Self::RiscV32 => "riscv32",
            Self::RiscV64 => "riscv64",
            Self::Ppc => "ppc",
            Self::Ppc64 => "ppc64",
            Self::Sparc => "sparc",
            Self::Dalvik => "dalvik",
            Self::Jvm => "jvm",
            Self::Cil => "cil",
            Self::Wasm32 => "wasm32",
            Self::Wasm64 => "wasm64",
            Self::Unknown => "unknown",
        }
    }

    /// Pointer width on this architecture, when meaningful.
    #[must_use]
    pub const fn bitness(self) -> Option<Bitness> {
        match self {
            Self::X86
            | Self::Arm
            | Self::Mips
            | Self::RiscV32
            | Self::Ppc
            | Self::Sparc
            | Self::Wasm32 => Some(Bitness::Bits32),
            Self::X86_64
            | Self::Arm64
            | Self::Mips64
            | Self::RiscV64
            | Self::Ppc64
            | Self::Wasm64 => Some(Bitness::Bits64),
            // Managed bytecodes don't really have a physical pointer width.
            Self::Dalvik | Self::Jvm | Self::Cil | Self::Unknown => None,
        }
    }

    /// `true` if this is a real machine ISA (not a managed VM).
    #[must_use]
    pub const fn is_native(self) -> bool {
        matches!(
            self,
            Self::X86
                | Self::X86_64
                | Self::Arm
                | Self::Arm64
                | Self::Mips
                | Self::Mips64
                | Self::RiscV32
                | Self::RiscV64
                | Self::Ppc
                | Self::Ppc64
                | Self::Sparc
        )
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Endianness of the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum Endian {
    /// Little-endian (x86, ARM by default, RISC-V).
    Little,
    /// Big-endian (older PowerPC, MIPS BE, network order).
    Big,
}

impl Endian {
    /// Short name used in CLI output.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Little => "little",
            Self::Big => "big",
        }
    }
}

impl std::fmt::Display for Endian {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Pointer/word width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum Bitness {
    /// 32-bit pointers.
    Bits32,
    /// 64-bit pointers.
    Bits64,
}

impl Bitness {
    /// Pointer width in bytes (4 or 8).
    #[must_use]
    pub const fn ptr_bytes(self) -> usize {
        match self {
            Self::Bits32 => 4,
            Self::Bits64 => 8,
        }
    }

    /// Pointer width in bits (32 or 64).
    #[must_use]
    pub const fn ptr_bits(self) -> u32 {
        match self {
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }
}

impl std::fmt::Display for Bitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-bit", self.ptr_bits())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_archs_have_bitness() {
        for arch in [
            Arch::X86,
            Arch::X86_64,
            Arch::Arm,
            Arch::Arm64,
            Arch::Mips,
            Arch::Mips64,
            Arch::RiscV32,
            Arch::RiscV64,
            Arch::Ppc,
            Arch::Ppc64,
            Arch::Sparc,
        ] {
            assert!(arch.is_native(), "{arch:?}");
            assert!(arch.bitness().is_some(), "{arch:?}");
        }
    }

    #[test]
    fn managed_archs_are_not_native() {
        for arch in [Arch::Dalvik, Arch::Jvm, Arch::Cil] {
            assert!(!arch.is_native());
        }
    }

    #[test]
    fn bitness_helpers() {
        assert_eq!(Bitness::Bits32.ptr_bytes(), 4);
        assert_eq!(Bitness::Bits64.ptr_bytes(), 8);
        assert_eq!(Bitness::Bits32.ptr_bits(), 32);
        assert_eq!(Bitness::Bits64.ptr_bits(), 64);
    }
}
