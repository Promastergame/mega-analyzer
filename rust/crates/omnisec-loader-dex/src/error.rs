//! Error types for DEX parsing.

use std::fmt;

/// All errors the DEX parser can produce.
#[derive(Debug, Clone)]
pub enum DexError {
    /// File too small to contain a valid DEX header.
    TooSmall {
        /// Actual size in bytes.
        actual: usize,
    },
    /// Bad magic bytes — not a DEX file.
    BadMagic,
    /// Invalid header field.
    BadHeader {
        /// Description of what went wrong.
        detail: String,
    },
    /// A section extends beyond the file boundary.
    SectionOutOfBounds {
        /// Section name.
        section: &'static str,
        /// Start offset.
        offset: u64,
        /// End offset.
        end: u64,
        /// File size.
        file_size: u64,
    },
    /// Item count is unreasonably large (OOM guard).
    CountTooLarge {
        /// Section name.
        section: &'static str,
        /// Count declared in header.
        count: u32,
    },
    /// Sections overlap in the file.
    SectionOverlap {
        /// First section name.
        a: &'static str,
        /// Second section name.
        b: &'static str,
    },
    /// Offset points outside data bounds.
    OutOfBounds {
        /// Description of what we tried to read.
        what: String,
        /// Offset attempted.
        offset: u64,
    },
    /// Bad ULEB128 / SLEB128 encoding.
    BadLeb128 {
        /// Description.
        what: String,
    },
    /// Bad MUTF-8 string encoding.
    BadMutf8 {
        /// Offset into the file.
        offset: u32,
        /// Detail.
        detail: String,
    },
}

impl fmt::Display for DexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall { actual } => {
                write!(f, "file too small for DEX header: {actual} bytes")
            }
            Self::BadMagic => write!(f, "bad magic: not a DEX file"),
            Self::BadHeader { detail } => write!(f, "bad header: {detail}"),
            Self::SectionOutOfBounds {
                section,
                offset,
                end,
                file_size,
            } => write!(
                f,
                "{section}: out of bounds [{offset}..{end}) > {file_size}"
            ),
            Self::CountTooLarge { section, count } => {
                write!(f, "{section}: count {count} exceeds safety limit")
            }
            Self::SectionOverlap { a, b } => {
                write!(f, "sections overlap: {a} ∩ {b}")
            }
            Self::OutOfBounds { what, offset } => {
                write!(f, "{what}: offset 0x{offset:x} out of bounds")
            }
            Self::BadLeb128 { what } => write!(f, "bad LEB128: {what}"),
            Self::BadMutf8 { offset, detail } => {
                write!(f, "bad MUTF-8 at 0x{offset:x}: {detail}")
            }
        }
    }
}

impl std::error::Error for DexError {}

/// Shorthand result type.
pub type DexResult<T> = Result<T, DexError>;
