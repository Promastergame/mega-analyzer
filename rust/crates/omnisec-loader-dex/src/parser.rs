//! Main DEX parser — orchestrates header parsing, section parsing, and index building.

use std::sync::Mutex;
use std::time::Instant;

use crate::error::{DexError, DexResult};
use crate::header::DexHeader;
use crate::sections;
use crate::types::{ParseMetrics, ParsedDex};

/// High-performance DEX parser.
///
/// # Example
///
/// ```ignore
/// let dex = DexParser::parse(&data)?;
/// println!("Version: {}", dex.version);
/// println!("Classes: {}", dex.classes.len());
/// ```
pub struct DexParser;

impl DexParser {
    /// Parse a DEX file from raw bytes. Returns a fully populated `ParsedDex`.
    pub fn parse(data: &[u8]) -> DexResult<ParsedDex> {
        let start = Instant::now();

        // Step 1: Parse and validate header
        let header = DexHeader::parse(data)?;

        let warnings = Mutex::new(Vec::new());
        let metrics_accum = Mutex::new((0u64, 0u64));

        // Step 2: Parse strings → types (sequential: types depend on strings)
        let strings = sections::parse_strings(data, &header, &warnings)?;
        let types = sections::parse_types(data, &header, &strings, &warnings)?;

        // Step 3: Parse protos + fields (both depend on strings + types)
        let protos = sections::parse_protos(data, &header, &strings, &types, &warnings)?;
        let fields = sections::parse_fields(data, &header, &strings, &types, &warnings)?;

        // Step 4: Parse methods (depends on protos)
        let methods = sections::parse_methods(data, &header, &strings, &types, &protos, &warnings)?;

        // Step 5: Parse classes (depends on strings + types)
        let mut classes = sections::parse_classes(data, &header, &strings, &types, &warnings)?;

        // Step 6: Parse class_data for all classes
        sections::parse_all_class_data(
            data,
            &mut classes,
            &fields,
            &methods,
            &warnings,
            &metrics_accum,
        );

        let final_warnings = warnings.into_inner().unwrap();
        let (total_code_bytes, instruction_count) = metrics_accum.into_inner().unwrap();

        let metrics = ParseMetrics {
            parse_duration: start.elapsed(),
            strings_count: strings.len(),
            types_count: types.len(),
            protos_count: protos.len(),
            fields_count: fields.len(),
            methods_count: methods.len(),
            classes_count: classes.len(),
            warnings_count: final_warnings.len(),
            total_code_bytes,
            instruction_count,
        };

        Ok(ParsedDex {
            version: header.version,
            strings,
            types,
            protos,
            fields,
            methods,
            classes,
            warnings: final_warnings,
            metrics,
        })
    }

    /// Parse a DEX file from a filesystem path.
    pub fn parse_file(path: &str) -> DexResult<ParsedDex> {
        let data = std::fs::read(path).map_err(|e| DexError::BadHeader {
            detail: format!("read {path}: {e}"),
        })?;
        Self::parse(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reject_non_dex() {
        let data = b"not a dex file at all";
        // 21 bytes < 112-byte header → TooSmall
        assert!(matches!(
            DexParser::parse(data),
            Err(DexError::TooSmall { .. })
        ));
    }

    #[test]
    fn test_reject_bad_magic() {
        // 112 bytes with wrong magic
        let data = [0xFFu8; 112];
        assert!(matches!(DexParser::parse(&data), Err(DexError::BadMagic)));
    }

    #[test]
    fn test_reject_too_small() {
        let data = [0u8; 10];
        assert!(matches!(
            DexParser::parse(&data),
            Err(DexError::TooSmall { .. })
        ));
    }
}
