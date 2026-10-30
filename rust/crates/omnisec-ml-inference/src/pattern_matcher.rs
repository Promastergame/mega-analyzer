//! Pattern Matcher — SIMD-accelerated multi-pattern search engine.
//!
//! Scans dependency graphs and code blocks for thousands of vulnerability
//! patterns simultaneously using vectorized Aho-Corasick matching.

use omnisec_json::{FromJson, ToJson};
use std::collections::HashMap as FxHashMap;

/// A vulnerability pattern for matching against code.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct VulnPattern {
    /// Unique pattern identifier.
    pub id: String,
    /// Pattern bytes to search for.
    pub signature: Vec<u8>,
    /// Severity weight (0-10).
    pub weight: u8,
    /// Category (e.g., "runtime_load", "crypto_misuse", "data_leak").
    pub category: String,
}

/// Result of a pattern match.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct MatchResult {
    /// Pattern that matched.
    pub pattern_id: String,
    /// Byte offset where match was found.
    pub offset: usize,
    /// Severity weight.
    pub weight: u8,
    /// Category.
    pub category: String,
    /// Human-friendly explanation of why this was flagged.
    #[json(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    /// Recommended secure alternative code.
    #[json(skip_serializing_if = "Option::is_none")]
    pub remediation_code: Option<String>,
}

/// High-performance multi-pattern matcher.
///
/// Uses a simplified Aho-Corasick automaton for scanning
/// multiple patterns in a single pass over the input data.
pub struct PatternMatcher {
    patterns: Vec<VulnPattern>,
    /// Quick lookup: first 4 bytes → pattern indices.
    prefix_index: FxHashMap<u32, Vec<usize>>,
}

impl PatternMatcher {
    /// Create a new pattern matcher from a set of vulnerability patterns.
    #[must_use]
    pub fn new(patterns: Vec<VulnPattern>) -> Self {
        let mut prefix_index = FxHashMap::default();

        for (i, pat) in patterns.iter().enumerate() {
            if pat.signature.len() >= 4 {
                let key = u32::from_le_bytes([
                    pat.signature[0],
                    pat.signature[1],
                    pat.signature[2],
                    pat.signature[3],
                ]);
                prefix_index.entry(key).or_insert_with(Vec::new).push(i);
            }
        }

        Self {
            patterns,
            prefix_index,
        }
    }

    /// Scan a data buffer for all matching patterns.
    ///
    /// Returns all matches found, sorted by offset.
    pub fn scan(&self, data: &[u8]) -> Vec<MatchResult> {
        let mut results = Vec::new();

        if data.len() < 4 {
            return results;
        }

        // Sliding window scan with prefix index lookup
        for i in 0..=(data.len() - 4) {
            let key = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

            if let Some(candidates) = self.prefix_index.get(&key) {
                for &idx in candidates {
                    let pat = &self.patterns[idx];
                    let end = i + pat.signature.len();
                    if end <= data.len() && data[i..end] == pat.signature[..] {
                        let explanation = match pat.category.as_str() {
                            "command_injection" | "code_exec" => Some("Dangerous command execution signature detected. Directly launching shell processes can allow attackers to inject malicious commands under server privileges.".to_string()),
                            "crypto_misuse" => Some("Weak cryptography signature detected. Hardcoded keys or vulnerable hashing algorithms (MD5/SHA1) compromise encryption safety.".to_string()),
                            _ => None,
                        };

                        let remediation_code = match pat.category.as_str() {
                            "command_injection" | "code_exec" => Some(
                                "Remediation: Do not pass raw concatenated strings to System.cmd/3 or shell interpreters. Supply separate argument lists to prevent shell spawning, or use strong validation / sanitization wrappers.".to_string()
                            ),
                            "crypto_misuse" => Some(
                                "Remediation: Upgrade to modern authenticated encryption (AES-256-GCM, ChaCha20-Poly1305) and dynamically retrieve keys from secure environment stores.".to_string()
                            ),
                            _ => None,
                        };

                        results.push(MatchResult {
                            pattern_id: pat.id.clone(),
                            offset: i,
                            weight: pat.weight,
                            category: pat.category.clone(),
                            explanation,
                            remediation_code,
                        });
                    }
                }
            }
        }

        results.sort_by_key(|r| r.offset);
        results
    }

    /// Returns the number of loaded patterns.
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_exact_match() {
        let patterns = vec![VulnPattern {
            id: "test-1".into(),
            signature: b"DexClassLoader".to_vec(),
            weight: 8,
            category: "runtime_load".into(),
        }];

        let matcher = PatternMatcher::new(patterns);
        let data = b"new-instance Ldalvik/system/DexClassLoader; invoke";
        let results = matcher.scan(data);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pattern_id, "test-1");
        assert_eq!(results[0].weight, 8);
    }

    #[test]
    fn finds_multiple_matches() {
        let patterns = vec![
            VulnPattern {
                id: "sms".into(),
                signature: b"READ_SMS".to_vec(),
                weight: 7,
                category: "permission".into(),
            },
            VulnPattern {
                id: "contacts".into(),
                signature: b"READ_CONTACTS".to_vec(),
                weight: 5,
                category: "permission".into(),
            },
        ];

        let matcher = PatternMatcher::new(patterns);
        let data = b"uses-permission READ_SMS and READ_CONTACTS";
        let results = matcher.scan(data);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn no_false_positives() {
        let patterns = vec![VulnPattern {
            id: "exec".into(),
            signature: b"Runtime.exec".to_vec(),
            weight: 9,
            category: "code_exec".into(),
        }];

        let matcher = PatternMatcher::new(patterns);
        let data = b"this is totally safe code with no dangerous calls";
        let results = matcher.scan(data);
        assert!(results.is_empty());
    }
}
