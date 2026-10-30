//! Evidence integration for NCER causal reconciliation.
//!
//! Stores raw reconciliation inputs in an immutable, content-addressed evidence
//! store (`omnisec-ncer-evidence`) and verifies references without panicking
//! on integrity failures.
//!
//! Not currently called from `omnisec-ncer-reconcile-ffi`'s exported
//! `omnisec_ncer_reconcile`, which only runs
//! `from_mitm_capture → bind_effects → score_causal`. Evidence tracking for
//! the result Go callers see is handled independently by `pkg/ncer`'s own
//! `EvidenceStore` (see `omnisec-ncer-evidence`'s crate doc). This function is
//! exercised by its own tests and available for a future FFI entry point that
//! threads Rust-side evidence through.

use omnisec_ncer_evidence::EvidenceStore;

/// Stores raw reconciliation input in `store` and verifies its integrity.
///
/// Returns `(sha256_hash, verified)`. If storing or verification fails,
/// `verified` is returned as `false` and processing continues without panicking.
pub fn store_and_verify(store: &EvidenceStore, raw_input: &[u8]) -> (String, bool) {
    match store.store(raw_input) {
        Ok(hash) => match store.verify(&hash) {
            Ok(ok) => (hash, ok),
            Err(_) => (hash, false),
        },
        Err(_) => (omnisec_ncer_evidence::hex_sha256(raw_input), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "omnisec-ncer-reconcile-evidence-{label}-{}-{n}",
                std::process::id()
            ));
            TestDir(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn store_and_verify_success() {
        let dir = TestDir::new("success");
        let store = EvidenceStore::open(&dir.0).unwrap();

        let payload = b"{\"test\": \"payload\"}";
        let (hash, verified) = store_and_verify(&store, payload);
        assert!(!hash.is_empty());
        assert!(verified);
    }

    #[test]
    fn store_and_verify_deduplication() {
        let dir = TestDir::new("dedup");
        let store = EvidenceStore::open(&dir.0).unwrap();

        let payload = b"{\"test\": \"duplicate\"}";
        let (hash1, ver1) = store_and_verify(&store, payload);
        let (hash2, ver2) = store_and_verify(&store, payload);
        assert_eq!(hash1, hash2);
        assert!(ver1);
        assert!(ver2);
    }

    #[test]
    fn store_and_verify_corrupted_evidence_does_not_panic() {
        let dir = TestDir::new("corrupt");
        let store = EvidenceStore::open(&dir.0).unwrap();

        let payload = b"original data";
        let (hash, _) = store_and_verify(&store, payload);

        // Tamper with the evidence file on disk
        let shard = &hash[..2];
        let rest = &hash[2..];
        let file_path = dir.0.join(shard).join(rest);
        fs::write(&file_path, b"corrupted data").unwrap();

        assert!(!store.verify(&hash).unwrap());
    }
}
