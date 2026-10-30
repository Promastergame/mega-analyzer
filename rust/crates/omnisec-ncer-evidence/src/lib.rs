//! Minimal content-addressed, append-only evidence store for the NCER
//! (Network Claim-Evidence Reconciliation) layer.
//!
//! Raw evidence (e.g. the original payload a typed event was derived from,
//! see `omnisec-ncer-types`) is written once, keyed by the SHA-256 hex
//! digest of its bytes, and this crate never modifies or deletes it after
//! that. Layout is deterministic and git-object-style: the first two hex
//! characters of the hash become a subdirectory, the remaining 62 become
//! the filename (`<root>/<xx>/<yy...y>`), so no single directory ends up
//! with millions of entries.
//!
//! This crate is intentionally narrow: no signing, no retention/eviction
//! policy, no network access, no FFI surface, no database. Those are
//! later-phase concerns layered on top once this primitive is in place.
//!
//! `pkg/ncer/evidence.go` on the Go side implements the identical on-disk
//! layout independently (not via FFI into this crate) so both languages can
//! read/write the same evidence store directory. This is intentional
//! duplication, not accidental drift: the Go implementation is what's wired
//! into the live CLI pipeline today, while this crate is exercised by its own
//! unit tests and by `omnisec-ncer-reconcile::evidence::store_and_verify`
//! (itself not yet called from `omnisec-ncer-reconcile-ffi`'s exported
//! `omnisec_ncer_reconcile`). Wiring the two together over FFI is future work.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use omnisec_crypto::sha256;

/// Errors returned by [`EvidenceStore`].
#[derive(Debug)]
pub enum Error {
    /// The store's root directory could not be created or is not usable.
    Init {
        /// Root directory that failed to initialize.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// Reading or writing a piece of evidence failed.
    Io {
        /// File the failing operation was issued against.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// A requested evidence reference is not a lowercase SHA-256 hex digest.
    InvalidHash {
        /// The invalid reference supplied by the caller.
        hash: String,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init { path, source } => {
                write!(
                    f,
                    "failed to initialize evidence store at '{}': {source}",
                    path.display()
                )
            }
            Self::Io { path, source } => {
                write!(
                    f,
                    "I/O error on evidence file '{}': {source}",
                    path.display()
                )
            }
            Self::InvalidHash { hash } => write!(f, "invalid evidence hash '{hash}'"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Init { source, .. } | Self::Io { source, .. } => Some(source),
            Self::InvalidHash { .. } => None,
        }
    }
}

/// Convenience alias for `std::result::Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// A content-addressed, append-only store of raw evidence bytes on disk.
///
/// # Examples
///
/// ```
/// use std::fs;
/// use omnisec_ncer_evidence::EvidenceStore;
///
/// let dir = std::env::temp_dir().join("omnisec_ncer_evidence_example");
/// let _ = fs::remove_dir_all(&dir);
/// let store = EvidenceStore::open(&dir).unwrap();
/// let hash = store.store(b"sample evidence payload").unwrap();
/// assert!(store.verify(&hash).unwrap());
/// let _ = fs::remove_dir_all(&dir);
/// ```
pub struct EvidenceStore {
    root: PathBuf,
}

impl EvidenceStore {
    /// Opens (creating if necessary) an evidence store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|source| Error::Init {
            path: root.clone(),
            source,
        })?;
        Ok(Self { root })
    }

    /// Writes `bytes` to the store and returns their SHA-256 hex digest.
    ///
    /// Storing the same bytes more than once is a cheap no-op after the
    /// first write: the destination path is derived from content, so a
    /// later `store` call for identical bytes finds the file already
    /// present and returns the same hash without rewriting it.
    pub fn store(&self, bytes: &[u8]) -> Result<String> {
        let hash = hex_sha256(bytes);
        let path = self.path_for(&hash);

        if path.exists() {
            return Ok(hash);
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| Error::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        // Write to a sibling temp file and rename into place so a
        // concurrent reader never observes a partially-written object at
        // the final content-addressed path.
        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, bytes).map_err(|source| Error::Io {
            path: tmp_path.clone(),
            source,
        })?;
        fs::rename(&tmp_path, &path).map_err(|source| Error::Io {
            path: path.clone(),
            source,
        })?;

        Ok(hash)
    }

    /// Retrieves the bytes stored under `hash`, or `None` if nothing has
    /// been stored under that hash.
    pub fn retrieve(&self, hash: &str) -> Result<Option<Vec<u8>>> {
        validate_hash(hash)?;
        let path = self.path_for(hash);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(Error::Io { path, source }),
        }
    }

    /// Verifies that the evidence stored under `hash` is intact: its bytes
    /// are read back from disk and re-hashed, and the result must match
    /// `hash` exactly. Returns `Ok(false)` if nothing is stored under
    /// `hash`, or if the stored bytes' digest no longer matches (e.g. the
    /// file was modified or corrupted on disk).
    pub fn verify(&self, hash: &str) -> Result<bool> {
        match self.retrieve(hash)? {
            Some(bytes) => Ok(hex_sha256(&bytes) == hash),
            None => Ok(false),
        }
    }

    /// Deterministic on-disk path for a given hex digest, git-object-style:
    /// `<root>/<first 2 hex chars>/<remaining hex chars>`.
    fn path_for(&self, hash: &str) -> PathBuf {
        let split = hash.len().min(2);
        let (shard, rest) = hash.split_at(split);
        self.root.join(shard).join(rest)
    }

    /// Root directory this store was opened with.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Validates the canonical identifier used by the evidence store.
fn validate_hash(hash: &str) -> Result<()> {
    const SHA256_HEX_LEN: usize = 64;
    if hash.len() == SHA256_HEX_LEN
        && hash.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
        })
    {
        Ok(())
    } else {
        Err(Error::InvalidHash {
            hash: hash.to_owned(),
        })
    }
}

/// Computes the lowercase hex SHA-256 digest of `bytes`.
pub fn hex_sha256(bytes: &[u8]) -> String {
    let digest = sha256(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A scratch directory under the OS temp dir, removed on drop.
    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "omnisec-ncer-evidence-test-{label}-{}-{n}",
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
    fn store_then_retrieve_round_trips() {
        let dir = TestDir::new("roundtrip");
        let store = EvidenceStore::open(&dir.0).unwrap();

        let hash = store.store(b"hello ncer").unwrap();
        let got = store.retrieve(&hash).unwrap();

        assert_eq!(got, Some(b"hello ncer".to_vec()));
    }

    #[test]
    fn retrieve_missing_hash_returns_none() {
        let dir = TestDir::new("missing");
        let store = EvidenceStore::open(&dir.0).unwrap();

        let got = store.retrieve(&"0".repeat(64)).unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn identical_bytes_produce_identical_hash_and_are_not_rewritten() {
        let dir = TestDir::new("dedup");
        let store = EvidenceStore::open(&dir.0).unwrap();

        let a = store.store(b"same payload").unwrap();
        let b = store.store(b"same payload").unwrap();

        assert_eq!(a, b);
        assert_eq!(store.retrieve(&a).unwrap(), Some(b"same payload".to_vec()));
    }

    #[test]
    fn distinct_bytes_produce_distinct_hashes() {
        let dir = TestDir::new("distinct");
        let store = EvidenceStore::open(&dir.0).unwrap();

        let a = store.store(b"payload a").unwrap();
        let b = store.store(b"payload b").unwrap();

        assert_ne!(a, b);
    }

    #[test]
    fn storage_layout_is_sharded_by_hash_prefix() {
        let dir = TestDir::new("layout");
        let store = EvidenceStore::open(&dir.0).unwrap();

        let hash = store.store(b"layout check").unwrap();
        let expected_path = dir.0.join(&hash[..2]).join(&hash[2..]);

        assert!(
            expected_path.is_file(),
            "expected evidence at {expected_path:?}"
        );
    }

    #[test]
    fn verify_returns_true_for_valid_evidence() {
        let dir = TestDir::new("verify-valid");
        let store = EvidenceStore::open(&dir.0).unwrap();

        let hash = store.store(b"trustworthy evidence").unwrap();

        assert!(store.verify(&hash).unwrap());
    }

    #[test]
    fn verify_returns_false_for_modified_evidence() {
        let dir = TestDir::new("verify-modified");
        let store = EvidenceStore::open(&dir.0).unwrap();

        let hash = store.store(b"original evidence").unwrap();
        fs::write(store.path_for(&hash), b"tampered evidence").unwrap();

        assert!(!store.verify(&hash).unwrap());
    }

    #[test]
    fn verify_returns_false_for_missing_evidence() {
        let dir = TestDir::new("verify-missing");
        let store = EvidenceStore::open(&dir.0).unwrap();

        assert!(!store.verify(&"0".repeat(64)).unwrap());
    }

    #[test]
    fn malformed_hashes_are_rejected_before_path_resolution() {
        let dir = TestDir::new("invalid-hash");
        let store = EvidenceStore::open(&dir.0).unwrap();

        for hash in ["", "abc", "../outside"] {
            assert!(matches!(
                store.retrieve(hash),
                Err(Error::InvalidHash { .. })
            ));
            assert!(matches!(store.verify(hash), Err(Error::InvalidHash { .. })));
        }
        let uppercase = "A".repeat(64);
        assert!(matches!(
            store.retrieve(&uppercase),
            Err(Error::InvalidHash { .. })
        ));
    }

    #[test]
    fn hex_sha256_matches_known_vector() {
        assert_eq!(
            hex_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
