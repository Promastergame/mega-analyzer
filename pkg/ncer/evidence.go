package ncer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// EvidenceStore is a minimal content-addressed, append-only store for raw
// evidence bytes on the local filesystem.
//
// It mirrors rust/crates/omnisec-ncer-evidence's on-disk layout byte for
// byte (SHA-256 hex digest, git-object-style sharding:
// <root>/<first 2 hex chars>/<remaining 62 hex chars>) so both sides agree
// on where a given hash lives on disk, even though nothing calls across the
// Go/Rust boundary yet. No signing, retention policy, or database layer —
// those are later-phase concerns.
type EvidenceStore struct {
	root string

	mu    sync.RWMutex
	known map[string]struct{}
}

// maxKnownHashes bounds the in-memory dedup cache. The cache only ever skips
// an os.Stat on a repeat Store of identical bytes — a miss costs one syscall,
// never a correctness problem — so once it reaches this size we evict rather
// than let a long-running process leak one map entry per distinct object
// stored (evidence hashes are 64-byte strings; an unbounded map over millions
// of objects is a real leak). The bound is generous enough that a single
// session's working set of duplicates stays fully cached.
const maxKnownHashes = 1 << 16 // 65536

// OpenEvidenceStore opens (creating if necessary) an evidence store rooted
// at root.
func OpenEvidenceStore(root string) (*EvidenceStore, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("ncer: init evidence store at %q: %w", root, err)
	}
	return &EvidenceStore{root: root, known: make(map[string]struct{})}, nil
}

// Store writes data to the store and returns its SHA-256 hex digest.
//
// Storing the same bytes more than once is a cheap no-op after the first
// write: the destination path is derived from content, so a later Store
// call for identical bytes finds the file already present and returns the
// same hash without rewriting it.
//
// A single sandbox run's evidence (HTTP bodies, correlation payloads, DNS
// records) is dominated by duplicates — the same request replayed, the same
// response body seen across retries (see TestValidation_DuplicateEvidenceRatio
// in ncer_validation_test.go). Storing each of those still cost an os.Stat
// syscall pre-cache, since content-addressing only skips the write, not the
// existence check. known caches hashes this store has already confirmed
// on disk this process, so a repeat Store call for identical bytes returns
// straight from memory instead of round-tripping through the filesystem.
func (s *EvidenceStore) Store(data []byte) (string, error) {
	hash := hexSHA256(data)

	s.mu.RLock()
	_, cached := s.known[hash]
	s.mu.RUnlock()
	if cached {
		return hash, nil
	}

	path := s.pathFor(hash)

	if _, err := os.Stat(path); err == nil {
		s.rememberHash(hash)
		return hash, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("ncer: stat evidence file %q: %w", path, err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("ncer: create evidence dir for %q: %w", path, err)
	}

	// Write to a uniquely-named sibling temp file and rename into place so a
	// concurrent reader never observes a partially-written object at the
	// final content-addressed path. The temp name must be unique per call,
	// not just per hash: two goroutines storing identical bytes concurrently
	// would otherwise both target the same "<path>.tmp", and whichever
	// renames first deletes the file out from under the other's Rename.
	// Both goroutines' Rename ultimately targets the same destination path;
	// on POSIX rename(2) performs that as an atomic replace, and on Windows
	// the rename below detects the already-present destination and converges
	// without error, so racing writes of identical content always succeed.
	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("ncer: create temp evidence file for %q: %w", path, err)
	}
	tmp := tmpFile.Name()
	_, writeErr := tmpFile.Write(data)
	// fsync the data before the rename so a crash between rename and the OS
	// flushing its page cache can't leave a zero-length or truncated object
	// under a valid content-addressed name (which Verify would later reject,
	// but only after the evidence is already lost). Durability of "immutable
	// evidence" is worth the extra syscall on the cold write path — repeat
	// Stores of identical bytes never reach here (known-cache / Stat short
	// circuit above).
	var syncErr error
	if writeErr == nil {
		syncErr = tmpFile.Sync()
	}
	closeErr := tmpFile.Close()
	if writeErr != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("ncer: write evidence file %q: %w", tmp, writeErr)
	}
	if syncErr != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("ncer: sync evidence file %q: %w", tmp, syncErr)
	}
	if closeErr != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("ncer: close evidence file %q: %w", tmp, closeErr)
	}
	if err := os.Rename(tmp, path); err != nil {
		// POSIX rename(2) atomically replaces an existing destination, so two
		// goroutines writing identical content both succeed. Windows
		// MoveFile, however, fails if the destination already exists — the
		// loser of the race here gets "Access is denied"/ERROR_ALREADY_EXISTS
		// even though the file it would have written is byte-for-byte
		// identical (content-addressing guarantees it). Treat "destination
		// already present" as success: the object is in place, just written
		// by the other goroutine. Any other rename error is real.
		if _, statErr := os.Stat(path); statErr == nil {
			os.Remove(tmp)
			s.rememberHash(hash)
			return hash, nil
		}
		os.Remove(tmp)
		return "", fmt.Errorf("ncer: finalize evidence file %q: %w", path, err)
	}

	s.rememberHash(hash)
	return hash, nil
}

// rememberHash records hash in the in-memory dedup cache so later Store
// calls for the same content skip the filesystem entirely.
func (s *EvidenceStore) rememberHash(hash string) {
	s.mu.Lock()
	// Evict a bounded batch once the cache is full. Map iteration order is
	// randomised, so this drops an arbitrary ~1/16 of entries — good enough
	// for a best-effort optimization cache (there is no recency to preserve;
	// any evicted hash simply costs one Stat next time it is stored). Deleting
	// a batch rather than one entry keeps the amortised cost of eviction O(1)
	// per insert instead of thrashing at exactly the cap.
	if len(s.known) >= maxKnownHashes {
		drop := maxKnownHashes / 16
		for k := range s.known {
			delete(s.known, k)
			drop--
			if drop <= 0 {
				break
			}
		}
	}
	s.known[hash] = struct{}{}
	s.mu.Unlock()
}

// Retrieve returns the bytes stored under hash, or (nil, nil) if nothing
// has been stored under that hash.
func (s *EvidenceStore) Retrieve(hash string) ([]byte, error) {
	if err := validateEvidenceHash(hash); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.pathFor(hash))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ncer: read evidence file for %q: %w", hash, err)
	}
	return data, nil
}

// Verify checks that the evidence stored under hash is intact: its bytes are
// read back from disk and re-hashed, and the result must match hash exactly.
// It returns false, not an error, if nothing is stored under hash or if the
// stored bytes' digest no longer matches (e.g. the file was modified or
// corrupted on disk).
func (s *EvidenceStore) Verify(hash string) (bool, error) {
	data, err := s.Retrieve(hash)
	if err != nil {
		return false, err
	}
	if data == nil {
		return false, nil
	}
	return hexSHA256(data) == hash, nil
}

// pathFor is the deterministic on-disk path for a given hex digest,
// git-object-style: <root>/<first 2 hex chars>/<remaining hex chars>.
func (s *EvidenceStore) pathFor(hash string) string {
	split := len(hash)
	if split > 2 {
		split = 2
	}
	return filepath.Join(s.root, hash[:split], hash[split:])
}

// validateEvidenceHash accepts only the canonical lowercase SHA-256 hex form
// shared with omnisec-ncer-evidence. Validation happens before path creation
// so an untrusted reference cannot escape the evidence-store root.
func validateEvidenceHash(hash string) error {
	if len(hash) != sha256.Size*2 {
		return fmt.Errorf("ncer: invalid evidence hash %q", hash)
	}
	for _, b := range []byte(hash) {
		if !(b >= '0' && b <= '9') && !(b >= 'a' && b <= 'f') {
			return fmt.Errorf("ncer: invalid evidence hash %q", hash)
		}
	}
	return nil
}

// hexSHA256 computes the lowercase hex SHA-256 digest of data.
func hexSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
