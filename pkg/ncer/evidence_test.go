package ncer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEvidenceStore_StoreThenRetrieveRoundTrips(t *testing.T) {
	store, err := OpenEvidenceStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenEvidenceStore: %v", err)
	}

	hash, err := store.Store([]byte("hello ncer"))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	got, err := store.Retrieve(hash)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if string(got) != "hello ncer" {
		t.Errorf("Retrieve = %q, want %q", got, "hello ncer")
	}
}

func TestEvidenceStore_RetrieveMissingHashReturnsNil(t *testing.T) {
	store, err := OpenEvidenceStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenEvidenceStore: %v", err)
	}

	got, err := store.Retrieve(strings.Repeat("0", 64))
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if got != nil {
		t.Errorf("Retrieve of missing hash = %v, want nil", got)
	}
}

func TestEvidenceStore_IdenticalBytesProduceIdenticalHash(t *testing.T) {
	store, err := OpenEvidenceStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenEvidenceStore: %v", err)
	}

	a, err := store.Store([]byte("same payload"))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	b, err := store.Store([]byte("same payload"))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if a != b {
		t.Errorf("identical bytes produced different hashes: %q vs %q", a, b)
	}
}

func TestEvidenceStore_DistinctBytesProduceDistinctHashes(t *testing.T) {
	store, err := OpenEvidenceStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenEvidenceStore: %v", err)
	}

	a, err := store.Store([]byte("payload a"))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	b, err := store.Store([]byte("payload b"))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if a == b {
		t.Errorf("distinct bytes produced the same hash: %q", a)
	}
}

func TestEvidenceStore_LayoutIsShardedByHashPrefix(t *testing.T) {
	root := t.TempDir()
	store, err := OpenEvidenceStore(root)
	if err != nil {
		t.Fatalf("OpenEvidenceStore: %v", err)
	}

	hash, err := store.Store([]byte("layout check"))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	want := filepath.Join(root, hash[:2], hash[2:])
	if store.pathFor(hash) != want {
		t.Errorf("pathFor(%q) = %q, want %q", hash, store.pathFor(hash), want)
	}
}

func TestEvidenceStore_VerifyReturnsTrueForValidEvidence(t *testing.T) {
	store, err := OpenEvidenceStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenEvidenceStore: %v", err)
	}

	hash, err := store.Store([]byte("trustworthy evidence"))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	ok, err := store.Verify(hash)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("Verify = false, want true for untouched evidence")
	}
}

func TestEvidenceStore_VerifyReturnsFalseForModifiedEvidence(t *testing.T) {
	store, err := OpenEvidenceStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenEvidenceStore: %v", err)
	}

	hash, err := store.Store([]byte("original evidence"))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := os.WriteFile(store.pathFor(hash), []byte("tampered evidence"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ok, err := store.Verify(hash)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Error("Verify = true, want false for tampered evidence")
	}
}

func TestEvidenceStore_VerifyReturnsFalseForMissingEvidence(t *testing.T) {
	store, err := OpenEvidenceStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenEvidenceStore: %v", err)
	}

	ok, err := store.Verify(strings.Repeat("0", 64))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Error("Verify = true, want false for missing evidence")
	}
}

func TestEvidenceStore_RejectsMalformedReferences(t *testing.T) {
	store, err := OpenEvidenceStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenEvidenceStore: %v", err)
	}

	for _, hash := range []string{"", "abc", strings.Repeat("A", 64), "../outside"} {
		if _, err := store.Retrieve(hash); err == nil {
			t.Errorf("Retrieve(%q) succeeded for malformed hash", hash)
		}
		if _, err := store.Verify(hash); err == nil {
			t.Errorf("Verify(%q) succeeded for malformed hash", hash)
		}
	}
}

// TestEvidenceStore_RepeatedStoreSkipsDiskAfterFirstWrite proves the
// in-memory dedup cache is consulted before touching the filesystem: once a
// hash has been stored, deleting the underlying file out from under the
// store and calling Store again for the same bytes must NOT recreate it,
// because the second call is served entirely from the known-hashes cache.
// If Store ever regresses to re-checking disk unconditionally, this test
// would start failing since Retrieve would once again find the file.
func TestEvidenceStore_RepeatedStoreSkipsDiskAfterFirstWrite(t *testing.T) {
	store, err := OpenEvidenceStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenEvidenceStore: %v", err)
	}

	hash, err := store.Store([]byte("cached payload"))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := os.Remove(store.pathFor(hash)); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	again, err := store.Store([]byte("cached payload"))
	if err != nil {
		t.Fatalf("Store (second): %v", err)
	}
	if again != hash {
		t.Errorf("second Store hash = %q, want %q", again, hash)
	}

	got, err := store.Retrieve(hash)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if got != nil {
		t.Errorf("Retrieve = %q after cache-served Store skipped disk, want nil (file was removed)", got)
	}
}

// TestEvidenceStore_StoreIsRaceFree exercises Store concurrently across
// many goroutines with overlapping content, so `go test -race` can catch
// unsynchronized access to the dedup cache added alongside it.
func TestEvidenceStore_StoreIsRaceFree(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(func() {
		for attempt := 0; attempt < 20; attempt++ {
			if err := os.RemoveAll(root); err == nil || os.IsNotExist(err) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	store, err := OpenEvidenceStore(root)
	if err != nil {
		t.Fatalf("OpenEvidenceStore: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := []byte(fmt.Sprintf("payload-%d", i%8))
			if _, err := store.Store(payload); err != nil {
				t.Errorf("Store: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestHexSHA256_MatchesKnownVector(t *testing.T) {
	got := hexSHA256(nil)
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("hexSHA256(nil) = %q, want %q", got, want)
	}
}
