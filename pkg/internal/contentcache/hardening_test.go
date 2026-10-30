package contentcache

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// shardKey builds a key that always lands in hot shard 0 so LRU ordering can
// be asserted exactly.
func shardKey(n byte) ContentKey {
	var k ContentKey
	k[0] = 0
	k[1] = n
	return k
}

func keysEqual(got []ContentKey, want ...ContentKey) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// ── hot cache LRU ──────────────────────────────────────────────────────────

func TestHotCacheEvictsLeastRecentlyUsed(t *testing.T) {
	hc := newHotCache(3*hotShardCount, 64*1024*hotShardCount)
	k1, k2, k3, k4 := shardKey(1), shardKey(2), shardKey(3), shardKey(4)
	for _, k := range []ContentKey{k1, k2, k3} {
		hc.put(NamespaceGNN, k, []byte("payload"))
	}
	if got := hc.orderedKeys(NamespaceGNN, 0); !keysEqual(got, k3, k2, k1) {
		t.Fatalf("insert order = %v, want k3,k2,k1", got)
	}

	// A hit must refresh recency; the old implementation could not do this
	// because Get only held a read lock.
	if _, ok := hc.get(NamespaceGNN, k1); !ok {
		t.Fatal("k1 missing")
	}
	if got := hc.orderedKeys(NamespaceGNN, 0); !keysEqual(got, k1, k3, k2) {
		t.Fatalf("after get order = %v, want k1,k3,k2", got)
	}

	if evicted := hc.put(NamespaceGNN, k4, []byte("payload")); evicted != 1 {
		t.Fatalf("evicted = %d, want 1", evicted)
	}
	if got := hc.orderedKeys(NamespaceGNN, 0); !keysEqual(got, k4, k1, k3) {
		t.Fatalf("after evict order = %v, want k4,k1,k3", got)
	}
	if _, ok := hc.get(NamespaceGNN, k2); ok {
		t.Fatal("least recently used entry survived eviction")
	}
}

func TestHotCacheEnforcesByteBudget(t *testing.T) {
	// 100 bytes per (shard, namespace).
	hc := newHotCache(1000*hotShardCount, 100*hotShardCount)

	big := make([]byte, 60)
	hc.put(NamespaceGNN, shardKey(1), big)
	if _, ok := hc.get(NamespaceGNN, shardKey(1)); ok {
		t.Fatal("entry larger than half the budget must stay on disk only")
	}

	hc.put(NamespaceGNN, shardKey(2), make([]byte, 40))
	hc.put(NamespaceGNN, shardKey(3), make([]byte, 40))
	_, bytesUsed := hc.stats()
	if bytesUsed != 80 {
		t.Fatalf("hot bytes = %d, want 80", bytesUsed)
	}
	hc.put(NamespaceGNN, shardKey(4), make([]byte, 40))
	if _, bytesUsed = hc.stats(); bytesUsed > 100 {
		t.Fatalf("hot bytes = %d, want <= 100", bytesUsed)
	}
	if _, ok := hc.get(NamespaceGNN, shardKey(2)); ok {
		t.Fatal("byte-budget eviction did not drop the oldest entry")
	}
}

func TestHotCacheNamespacesAreIsolated(t *testing.T) {
	hc := newHotCache(1*hotShardCount, 64*1024*hotShardCount)
	hc.put(NamespaceGNN, shardKey(1), []byte("gnn"))
	hc.put(NamespaceMetrics, shardKey(2), []byte("metrics"))
	hc.put(NamespaceMetrics, shardKey(3), []byte("metrics"))
	if _, ok := hc.get(NamespaceGNN, shardKey(1)); !ok {
		t.Fatal("churn in one namespace evicted another namespace")
	}
}

// TestStoreHotCacheDoesNotFreeze covers the old bug where promotion stopped
// entirely once a namespace map reached its entry limit.
func TestStoreHotCacheDoesNotFreeze(t *testing.T) {
	store, err := NewStore(StoreConfig{BaseDir: t.TempDir(), MaxMemoryPerNS: hotShardCount})
	if err != nil {
		t.Fatal(err)
	}
	var first ContentKey
	for i := 0; i < 200; i++ {
		key := ComputeKey([]byte(fmt.Sprintf("entry-%d", i)))
		if i == 0 {
			first = key
		}
		if err := store.Put(NamespaceCFG, key, []byte(fmt.Sprintf("value-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	store.hot.clear()
	if _, ok := store.Get(NamespaceCFG, first); !ok {
		t.Fatal("entry not readable from disk")
	}
	if !store.hot.has(NamespaceCFG, first) {
		t.Fatal("disk hit was not promoted into the hot cache")
	}
}

func TestStoreConcurrentAccessIsRaceFree(t *testing.T) {
	store, err := NewStore(StoreConfig{
		BaseDir:             t.TempDir(),
		MaxMemoryPerNS:      64,
		MaxMemoryBytesPerNS: 64 * 1024,
		MaxDiskBytes:        256 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for w := 0; w < 32; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 60; i++ {
				key := ComputeKey([]byte(fmt.Sprintf("k-%d-%d", w, i%20)))
				payload := []byte(fmt.Sprintf("payload-%d-%d", w, i))
				if err := store.Put(NamespaceGNN, key, payload); err != nil {
					t.Errorf("put: %v", err)
					return
				}
				store.Get(NamespaceGNN, key)
				if i%7 == 0 {
					store.Delete(NamespaceGNN, key)
				}
			}
		}(w)
	}
	wg.Wait()
	if runtime.GOOS == "windows" {
		time.Sleep(50 * time.Millisecond)
	}
	if entries, bytesUsed := store.hot.stats(); entries < 0 || bytesUsed < 0 {
		t.Fatalf("corrupt hot stats: %d entries, %d bytes", entries, bytesUsed)
	}
}

// ── disk eviction ────────────────────────────────────────────────────────

func fillStore(t *testing.T, store *Store, n int, payload []byte) []ContentKey {
	t.Helper()
	keys := make([]ContentKey, 0, n)
	for i := 0; i < n; i++ {
		key := ComputeKey([]byte(fmt.Sprintf("disk-%d", i)))
		if err := store.Put(NamespaceGNN, key, payload); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
		keys = append(keys, key)
	}
	return keys
}

// TestDiskEvictionInvalidatesHotCache covers the main consistency bug: files
// were deleted from disk while this process kept serving them from RAM.
func TestDiskEvictionInvalidatesHotCache(t *testing.T) {
	store, err := NewStore(StoreConfig{
		BaseDir:      t.TempDir(),
		MaxDiskBytes: 8 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	keys := fillStore(t, store, 60, make([]byte, 256))
	if store.Stats().DiskEvictions == 0 {
		t.Fatal("expected disk evictions")
	}
	for _, key := range keys {
		path := store.diskPath(NamespaceGNN, key)
		_, statErr := os.Stat(path)
		onDisk := statErr == nil
		inHot := store.hot.has(NamespaceGNN, key)
		if inHot && !onDisk {
			t.Fatalf("key %s served from RAM after disk eviction", key.Short())
		}
		if _, ok := store.Get(NamespaceGNN, key); ok && !onDisk {
			t.Fatalf("Get returned an entry that no longer exists on disk: %s", key.Short())
		}
	}
}

func TestDiskEvictionRespectsLowWaterMark(t *testing.T) {
	const limit = 16 * 1024
	store, err := NewStore(StoreConfig{BaseDir: t.TempDir(), MaxDiskBytes: limit})
	if err != nil {
		t.Fatal(err)
	}
	fillStore(t, store, 120, make([]byte, 256))
	st := store.Stats()
	if st.DiskBytes > limit {
		t.Fatalf("disk usage %d exceeds limit %d", st.DiskBytes, limit)
	}
	if st.DiskEvictions == 0 {
		t.Fatal("expected disk evictions")
	}
	actual, err := directorySize(store.baseDir)
	if err != nil {
		t.Fatal(err)
	}
	if actual > limit {
		t.Fatalf("on-disk size %d exceeds limit %d", actual, limit)
	}
}

func TestDiskBytesTracksRealUsage(t *testing.T) {
	store, err := NewStore(StoreConfig{BaseDir: t.TempDir(), MaxDiskBytes: 64 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	keys := fillStore(t, store, 40, make([]byte, 128))
	for i, key := range keys {
		if i%3 == 0 {
			store.Delete(NamespaceGNN, key)
		}
	}
	actual, err := directorySize(store.baseDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Stats().DiskBytes; got != actual {
		t.Fatalf("tracked disk bytes = %d, actual = %d", got, actual)
	}
}

func TestOrphanTempFilesAreCollected(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(StoreConfig{BaseDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(store.baseDir, string(NamespaceGNN), tmpFilePrefix+"crashed")
	if err := os.WriteFile(orphan, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * tmpFileMaxAge)
	if err := os.Chtimes(orphan, old, old); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewStore(StoreConfig{BaseDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("stale temp file survived: %v", err)
	}
	if fresh.Stats().OrphansRemoved == 0 {
		t.Fatal("orphan removal was not counted")
	}
}

func TestClearRecreatesLayout(t *testing.T) {
	store, err := NewStore(StoreConfig{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	key := ComputeKey([]byte("cleared"))
	if err := store.Put(NamespaceGNN, key, []byte("value")); err != nil {
		t.Fatal(err)
	}
	if err := store.Clear(); err != nil {
		t.Fatal(err)
	}
	for _, ns := range AllNamespaces() {
		info, statErr := os.Stat(filepath.Join(store.baseDir, string(ns)))
		if statErr != nil || !info.IsDir() {
			t.Fatalf("namespace %s not recreated: %v", ns, statErr)
		}
	}
	// The store must remain usable, and the cleared value must be gone.
	if _, ok := store.Get(NamespaceGNN, key); ok {
		t.Fatal("cleared entry still readable")
	}
	if err := store.Put(NamespaceGNN, key, []byte("value")); err != nil {
		t.Fatalf("store unusable after Clear: %v", err)
	}
}

func TestInvalidateNamespaceRecreatesDirectory(t *testing.T) {
	store, err := NewStore(StoreConfig{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	key := ComputeKey([]byte("ns"))
	if err := store.Put(NamespaceTaint, key, []byte("value")); err != nil {
		t.Fatal(err)
	}
	if err := store.InvalidateNamespace(NamespaceTaint); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get(NamespaceTaint, key); ok {
		t.Fatal("invalidated entry still readable")
	}
	if err := store.Put(NamespaceTaint, key, []byte("value")); err != nil {
		t.Fatalf("namespace unusable after invalidation: %v", err)
	}
}

// ── record framing / integrity ─────────────────────────────────────────────

func TestRecordRoundTrip(t *testing.T) {
	key := ComputeKey([]byte("round-trip"))
	payload := []byte(`{"hello":"world"}`)
	decoded, err := decodeRecord(NamespaceCFG, key, encodeRecord(NamespaceCFG, key, payload))
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(payload) {
		t.Fatalf("payload = %q, want %q", decoded, payload)
	}
}

func TestDecodeRecordRejectsDamage(t *testing.T) {
	key := ComputeKey([]byte("damage"))
	otherKey := ComputeKey([]byte("other"))
	payload := []byte("a reasonably sized payload")
	good := encodeRecord(NamespaceCFG, key, payload)

	flipped := append([]byte(nil), good...)
	flipped[len(flipped)-1] ^= 0x01

	truncated := append([]byte(nil), good[:len(good)-3]...)

	badMagic := append([]byte(nil), good...)
	badMagic[0] = 'X'

	cases := map[string][]byte{
		"flipped bit":     flipped,
		"truncated":       truncated,
		"bad magic":       badMagic,
		"empty file":      {},
		"junk":            []byte("not a cache record at all"),
		"foreign key":     encodeRecord(NamespaceCFG, otherKey, payload),
		"foreign ns":      encodeRecord(NamespaceGNN, key, payload),
		"header only":     good[:recordFixedBytes+len(NamespaceCFG)],
		"single byte":     good[:1],
		"legacy raw json": []byte(`{"legacy":true}`),
	}
	for name, raw := range cases {
		if _, err := decodeRecord(NamespaceCFG, key, raw); !errors.Is(err, ErrCorruptEntry) {
			t.Errorf("%s: error = %v, want ErrCorruptEntry", name, err)
		}
	}
}

func TestStoreDropsCorruptEntry(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(StoreConfig{BaseDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	key := ComputeKey([]byte("corrupt"))
	if err := store.Put(NamespaceCFG, key, []byte("trusted payload")); err != nil {
		t.Fatal(err)
	}
	path := store.diskPath(NamespaceCFG, key)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xFF
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	// A fresh store cannot mask the damage with a valid RAM copy.
	fresh, err := NewStore(StoreConfig{BaseDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.Get(NamespaceCFG, key); ok {
		t.Fatal("corrupt entry was served")
	}
	if got := fresh.Stats().CorruptEntries; got != 1 {
		t.Fatalf("CorruptEntries = %d, want 1", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("corrupt entry was not deleted: %v", err)
	}
}

func TestStoreRejectsEntryCopiedFromAnotherKey(t *testing.T) {
	store, err := NewStore(StoreConfig{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	k1 := ComputeKey([]byte("first"))
	k2 := ComputeKey([]byte("second"))
	if err := store.Put(NamespaceCFG, k1, []byte("first payload")); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(NamespaceCFG, k2, []byte("second payload")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(store.diskPath(NamespaceCFG, k1))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.diskPath(NamespaceCFG, k2), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store.hot.clear()
	if _, ok := store.Get(NamespaceCFG, k2); ok {
		t.Fatal("payload belonging to another key was accepted")
	}
}

func TestStoreRejectsWorldReadableEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permission bits are not supported on Windows")
	}
	store, err := NewStore(StoreConfig{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	key := ComputeKey([]byte("perm"))
	if err := store.Put(NamespaceCFG, key, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.diskPath(NamespaceCFG, key), 0o644); err != nil {
		t.Fatal(err)
	}
	store.hot.clear()
	if _, ok := store.Get(NamespaceCFG, key); ok {
		t.Fatal("group/other-accessible cache entry was trusted")
	}
}

// ── benchmarks ────────────────────────────────────────────────────────────

func BenchmarkStoreGetHot(b *testing.B) {
	store, err := NewStore(StoreConfig{BaseDir: b.TempDir()})
	if err != nil {
		b.Fatal(err)
	}
	keys := make([]ContentKey, 256)
	payload := make([]byte, 512)
	if _, err := rand.Read(payload); err != nil {
		b.Fatal(err)
	}
	for i := range keys {
		keys[i] = ComputeKey([]byte(fmt.Sprintf("bench-%d", i)))
		if err := store.Put(NamespaceGNN, keys[i], payload); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			store.Get(NamespaceGNN, keys[i%len(keys)])
			i++
		}
	})
}

func BenchmarkEnsureDiskCapacity(b *testing.B) {
	dir := b.TempDir()
	store, err := NewStore(StoreConfig{BaseDir: dir, MaxDiskBytes: 1 << 30})
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 64)
	for i := 0; i < 50000; i++ {
		if err := store.Put(NamespaceGNN, ComputeKey([]byte(fmt.Sprintf("scale-%d", i))), payload); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.diskMu.Lock()
		store.evictIndex = nil
		store.diskMu.Unlock()
		if err := store.ensureDiskCapacity(1024, -1); err != nil {
			b.Fatal(err)
		}
	}
}
