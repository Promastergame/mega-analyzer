package contentcache

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func cacheTestDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "contentcache-unit-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var cleanupErr error
		for attempt := 0; attempt < 10; attempt++ {
			cleanupErr = os.RemoveAll(dir)
			if cleanupErr == nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Errorf("cleanup content cache: %v", cleanupErr)
	})
	return dir
}

func TestComputeKey(t *testing.T) {
	data := []byte("invoke-virtual {v0}, Lcom/app/License;->isValid()Z")
	key := ComputeKey(data)

	if key.IsZero() {
		t.Fatal("key should not be zero")
	}

	// Same input → same key
	key2 := ComputeKey(data)
	if key != key2 {
		t.Fatal("same input should produce same key")
	}

	// Different input → different key
	key3 := ComputeKey([]byte("different bytecode"))
	if key == key3 {
		t.Fatal("different input should produce different key")
	}
}

func TestComputeKeyFromBody(t *testing.T) {
	body := []string{
		"    .locals 2",
		"    # comment",
		"    const/4 v0, 0x1",
		"    return v0",
		"",
	}

	key := ComputeKeyFromBody(body)
	if key.IsZero() {
		t.Fatal("key should not be zero")
	}

	// Same body with different whitespace/comments → same key
	body2 := []string{
		".locals 2",
		"const/4 v0, 0x1",
		"return v0",
	}
	key2 := ComputeKeyFromBody(body2)
	if key != key2 {
		t.Fatal("normalized bodies should produce same key")
	}
}

func TestContentKeyHex(t *testing.T) {
	key := ComputeKey([]byte("test"))
	hex := key.Hex()
	if len(hex) != 64 {
		t.Fatalf("hex should be 64 chars, got %d", len(hex))
	}

	short := key.Short()
	if len(short) != 16 {
		t.Fatalf("short should be 16 chars, got %d", len(short))
	}
}

func TestStoreGetPut(t *testing.T) {
	dir := cacheTestDir(t)
	store, err := NewStore(StoreConfig{
		BaseDir:        dir,
		MaxMemoryPerNS: 100,
	})
	if err != nil {
		t.Fatal(err)
	}

	key := ComputeKey([]byte("method bytecode"))
	data := []byte(`{"cyclomatic": 5, "nesting": 2}`)

	// Get non-existent
	_, found := store.Get(NamespaceMetrics, key)
	if found {
		t.Fatal("should not find non-existent key")
	}

	// Put
	if err := store.Put(NamespaceMetrics, key, data); err != nil {
		t.Fatal(err)
	}

	// Get from hot cache
	got, found := store.Get(NamespaceMetrics, key)
	if !found {
		t.Fatal("should find key after put")
	}
	if string(got) != string(data) {
		t.Fatalf("got %s, want %s", got, data)
	}

	// Verify stats
	stats := store.Stats()
	if stats.Hits != 1 {
		t.Fatalf("expected 1 hit, got %d", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Fatalf("expected 1 miss, got %d", stats.Misses)
	}
	if stats.Writes != 1 {
		t.Fatalf("expected 1 write, got %d", stats.Writes)
	}
}

func TestStoreDiskPersistence(t *testing.T) {
	dir := cacheTestDir(t)

	key := ComputeKey([]byte("persistent method"))
	data := []byte(`{"score": 42}`)

	// Write with first store instance
	store1, err := NewStore(StoreConfig{BaseDir: dir, MaxMemoryPerNS: 100})
	if err != nil {
		t.Fatal(err)
	}
	if err := store1.Put(NamespaceCFG, key, data); err != nil {
		t.Fatal(err)
	}

	// Read with second store instance (empty hot cache)
	store2, err := NewStore(StoreConfig{BaseDir: dir, MaxMemoryPerNS: 100})
	if err != nil {
		t.Fatal(err)
	}
	got, found := store2.Get(NamespaceCFG, key)
	if !found {
		t.Fatal("should find key from disk")
	}
	if string(got) != string(data) {
		t.Fatalf("got %s, want %s", got, data)
	}
}

func TestStoreHas(t *testing.T) {
	dir := cacheTestDir(t)
	store, _ := NewStore(StoreConfig{BaseDir: dir, MaxMemoryPerNS: 100})

	key := ComputeKey([]byte("check"))
	if store.Has(NamespaceSSA, key) {
		t.Fatal("should not have non-existent key")
	}

	store.Put(NamespaceSSA, key, []byte("data"))
	if !store.Has(NamespaceSSA, key) {
		t.Fatal("should have key after put")
	}
}

func TestStoreDelete(t *testing.T) {
	dir := cacheTestDir(t)
	store, _ := NewStore(StoreConfig{BaseDir: dir, MaxMemoryPerNS: 100})

	key := ComputeKey([]byte("deleteme"))
	store.Put(NamespaceTaint, key, []byte("taint data"))

	store.Delete(NamespaceTaint, key)

	if store.Has(NamespaceTaint, key) {
		t.Fatal("should not have key after delete")
	}
}

func TestStoreNamespaceIsolation(t *testing.T) {
	dir := cacheTestDir(t)
	store, _ := NewStore(StoreConfig{BaseDir: dir, MaxMemoryPerNS: 100})

	key := ComputeKey([]byte("shared key"))
	store.Put(NamespaceCFG, key, []byte("cfg data"))
	store.Put(NamespaceSSA, key, []byte("ssa data"))

	cfgData, _ := store.Get(NamespaceCFG, key)
	ssaData, _ := store.Get(NamespaceSSA, key)

	if string(cfgData) == string(ssaData) {
		t.Fatal("namespaces should be isolated")
	}
}

func TestGetPutJSON(t *testing.T) {
	dir := cacheTestDir(t)
	store, _ := NewStore(StoreConfig{BaseDir: dir, MaxMemoryPerNS: 100})

	type Metrics struct {
		Cyclomatic int     `json:"cyclomatic"`
		Score      float64 `json:"score"`
	}

	key := ComputeKey([]byte("json method"))
	input := &Metrics{Cyclomatic: 7, Score: 42.5}

	if err := PutJSON(store, NamespaceMetrics, key, input); err != nil {
		t.Fatal(err)
	}

	got, found := GetJSON[Metrics](store, NamespaceMetrics, key)
	if !found {
		t.Fatal("should find JSON entry")
	}
	if got.Cyclomatic != 7 || got.Score != 42.5 {
		t.Fatalf("got %+v, want %+v", got, input)
	}
}

func TestStoreClear(t *testing.T) {
	dir := cacheTestDir(t)
	store, _ := NewStore(StoreConfig{BaseDir: dir, MaxMemoryPerNS: 100})

	key := ComputeKey([]byte("clearme"))
	store.Put(NamespaceCFG, key, []byte("data"))

	if err := store.Clear(); err != nil {
		t.Fatal(err)
	}

	if store.Has(NamespaceCFG, key) {
		t.Fatal("should not have key after clear")
	}

	// Verify directory is gone
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		// dir itself might still exist since it's the temp dir
	}
}

func TestZeroKey(t *testing.T) {
	dir := cacheTestDir(t)
	store, _ := NewStore(StoreConfig{BaseDir: dir, MaxMemoryPerNS: 100})

	var zeroKey ContentKey
	if !zeroKey.IsZero() {
		t.Fatal("zero key should be zero")
	}

	// Operations with zero key should be no-ops
	_, found := store.Get(NamespaceCFG, zeroKey)
	if found {
		t.Fatal("should not find zero key")
	}

	if store.Has(NamespaceCFG, zeroKey) {
		t.Fatal("should not have zero key")
	}
}

func TestStoreSchemaVersionsAreIsolated(t *testing.T) {
	dir := cacheTestDir(t)
	key := ComputeKey([]byte("same-method"))
	v1, err := NewStore(StoreConfig{BaseDir: dir, Version: 1, MaxMemoryPerNS: 2})
	if err != nil {
		t.Fatal(err)
	}
	v2, err := NewStore(StoreConfig{BaseDir: dir, Version: 2, MaxMemoryPerNS: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := v1.Put(NamespaceFeatures, key, []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if _, ok := v2.Get(NamespaceFeatures, key); ok {
		t.Fatal("schema v2 reused a v1 entry")
	}
}

func TestStoreReturnsDefensiveCopies(t *testing.T) {
	store, err := NewStore(StoreConfig{BaseDir: cacheTestDir(t), Version: 1, MaxMemoryPerNS: 2})
	if err != nil {
		t.Fatal(err)
	}
	key := ComputeKey([]byte("immutable"))
	input := []byte("original")
	if err := store.Put(NamespaceFeatures, key, input); err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'
	first, ok := store.Get(NamespaceFeatures, key)
	if !ok || string(first) != "original" {
		t.Fatalf("put retained caller-owned memory: %q", first)
	}
	first[0] = 'Y'
	second, _ := store.Get(NamespaceFeatures, key)
	if string(second) != "original" {
		t.Fatalf("get exposed cache-owned memory: %q", second)
	}
}

func TestStoreConcurrentIdenticalWrites(t *testing.T) {
	dir := cacheTestDir(t)
	stores := make([]*Store, 4)
	for i := range stores {
		var err error
		stores[i], err = NewStore(StoreConfig{BaseDir: dir, Version: 1, MaxMemoryPerNS: 2})
		if err != nil {
			t.Fatal(err)
		}
	}
	key := ComputeKey([]byte("shared"))
	data := []byte(`{"feature_ids":["a"]}`)
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(store *Store) {
			defer wg.Done()
			errs <- store.Put(NamespaceFeatures, key, data)
		}(stores[i%len(stores)])
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Put: %v", err)
		}
	}
	got, ok := stores[0].Get(NamespaceFeatures, key)
	if !ok || string(got) != string(data) {
		t.Fatalf("corrupt concurrent result: %q", got)
	}
}

func TestStoreRejectsInvalidNamespace(t *testing.T) {
	dir := cacheTestDir(t)
	store, err := NewStore(StoreConfig{BaseDir: dir, MaxMemoryPerNS: 2})
	if err != nil {
		t.Fatal(err)
	}
	key := ComputeKey([]byte("escape"))
	unsafeNS := Namespace(filepath.Join("..", "outside"))
	if err := store.Put(unsafeNS, key, []byte("data")); !errors.Is(err, ErrInvalidNamespace) {
		t.Fatalf("Put error = %v, want ErrInvalidNamespace", err)
	}
	if _, ok := store.Get(unsafeNS, key); ok {
		t.Fatal("Get accepted an invalid namespace")
	}
	if store.Has(unsafeNS, key) {
		t.Fatal("Has accepted an invalid namespace")
	}
	if err := store.InvalidateNamespace(unsafeNS); !errors.Is(err, ErrInvalidNamespace) {
		t.Fatalf("InvalidateNamespace error = %v, want ErrInvalidNamespace", err)
	}
}

func TestStoreEnforcesEntrySizeBeforeHotCache(t *testing.T) {
	store, err := NewStore(StoreConfig{
		BaseDir:        cacheTestDir(t),
		MaxMemoryPerNS: 2,
		MaxEntryBytes:  4,
	})
	if err != nil {
		t.Fatal(err)
	}
	key := ComputeKey([]byte("oversized"))
	if err := store.Put(NamespaceGNN, key, []byte("12345")); !errors.Is(err, ErrEntryTooLarge) {
		t.Fatalf("Put error = %v, want ErrEntryTooLarge", err)
	}
	if _, ok := store.Get(NamespaceGNN, key); ok {
		t.Fatal("oversized failed write leaked into the hot cache")
	}
}

func TestStoreReplacesSameLengthEntryOnDisk(t *testing.T) {
	dir := cacheTestDir(t)
	store, err := NewStore(StoreConfig{BaseDir: dir, MaxMemoryPerNS: 2})
	if err != nil {
		t.Fatal(err)
	}
	key := ComputeKey([]byte("same-key"))
	if err := store.Put(NamespaceGNN, key, []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(NamespaceGNN, key, []byte("new")); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewStore(StoreConfig{BaseDir: dir, MaxMemoryPerNS: 2})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := fresh.Get(NamespaceGNN, key)
	if !ok || string(got) != "new" {
		t.Fatalf("fresh Get = %q, %v; want new, true", got, ok)
	}
}

func TestGetJSONDeletesMalformedEntry(t *testing.T) {
	store, err := NewStore(StoreConfig{BaseDir: cacheTestDir(t), MaxMemoryPerNS: 2})
	if err != nil {
		t.Fatal(err)
	}
	key := ComputeKey([]byte("bad-json"))
	if err := store.Put(NamespaceMetrics, key, []byte("{broken")); err != nil {
		t.Fatal(err)
	}
	if _, ok := GetJSON[map[string]any](store, NamespaceMetrics, key); ok {
		t.Fatal("malformed JSON was accepted")
	}
	if store.Has(NamespaceMetrics, key) {
		t.Fatal("malformed JSON entry was not purged")
	}
}

func TestStoreRejectsSymlinkEntry(t *testing.T) {
	dir := cacheTestDir(t)
	store, err := NewStore(StoreConfig{BaseDir: dir, MaxMemoryPerNS: 2})
	if err != nil {
		t.Fatal(err)
	}
	key := ComputeKey([]byte("symlink"))
	path := store.diskPath(NamespaceGNN, key)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("untrusted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, err := os.Readlink(path); err != nil {
		t.Skipf("symlink creation was not materialized: %v", err)
	}
	if _, ok := store.Get(NamespaceGNN, key); ok {
		t.Fatal("symlink cache entry was followed")
	}
	if err := store.Put(NamespaceGNN, key, []byte("trusted")); !errors.Is(err, ErrUnsafeCachePath) {
		t.Fatalf("Put through symlink error = %v, want ErrUnsafeCachePath", err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "untrusted" {
		t.Fatalf("symlink target was modified: %q, %v", data, err)
	}
}

func TestStoreRejectsSymlinkShardDirectory(t *testing.T) {
	dir := cacheTestDir(t)
	store, err := NewStore(StoreConfig{BaseDir: dir, MaxMemoryPerNS: 2})
	if err != nil {
		t.Fatal(err)
	}
	key := ComputeKey([]byte("symlink-parent"))
	path := store.diskPath(NamespaceGNN, key)
	shardDir := filepath.Dir(path)
	if err := os.MkdirAll(shardDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(shardDir); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	outsideEntry := filepath.Join(outside, filepath.Base(path))
	if err := os.WriteFile(outsideEntry, []byte("untrusted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, shardDir); err != nil {
		t.Skipf("directory symlink creation unavailable: %v", err)
	}
	if _, err := os.Readlink(shardDir); err != nil {
		t.Skipf("directory symlink creation was not materialized: %v", err)
	}
	if _, ok := store.Get(NamespaceGNN, key); ok {
		t.Fatal("cache read followed a symlinked shard directory")
	}
	if err := store.Put(NamespaceGNN, key, []byte("trusted")); !errors.Is(err, ErrUnsafeCachePath) {
		t.Fatalf("Put through shard symlink error = %v, want ErrUnsafeCachePath", err)
	}
	store.Delete(NamespaceGNN, key)
	data, err := os.ReadFile(outsideEntry)
	if err != nil || string(data) != "untrusted" {
		t.Fatalf("external entry changed through shard symlink: %q, %v", data, err)
	}
}
