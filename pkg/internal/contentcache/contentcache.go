// Package contentcache — Content-Addressed Cache Engine
//
// SHA256(method_bytecode) → cached analysis artifacts.
// Separate namespaces: cfg/ ssa/ taint/ metrics/ features/
//
// Benefits:
//   - Repeated scans become ~10x faster
//   - Incremental analysis becomes near-free
//   - Cross-APK deduplication (shared libraries)
//
// Architecture:
//
//	method bytecode hash → cache lookup → reuse IR / CFG / taint / SSA
//
// Every on-disk entry is framed and checksummed (see record.go); the hot
// cache is a sharded per-namespace LRU (see hotcache.go). Disk is the single
// source of truth: any disk removal invalidates the corresponding hot entry.
package contentcache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	defaultMaxEntryBytes    int64 = 16 * 1024 * 1024 // 16 MiB max per single entry
	defaultMaxHotBytesPerNS int64 = 12 * 1024 * 1024 // 12 MiB per namespace (was 64 MiB — 8 NS × 64 = 512 MiB OOM)

	// evictTargetRatio is the low-water mark for disk eviction. Cleaning down
	// to the exact limit made every subsequent Put re-run a full WalkDir.
	evictTargetRatio = 0.85

	// evictIndexTTL bounds how long a collected eviction index is reused
	// before the cache directory is walked again.
	evictIndexTTL = 5 * time.Second

	// diskTouchInterval throttles access-time updates on disk hits. Touching
	// on every hit would add a syscall per read and needless SSD wear.
	diskTouchInterval = time.Hour

	// tmpFileMaxAge is how long an orphaned .cache-write-* temp file (left by
	// a crashed process) is kept before it is garbage collected.
	tmpFileMaxAge = time.Hour

	tmpFilePrefix = ".cache-write-"
)

var (
	ErrInvalidNamespace = errors.New("contentcache: invalid namespace")
	ErrEntryTooLarge    = errors.New("contentcache: entry exceeds size limit")
	ErrUnsafeCachePath  = errors.New("contentcache: unsafe cache path")
	ErrCorruptEntry     = errors.New("contentcache: corrupt cache entry")
	cacheWriteLocks     [256]sync.Mutex
)

// ═══════════════════════════════════════════════════════════════════════════════
// NAMESPACES
// ═══════════════════════════════════════════════════════════════════════════════

type Namespace string

const (
	NamespaceCFG      Namespace = "cfg"
	NamespaceSSA      Namespace = "ssa"
	NamespaceTaint    Namespace = "taint"
	NamespaceMetrics  Namespace = "metrics"
	NamespaceFeatures Namespace = "features"
	NamespaceDFG      Namespace = "dfg"
	NamespaceDeobf    Namespace = "deobf"
	NamespaceGNN      Namespace = "gnn"
)

// AllNamespaces returns all valid namespaces.
func AllNamespaces() []Namespace {
	return []Namespace{
		NamespaceCFG, NamespaceSSA, NamespaceTaint,
		NamespaceMetrics, NamespaceFeatures, NamespaceDFG, NamespaceDeobf,
		NamespaceGNN,
	}
}

// DefaultNamespaceWeights ranks how expensive an entry is to recompute.
// Disk eviction drops cheap namespaces first, so a full cache does not throw
// away GNN predictions (native inference over FFI) to keep trivial metrics.
func DefaultNamespaceWeights() map[Namespace]int {
	return map[Namespace]int{
		NamespaceMetrics:  1,
		NamespaceFeatures: 1,
		NamespaceCFG:      2,
		NamespaceSSA:      2,
		NamespaceDFG:      2,
		NamespaceDeobf:    2,
		NamespaceTaint:    3,
		NamespaceGNN:      4,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTENT KEY — SHA256 of method bytecode
// ═══════════════════════════════════════════════════════════════════════════════

// ContentKey is a SHA256 hash of method bytecode (code_item).
type ContentKey [32]byte

// ComputeKey computes SHA256 of raw method bytecode.
func ComputeKey(bytecode []byte) ContentKey {
	return sha256.Sum256(bytecode)
}

// ComputeKeyFromBody computes key from smali method body lines.
// This normalizes the body (strips comments, trims whitespace) for stable hashing.
func ComputeKeyFromBody(body []string) ContentKey {
	h := sha256.New()
	for _, line := range body {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue // skip empty lines and comments
		}
		h.Write([]byte(trimmed))
		h.Write([]byte{'\n'})
	}
	var key ContentKey
	copy(key[:], h.Sum(nil))
	return key
}

// Hex returns the hex string representation.
func (k ContentKey) Hex() string {
	return hex.EncodeToString(k[:])
}

// Short returns first 16 hex chars (for display).
func (k ContentKey) Short() string {
	return hex.EncodeToString(k[:8])
}

// IsZero returns true if key is all zeros (invalid).
func (k ContentKey) IsZero() bool {
	for _, b := range k {
		if b != 0 {
			return false
		}
	}
	return true
}

// ═══════════════════════════════════════════════════════════════════════════════
// CACHE ENTRY METADATA
// ═══════════════════════════════════════════════════════════════════════════════

type EntryMeta struct {
	Key       ContentKey `json:"key"`
	Namespace Namespace  `json:"namespace"`
	CreatedAt time.Time  `json:"created_at"`
	Size      int64      `json:"size"`
	Version   uint32     `json:"version"` // schema version for invalidation
	Hits      int64      `json:"hits"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTENT-ADDRESSED STORE
// ═══════════════════════════════════════════════════════════════════════════════

// Store is the content-addressed cache store.
// Thread-safe for concurrent reads/writes.
type Store struct {
	baseDir string
	version uint32

	// In-memory hot cache: sharded LRU, one list per (shard, namespace).
	hot *hotCache

	// Stats
	hits        atomic.Int64
	misses      atomic.Int64
	writes      atomic.Int64
	hotEvicts   atomic.Int64
	diskEvicts  atomic.Int64
	corrupt     atomic.Int64
	orphans     atomic.Int64
	diskTouches atomic.Int64

	// Config
	maxMemoryPerNS   int // max entries per namespace in hot cache
	maxHotBytesPerNS int64
	maxDiskBytes     int64
	maxEntryBytes    int64
	diskLRUTouch     bool
	nsWeights        map[Namespace]int

	diskMu    sync.Mutex
	diskBytes atomic.Int64

	// Eviction index cache, guarded by diskMu.
	evictIndex   []diskEntry
	evictIndexAt time.Time
}

// StoreConfig configures the content-addressed store.
type StoreConfig struct {
	BaseDir        string // disk cache directory
	Version        uint32 // schema version (bump to invalidate all)
	MaxMemoryPerNS int    // max hot cache entries per namespace (default: 4096)
	MaxDiskBytes   int64  // max total disk usage (0 = unlimited)
	MaxEntryBytes  int64  // max bytes per entry (0 = safe default of 64 MiB)

	// MaxMemoryBytesPerNS caps resident hot-cache bytes per namespace
	// (0 = default of 64 MiB). Without it, MaxMemoryPerNS alone allowed
	// 4096 x MaxEntryBytes of RAM per namespace.
	MaxMemoryBytesPerNS int64

	// DisableDiskLRUTouch turns off throttled mtime refresh on disk hits.
	// With touch enabled (the default), disk eviction is LRU rather than FIFO.
	DisableDiskLRUTouch bool

	// NamespaceWeights overrides DefaultNamespaceWeights for eviction
	// priority. Lower weight is evicted first.
	NamespaceWeights map[Namespace]int

	// PurgeLegacyVersions removes older vN directories under BaseDir at open
	// time. Records written before the framing change are unreadable, so
	// keeping them only wastes disk.
	PurgeLegacyVersions bool
}

// DefaultStoreConfig returns production defaults.
//
// Version 2 introduces framed, checksummed on-disk records. v1 payloads are
// raw bytes and are intentionally unreadable by this version.
func DefaultStoreConfig() StoreConfig {
	return StoreConfig{
		BaseDir:             ".omnisec-cache/content",
		Version:             2,
		MaxMemoryPerNS:      512,               // was 4096; 512 entries is ample with 12 MiB byte budget
		MaxDiskBytes:        512 * 1024 * 1024, // 512 MiB disk cap (was 0 = unlimited)
		MaxEntryBytes:       defaultMaxEntryBytes,
		MaxMemoryBytesPerNS: defaultMaxHotBytesPerNS,
		PurgeLegacyVersions: true,
	}
}

// NewStore creates a new content-addressed store.
func NewStore(cfg StoreConfig) (*Store, error) {
	if cfg.BaseDir == "" {
		cfg.BaseDir = DefaultStoreConfig().BaseDir
	}
	if cfg.MaxMemoryPerNS <= 0 {
		cfg.MaxMemoryPerNS = 4096
	}
	if cfg.Version == 0 {
		cfg.Version = DefaultStoreConfig().Version
	}
	if cfg.MaxDiskBytes < 0 {
		return nil, fmt.Errorf("negative cache disk limit: %d", cfg.MaxDiskBytes)
	}
	if cfg.MaxEntryBytes < 0 {
		return nil, fmt.Errorf("negative cache entry limit: %d", cfg.MaxEntryBytes)
	}
	if cfg.MaxEntryBytes == 0 {
		cfg.MaxEntryBytes = defaultMaxEntryBytes
	}
	if cfg.MaxMemoryBytesPerNS < 0 {
		return nil, fmt.Errorf("negative cache memory limit: %d", cfg.MaxMemoryBytesPerNS)
	}
	if cfg.MaxMemoryBytesPerNS == 0 {
		cfg.MaxMemoryBytesPerNS = defaultMaxHotBytesPerNS
	}
	baseDir, err := filepath.Abs(cfg.BaseDir)
	if err != nil {
		return nil, fmt.Errorf("resolve cache directory: %w", err)
	}
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}
	// Resolve a caller-supplied symlink once and keep all derived paths rooted
	// at its real target. Namespace/shard paths are checked again before I/O.
	baseDir, err = filepath.EvalSymlinks(baseDir)
	if err != nil {
		return nil, fmt.Errorf("resolve cache symlinks: %w", err)
	}
	versionDir := filepath.Join(baseDir, fmt.Sprintf("v%d", cfg.Version))

	weights := cfg.NamespaceWeights
	if weights == nil {
		weights = DefaultNamespaceWeights()
	}

	s := &Store{
		baseDir:          versionDir,
		version:          cfg.Version,
		hot:              newHotCache(cfg.MaxMemoryPerNS, cfg.MaxMemoryBytesPerNS),
		maxMemoryPerNS:   cfg.MaxMemoryPerNS,
		maxHotBytesPerNS: cfg.MaxMemoryBytesPerNS,
		maxDiskBytes:     cfg.MaxDiskBytes,
		maxEntryBytes:    cfg.MaxEntryBytes,
		diskLRUTouch:     !cfg.DisableDiskLRUTouch,
		nsWeights:        weights,
	}

	if err := s.createLayout(); err != nil {
		return nil, err
	}

	if cfg.PurgeLegacyVersions {
		// Best effort: unreadable legacy generations must not occupy disk
		// forever, but failing to remove them is not fatal. Purging can
		// dominate init on caches with millions of small files (observed
		// 20+ min of pure RemoveAll I/O), so it must never block startup.
		go func() {
			defer func() { notePanic("contentcache", recover()) }()
			purgeLegacyVersionDirs(baseDir, cfg.Version)
		}()
	}

	// Reclaim temp files left behind by a crashed writer. Previously these
	// accumulated forever and were excluded from eviction accounting.
	s.collectOrphanTempFiles(time.Now())

	if cfg.MaxDiskBytes > 0 {
		usage, err := directorySize(versionDir)
		if err != nil {
			return nil, fmt.Errorf("measure cache directory: %w", err)
		}
		s.diskBytes.Store(usage)
	}

	return s, nil
}

// createLayout (re)creates the version directory and every namespace
// directory with strict permissions. Clear/InvalidateNamespace reuse it so a
// wiped cache stays usable instead of failing every later validateCacheDirectory.
func (s *Store) createLayout() error {
	if err := os.MkdirAll(s.baseDir, 0o700); err != nil {
		return fmt.Errorf("create cache version directory: %w", err)
	}
	if err := secureCacheDirectory(s.baseDir); err != nil {
		return err
	}
	if err := os.Chmod(s.baseDir, 0o700); err != nil {
		return fmt.Errorf("secure cache version directory: %w", err)
	}
	for _, ns := range AllNamespaces() {
		if err := s.createNamespaceDir(ns); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) createNamespaceDir(ns Namespace) error {
	dir := filepath.Join(s.baseDir, string(ns))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create namespace dir %s: %w", ns, err)
	}
	if err := secureCacheDirectory(dir); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure namespace dir %s: %w", ns, err)
	}
	return nil
}

func purgeLegacyVersionDirs(baseDir string, current uint32) {
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return
	}
	keep := fmt.Sprintf("v%d", current)
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || name == keep || !strings.HasPrefix(name, "v") {
			continue
		}
		if _, convErr := parseUint(name[1:]); convErr != nil {
			continue // not a version directory; leave foreign content alone
		}
		_ = os.RemoveAll(filepath.Join(baseDir, name))
	}
}

func parseUint(s string) (uint64, error) {
	if s == "" {
		return 0, errors.New("empty")
	}
	var v uint64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errors.New("not a number")
		}
		v = v*10 + uint64(r-'0')
	}
	return v, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// GET / PUT / HAS
// ═══════════════════════════════════════════════════════════════════════════════

// Get retrieves cached data for a content key in a namespace.
// Returns nil, false if not found.
func (s *Store) Get(ns Namespace, key ContentKey) ([]byte, bool) {
	if key.IsZero() || !validNamespace(ns) {
		return nil, false
	}

	// Check hot cache first (this also refreshes LRU recency).
	if data, ok := s.hot.get(ns, key); ok {
		s.hits.Add(1)
		return data, true
	}

	// Check disk
	data, modTime, err := s.readDisk(ns, key)
	if err != nil || data == nil {
		// Only a framing/checksum failure justifies deleting the file: such an
		// entry can never be served again. An unsafe path (symlink, permissive
		// mode) is deliberately left alone; removing attacker-controlled paths
		// is a hazard of its own and writeDisk already refuses to write there.
		if errors.Is(err, ErrCorruptEntry) {
			s.corrupt.Add(1)
			s.Delete(ns, key)
		}
		s.misses.Add(1)
		return nil, false
	}

	// Throttled access-time refresh turns disk eviction from FIFO into LRU.
	if s.diskLRUTouch && time.Since(modTime) > diskTouchInterval {
		s.touchDisk(ns, key)
	}

	// Promote to hot cache. This now always happens (with eviction) instead
	// of silently stopping once the namespace map was full.
	s.hotEvicts.Add(s.hot.put(ns, key, data))

	s.hits.Add(1)
	return data, true
}

// Put stores data for a content key in a namespace.
func (s *Store) Put(ns Namespace, key ContentKey, data []byte) error {
	if key.IsZero() || len(data) == 0 {
		return nil
	}
	if !validNamespace(ns) {
		return fmt.Errorf("%w: %q", ErrInvalidNamespace, ns)
	}
	if int64(len(data)) > s.maxEntryBytes {
		return fmt.Errorf("%w: %d > %d", ErrEntryTooLarge, len(data), s.maxEntryBytes)
	}

	// Persist first. A failed disk write must not leave a value visible only
	// from this Store's hot cache while fresh processes observe a miss or stale
	// entry for the same content key.
	if err := s.writeDisk(ns, key, data); err != nil {
		return err
	}

	s.hotEvicts.Add(s.hot.put(ns, key, data))
	s.writes.Add(1)
	return nil
}

// Has checks if a key exists in a namespace (hot cache or disk).
func (s *Store) Has(ns Namespace, key ContentKey) bool {
	if key.IsZero() || !validNamespace(ns) {
		return false
	}
	if s.hot.has(ns, key) {
		return true
	}
	return s.existsOnDisk(ns, key)
}

// Delete removes a key from both hot cache and disk.
func (s *Store) Delete(ns Namespace, key ContentKey) {
	if key.IsZero() || !validNamespace(ns) {
		return
	}
	s.hot.delete(ns, key)

	path := s.diskPath(ns, key)
	if err := s.validateCacheDirectory(filepath.Dir(path)); err != nil {
		return
	}
	// Lock order is always writeLock → diskMu (see ensureDiskCapacity).
	writeLock := &cacheWriteLocks[key[0]]
	writeLock.Lock()
	defer writeLock.Unlock()
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	var size int64
	if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
		size = info.Size()
	}
	if err := os.Remove(path); err == nil && size > 0 && s.maxDiskBytes > 0 {
		s.diskBytes.Add(-size)
	}
	s.evictIndex = nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// TYPED HELPERS — JSON serialization
// ═══════════════════════════════════════════════════════════════════════════════

// GetJSON retrieves and unmarshals cached JSON data.
func GetJSON[T any](s *Store, ns Namespace, key ContentKey) (*T, bool) {
	data, ok := s.Get(ns, key)
	if !ok {
		return nil, false
	}
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		s.Delete(ns, key)
		return nil, false
	}
	return &result, true
}

// PutJSON marshals and stores data as JSON.
func PutJSON[T any](s *Store, ns Namespace, key ContentKey, value *T) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal cache entry: %w", err)
	}
	return s.Put(ns, key, data)
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATS
// ═══════════════════════════════════════════════════════════════════════════════

// Stats returns cache statistics.
//
// Evictions used to conflate two unrelated events (a hot-cache entry dropped
// from RAM and a file deleted from disk), which made the "raise the disk
// limit" hint fire on pure memory pressure. They are now reported separately.
type Stats struct {
	Hits           int64   `json:"hits"`
	Misses         int64   `json:"misses"`
	Writes         int64   `json:"writes"`
	Evictions      int64   `json:"evictions"` // HotEvictions + DiskEvictions
	HotEvictions   int64   `json:"hot_evictions"`
	DiskEvictions  int64   `json:"disk_evictions"`
	CorruptEntries int64   `json:"corrupt_entries"`
	OrphansRemoved int64   `json:"orphans_removed"`
	HitRate        float64 `json:"hit_rate"`
	HotEntries     int     `json:"hot_entries"`
	HotBytes       int64   `json:"hot_bytes"`
	DiskBytes      int64   `json:"disk_bytes"`
}

func (s *Store) Stats() Stats {
	hits := s.hits.Load()
	misses := s.misses.Load()
	total := hits + misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	hotEntries, hotBytes := s.hot.stats()
	hotEvicts := s.hotEvicts.Load()
	diskEvicts := s.diskEvicts.Load()

	return Stats{
		Hits:           hits,
		Misses:         misses,
		Writes:         s.writes.Load(),
		Evictions:      hotEvicts + diskEvicts,
		HotEvictions:   hotEvicts,
		DiskEvictions:  diskEvicts,
		CorruptEntries: s.corrupt.Load(),
		OrphansRemoved: s.orphans.Load(),
		HitRate:        hitRate,
		HotEntries:     hotEntries,
		HotBytes:       hotBytes,
		DiskBytes:      s.diskBytes.Load(),
	}
}

// ResetStats clears counters while preserving cached content.
func (s *Store) ResetStats() {
	s.hits.Store(0)
	s.misses.Store(0)
	s.writes.Store(0)
	s.hotEvicts.Store(0)
	s.diskEvicts.Store(0)
	s.corrupt.Store(0)
	s.orphans.Store(0)
	s.diskTouches.Store(0)
}

// ═══════════════════════════════════════════════════════════════════════════════
// DISK I/O — atomic writes via temp+rename
// ═══════════════════════════════════════════════════════════════════════════════

func (s *Store) diskPath(ns Namespace, key ContentKey) string {
	hex := key.Hex()
	// Use 2-level directory structure: ab/cdef... to avoid too many files in one dir
	return filepath.Join(s.baseDir, string(ns), hex[:2], hex[2:])
}

// readDisk returns the validated payload and the entry's mtime.
func (s *Store) readDisk(ns Namespace, key ContentKey) ([]byte, time.Time, error) {
	var zero time.Time
	path := s.diskPath(ns, key)
	if err := s.validateCacheDirectory(filepath.Dir(path)); err != nil {
		if os.IsNotExist(err) {
			return nil, zero, nil
		}
		return nil, zero, err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, zero, nil
	}
	if err != nil {
		return nil, zero, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, zero, fmt.Errorf("%w: cache entry is not a regular file: %s", ErrUnsafeCachePath, path)
	}
	// The cache lives in ~/.analyzer and feeds security decisions. A
	// group/other-accessible entry is attacker-writable; refuse to trust it.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, zero, fmt.Errorf("%w: cache entry has permissive mode %o: %s", ErrUnsafeCachePath, info.Mode().Perm(), path)
	}
	maxFileBytes := s.maxEntryBytes + recordOverhead(ns)
	if info.Size() > maxFileBytes {
		return nil, zero, fmt.Errorf("%w: %d > %d", ErrEntryTooLarge, info.Size(), maxFileBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, zero, err
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil {
		return nil, zero, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, zero, fmt.Errorf("%w: cache entry changed while opening: %s", ErrUnsafeCachePath, path)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, zero, err
	}
	if int64(len(raw)) > maxFileBytes {
		return nil, zero, fmt.Errorf("%w: entry grew while reading", ErrEntryTooLarge)
	}
	payload, err := decodeRecord(ns, key, raw)
	if err != nil {
		return nil, zero, err
	}
	if int64(len(payload)) > s.maxEntryBytes {
		return nil, zero, fmt.Errorf("%w: %d > %d", ErrEntryTooLarge, len(payload), s.maxEntryBytes)
	}
	return payload, openedInfo.ModTime(), nil
}

// touchDisk refreshes the entry mtime so disk eviction approximates LRU.
// Failures are ignored: this is an optimization, not a correctness step.
func (s *Store) touchDisk(ns Namespace, key ContentKey) {
	path := s.diskPath(ns, key)
	now := time.Now()
	if err := os.Chtimes(path, now, now); err == nil {
		s.diskTouches.Add(1)
	}
}

func (s *Store) writeDisk(ns Namespace, key ContentKey, data []byte) error {
	// Store instances are cheap and several of them can point at the same
	// directory. Serialize same-shard replacement within the process so Windows
	// never observes another Store between opening and atomically renaming an
	// entry. Different hash shards still write concurrently.
	writeLock := &cacheWriteLocks[key[0]]
	writeLock.Lock()
	defer writeLock.Unlock()

	path := s.diskPath(ns, key)
	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := s.validateCacheDirectory(dir); err != nil {
		return err
	}

	framed := encodeRecord(ns, key, data)

	var oldSize int64
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: cache destination is not a regular file: %s", ErrUnsafeCachePath, path)
		}
		oldSize = info.Size()
		existing, _, readErr := s.readDisk(ns, key)
		switch {
		case readErr == nil && bytes.Equal(existing, data):
			return nil
		case readErr != nil && !errors.Is(readErr, ErrEntryTooLarge) && !errors.Is(readErr, ErrCorruptEntry):
			return readErr
		}
		// A corrupt destination is simply overwritten below.
	} else if !os.IsNotExist(err) {
		return err
	}

	growth := int64(len(framed)) - oldSize
	if growth < 0 {
		growth = 0
	}
	if err := s.ensureDiskCapacity(growth, int(key[0])); err != nil {
		return err
	}

	// Each writer gets a unique temporary file. This remains safe when several
	// Store instances share a directory (the common CLI/server deployment).
	tmp, err := os.CreateTemp(dir, tmpFilePrefix+"*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(framed); err != nil {
		_ = tmp.Close()
		return err
	}
	// Deliberately no fsync: this is a recomputable cache, not a database.
	// Flushing every entry to stable storage (FlushFileBuffers per Put on
	// Windows) stalled the whole DEX pipeline — live goroutine dumps showed
	// every class worker parked in writeDisk while CPU sat ~3% idle. Atomic
	// rename already makes each entry crash-atomic; the worst a crash loses
	// is a recompute of that entry.
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		// Windows refuses replacing an existing destination. A concurrent writer
		// only counts as success when it wrote the exact same bytes; otherwise
		// repair the stale/corrupt entry and retry the rename.
		if existing, _, readErr := s.readDisk(ns, key); readErr == nil && bytes.Equal(existing, data) {
			return nil
		}
		if info, statErr := os.Lstat(path); statErr == nil {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: refusing to replace %s", ErrUnsafeCachePath, path)
			}
			if removeErr := os.Remove(path); removeErr != nil {
				return removeErr
			}
			if retryErr := os.Rename(tmpName, path); retryErr != nil {
				return retryErr
			}
		} else {
			return err
		}
	}
	// No directory fsync either (same rationale as above): after an OS crash
	// the rename may be lost while diskBytes already counts the entry. The
	// counter is reconciled by the next full eviction walk; a slight
	// transient overfill beats stalling every analysis worker on a flush.
	if s.maxDiskBytes > 0 {
		s.diskBytes.Add(int64(len(framed)) - oldSize)
	}
	return nil
}

func (s *Store) validateCacheDirectory(dir string) error {
	rel, err := filepath.Rel(s.baseDir, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: directory escapes cache root: %s", ErrUnsafeCachePath, dir)
	}
	current := s.baseDir
	parts := strings.FieldsFunc(rel, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	for _, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: cache directory component is not a real directory: %s", ErrUnsafeCachePath, current)
		}
	}
	return nil
}

func secureCacheDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: cache directory is not a real directory: %s", ErrUnsafeCachePath, dir)
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// DISK EVICTION
// ═══════════════════════════════════════════════════════════════════════════════

type diskEntry struct {
	path    string
	size    int64
	modTime time.Time
	ns      Namespace
	key     ContentKey
	parsed  bool // path maps to a real (namespace, key) slot
	weight  int
}

// ensureDiskCapacity frees room for an incoming write.
//
// heldShard is the cacheWriteLocks index already held by the caller (writeDisk
// holds it for the key being written); entries in that shard are removed
// without re-locking. For other shards TryLock is used: the canonical lock
// order is writeLock → diskMu, and this function runs with diskMu held, so a
// blocking Lock here could deadlock against Delete. Skipping a contended shard
// only defers its eviction to the next call.
func (s *Store) ensureDiskCapacity(incoming int64, heldShard int) error {
	if s.maxDiskBytes <= 0 || incoming <= 0 {
		return nil
	}
	if incoming > s.maxDiskBytes {
		return fmt.Errorf("cache entry size %d exceeds disk limit %d", incoming, s.maxDiskBytes)
	}

	if s.diskBytes.Load()+incoming <= s.maxDiskBytes {
		return nil
	}

	s.diskMu.Lock()
	defer s.diskMu.Unlock()

	// Low-water mark: free down to evictTargetRatio of the limit so the next
	// writes do not each trigger another full sweep.
	target := int64(float64(s.maxDiskBytes) * evictTargetRatio)
	if target > s.maxDiskBytes-incoming {
		target = s.maxDiskBytes - incoming
	}
	if target < 0 {
		target = 0
	}

	// Two attempts at most: the cached index only lists files that existed
	// when it was collected, so if it cannot free enough we fall back to a
	// fresh walk instead of silently leaving the cache over its limit.
	for attempt := 0; attempt < 2; attempt++ {
		now := time.Now()
		entries, walked, fresh, err := s.evictionIndex(now)
		if err != nil {
			return err
		}

		usage := walked
		if fresh {
			// A full walk is authoritative.
			s.diskBytes.Store(usage)
		} else if tracked := s.diskBytes.Load(); tracked > usage {
			// The cached index predates the entries written since; the running
			// counter is the safer estimate, never the (smaller) index sum.
			usage = tracked
		}
		if usage+incoming <= s.maxDiskBytes {
			return nil
		}

		kept := entries[:0]
		for _, entry := range entries {
			if usage <= target {
				kept = append(kept, entry)
				continue
			}
			removed, skipped := s.removeEvictionCandidate(entry, heldShard)
			if skipped {
				kept = append(kept, entry)
				continue
			}
			if removed {
				usage -= entry.size
			}
		}
		if usage < 0 {
			usage = 0
		}
		s.diskBytes.Store(usage)

		if usage+incoming <= s.maxDiskBytes {
			// Incrementally maintain the index instead of re-walking per Put.
			s.evictIndex = slices.Clone(kept)
			return nil
		}
		// Candidates exhausted while still over budget: force a fresh walk.
		s.evictIndex = nil
	}
	return nil
}

// removeEvictionCandidate deletes one file, invalidating the matching hot
// entry. Returns (removed, skipped).
func (s *Store) removeEvictionCandidate(entry diskEntry, heldShard int) (bool, bool) {
	if !entry.parsed {
		// Unparseable path inside the cache tree: not a valid entry, so it can
		// never be served. Remove it and account it as an orphan.
		if err := os.Remove(entry.path); err == nil {
			s.orphans.Add(1)
			return true, false
		} else if os.IsNotExist(err) {
			return true, false
		}
		return false, false
	}

	shard := int(entry.key[0])
	if shard != heldShard {
		lock := &cacheWriteLocks[shard]
		if !lock.TryLock() {
			return false, true
		}
		defer lock.Unlock()
	}

	// Re-check: a concurrent writer may have replaced the file with fresh
	// content after the index was collected.
	if info, err := os.Lstat(entry.path); err == nil {
		if info.ModTime().After(entry.modTime) {
			return false, true
		}
	}
	err := os.Remove(entry.path)
	if err != nil && !os.IsNotExist(err) {
		return false, false
	}
	// Disk is the source of truth: drop the RAM copy too, otherwise this
	// process keeps serving data that no longer exists for anyone else.
	s.hot.delete(entry.ns, entry.key)
	if err == nil {
		s.diskEvicts.Add(1)
		return true, false
	}
	return true, false
}

// evictionIndex returns the eviction-ordered file list, the usage it accounts
// for, and whether the list comes from a fresh walk (and is therefore
// authoritative). Caller must hold diskMu.
func (s *Store) evictionIndex(now time.Time) ([]diskEntry, int64, bool, error) {
	if s.evictIndex != nil && now.Sub(s.evictIndexAt) < evictIndexTTL {
		var usage int64
		for _, e := range s.evictIndex {
			usage += e.size
		}
		return s.evictIndex, usage, false, nil
	}

	entries := make([]diskEntry, 0, 256)
	var usage int64
	err := filepath.WalkDir(s.baseDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			if os.IsNotExist(infoErr) {
				return nil
			}
			return infoErr
		}
		if strings.HasPrefix(d.Name(), tmpFilePrefix) {
			// Orphaned writer temp file. Old ones are garbage; recent ones may
			// belong to an in-flight write, so leave them alone.
			if now.Sub(info.ModTime()) > tmpFileMaxAge {
				if rmErr := os.Remove(path); rmErr == nil {
					s.orphans.Add(1)
					return nil
				}
			}
			usage += info.Size()
			return nil
		}
		usage += info.Size()
		entry := diskEntry{path: path, size: info.Size(), modTime: info.ModTime()}
		if ns, key, ok := s.parseEntryPath(path); ok {
			entry.ns, entry.key, entry.parsed = ns, key, true
			entry.weight = s.nsWeights[ns]
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return nil, 0, false, err
	}

	slices.SortFunc(entries, func(a, b diskEntry) int {
		// Unparseable junk goes first, then cheap namespaces, then oldest.
		if a.parsed != b.parsed {
			if !a.parsed {
				return -1
			}
			return 1
		}
		if a.weight != b.weight {
			return a.weight - b.weight
		}
		if a.modTime.Before(b.modTime) {
			return -1
		}
		if a.modTime.After(b.modTime) {
			return 1
		}
		return strings.Compare(a.path, b.path)
	})

	s.evictIndex = entries
	s.evictIndexAt = now
	return entries, usage, true, nil
}

// parseEntryPath recovers (namespace, key) from <ns>/<ab>/<62 hex chars>.
func (s *Store) parseEntryPath(path string) (Namespace, ContentKey, bool) {
	var key ContentKey
	rel, err := filepath.Rel(s.baseDir, path)
	if err != nil {
		return "", key, false
	}
	parts := strings.FieldsFunc(rel, func(r rune) bool { return r == '/' || r == '\\' })
	if len(parts) != 3 {
		return "", key, false
	}
	ns := Namespace(parts[0])
	if !validNamespace(ns) {
		return "", key, false
	}
	if len(parts[1]) != 2 || len(parts[2]) != 62 {
		return "", key, false
	}
	raw, err := hex.DecodeString(parts[1] + parts[2])
	if err != nil || len(raw) != len(key) {
		return "", key, false
	}
	copy(key[:], raw)
	return ns, key, true
}

// collectOrphanTempFiles removes stale writer temp files at open time.
func (s *Store) collectOrphanTempFiles(now time.Time) {
	_ = filepath.WalkDir(s.baseDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil //nolint:nilerr // best effort GC
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), tmpFilePrefix) {
			return nil
		}
		info, err := d.Info()
		if err != nil || now.Sub(info.ModTime()) <= tmpFileMaxAge {
			return nil
		}
		if os.Remove(path) == nil {
			s.orphans.Add(1)
		}
		return nil
	})
}

func directorySize(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(_ string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

func (s *Store) existsOnDisk(ns Namespace, key ContentKey) bool {
	path := s.diskPath(ns, key)
	if err := s.validateCacheDirectory(filepath.Dir(path)); err != nil {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
		info.Size() <= s.maxEntryBytes+recordOverhead(ns)
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLEAR / INVALIDATE
// ═══════════════════════════════════════════════════════════════════════════════

// Clear removes all cached data (hot + disk) and recreates the directory
// layout, so the store stays usable afterwards.
func (s *Store) Clear() error {
	s.hot.clear()

	s.diskMu.Lock()
	s.evictIndex = nil
	s.diskMu.Unlock()

	s.diskBytes.Store(0)
	if err := removeCacheTree(s.baseDir); err != nil {
		return err
	}
	return s.createLayout()
}

// InvalidateNamespace clears a single namespace and recreates its directory.
func (s *Store) InvalidateNamespace(ns Namespace) error {
	if !validNamespace(ns) {
		return fmt.Errorf("%w: %q", ErrInvalidNamespace, ns)
	}
	s.hot.clearNamespace(ns)

	s.diskMu.Lock()
	s.evictIndex = nil
	s.diskMu.Unlock()

	if err := removeCacheTree(filepath.Join(s.baseDir, string(ns))); err != nil {
		return err
	}
	if err := s.createNamespaceDir(ns); err != nil {
		return err
	}
	if s.maxDiskBytes > 0 {
		if usage, sizeErr := directorySize(s.baseDir); sizeErr == nil {
			s.diskBytes.Store(usage)
		}
	}
	return nil
}

// Windows can briefly report a sharing violation or a nonempty directory
// after its files were removed. Give those transient errors a bounded retry
// window; permanent errors still reach the caller.
func removeCacheTree(path string) error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := os.RemoveAll(path)
		if err == nil {
			return nil
		}
		retry := runtime.GOOS == "windows" && (errors.Is(err, syscall.Errno(5)) ||
			errors.Is(err, syscall.Errno(32)) || errors.Is(err, syscall.Errno(145)))
		if !retry || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func validNamespace(ns Namespace) bool {
	switch ns {
	case NamespaceCFG, NamespaceSSA, NamespaceTaint, NamespaceMetrics,
		NamespaceFeatures, NamespaceDFG, NamespaceDeobf, NamespaceGNN:
		return true
	default:
		return false
	}
}
