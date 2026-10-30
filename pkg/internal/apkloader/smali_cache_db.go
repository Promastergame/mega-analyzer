package apkloader

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const nativeSmaliClassCacheDB = ".mega-analyzer-cache.db"
const cacheMagic = "MACDB001"
const recPut byte = 1
const recDel byte = 2

type SmaliCacheRecord struct {
	DexHash      string
	ClassName    string
	Emitter      string
	Smali        string
	CreatedUnix  int64
	AccessedUnix int64
	SizeBytes    int64
	offset       int64
	recordSize   int64
}

type smaliCacheDBHandle struct {
	path    string
	mu      sync.Mutex
	entries map[string]SmaliCacheRecord
	dirty   bool
}

func openSmaliCacheDB(root string) *smaliCacheDBHandle {
	h := &smaliCacheDBHandle{path: filepath.Join(root, nativeSmaliClassCacheDB), entries: map[string]SmaliCacheRecord{}}
	if err := h.load(); err != nil {
		h.dirty = true
	}
	return h
}

func smaliCacheKey(dexHash, className string) string {
	return dexHash + "\x00" + nativeSmaliEmitterVersion + "\x00" + className
}

func (h *smaliCacheDBHandle) load() error {
	f, err := os.Open(h.path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	r := bufio.NewReaderSize(f, 64*1024)
	magic := make([]byte, len(cacheMagic))
	if _, err := io.ReadFull(r, magic); err != nil {
		return err
	}
	if string(magic) != cacheMagic {
		return errors.New("bad cache magic")
	}
	start := int64(len(cacheMagic))
	for {
		var typ [1]byte
		_, err := io.ReadFull(r, typ[:])
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil
		}
		if err != nil {
			return err
		}
		var lens [12]byte
		if _, err := io.ReadFull(r, lens[:]); err != nil {
			return err
		}
		kl := binary.LittleEndian.Uint32(lens[0:4])
		vl := binary.LittleEndian.Uint64(lens[4:12])
		// Check untrusted lengths against the actual file before allocating.
		// Subtract in stages to avoid overflow from a forged uint64 length.
		remaining := info.Size() - start - 17 // type, lengths and CRC
		if remaining < 0 || uint64(kl) > uint64(remaining) || vl > uint64(remaining)-uint64(kl) {
			return io.ErrUnexpectedEOF
		}
		recordSize := int64(17) + int64(kl) + int64(vl)
		key := make([]byte, kl)
		if _, err := io.ReadFull(r, key); err != nil {
			return err
		}
		val := make([]byte, vl)
		if _, err := io.ReadFull(r, val); err != nil {
			return err
		}
		var crcBuf [4]byte
		if _, err := io.ReadFull(r, crcBuf[:]); err != nil {
			return err
		}
		offset := start
		start += recordSize
		if crc32.Update(crc32.ChecksumIEEE(key), crc32.IEEETable, val) != binary.LittleEndian.Uint32(crcBuf[:]) {
			h.dirty = true
			continue
		}
		k := string(key)
		if typ[0] == recDel {
			delete(h.entries, k)
			continue
		}
		if typ[0] != recPut {
			h.dirty = true
			continue
		}
		parts := strings.Split(k, "\x00")
		if len(parts) != 3 {
			continue
		}
		now := time.Now().Unix()
		h.entries[k] = SmaliCacheRecord{DexHash: parts[0], Emitter: parts[1], ClassName: parts[2], Smali: string(val), CreatedUnix: now, AccessedUnix: now, SizeBytes: int64(len(val)), offset: offset, recordSize: recordSize}
	}
}

func (h *smaliCacheDBHandle) Get(dexHash, className string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := smaliCacheKey(dexHash, className)
	r, ok := h.entries[key]
	if !ok {
		return "", false
	}
	r.AccessedUnix = time.Now().Unix()
	h.entries[key] = r
	return r.Smali, true
}
func (h *smaliCacheDBHandle) Put(dexHash, className, smali string) {
	now := time.Now().Unix()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries[smaliCacheKey(dexHash, className)] = SmaliCacheRecord{DexHash: dexHash, ClassName: className, Emitter: nativeSmaliEmitterVersion, Smali: smali, CreatedUnix: now, AccessedUnix: now, SizeBytes: int64(len(smali))}
	h.dirty = true
}

func (h *smaliCacheDBHandle) Save(maxEntries int, maxBytes int64) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if maxEntries <= 0 {
		maxEntries = 250000
	}
	if maxBytes <= 0 {
		maxBytes = 2 * 1024 * 1024 * 1024
	}
	h.pruneLocked(maxEntries, maxBytes)
	if !h.dirty {
		return nil
	}
	if err := h.compactLocked(); err != nil {
		return err
	}
	h.dirty = false
	return nil
}

func (h *smaliCacheDBHandle) compactLocked() error {
	if err := os.MkdirAll(filepath.Dir(h.path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(h.path), filepath.Base(h.path)+"-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	w := bufio.NewWriterSize(f, 64*1024)
	if _, err = w.WriteString(cacheMagic); err != nil {
		f.Close()
		return err
	}
	keys := make([]string, 0, len(h.entries))
	for k := range h.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := writeCacheRecord(w, recPut, []byte(k), []byte(h.entries[k].Smali)); err != nil {
			f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, h.path)
}
func writeCacheRecord(w io.Writer, typ byte, key, val []byte) error {
	if _, err := w.Write([]byte{typ}); err != nil {
		return err
	}
	var hdr [12]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(len(key)))
	binary.LittleEndian.PutUint64(hdr[4:12], uint64(len(val)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.Write(key); err != nil {
		return err
	}
	if _, err := w.Write(val); err != nil {
		return err
	}
	var c [4]byte
	binary.LittleEndian.PutUint32(c[:], crc32.Update(crc32.ChecksumIEEE(key), crc32.IEEETable, val))
	_, err := w.Write(c[:])
	return err
}

func (h *smaliCacheDBHandle) pruneLocked(maxEntries int, maxBytes int64) {
	type kv struct {
		k    string
		a, s int64
	}
	items := make([]kv, 0, len(h.entries))
	var total int64
	for k, r := range h.entries {
		items = append(items, kv{k, r.AccessedUnix, r.SizeBytes})
		total += r.SizeBytes
	}
	if len(h.entries) <= maxEntries && total <= maxBytes {
		return
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].a != items[j].a {
			return items[i].a < items[j].a
		}
		return items[i].k < items[j].k
	})
	for (len(h.entries) > maxEntries || total > maxBytes) && len(items) > 0 {
		it := items[0]
		items = items[1:]
		delete(h.entries, it.k)
		h.dirty = true
		total -= it.s
	}
}

func InspectSmaliCacheDB(path string, limit int) (string, error) {
	h := &smaliCacheDBHandle{path: path, entries: map[string]SmaliCacheRecord{}}
	if err := h.load(); err != nil {
		return "", err
	}
	rows := make([]SmaliCacheRecord, 0, len(h.entries))
	var bytes int64
	for _, r := range h.entries {
		rows = append(rows, r)
		bytes += r.SizeBytes
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].AccessedUnix > rows[j].AccessedUnix })
	if limit <= 0 || limit > len(rows) {
		limit = len(rows)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Mega Analyzer binary cache DB\nentries: %d\nsmali bytes: %d\n\n", len(rows), bytes)
	for i := 0; i < limit; i++ {
		fmt.Fprintf(&sb, "%6d  %8d  %.12s  %s\n", i+1, rows[i].SizeBytes, rows[i].DexHash, rows[i].ClassName)
	}
	return sb.String(), nil
}
