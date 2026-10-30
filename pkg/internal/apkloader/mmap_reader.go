package apkloader

import (
	"fmt"
	"os"
	"sync"
)

const (
	// largeDEXThreshold defines the size threshold for partial mapping (100MB)
	largeDEXThreshold = 100 * 1024 * 1024
)

// MmapDEXReader provides memory-mapped access to DEX files.
// On Windows: uses CreateFileMapping + MapViewOfFile.
// On Unix:    uses syscall.Mmap.
// Fallback:   reads into heap memory if mmap fails.
type MmapDEXReader struct {
	file     *os.File
	data     []byte
	fileSize int64
	isLarge  bool
	isMapped bool // true if data came from mmap (not heap fallback)

	// Windows-specific handles for cleanup
	mapHandle uintptr // HANDLE from CreateFileMapping
	mapAddr   uintptr // address from MapViewOfFile

	// For partial mapping tracking
	activeMappings map[uint32]*mappedSection
	mappingsMu     sync.Mutex // guards activeMappings (sections map in parallel)
}

// mappedSection tracks a partially mapped section
type mappedSection struct {
	offset uint32
	size   uint32
	data   []byte
}

// NewMmapDEXReader creates a new memory-mapped DEX reader.
// The complete file is mapped. Virtual-memory mapping does not eagerly commit
// every page, so this remains memory-efficient while allowing the production
// parser to access arbitrary DEX sections without heap copies.
//
// The reader must be released with an explicit Close(): no finalizer is
// installed. A finalizer could unmap the region while byte slices handed out
// via Data()/MapSection() are still referenced elsewhere (GC cannot see that
// those pointers keep the mapping in use), turning them into dangling
// pointers and eventually SIGSEGV.
func NewMmapDEXReader(path string) (*MmapDEXReader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}

	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("stat file: %w", err)
	}

	fileSize := stat.Size()
	if fileSize == 0 {
		file.Close()
		return nil, fmt.Errorf("empty file")
	}

	reader := &MmapDEXReader{
		file:           file,
		fileSize:       fileSize,
		isLarge:        fileSize > largeDEXThreshold,
		activeMappings: make(map[uint32]*mappedSection),
	}

	// Map the file
	if err := reader.mapFile(); err != nil {
		file.Close()
		return nil, err
	}

	return reader, nil
}

// mapFile performs the actual memory mapping.
func (r *MmapDEXReader) mapFile() error {
	// Map the complete DEX. The OS pages data in on demand.
	mapSize := r.fileSize

	// Try platform-specific mmap first, fall back to read
	data, err := r.mmapPlatform(int(mapSize))
	if err != nil {
		// Fall back to reading into memory
		data = make([]byte, mapSize)
		n, readErr := r.file.ReadAt(data, 0)
		if readErr != nil && n == 0 {
			return fmt.Errorf("read file: %w", readErr)
		}
		r.data = data[:n]
		r.isMapped = false
		return nil
	}

	r.data = data
	r.isMapped = true
	return nil
}

// Data returns the mapped data.
// For large files, this returns only the initially mapped portion.
func (r *MmapDEXReader) Data() []byte {
	return r.data
}

// Size returns the total file size.
func (r *MmapDEXReader) Size() int64 {
	return r.fileSize
}

// IsLarge returns true if the file uses partial mapping.
func (r *MmapDEXReader) IsLarge() bool {
	return r.isLarge
}

// IsMapped returns true if the data is memory-mapped (not heap fallback).
func (r *MmapDEXReader) IsMapped() bool {
	return r.isMapped
}

// MapSection maps a specific section of a large DEX file on demand.
// For small files, this returns a slice of the already-mapped data.
func (r *MmapDEXReader) MapSection(offset, size uint32) ([]byte, error) {
	// Validate bounds
	if uint64(offset)+uint64(size) > uint64(r.fileSize) {
		return nil, fmt.Errorf("section out of bounds: offset=%d size=%d fileSize=%d",
			offset, size, r.fileSize)
	}

	// Return a zero-copy slice whenever the complete mapping is available.
	if uint64(offset)+uint64(size) <= uint64(len(r.data)) {
		return r.data[offset : offset+size], nil
	}
	if !r.isLarge {
		return nil, fmt.Errorf("section beyond mapped region")
	}

	// Check if already mapped
	r.mappingsMu.Lock()
	section, exists := r.activeMappings[offset]
	r.mappingsMu.Unlock()
	if exists {
		if section.size >= size {
			return section.data[:size], nil
		}
	}

	// For large files, read the section into memory
	// In a production implementation, this would use additional mmap calls
	data := make([]byte, size)
	n, err := r.file.ReadAt(data, int64(offset))
	if err != nil && n == 0 {
		return nil, fmt.Errorf("read section: %w", err)
	}

	section = &mappedSection{
		offset: offset,
		size:   size,
		data:   data[:n],
	}
	r.mappingsMu.Lock()
	r.activeMappings[offset] = section
	r.mappingsMu.Unlock()

	return section.data, nil
}

// UnmapSection releases a mapped section (for large files).
func (r *MmapDEXReader) UnmapSection(offset uint32) {
	if !r.isLarge {
		return
	}
	r.mappingsMu.Lock()
	delete(r.activeMappings, offset)
	r.mappingsMu.Unlock()
}

// Close unmaps the memory and closes the file.
func (r *MmapDEXReader) Close() error {
	if r.data == nil {
		return nil
	}

	var err error

	// Unmap using platform-specific code (only if actually mmapped)
	if r.isMapped {
		if unmapErr := r.munmapPlatform(); unmapErr != nil {
			err = fmt.Errorf("munmap failed: %w", unmapErr)
		}
	}

	r.data = nil
	r.activeMappings = nil

	if r.file != nil {
		if closeErr := r.file.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		r.file = nil
	}

	return err
}
