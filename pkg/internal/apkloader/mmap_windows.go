//go:build windows

package apkloader

import (
	"fmt"
	"syscall"
	"unsafe"
)

// ptrToSlice converts a uintptr from MapViewOfFile to a []byte.
func ptrToSlice(ptr uintptr, size int) []byte {
	return unsafe.Slice((*byte)(unsafe.Add(unsafe.Pointer(nil), ptr)), size)
}

// mmapPlatform performs memory mapping on Windows using CreateFileMapping +
// MapViewOfFile from the standard library syscall package (no golang.org/x/sys).
func (r *MmapDEXReader) mmapPlatform(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("mmap: invalid size %d", size)
	}

	handle := syscall.Handle(r.file.Fd())
	if handle == syscall.InvalidHandle {
		return nil, fmt.Errorf("mmap: invalid file handle")
	}

	// PAGE_READONLY + max size 0/0 => map the entire file, read-only.
	mapHandle, err := syscall.CreateFileMapping(handle, nil, syscall.PAGE_READONLY, 0, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("mmap: CreateFileMapping: %w", err)
	}
	r.mapHandle = uintptr(mapHandle)

	ptr, err := syscall.MapViewOfFile(mapHandle, syscall.FILE_MAP_READ, 0, 0, uintptr(size))
	if err != nil {
		syscall.CloseHandle(mapHandle)
		r.mapHandle = 0
		return nil, fmt.Errorf("mmap: MapViewOfFile: %w", err)
	}
	r.mapAddr = ptr

	return ptrToSlice(ptr, size), nil
}

// munmapPlatform unmaps memory on Windows. Order matters: UnmapViewOfFile first,
// then CloseHandle.
func (r *MmapDEXReader) munmapPlatform() error {
	var firstErr error

	if r.mapAddr != 0 {
		if err := syscall.UnmapViewOfFile(r.mapAddr); err != nil {
			firstErr = fmt.Errorf("mmap: UnmapViewOfFile: %w", err)
		}
		r.mapAddr = 0
	}

	if r.mapHandle != 0 {
		if err := syscall.CloseHandle(syscall.Handle(r.mapHandle)); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("mmap: CloseHandle: %w", err)
		}
		r.mapHandle = 0
	}

	return firstErr
}
