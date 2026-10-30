//go:build unix || linux || darwin || freebsd || openbsd || netbsd

package apkloader

import "syscall"

// mmapPlatform performs memory mapping on Unix-like systems.
// Uses MAP_PRIVATE for copy-on-write (safer than MAP_SHARED for analysis).
func (r *MmapDEXReader) mmapPlatform(size int) ([]byte, error) {
	return syscall.Mmap(
		int(r.file.Fd()),
		0,
		size,
		syscall.PROT_READ,
		syscall.MAP_PRIVATE,
	)
}

// munmapPlatform unmaps memory on Unix-like systems.
func (r *MmapDEXReader) munmapPlatform() error {
	if len(r.data) == 0 {
		return nil
	}
	return syscall.Munmap(r.data)
}
