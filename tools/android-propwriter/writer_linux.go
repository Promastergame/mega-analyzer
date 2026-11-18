package main

import (
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"
)

func writeProperty(path, key, value string) error {
	// Inspect through a read-only mapping first. A process need not have write
	// access to unrelated contexts to find the requested property area.
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if st.Size() < areaHeader || st.Size() > 16<<20 {
		f.Close()
		return errNotFound
	}
	data, err := syscall.Mmap(int(f.Fd()), 0, int(st.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		f.Close()
		return err
	}
	offset, locateErr := locateProperty(data, key)
	syscall.Munmap(data)
	f.Close()
	if locateErr != nil {
		return locateErr
	}

	f, err = os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err = syscall.Mmap(int(f.Fd()), 0, int(st.Size()), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return err
	}
	defer syscall.Munmap(data)
	confirmed, err := locateProperty(data, key)
	if err != nil || confirmed != offset {
		return fmt.Errorf("property area changed during write: %v", err)
	}
	serial := (*uint32)(unsafe.Pointer(&data[offset]))
	old := atomic.LoadUint32(serial)
	if old&1 != 0 {
		return fmt.Errorf("property has an active writer")
	}
	if old&longFlag == 0 && old>>24 > 91 {
		return fmt.Errorf("invalid short property length")
	}
	// This tool edits only read-only Build identity and emulator marker fields.
	// Refuse mutable values: their dirty backup protocol differs by Android API.
	if len(key) < 3 || key[:3] != "ro." {
		return fmt.Errorf("existing mutable property %q is not supported", key)
	}
	if !atomic.CompareAndSwapUint32(serial, old, old|1) {
		return fmt.Errorf("property changed concurrently")
	}
	buffer := data[offset+4 : offset+infoNameOffset]
	clear(buffer)
	copy(buffer, value)
	// Converting a long read-only value to a short value clears its long flag.
	next := uint32(len(value))<<24 | ((old + 2) & 0x00ffffff &^ (longFlag | 1))
	atomic.StoreUint32(serial, next)
	wake(serial)
	areaSerial := (*uint32)(unsafe.Pointer(&data[4]))
	atomic.AddUint32(areaSerial, 1)
	wake(areaSerial)
	return nil
}

func wake(serial *uint32) {
	// Android property readers use shared futexes, not FUTEX_PRIVATE_FLAG.
	syscall.Syscall6(syscall.SYS_FUTEX, uintptr(unsafe.Pointer(serial)), 1, 0x7fffffff, 0, 0, 0)
}
