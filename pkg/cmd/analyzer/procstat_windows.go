//go:build windows

package main

import (
	"sync"
	"syscall"
	"unsafe"
)

// PDH (Performance Data Helper) — the same source Task Manager reads from.
// Counter: \Processor(_Total)\% Processor Time
var (
	modPdh                        = syscall.NewLazyDLL("pdh.dll")
	procPdhOpenQuery              = modPdh.NewProc("PdhOpenQuery")
	procPdhAddEnglishCounter      = modPdh.NewProc("PdhAddEnglishCounterW")
	procPdhCollectQueryData       = modPdh.NewProc("PdhCollectQueryData")
	procPdhGetFormattedCounterVal = modPdh.NewProc("PdhGetFormattedCounterValue")
	procPdhCloseQuery             = modPdh.NewProc("PdhCloseQuery")

	modKernel32      = syscall.NewLazyDLL("kernel32.dll")
	procGlobalMemory = modKernel32.NewProc("GlobalMemoryStatusEx")

	pdhMu      sync.Mutex
	pdhQuery   uintptr
	pdhCounter uintptr
	pdhReady   bool
)

const pdhFmtDouble = 0x00000200

// pdhFmtValue mirrors PDH_FMT_COUNTERVALUE on 64-bit Windows:
// CStatus (4 bytes) + 4-byte alignment pad + doubleValue (8 bytes) = 16 bytes.
type pdhFmtValue struct {
	status  uint32
	_       uint32 // alignment pad
	doubleV float64
}

type memoryStatusEx struct {
	length               uint32
	memoryLoad           uint32
	totalPhys            uint64
	availPhys            uint64
	totalPageFile        uint64
	availPageFile        uint64
	totalVirtual         uint64
	availVirtual         uint64
	availExtendedVirtual uint64
}

func initPDH() bool {
	if pdhReady {
		return true
	}
	r, _, _ := procPdhOpenQuery.Call(0, 0, uintptr(unsafe.Pointer(&pdhQuery)))
	if r != 0 {
		return false
	}
	path, _ := syscall.UTF16PtrFromString(`\Processor(_Total)\% Processor Time`)
	r, _, _ = procPdhAddEnglishCounter.Call(
		pdhQuery, uintptr(unsafe.Pointer(path)), 0, uintptr(unsafe.Pointer(&pdhCounter)),
	)
	if r != 0 {
		procPdhCloseQuery.Call(pdhQuery)
		pdhQuery = 0
		return false
	}
	// First collect establishes the baseline for this rate counter.
	procPdhCollectQueryData.Call(pdhQuery)
	pdhReady = true
	return true
}

// sampleHostStats returns host CPU % (from PDH, same source as Task Manager)
// and RAM % (from GlobalMemoryStatusEx). The very first call after process start
// primes the PDH baseline and returns CPU 0 with ok=true; all subsequent calls
// return the real delta since the last sample.
func sampleHostStats() (cpuPct int, ramPct int, ok bool) {
	pdhMu.Lock()
	defer pdhMu.Unlock()

	if !initPDH() {
		return 0, 0, false
	}

	procPdhCollectQueryData.Call(pdhQuery)

	var fv pdhFmtValue
	r, _, _ := procPdhGetFormattedCounterVal.Call(
		pdhCounter, uintptr(pdhFmtDouble), 0, uintptr(unsafe.Pointer(&fv)),
	)
	if r == 0 && fv.status == 0 {
		cpuPct = int(fv.doubleV + 0.5)
		if cpuPct < 0 {
			cpuPct = 0
		} else if cpuPct > 100 {
			cpuPct = 100
		}
	}

	var mem memoryStatusEx
	mem.length = uint32(unsafe.Sizeof(mem))
	if r2, _, _ := procGlobalMemory.Call(uintptr(unsafe.Pointer(&mem))); r2 != 0 {
		ramPct = int(mem.memoryLoad)
		ok = true
	}

	return cpuPct, ramPct, ok
}
