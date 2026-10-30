package axml

import "unsafe"

// unsafePointerCast is the std-free equivalent of *(*float32)(unsafe.Pointer(&u32)).
// Isolated in its own file so the surrounding decoder.go stays free of
// unsafe imports — easier to audit and to swap with a math.Float32frombits
// call if the cgo policy ever changes.
func unsafePointerCast(p *uint32) unsafe.Pointer {
	return unsafe.Pointer(p)
}
