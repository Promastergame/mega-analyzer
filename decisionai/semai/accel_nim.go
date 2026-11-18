//go:build nim && cgo

package semai

/*
#cgo LDFLAGS: ${SRCDIR}/../nim/libdainim.a -lm
#include <stdlib.h>
int dn_new(int hidden, int heads, int inter, int nlayers, float eps);
int dn_set(int h, int layer, const char* name, float* data, int n, int inp, int outp);
int dn_forward(int h, float* x, int n);
void NimMain(void);
int dn_kind(void);
*/
import "C"

import (
	"sync"
	"unsafe"
)

var nimOnce sync.Once

// Nim's model registry is a growable sequence. Lazy initialization may append
// to it during inference, so registration must exclude every forward call.
// Readers remain concurrent across models and requests.
var nimModels sync.RWMutex

type nimAccel struct{ h C.int }

func (a nimAccel) forward(x []float32, n int) bool {
	nimModels.RLock()
	defer nimModels.RUnlock()
	return C.dn_forward(a.h, (*C.float)(unsafe.Pointer(&x[0])), C.int(n)) == 0
}

func init() {
	nimKind = func() int { return int(C.dn_kind()) }
	newAccel = func(e *Encoder) accel {
		nimModels.Lock()
		defer nimModels.Unlock()
		nimOnce.Do(func() { C.NimMain() })
		h := C.dn_new(C.int(e.hidden), C.int(e.nHead), C.int(e.inter), C.int(len(e.layers)), C.float(e.eps))
		set := func(layer int, name string, v []float32, in, out int) bool {
			cs := C.CString(name)
			defer C.free(unsafe.Pointer(cs))
			return C.dn_set(h, C.int(layer), cs, (*C.float)(unsafe.Pointer(&v[0])), C.int(len(v)), C.int(in), C.int(out)) == 0
		}
		ok := set(-1, "emb_ln.w", e.embLN.w, 0, 0) && set(-1, "emb_ln.b", e.embLN.b, 0, 0)
		for i, L := range e.layers {
			for _, it := range []struct {
				n string
				l lin
			}{{"q", L.q}, {"k", L.k}, {"v", L.v}, {"o", L.o}, {"f1", L.f1}, {"f2", L.f2}} {
				ok = ok && set(i, it.n+".w", it.l.w, it.l.in, it.l.out) && set(i, it.n+".b", it.l.b, 0, 0)
			}
			ok = ok && set(i, "ln1.w", L.ln1.w, 0, 0) && set(i, "ln1.b", L.ln1.b, 0, 0) && set(i, "ln2.w", L.ln2.w, 0, 0) && set(i, "ln2.b", L.ln2.b, 0, 0)
		}
		if !ok {
			return nil
		}
		return nimAccel{h}
	}
}
