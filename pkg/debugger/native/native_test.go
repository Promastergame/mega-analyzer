package native

import (
	"testing"
	"unsafe"
)

func TestNativeDebuggerEdgeCases(t *testing.T) {
	n := NewNative()
	if n == nil {
		t.Fatal("Expected NewNative to return non-nil")
	}

	// Helper to recover from LazyProc.Call panics due to missing ffi.dll or environment differences
	runSafe := func(f func()) {
		defer func() {
			recover()
		}()
		f()
	}

	runSafe(func() {
		n.Start("dummy.exe", 0x1000)
	})

	runSafe(func() {
		n.Stop(12345)
	})

	runSafe(func() {
		n.Step(12345)
	})

	runSafe(func() {
		n.Continue(12345)
	})

	runSafe(func() {
		n.Registers(12345)
	})

	runSafe(func() {
		n.Disassemble(12345, 0x1000, 10)
	})

	runSafe(func() {
		n.ReadMemory(12345, 0x1000, 32)
	})

	runSafe(func() {
		n.WriteMemory(12345, 0x1000, "9090")
	})

	runSafe(func() {
		n.SetRegister(12345, "rip", 0x1000)
	})

	runSafe(func() {
		n.Breakpoint(12345, "main")
	})

	runSafe(func() {
		n.RemoveBreakpoint(12345, 1)
	})

	runSafe(func() {
		n.SetFlavor(12345, "intel")
	})

	runSafe(func() {
		n.Next(12345)
	})

	runSafe(func() {
		n.TraceEnable(12345, true)
	})

	runSafe(func() {
		n.ReverseStep(12345)
	})

	runSafe(func() {
		n.ReverseContinue(12345)
	})

	runSafe(func() {
		n.ScanMemory(12345, "?? ??")
	})

	// Test goCString helper with edge values
	s := goCString(nil)
	if s != "" {
		t.Errorf("Expected empty string for nil pointer, got %q", s)
	}

	dummyStr := []byte("hello\x00")
	ptr := unsafe.Pointer(&dummyStr[0])
	s2 := goCString(ptr)
	if s2 != "hello" {
		t.Errorf("Expected 'hello', got %q", s2)
	}
}

func TestCommandJSONError(t *testing.T) {
	n := NewNative()
	// Pass an unmarshalable map key/value or value containing channels to trigger json.Marshal error
	badMap := map[string]interface{}{
		"bad": make(chan int),
	}
	_, err := n.command(12345, badMap)
	if err == nil {
		t.Error("Expected marshal error for channel value, got nil")
	}
}
