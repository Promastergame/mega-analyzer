//go:build !windows

package native

import (
	"encoding/json"
	"fmt"
	"unsafe"
)

// Native is a portable stub for the Windows Rust debugger DLL bridge.
type Native struct{}

// NewNative creates a non-nil stub handle so CLI/tests can run off Windows.
func NewNative() *Native { return &Native{} }

func goCString(ptr unsafe.Pointer) string {
	if ptr == nil {
		return ""
	}
	p := (*byte)(ptr)
	n, lim := 0, 1<<20
	for n < lim {
		if *(*byte)(unsafe.Add(ptr, n)) == 0 {
			break
		}
		n++
	}
	return string(unsafe.Slice(p, n))
}

func (n *Native) command(_ uint64, cmd map[string]interface{}) (map[string]interface{}, error) {
	if _, err := json.Marshal(cmd); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("native debugger DLL bridge is supported on Windows only")
}

func (n *Native) Start(filePath string, entry uint64) uint64 { return 0 }
func (n *Native) Stop(sessionID uint64)                      {}
func (n *Native) Step(sessionID uint64) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "step"})
}
func (n *Native) Continue(sessionID uint64) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "continue"})
}
func (n *Native) Registers(sessionID uint64) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "registers"})
}
func (n *Native) Disassemble(sessionID uint64, address uint64, count int) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "disassemble", "address": address, "count": count})
}
func (n *Native) ReadMemory(sessionID uint64, address uint64, size uint64) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "read_memory", "address": address, "size": size})
}
func (n *Native) WriteMemory(sessionID uint64, address uint64, hex string) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "write_memory", "address": address, "hex_data": hex})
}
func (n *Native) SetRegister(sessionID uint64, reg string, value uint64) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "set_register", "register": reg, "value": value})
}
func (n *Native) Breakpoint(sessionID uint64, target string) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "breakpoint", "target": target})
}
func (n *Native) RemoveBreakpoint(sessionID uint64, id uint32) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "remove_breakpoint", "id": id})
}
func (n *Native) SetFlavor(sessionID uint64, flavor string) {
	_, _ = n.command(sessionID, map[string]interface{}{"command": "set_flavor", "flavor": flavor})
}
func (n *Native) Next(sessionID uint64) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "next"})
}
func (n *Native) TraceEnable(sessionID uint64, enabled bool) {
	_, _ = n.command(sessionID, map[string]interface{}{"command": "trace_enable", "enabled": enabled})
}
func (n *Native) ReverseStep(sessionID uint64) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "reverse_step"})
}
func (n *Native) ReverseContinue(sessionID uint64) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "reverse_continue"})
}
func (n *Native) ScanMemory(sessionID uint64, pattern string) (map[string]interface{}, error) {
	return n.command(sessionID, map[string]interface{}{"command": "scan_memory", "pattern": pattern})
}
