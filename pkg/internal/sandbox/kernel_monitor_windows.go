//go:build windows

package sandbox

import (
	"context"
	"encoding/binary"
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// Windows Kernel Monitor Implementation
//
// This file implements the user-mode service that receives kernel-level events
// from a minifilter driver. The minifilter driver must be implemented
// separately in C/C++. See the project docs for the driver contract
// (FltRegisterFilter / CmRegisterCallbackEx, named pipe, IOCP, etc.).
//
// All Win32 calls below use the standard library syscall package directly, so
// the project keeps zero third-party dependencies (no golang.org/x/sys) and
// still cross-compiles with a plain `go build`.

// cWaitTimeout is the Win32 WAIT_TIMEOUT status returned by
// GetQueuedCompletionStatus when no completion arrives before the timeout.
const cWaitTimeout = syscall.Errno(0x102)

// Windows-specific constants for named pipe communication
const (
	pipeBufferSize     = 8192
	pipeTimeoutMS      = 1000
	iocpMaxConcurrency = 2 // Number of threads for IOCP
)

// kernelEventWireFormat represents the binary structure sent by the minifilter
// driver. This must match the structure defined in the kernel driver.
type kernelEventWireFormat struct {
	Timestamp      int64  // Windows FILETIME
	EventType      uint32 // Maps to KernelEventType
	ProcessID      uint32
	ThreadID       uint32
	IntegrityLevel uint32 // 0=Low, 1=Medium, 2=High, 3=System
	Status         uint32 // NTSTATUS code
	PathLength     uint16 // Length of Path in UTF-16 characters
	OperationLen   uint16 // Length of Operation in UTF-16 characters
	ValueNameLen   uint16 // Length of ValueName in UTF-16 characters (registry events only)
	ValueType      uint32 // Registry value type (REG_SZ=1, REG_DWORD=4, etc.)
	ValueDataLen   uint32 // Length of ValueData in bytes (registry events only)
	Reserved       uint16 // Padding for alignment
}

// pipeHandle wraps Windows HANDLEs for the named pipe and its IOCP.
type pipeHandle struct {
	handle syscall.Handle
	iocp   syscall.Handle // I/O Completion Port handle
}

// connectToPipe establishes a connection to the minifilter driver's named pipe.
func (km *kernelMonitorImpl) connectToPipe(_ context.Context) (pipeHandle, error) {
	pipeName, err := syscall.UTF16PtrFromString(km.pipeName)
	if err != nil {
		return pipeHandle{}, fmt.Errorf("invalid pipe name: %w", err)
	}

	handle, err := syscall.CreateFile(
		pipeName,
		syscall.GENERIC_READ,
		0, // No sharing
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_OVERLAPPED, // Enable async I/O
		0,
	)
	if err != nil {
		return pipeHandle{}, fmt.Errorf("failed to open pipe: %w", err)
	}

	iocp, err := syscall.CreateIoCompletionPort(handle, 0, 0, iocpMaxConcurrency)
	if err != nil {
		syscall.CloseHandle(handle)
		return pipeHandle{}, fmt.Errorf("failed to create IOCP: %w", err)
	}

	return pipeHandle{
		handle: handle,
		iocp:   iocp,
	}, nil
}

// readEvent reads a single event from the pipe using IOCP.
func (km *kernelMonitorImpl) readEvent(pipe pipeHandle, buffer []byte) (KernelEvent, error) {
	overlapped := new(syscall.Overlapped)
	var bytesRead uint32

	// Pin the overlapped structure so the Go runtime cannot move it while the
	// async I/O is in flight.
	var pinner runtime.Pinner
	pinner.Pin(overlapped)
	defer pinner.Unpin()

	err := syscall.ReadFile(pipe.handle, buffer, &bytesRead, overlapped)
	if err != nil && err != syscall.ERROR_IO_PENDING {
		return KernelEvent{}, fmt.Errorf("ReadFile failed: %w", err)
	}

	var completionKey uint32
	var lpOverlapped *syscall.Overlapped
	err = syscall.GetQueuedCompletionStatus(
		pipe.iocp,
		&bytesRead,
		&completionKey,
		&lpOverlapped,
		pipeTimeoutMS,
	)
	if err != nil {
		if err == cWaitTimeout {
			return KernelEvent{}, fmt.Errorf("read timeout")
		}
		return KernelEvent{}, fmt.Errorf("IOCP wait failed: %w", err)
	}

	return km.parseEvent(buffer[:bytesRead])
}

// parseEvent converts the binary wire format to a KernelEvent struct.
func (km *kernelMonitorImpl) parseEvent(data []byte) (KernelEvent, error) {
	if len(data) < int(unsafe.Sizeof(kernelEventWireFormat{})) {
		return KernelEvent{}, fmt.Errorf("event data too short")
	}

	var wire kernelEventWireFormat
	headerSize := int(unsafe.Sizeof(wire))

	wire.Timestamp = int64(binary.LittleEndian.Uint64(data[0:8]))
	wire.EventType = binary.LittleEndian.Uint32(data[8:12])
	wire.ProcessID = binary.LittleEndian.Uint32(data[12:16])
	wire.ThreadID = binary.LittleEndian.Uint32(data[16:20])
	wire.IntegrityLevel = binary.LittleEndian.Uint32(data[20:24])
	wire.Status = binary.LittleEndian.Uint32(data[24:28])
	wire.PathLength = binary.LittleEndian.Uint16(data[28:30])
	wire.OperationLen = binary.LittleEndian.Uint16(data[30:32])
	wire.ValueNameLen = binary.LittleEndian.Uint16(data[32:34])
	wire.ValueType = binary.LittleEndian.Uint32(data[34:38])
	wire.ValueDataLen = binary.LittleEndian.Uint32(data[38:42])

	offset := headerSize

	if offset+int(wire.PathLength)*2 > len(data) {
		return KernelEvent{}, fmt.Errorf("path data exceeds buffer")
	}
	pathBytes := data[offset : offset+int(wire.PathLength)*2]
	path := utf16ToString(pathBytes)
	offset += int(wire.PathLength) * 2

	if offset+int(wire.OperationLen)*2 > len(data) {
		return KernelEvent{}, fmt.Errorf("operation data exceeds buffer")
	}
	operationBytes := data[offset : offset+int(wire.OperationLen)*2]
	operation := utf16ToString(operationBytes)
	offset += int(wire.OperationLen) * 2

	event := KernelEvent{
		Timestamp:      fileTimeToTime(wire.Timestamp),
		EventType:      KernelEventType(wire.EventType),
		ProcessID:      int(wire.ProcessID),
		ThreadID:       int(wire.ThreadID),
		IntegrityLevel: integrityLevelToString(wire.IntegrityLevel),
		Path:           path,
		Operation:      operation,
		Status:         ntStatusToString(wire.Status),
		Details:        make(map[string]string),
	}

	if isRegistryEvent(event.EventType) {
		if wire.ValueNameLen > 0 {
			if offset+int(wire.ValueNameLen)*2 > len(data) {
				return KernelEvent{}, fmt.Errorf("value name data exceeds buffer")
			}
			valueNameBytes := data[offset : offset+int(wire.ValueNameLen)*2]
			valueName := utf16ToString(valueNameBytes)
			event.Details["value_name"] = valueName
			offset += int(wire.ValueNameLen) * 2
		}

		if wire.ValueType > 0 {
			event.Details["value_type"] = regTypeToString(wire.ValueType)
		}

		if wire.ValueDataLen > 0 {
			if offset+int(wire.ValueDataLen) > len(data) {
				return KernelEvent{}, fmt.Errorf("value data exceeds buffer")
			}
			valueData := data[offset : offset+int(wire.ValueDataLen)]
			event.Details["value_data"] = formatRegistryData(wire.ValueType, valueData)
			offset += int(wire.ValueDataLen)
		}
	}

	km.enrichEventDetails(&event)

	return event, nil
}

// enrichEventDetails adds additional context to the event based on its type.
func (km *kernelMonitorImpl) enrichEventDetails(event *KernelEvent) {
	switch event.EventType {
	case EventFileCreate:
		event.Details["irp_type"] = "IRP_MJ_CREATE"
		event.Details["description"] = "File or directory open/create operation"
	case EventFileWrite:
		event.Details["irp_type"] = "IRP_MJ_WRITE"
		event.Details["description"] = "File write operation"
	case EventFileDelete:
		event.Details["description"] = "File deletion operation"
	case EventFileRename:
		event.Details["description"] = "File rename operation"
	case EventRegSetValue:
		event.Details["callback_type"] = "RegNtPreSetValueKey"
		event.Details["description"] = "Registry value set operation"
	case EventRegDeleteValue:
		event.Details["callback_type"] = "RegNtPreDeleteValueKey"
		event.Details["description"] = "Registry value deletion operation"
	case EventRegCreateKey:
		event.Details["callback_type"] = "RegNtPreCreateKeyEx"
		event.Details["description"] = "Registry key creation operation"
	case EventRegDeleteKey:
		event.Details["callback_type"] = "RegNtPreDeleteKey"
		event.Details["description"] = "Registry key deletion operation"
	}
}

// closePipe closes the named pipe and IOCP handles.
func (km *kernelMonitorImpl) closePipe(pipe pipeHandle) {
	if pipe.handle != 0 {
		syscall.CloseHandle(pipe.handle)
	}
	if pipe.iocp != 0 {
		syscall.CloseHandle(pipe.iocp)
	}
}

// verifyDriverLoaded checks if the minifilter driver is loaded by probing the
// named pipe.
func (km *kernelMonitorImpl) verifyDriverLoaded() error {
	pipeName, err := syscall.UTF16PtrFromString(km.pipeName)
	if err != nil {
		return fmt.Errorf("invalid pipe name: %w", err)
	}

	handle, err := syscall.CreateFile(
		pipeName,
		syscall.GENERIC_READ,
		0,
		nil,
		syscall.OPEN_EXISTING,
		0, // Synchronous for this check
		0,
	)
	if err != nil {
		return fmt.Errorf("minifilter driver pipe not available: %w", err)
	}

	syscall.CloseHandle(handle)
	return nil
}

// Helper functions

// fileTimeToTime converts Windows FILETIME to Go time.Time.
func fileTimeToTime(ft int64) time.Time {
	const epochDiff = 116444736000000000 // 100-ns intervals between 1601 and 1970
	unixNano := (ft - epochDiff) * 100
	return time.Unix(0, unixNano)
}

func integrityLevelToString(level uint32) string {
	switch level {
	case 0:
		return "Low"
	case 1:
		return "Medium"
	case 2:
		return "High"
	case 3:
		return "System"
	default:
		return "Unknown"
	}
}

func ntStatusToString(status uint32) string {
	switch status {
	case 0x00000000:
		return "Success"
	case 0xC0000022:
		return "AccessDenied"
	case 0xC0000034:
		return "ObjectNameNotFound"
	case 0xC000003A:
		return "ObjectPathNotFound"
	case 0xC0000043:
		return "SharingViolation"
	default:
		return fmt.Sprintf("0x%08X", status)
	}
}

// utf16ToString converts a little-endian UTF-16 byte slice to a Go string.
func utf16ToString(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return syscall.UTF16ToString(u16)
}

func isRegistryEvent(eventType KernelEventType) bool {
	return eventType == EventRegSetValue ||
		eventType == EventRegDeleteValue ||
		eventType == EventRegCreateKey ||
		eventType == EventRegDeleteKey
}

func regTypeToString(regType uint32) string {
	switch regType {
	case 0:
		return "REG_NONE"
	case 1:
		return "REG_SZ"
	case 2:
		return "REG_EXPAND_SZ"
	case 3:
		return "REG_BINARY"
	case 4:
		return "REG_DWORD"
	case 5:
		return "REG_DWORD_BIG_ENDIAN"
	case 6:
		return "REG_LINK"
	case 7:
		return "REG_MULTI_SZ"
	case 8:
		return "REG_RESOURCE_LIST"
	case 9:
		return "REG_FULL_RESOURCE_DESCRIPTOR"
	case 10:
		return "REG_RESOURCE_REQUIREMENTS_LIST"
	case 11:
		return "REG_QWORD"
	default:
		return fmt.Sprintf("UNKNOWN(0x%x)", regType)
	}
}

func formatRegistryData(regType uint32, data []byte) string {
	if len(data) == 0 {
		return ""
	}
	switch regType {
	case 1, 2: // REG_SZ, REG_EXPAND_SZ
		return utf16ToString(data)
	case 4: // REG_DWORD
		if len(data) >= 4 {
			value := binary.LittleEndian.Uint32(data)
			return fmt.Sprintf("0x%08x (%d)", value, value)
		}
		return fmt.Sprintf("<invalid DWORD: %d bytes>", len(data))
	case 11: // REG_QWORD
		if len(data) >= 8 {
			value := binary.LittleEndian.Uint64(data)
			return fmt.Sprintf("0x%016x (%d)", value, value)
		}
		return fmt.Sprintf("<invalid QWORD: %d bytes>", len(data))
	case 7: // REG_MULTI_SZ
		strings := parseMultiSZ(data)
		if len(strings) == 0 {
			return ""
		}
		return fmt.Sprintf("[%s]", strings[0])
	case 3: // REG_BINARY
		maxBytes := 32
		if len(data) < maxBytes {
			maxBytes = len(data)
		}
		hex := fmt.Sprintf("%x", data[:maxBytes])
		if len(data) > maxBytes {
			hex += "..."
		}
		return hex
	default:
		maxBytes := 32
		if len(data) < maxBytes {
			maxBytes = len(data)
		}
		hex := fmt.Sprintf("%x", data[:maxBytes])
		if len(data) > maxBytes {
			hex += "..."
		}
		return hex
	}
}

func parseMultiSZ(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	var strings []string
	offset := 0
	for offset < len(data)-1 {
		end := offset
		for end < len(data)-1 {
			if data[end] == 0 && data[end+1] == 0 {
				break
			}
			end += 2
		}
		if end > offset {
			str := utf16ToString(data[offset:end])
			if str != "" {
				strings = append(strings, str)
			}
		}
		offset = end + 2
		if offset < len(data)-1 && data[offset] == 0 && data[offset+1] == 0 {
			break
		}
	}
	return strings
}
