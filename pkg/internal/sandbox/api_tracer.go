package sandbox

import (
	"context"
	"strings"
	"time"
)

// APITracer is the interface for observed user-mode Windows API calls.
//
// Backend architecture (Windows):
//   - Uses Frida (local frida CLI / frida-server + frida_windows_default.js)
//     to install inline user-mode hooks (Interceptor.attach) into the suspended
//     target process BEFORE resumeProcess() runs, and follows child processes.
//   - ETW (Event Tracing for Windows) observes kernel/provider process, image,
//     file, and network telemetry — ETW is NOT arbitrary WinAPI interception
//     and is never presented as hooked WinAPI calls.
//   - If the Frida backend, server binary, or privileges are unavailable,
//     Attach returns a typed error wrapping errAPITracingUnavailable so the gap
//     is surfaced in degraded_components without generating synthetic events.
//
// Validates: Requirements 4.1, 4.2, 4.3, 4.4
type APITracer interface {
	// Attach connects a real tracing backend or returns an availability error.
	Attach(ctx context.Context, pid int) error

	// Detach removes the API hooking agent from the target process.
	Detach(pid int) error

	// Calls returns a channel of intercepted API calls.
	Calls() <-chan APICall

	// Stop stops the API tracer and closes the calls channel.
	Stop() error
}

// API category constants for filtering.
const (
	CategoryMemory   = "Memory"   // VirtualAllocEx, VirtualProtect, WriteProcessMemory, NtAllocateVirtualMemory, NtWriteVirtualMemory
	CategoryProcess  = "Process"  // CreateRemoteThread, CreateProcessW, NtUnmapViewOfSection, ResumeThread, NtCreateThreadEx
	CategoryRegistry = "Registry" // RegSetValueEx, RegCreateKeyEx, NtSetValueKey
	CategoryFile     = "File"     // CreateFileW, WriteFile, DeleteFileW
	CategoryCrypto   = "Crypto"   // CryptEncrypt, CryptDecrypt, BCryptEncrypt
	CategoryNetwork  = "Network"  // connect, WSAConnect, send, WSASend, recv, WSARecv
)

// WindowsSupportedAPIMatrix is the canonical supported-event matrix for the
// Windows Frida user-mode API-tracing backend. Anything outside this matrix
// (such as direct syscalls bypassing ntdll.dll, kernel callbacks, or unhooked
// categories) is reported as an explicit coverage gap in degraded_components
// rather than fabricated.
const WindowsSupportedAPIMatrix = `Category|Module|Function|TargetIdentityParam|ReturnConvention
Memory|kernel32.dll/kernelbase.dll|VirtualAllocEx|hProcess|Win32Pointer(non-zero=success,0x0=failure)
Memory|kernel32.dll/kernelbase.dll|VirtualAlloc|self|Win32Pointer(non-zero=success,0x0=failure)
Memory|kernel32.dll/kernelbase.dll|VirtualProtectEx|hProcess|Win32Bool(non-zero=success,0x0=failure)
Memory|kernel32.dll/kernelbase.dll|VirtualProtect|self|Win32Bool(non-zero=success,0x0=failure)
Memory|kernel32.dll/kernelbase.dll|WriteProcessMemory|hProcess|Win32Bool(non-zero=success,0x0=failure)
Memory|kernel32.dll/kernelbase.dll|ReadProcessMemory|hProcess|Win32Bool(non-zero=success,0x0=failure)
Memory|ntdll.dll|NtAllocateVirtualMemory|ProcessHandle|NTSTATUS(0x00000000=success,non-zero=failure)
Memory|ntdll.dll|ZwAllocateVirtualMemory|ProcessHandle|NTSTATUS(0x00000000=success,non-zero=failure)
Memory|ntdll.dll|NtWriteVirtualMemory|ProcessHandle|NTSTATUS(0x00000000=success,non-zero=failure)
Memory|ntdll.dll|ZwWriteVirtualMemory|ProcessHandle|NTSTATUS(0x00000000=success,non-zero=failure)
Memory|ntdll.dll|NtProtectVirtualMemory|ProcessHandle|NTSTATUS(0x00000000=success,non-zero=failure)
Memory|ntdll.dll|ZwProtectVirtualMemory|ProcessHandle|NTSTATUS(0x00000000=success,non-zero=failure)
Process|kernel32.dll/kernelbase.dll|CreateRemoteThread|hProcess|Win32Handle(non-zero=success,0x0=failure)
Process|kernel32.dll/kernelbase.dll|CreateRemoteThreadEx|hProcess|Win32Handle(non-zero=success,0x0=failure)
Process|kernel32.dll/kernelbase.dll|CreateProcessW|hProcess,hThread,dwProcessId|Win32Bool(non-zero=success,0x0=failure)
Process|kernel32.dll/kernelbase.dll|CreateProcessA|hProcess,hThread,dwProcessId|Win32Bool(non-zero=success,0x0=failure)
Process|kernel32.dll/kernelbase.dll|OpenProcess|dwProcessId|Win32Handle(non-zero=success,0x0=failure)
Process|kernel32.dll/kernelbase.dll|ResumeThread|hThread|Win32SuspendCount(0xffffffff=failure,other=success)
Process|ntdll.dll|NtUnmapViewOfSection|ProcessHandle|NTSTATUS(0x00000000=success,non-zero=failure)
Process|ntdll.dll|ZwUnmapViewOfSection|ProcessHandle|NTSTATUS(0x00000000=success,non-zero=failure)
Process|ntdll.dll|NtCreateThreadEx|ProcessHandle|NTSTATUS(0x00000000=success,non-zero=failure)
Process|ntdll.dll|ZwCreateThreadEx|ProcessHandle|NTSTATUS(0x00000000=success,non-zero=failure)
Process|ntdll.dll|RtlCreateUserThread|ProcessHandle|NTSTATUS(0x00000000=success,non-zero=failure)
Process|ntdll.dll|NtResumeThread|ThreadHandle|NTSTATUS(0x00000000=success,non-zero=failure)
Process|ntdll.dll|ZwResumeThread|ThreadHandle|NTSTATUS(0x00000000=success,non-zero=failure)
Process|ntdll.dll|NtCreateUserProcess|ProcessHandle,ThreadHandle|NTSTATUS(0x00000000=success,non-zero=failure)
Process|ntdll.dll|ZwCreateUserProcess|ProcessHandle,ThreadHandle|NTSTATUS(0x00000000=success,non-zero=failure)
Crypto|advapi32.dll/cryptsp.dll|CryptEncrypt|hKey|Win32Bool(non-zero=success,0x0=failure)
Crypto|advapi32.dll/cryptsp.dll|CryptDecrypt|hKey|Win32Bool(non-zero=success,0x0=failure)
Crypto|bcrypt.dll|BCryptEncrypt|hKey|NTSTATUS(0x00000000=success,non-zero=failure)
Crypto|bcrypt.dll|BCryptDecrypt|hKey|NTSTATUS(0x00000000=success,non-zero=failure)
Crypto|bcrypt.dll|BCryptOpenAlgorithmProvider|self|NTSTATUS(0x00000000=success,non-zero=failure)
Crypto|bcrypt.dll|BCryptCloseAlgorithmProvider|self|NTSTATUS(0x00000000=success,non-zero=failure)
Crypto|bcrypt.dll|BCryptGenerateSymmetricKey|hKey|NTSTATUS(0x00000000=success,non-zero=failure)
Crypto|bcrypt.dll|BCryptImportKey|hKey|NTSTATUS(0x00000000=success,non-zero=failure)
Crypto|bcrypt.dll|BCryptDestroyKey|hKey|NTSTATUS(0x00000000=success,non-zero=failure)
Registry|advapi32.dll/kernelbase.dll|RegSetValueEx|hKey|LSTATUS(0x0=success,non-zero=failure)
Registry|advapi32.dll/kernelbase.dll|RegSetValueExW|hKey|LSTATUS(0x0=success,non-zero=failure)
Registry|advapi32.dll/kernelbase.dll|RegSetValueExA|hKey|LSTATUS(0x0=success,non-zero=failure)
Registry|advapi32.dll/kernelbase.dll|RegCreateKeyExW|hKey|LSTATUS(0x0=success,non-zero=failure)
Registry|advapi32.dll/kernelbase.dll|RegCreateKeyExA|hKey|LSTATUS(0x0=success,non-zero=failure)
Registry|ntdll.dll|NtSetValueKey|KeyHandle|NTSTATUS(0x00000000=success,non-zero=failure)
Registry|ntdll.dll|ZwSetValueKey|KeyHandle|NTSTATUS(0x00000000=success,non-zero=failure)
File|kernel32.dll/kernelbase.dll|CreateFileW|lpFileName|Win32FileHandle(INVALID_HANDLE_VALUE=failure,other=success)
File|kernel32.dll/kernelbase.dll|CreateFileA|lpFileName|Win32FileHandle(INVALID_HANDLE_VALUE=failure,other=success)
File|kernel32.dll/kernelbase.dll|WriteFile|hFile|Win32Bool(non-zero=success,0x0=failure)
File|kernel32.dll/kernelbase.dll|DeleteFileW|lpFileName|Win32Bool(non-zero=success,0x0=failure)
File|kernel32.dll/kernelbase.dll|DeleteFileA|lpFileName|Win32Bool(non-zero=success,0x0=failure)
File|kernel32.dll/kernelbase.dll|MoveFileExW|lpExistingFileName|Win32Bool(non-zero=success,0x0=failure)
Network|ws2_32.dll|connect|s|WinsockStatus(0x0=success,0xffffffff=failure)
Network|ws2_32.dll|WSAConnect|s|WinsockStatus(0x0=success,0xffffffff=failure)
Network|ws2_32.dll|send|s|WinsockCount(0xffffffff=failure,other=success)
Network|ws2_32.dll|WSASend|s|WinsockStatus(0x0=success,non-zero=failure)
Network|ws2_32.dll|recv|s|WinsockCount(0xffffffff=failure,other=success)
Network|ws2_32.dll|WSARecv|s|WinsockStatus(0x0=success,non-zero=failure)`

// SupportedAPIHook describes one entry in the Windows API-tracing support matrix.
type SupportedAPIHook struct {
	Category            string
	Module              string
	Function            string
	TargetIdentityParam string
	ReturnConvention    string
}

// SupportedWindowsAPIHooks parses WindowsSupportedAPIMatrix into structured entries.
func SupportedWindowsAPIHooks() []SupportedAPIHook {
	lines := strings.Split(strings.TrimSpace(WindowsSupportedAPIMatrix), "\n")
	if len(lines) <= 1 {
		return nil
	}
	hooks := make([]SupportedAPIHook, 0, len(lines)-1)
	for _, line := range lines[1:] {
		parts := strings.Split(line, "|")
		if len(parts) != 5 {
			continue
		}
		hooks = append(hooks, SupportedAPIHook{
			Category:            parts[0],
			Module:              parts[1],
			Function:            parts[2],
			TargetIdentityParam: parts[3],
			ReturnConvention:    parts[4],
		})
	}
	return hooks
}

// SupportedAPICategories returns the canonical list of supported Windows API trace categories.
func SupportedAPICategories() []string {
	return []string{
		CategoryMemory,
		CategoryProcess,
		CategoryRegistry,
		CategoryFile,
		CategoryCrypto,
		CategoryNetwork,
	}
}

// IsSupportedAPICategory reports whether category is supported by the Windows API tracer.
func IsSupportedAPICategory(category string) bool {
	trimmed := strings.TrimSpace(category)
	for _, c := range SupportedAPICategories() {
		if strings.EqualFold(c, trimmed) {
			return true
		}
	}
	return false
}

// IsSupportedAPIFunction reports whether fn is in the WindowsSupportedAPIMatrix.
func IsSupportedAPIFunction(fn string) bool {
	trimmed := strings.TrimSpace(fn)
	for _, h := range SupportedWindowsAPIHooks() {
		if strings.EqualFold(h.Function, trimmed) {
			return true
		}
	}
	return false
}

// NewAPITracer creates a new API tracer with the specified categories.
// An empty category list requests all categories when a backend is available.
func NewAPITracer(categories []string) APITracer {
	return newAPITracer(categories)
}

// APICallSequence represents a sequence of API calls for pattern matching
type APICallSequence struct {
	Calls     []APICall
	StartTime time.Time
	EndTime   time.Time
	ProcessID int
}

// DetectProcessInjection analyzes API call sequences to detect process injection patterns.
// Returns true if the sequence matches known injection techniques.
func DetectProcessInjection(calls []APICall) bool {
	// Look for VirtualAllocEx + WriteProcessMemory + CreateRemoteThread sequence
	hasVirtualAlloc := false
	hasWriteProcess := false
	hasCreateThread := false

	for _, call := range calls {
		switch call.Function {
		case "VirtualAllocEx", "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory":
			hasVirtualAlloc = true
		case "WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory":
			hasWriteProcess = true
		case "CreateRemoteThread", "CreateRemoteThreadEx", "CreateRemoteThreadW", "CreateRemoteThreadA",
			"NtCreateThreadEx", "ZwCreateThreadEx", "RtlCreateUserThread":
			hasCreateThread = true
		}
	}

	return hasVirtualAlloc && hasWriteProcess && hasCreateThread
}

// DetectProcessHollowing analyzes API call sequences to detect process hollowing patterns.
// Returns true if the sequence matches known hollowing techniques.
func DetectProcessHollowing(calls []APICall) bool {
	// Look for CreateProcess (suspended) + NtUnmapViewOfSection + WriteProcessMemory + ResumeThread
	hasCreateSuspended := false
	hasUnmap := false
	hasWriteProcess := false
	hasResume := false

	for _, call := range calls {
		switch call.Function {
		case "CreateProcessA", "CreateProcessW", "CreateProcessInternalW", "NtCreateUserProcess", "ZwCreateUserProcess":
			// Check if CREATE_SUSPENDED flag is present
			for _, param := range call.Parameters {
				if param.Name == "dwCreationFlags" && (param.Value == "CREATE_SUSPENDED" || strings.Contains(param.Value, "CREATE_SUSPENDED")) {
					hasCreateSuspended = true
				}
			}
		case "NtUnmapViewOfSection", "ZwUnmapViewOfSection":
			hasUnmap = true
		case "WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory":
			hasWriteProcess = true
		case "ResumeThread", "NtResumeThread", "ZwResumeThread":
			hasResume = true
		}
	}

	return hasCreateSuspended && hasUnmap && hasWriteProcess && hasResume
}
