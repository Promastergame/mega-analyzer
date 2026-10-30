//go:build windows

package main

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	adminAdvapi32            = syscall.NewLazyDLL("advapi32.dll")
	adminShell32             = syscall.NewLazyDLL("shell32.dll")
	adminOle32               = syscall.NewLazyDLL("ole32.dll")
	adminOpenProcessToken    = adminAdvapi32.NewProc("OpenProcessToken")
	adminGetTokenInformation = adminAdvapi32.NewProc("GetTokenInformation")
	adminShellExecuteExW     = adminShell32.NewProc("ShellExecuteExW")
	adminCoInitializeEx      = adminOle32.NewProc("CoInitializeEx")
	adminCoUninitialize      = adminOle32.NewProc("CoUninitialize")
)

func processIsElevated() (bool, error) {
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return false, err
	}
	var token syscall.Handle
	ok, _, e := adminOpenProcessToken.Call(uintptr(process), 0x0008, uintptr(unsafe.Pointer(&token))) // TOKEN_QUERY
	if ok == 0 {
		return false, fmt.Errorf("OpenProcessToken failed: %v", e)
	}
	defer syscall.CloseHandle(token)
	var elevation, returned uint32
	ok, _, e = adminGetTokenInformation.Call(uintptr(token), 20, uintptr(unsafe.Pointer(&elevation)), unsafe.Sizeof(elevation), uintptr(unsafe.Pointer(&returned))) // TokenElevation
	if ok == 0 {
		return false, fmt.Errorf("GetTokenInformation(TokenElevation) failed: %v", e)
	}
	return elevation != 0, nil
}

// Native SHELLEXECUTEINFOW, including pointer-sized union and handles.
type adminShellExecuteInfoW struct {
	Size       uint32
	Mask       uint32
	Window     uintptr
	Verb       *uint16
	File       *uint16
	Parameters *uint16
	Directory  *uint16
	Show       int32
	Instance   uintptr
	IDList     unsafe.Pointer
	Class      *uint16
	KeyClass   uintptr
	HotKey     uint32
	Icon       uintptr
	Process    syscall.Handle
}

func restartElevated(exe string, args []string, cwd string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hr, _, _ := adminCoInitializeEx.Call(0, 0x2|0x4) // STA; disable OLE1 DDE
	if int32(hr) < 0 && uint32(hr) != 0x80010106 {
		return fmt.Errorf("Windows shell initialization failed: HRESULT 0x%08x", uint32(hr))
	}
	if hr == 0 || hr == 1 {
		defer adminCoUninitialize.Call()
	}
	parameters, err := windowsAdminParameters(args)
	if err != nil {
		return err
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	params, err := syscall.UTF16PtrFromString(parameters)
	if err != nil {
		return err
	}
	directory, err := syscall.UTF16PtrFromString(cwd)
	if err != nil {
		return err
	}
	info := adminShellExecuteInfoW{Mask: 0x00000040 | 0x00000100, Verb: verb, File: file, Parameters: params, Directory: directory, Show: 1}
	info.Size = uint32(unsafe.Sizeof(info))
	ok, _, e := adminShellExecuteExW.Call(uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive(verb)
	runtime.KeepAlive(file)
	runtime.KeepAlive(params)
	runtime.KeepAlive(directory)
	if ok == 0 {
		if e == syscall.Errno(1223) {
			return fmt.Errorf("administrator launch cancelled in Windows UAC; no privileged web server was started")
		}
		return fmt.Errorf("Windows UAC administrator launch failed: %v", e)
	}
	if info.Process == 0 {
		return nil
	}
	defer syscall.CloseHandle(info.Process)
	// Keep go-run's temporary executable alive until the elevated child exits.
	if _, err := syscall.WaitForSingleObject(info.Process, 0xffffffff); err != nil {
		return err
	}
	var code uint32
	if err := syscall.GetExitCodeProcess(info.Process, &code); err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("elevated web server exited with code %d", code)
	}
	return nil
}
