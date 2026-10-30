//go:build windows

package netproxy

import (
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

// RustMITMEngine manages the CGO/syscall bindings to the omnisec-mitm Rust DLL.
type RustMITMEngine struct {
	dll *syscall.LazyDLL

	initProc           *syscall.LazyProc
	startDnsSpoofProc  *syscall.LazyProc
	startDhcpSpoofProc *syscall.LazyProc
	startSslStripProc  *syscall.LazyProc
	startObfsProxyProc *syscall.LazyProc
	generateCaProc     *syscall.LazyProc
}

var engine *RustMITMEngine

// InitRustMITM loads the omnisec-mitm DLL and initializes its internal runtime.
func InitRustMITM(dllPath string) error {
	dllPath, _ = filepath.Abs(dllPath)
	dll := syscall.NewLazyDLL(dllPath)
	if err := dll.Load(); err != nil {
		return fmt.Errorf("load Rust MITM DLL %s: %w", dllPath, err)
	}

	engine = &RustMITMEngine{
		dll:                dll,
		initProc:           dll.NewProc("omnisec_mitm_init"),
		startDnsSpoofProc:  dll.NewProc("omnisec_mitm_start_dns_spoof"),
		startDhcpSpoofProc: dll.NewProc("omnisec_mitm_start_dhcp_spoof"),
		startSslStripProc:  dll.NewProc("omnisec_mitm_start_ssl_strip"),
		startObfsProxyProc: dll.NewProc("omnisec_mitm_start_obfs_proxy"),
		generateCaProc:     dll.NewProc("omnisec_mitm_generate_ca"),
	}

	for name, proc := range map[string]*syscall.LazyProc{
		"omnisec_mitm_init":             engine.initProc,
		"omnisec_mitm_start_dns_spoof":  engine.startDnsSpoofProc,
		"omnisec_mitm_start_dhcp_spoof": engine.startDhcpSpoofProc,
		"omnisec_mitm_start_ssl_strip":  engine.startSslStripProc,
		"omnisec_mitm_start_obfs_proxy": engine.startObfsProxyProc,
		"omnisec_mitm_generate_ca":      engine.generateCaProc,
	} {
		if err := proc.Find(); err != nil {
			return fmt.Errorf("missing Rust MITM export %s: %w", name, err)
		}
	}

	// Call init
	ret, _, err := engine.initProc.Call()
	if ret != 0 {
		return fmt.Errorf("omnisec_mitm_init failed: %v", err)
	}

	return nil
}

// GenerateRootCA calls the Rust DLL to generate a Root CA in the given directory.
func GenerateRootCA(outDir string) error {
	if engine == nil {
		return fmt.Errorf("Rust MITM Engine not initialized")
	}

	outDirPtr, err := syscall.BytePtrFromString(outDir)
	if err != nil {
		return err
	}

	ret, _, callErr := engine.generateCaProc.Call(uintptr(unsafe.Pointer(outDirPtr)))
	runtime.KeepAlive(outDirPtr)
	if int32(ret) != 0 {
		return fmt.Errorf("omnisec_mitm_generate_ca failed with code %d (err: %v)", int32(ret), callErr)
	}
	return nil
}

// StartDNSSpoof calls the Rust DLL to start DNS spoofing.
func StartDNSSpoof(listenAddr, targetDomain, spoofedIP string) error {
	if engine == nil {
		return fmt.Errorf("Rust MITM Engine not initialized")
	}

	addrPtr, err := syscall.BytePtrFromString(listenAddr)
	if err != nil {
		return err
	}
	domainPtr, err := syscall.BytePtrFromString(targetDomain)
	if err != nil {
		return err
	}
	ipPtr, err := syscall.BytePtrFromString(spoofedIP)
	if err != nil {
		return err
	}

	ret, _, _ := engine.startDnsSpoofProc.Call(
		uintptr(unsafe.Pointer(addrPtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(ipPtr)),
	)
	runtime.KeepAlive(addrPtr)
	runtime.KeepAlive(domainPtr)
	runtime.KeepAlive(ipPtr)

	if int32(ret) != 0 {
		return fmt.Errorf("omnisec_mitm_start_dns_spoof failed")
	}
	return nil
}

// StartDHCPSpoof calls the Rust DLL to start DHCP spoofing.
func StartDHCPSpoof(listenAddr, gatewayIP string) error {
	if engine == nil {
		return fmt.Errorf("Rust MITM Engine not initialized")
	}

	addrPtr, err := syscall.BytePtrFromString(listenAddr)
	if err != nil {
		return err
	}
	gatewayPtr, err := syscall.BytePtrFromString(gatewayIP)
	if err != nil {
		return err
	}

	ret, _, _ := engine.startDhcpSpoofProc.Call(
		uintptr(unsafe.Pointer(addrPtr)),
		uintptr(unsafe.Pointer(gatewayPtr)),
	)
	runtime.KeepAlive(addrPtr)
	runtime.KeepAlive(gatewayPtr)

	if int32(ret) != 0 {
		return fmt.Errorf("omnisec_mitm_start_dhcp_spoof failed")
	}
	return nil
}

// StartSSLStrip calls the Rust DLL to start the SSL stripping proxy.
func StartSSLStrip(listenAddr string) error {
	if engine == nil {
		return fmt.Errorf("Rust MITM Engine not initialized")
	}

	addrPtr, err := syscall.BytePtrFromString(listenAddr)
	if err != nil {
		return err
	}

	ret, _, _ := engine.startSslStripProc.Call(uintptr(unsafe.Pointer(addrPtr)))
	runtime.KeepAlive(addrPtr)

	if int32(ret) != 0 {
		return fmt.Errorf("omnisec_mitm_start_ssl_strip failed")
	}
	return nil
}

// StartObfsProxy calls the Rust DLL to start the obfuscated TCP proxy.
func StartObfsProxy(listenAddr, upstreamAddr string, key [32]byte) error {
	if engine == nil {
		return fmt.Errorf("Rust MITM Engine not initialized")
	}

	listenPtr, err := syscall.BytePtrFromString(listenAddr)
	if err != nil {
		return err
	}
	upstreamPtr, err := syscall.BytePtrFromString(upstreamAddr)
	if err != nil {
		return err
	}

	ret, _, _ := engine.startObfsProxyProc.Call(
		uintptr(unsafe.Pointer(listenPtr)),
		uintptr(unsafe.Pointer(upstreamPtr)),
		uintptr(unsafe.Pointer(&key[0])),
	)
	runtime.KeepAlive(listenPtr)
	runtime.KeepAlive(upstreamPtr)
	runtime.KeepAlive(&key)

	if int32(ret) != 0 {
		return fmt.Errorf("omnisec_mitm_start_obfs_proxy failed")
	}
	return nil
}
