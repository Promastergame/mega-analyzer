//go:build windows

package sandbox

import (
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
)

func verifyVMwareGuestHardware() error {
	subkey, _ := syscall.UTF16PtrFromString(`HARDWARE\DESCRIPTION\System\BIOS`)
	var key syscall.Handle
	err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, subkey, 0, syscall.KEY_QUERY_VALUE, &key)
	if err != nil {
		return fmt.Errorf("не удалось подтвердить оборудование гостя VMware: %w", err)
	}
	defer syscall.RegCloseKey(key)
	name, _ := syscall.UTF16PtrFromString("SystemManufacturer")
	var kind uint32
	var data [2048]byte
	size := uint32(len(data))
	err = syscall.RegQueryValueEx(key, name, nil, &kind, &data[0], &size)
	if err != nil || kind != syscall.REG_SZ || size > uint32(len(data)) || size%2 != 0 {
		return fmt.Errorf("не удалось прочитать производителя гостевой системы")
	}
	text := make([]uint16, size/2)
	for i := range text {
		text[i] = binary.LittleEndian.Uint16(data[2*i:])
	}
	if !strings.Contains(strings.ToLower(syscall.UTF16ToString(text)), "vmware") {
		return fmt.Errorf("гостевой сборщик работает только внутри VMware; запуск на основном ПК запрещён")
	}
	return nil
}
