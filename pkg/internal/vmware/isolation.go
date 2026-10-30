package vmware

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var diskSetting = regexp.MustCompile(`^(?:scsi|sata|ide|nvme)[0-9]+:[0-9]+\.filename$`)
var diskExtent = regexp.MustCompile(`(?i)^(RW|RDONLY|NOACCESS)\s+[0-9]+\s+([A-Z]+)(?:\s+"([^"]+)")?(?:\s+[0-9]+)?\s*$`)

// Prepare changes only a powered-off VM and keeps a byte-for-byte VMX backup.
// Networking is disabled at the virtual hardware boundary, including children.
func (c *Controller) Prepare(ctx context.Context, path string) (Report, error) {
	if !c.mu.TryLock() {
		return Report{}, ErrBusy
	}
	defer c.mu.Unlock()
	real, err := c.requireOff(ctx, path)
	if err != nil {
		return Report{}, err
	}
	_, props, err := validateVMX(real)
	if err != nil {
		return Report{}, err
	}
	if !strings.Contains(props["guestos"], "windows") {
		return Report{}, errors.New("для исполнения поддерживается гостевая Windows")
	}
	if disk := checkVirtualDisks(real, props); !disk.OK {
		return Report{}, errors.New(disk.Message)
	}
	original, err := os.ReadFile(real)
	if err != nil {
		return Report{}, err
	}
	settings := map[string]string{
		"isolation.tools.hgfs.disable": "TRUE", "isolation.tools.copy.disable": "TRUE",
		"isolation.tools.paste.disable": "TRUE", "isolation.tools.dnd.disable": "TRUE",
		"usb.present": "FALSE", "ehci.present": "FALSE", "usb_xhci.present": "FALSE",
	}
	for key := range props {
		if strings.HasPrefix(key, "ethernet") {
			if i := strings.IndexByte(key, '.'); i > 0 {
				settings[key[:i]+".present"] = "FALSE"
				settings[key[:i]+".startconnected"] = "FALSE"
			}
		}
		if strings.HasPrefix(key, "sharedfolder") && strings.HasSuffix(key, ".enabled") {
			settings[key] = "FALSE"
		}
	}
	var lines []string
	for _, line := range strings.Split(string(original), "\n") {
		key, _, found := strings.Cut(strings.TrimPrefix(strings.TrimSpace(line), "\ufeff"), "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if found && strings.HasPrefix(key, "usb.autoconnect.device") {
			continue
		}
		if value, ok := settings[key]; found && ok {
			line = key + ` = "` + value + `"`
			delete(settings, key)
		}
		lines = append(lines, strings.TrimSuffix(line, "\r"))
	}
	var keys []string
	for key := range settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		lines = append(lines, key+` = "`+settings[key]+`"`)
	}
	updated := []byte(strings.TrimRight(strings.Join(lines, "\r\n"), "\r\n") + "\r\n")
	var token [12]byte
	if _, err := rand.Read(token[:]); err != nil {
		return Report{}, err
	}
	backup := real + ".mega-backup-" + hex.EncodeToString(token[:])
	if err := os.WriteFile(backup, original, 0600); err != nil {
		return Report{}, fmt.Errorf("резервная копия VMX: %w", err)
	}
	staged := backup + ".tmp"
	if err := os.WriteFile(staged, updated, 0600); err != nil {
		return Report{}, err
	}
	defer os.Remove(staged)
	if _, err := c.requireOff(ctx, real); err != nil {
		return Report{}, err
	}
	current, err := os.ReadFile(real)
	if err != nil || !bytes.Equal(current, original) {
		return Report{}, errors.New("настройки ВМ изменились во время подготовки; повторите проверку")
	}
	if err := os.Rename(staged, real); err != nil {
		return Report{}, fmt.Errorf("сохранить настройки выключенной ВМ: %w", err)
	}
	report, err := c.inspect(ctx, real)
	report.Notice = "ВМ подготовлена: виртуальные сетевые адаптеры, общие папки, буфер обмена, drag-and-drop и USB отключены. Резервная копия VMX: " + filepath.Base(backup)
	return report, err
}

func checkVirtualDisks(vmx string, props map[string]string) Check {
	result := Check{Key: "disks"}
	count := 0
	for key, name := range props {
		if !diskSetting.MatchString(key) {
			continue
		}
		prefix := strings.TrimSuffix(key, "filename")
		if device := props[prefix+"devicetype"]; strings.Contains(device, "raw") || strings.Contains(device, "physical") {
			result.Message = "Диски: прямой доступ к физическому диску должен быть отключён."
			return result
		}
		if props[prefix+"present"] == "false" || strings.Contains(props[prefix+"devicetype"], "cdrom") {
			continue
		}
		if !strings.EqualFold(filepath.Ext(name), ".vmdk") {
			result.Message = "Диски: обнаружен диск без поддерживаемого дескриптора VMDK."
			return result
		}
		if err := inspectVMDK(filepath.Dir(vmx), name, map[string]bool{}); err != nil {
			result.Message = "Диски: " + err.Error()
			return result
		}
		count++
	}
	if count == 0 {
		result.Message = "Диски: не найдены доступные виртуальные диски VMDK."
		return result
	}
	result.OK = true
	result.Message = "Диски: дескрипторы VMDK и цепочки снимков ссылаются на обычные локальные файлы; прямых физических дисков нет."
	return result
}

func localDiskPath(dir, name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "\x00\r\n") || strings.HasPrefix(name, `\\`) || strings.HasPrefix(name, "//") || strings.Contains(strings.ToLower(name), "physicaldrive") {
		return "", errors.New("ссылка на внешний или физический диск не поддерживается")
	}
	path := name
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, path)
	}
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("файл виртуального диска недоступен: %w", err)
	}
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//") {
		return "", errors.New("диск должен находиться на локальном файловом томе")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("виртуальный диск должен быть обычным файлом")
	}
	return path, nil
}

func inspectVMDK(dir, name string, seen map[string]bool) error {
	path, err := localDiskPath(dir, name)
	if err != nil {
		return err
	}
	if seen[path] || len(seen) >= 32 {
		return errors.New("неоднозначная или слишком длинная цепочка снимков VMDK")
	}
	seen[path] = true
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	header := make([]byte, 512)
	n, readErr := f.ReadAt(header, 0)
	if readErr != nil && readErr != io.EOF {
		return readErr
	}
	var descriptor []byte
	if n >= 44 && string(header[:4]) == "KDMV" {
		offset := binary.LittleEndian.Uint64(header[28:36])
		sectors := binary.LittleEndian.Uint64(header[36:44])
		info, err := f.Stat()
		if err != nil || offset < 1 || sectors < 1 || sectors > 2048 || offset > uint64(info.Size())/512 || sectors*512 > uint64(info.Size())-offset*512 {
			return errors.New("недопустимое расположение дескриптора VMDK")
		}
		descriptor = make([]byte, sectors*512)
		if _, err := f.ReadAt(descriptor, int64(offset*512)); err != nil {
			return err
		}
	} else {
		descriptor, err = io.ReadAll(io.LimitReader(f, (1<<20)+1))
		if err != nil || len(descriptor) > 1<<20 {
			return errors.New("не удалось прочитать текстовый дескриптор VMDK")
		}
	}
	text := strings.TrimRight(string(descriptor), "\x00")
	if !strings.HasPrefix(strings.TrimSpace(text), "# Disk DescriptorFile") {
		return errors.New("формат дескриптора VMDK не распознан")
	}
	extents, diskType, parent := 0, "", ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if key, value, ok := strings.Cut(line, "="); ok {
			value = strings.Trim(strings.TrimSpace(value), `"`)
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "createtype":
				diskType = strings.ToLower(value)
			case "parentfilenamehint":
				parent = value
			}
			continue
		}
		m := diskExtent.FindStringSubmatch(line)
		if m == nil {
			return errors.New("неоднозначная запись экстента VMDK")
		}
		switch strings.ToUpper(m[2]) {
		case "ZERO":
		case "SPARSE", "FLAT", "VMFS", "VMFSSPARSE", "SESPARSE":
			if _, err := localDiskPath(filepath.Dir(path), m[3]); err != nil {
				return err
			}
		default:
			return errors.New("физический или неподдерживаемый тип экстента VMDK")
		}
		extents++
	}
	switch diskType {
	case "monolithicsparse", "monolithicflat", "twogbmaxextentsparse", "twogbmaxextentflat", "vmfs", "vmfssparse", "sesparse", "streamoptimized":
	default:
		return errors.New("физический или неподдерживаемый тип диска VMDK")
	}
	if extents == 0 {
		return errors.New("в дескрипторе VMDK нет экстентов")
	}
	if parent != "" {
		return inspectVMDK(filepath.Dir(path), parent, seen)
	}
	return nil
}
