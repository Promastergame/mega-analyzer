// Package vmware manages detected VMware guests, snapshots and analysis sessions.
// Sample execution is performed by the collector inside the selected guest.
package vmware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrBusy = errors.New("операция VMware уже выполняется; дождитесь завершения")
var managedName = regexp.MustCompile(`^mega-baseline-[0-9a-f]{24}$`)

// Runner executes the controller's fixed vmrun operations without a host shell.
type Runner func(context.Context, ...string) ([]byte, error)

func ExecRunner(tool string) Runner {
	return func(ctx context.Context, args ...string) ([]byte, error) {
		target := "ws"
		if runtime.GOOS == "darwin" {
			target = "fusion"
		}
		cmd := exec.CommandContext(ctx, tool, append([]string{"-T", target}, args...)...)
		out := &boundedOutput{}
		cmd.Stdout = out
		cmd.Stderr = out
		if err := cmd.Run(); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			message := strings.TrimSpace(string(out.Bytes()))
			for i, arg := range args {
				if arg == "-gp" && i+1 < len(args) && args[i+1] != "" {
					message = strings.ReplaceAll(message, args[i+1], "[redacted]")
				}
			}
			if len(message) > 512 {
				message = message[:512]
			}
			return nil, fmt.Errorf("vmrun: %w: %s", err, message)
		}
		if out.overflow {
			return nil, errors.New("ответ VMware превышает допустимый размер")
		}
		return out.Bytes(), nil
	}
}

type boundedOutput struct {
	data     []byte
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	left := (1 << 20) - len(b.data)
	if len(p) > left {
		b.overflow = true
		p = p[:left]
	}
	b.data = append(b.data, p...)
	return n, nil
}
func (b *boundedOutput) Bytes() []byte { return b.data }

type Check struct {
	Key     string `json:"key"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}
type Snapshot struct {
	Name       string `json:"name"`
	Restorable bool   `json:"restorable"`
}
type Report struct {
	Running           bool       `json:"running"`
	Suspended         bool       `json:"suspended"`
	Tools             string     `json:"tools"`
	Checks            []Check    `json:"checks"`
	Snapshots         []Snapshot `json:"snapshots"`
	ConfigurationPass bool       `json:"configurationPass"`
	GuestExecution    bool       `json:"guestExecution"`
	Notice            string     `json:"notice"`
	LastSnapshot      string     `json:"lastSnapshot,omitempty"`
}

type Controller struct {
	run      Runner
	stateDir string
	mu       sync.Mutex
}

func New(run Runner, stateDir string) *Controller { return &Controller{run: run, stateDir: stateDir} }

func (c *Controller) command(ctx context.Context, args ...string) ([]byte, error) {
	if c.run == nil {
		return nil, errors.New("vmrun не найден; установите компонент управления VMware")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	return c.run(ctx, args...)
}

func validateVMX(path string) (string, map[string]string, error) {
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".vmx") || strings.ContainsAny(path, "\x00\r\n") {
		return "", nil, errors.New("недопустимый путь конфигурации ВМ")
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", nil, err
	}
	f, err := os.Open(real)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 2<<20 {
		return "", nil, errors.New("недопустимый файл VMX")
	}
	data, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil {
		return "", nil, err
	}
	if len(data) > 2<<20 {
		return "", nil, errors.New("конфигурация VMX слишком велика")
	}
	props := map[string]string{}
	for _, line := range strings.Split(strings.TrimPrefix(string(data), "\ufeff"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return "", nil, errors.New("не удалось однозначно прочитать VMX")
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "" {
			return "", nil, errors.New("пустой параметр VMX")
		}
		if _, exists := props[key]; exists {
			return "", nil, errors.New("повторяющийся параметр VMX: " + key)
		}
		if strings.HasPrefix(value, `"`) {
			if len(value) < 2 || !strings.HasSuffix(value, `"`) {
				return "", nil, errors.New("неоднозначное значение VMX")
			}
			value = value[1 : len(value)-1]
		}
		props[key] = strings.ToLower(value)
	}
	version, err := strconv.Atoi(props["config.version"])
	if err != nil || version <= 0 {
		return "", nil, errors.New("не найдена версия конфигурации VMX")
	}
	return filepath.Clean(real), props, nil
}

func Audit(props map[string]string) []Check {
	var checks []Check
	add := func(k string, ok bool, msg string) { checks = append(checks, Check{k, ok, msg}) }
	netOK := true
	for key := range props {
		if !strings.HasPrefix(key, "ethernet") {
			continue
		}
		i := strings.IndexByte(key, '.')
		if i < 0 {
			continue
		}
		prefix := key[:i]
		present, exists := props[prefix+".present"]
		if exists && present == "false" {
			continue
		}
		if present != "true" || props[prefix+".startconnected"] != "false" {
			netOK = false
		}
	}
	add("network", netOK, "Сеть: все настроенные сетевые адаптеры должны быть отключены при включении ВМ.")
	sharedOK := props["isolation.tools.hgfs.disable"] == "true"
	for key, value := range props {
		if strings.HasPrefix(key, "sharedfolder") && strings.HasSuffix(key, ".enabled") && value != "false" {
			sharedOK = false
		}
	}
	add("folders", sharedOK, "Общие папки: требуется isolation.tools.hgfs.disable = TRUE; включённых общих папок быть не должно.")
	add("clipboard", props["isolation.tools.copy.disable"] == "true" && props["isolation.tools.paste.disable"] == "true", "Буфер обмена: копирование и вставка между хостом и гостем должны быть отключены.")
	add("dragdrop", props["isolation.tools.dnd.disable"] == "true", "Перетаскивание файлов: должно быть отключено.")
	usbOK := props["usb.present"] == "false" && props["ehci.present"] == "false" && props["usb_xhci.present"] == "false"
	for key := range props {
		if strings.HasPrefix(key, "usb.autoconnect.device") {
			usbOK = false
		}
	}
	add("usb", usbOK, "USB: контроллеры и правила автоматического подключения устройств должны быть отключены.")
	rawOK := true
	for key, value := range props {
		if strings.Contains(key, ".devicetype") && (strings.Contains(value, "raw") || strings.Contains(value, "physical")) {
			rawOK = false
		}
		if strings.HasSuffix(key, ".filename") && strings.Contains(value, "physicaldrive") {
			rawOK = false
		}
	}
	add("disks", false, "Проверьте диски вручную: анализ VMX не доказывает отсутствие доступа к физическим дискам через VMDK.")
	if !rawOK {
		checks[len(checks)-1].Message = "Обнаружена ссылка на физический диск: такой доступ необходимо убрать."
	}
	return checks
}

func (c *Controller) running(ctx context.Context, path string) (bool, error) {
	data, err := c.command(ctx, "list")
	if err != nil {
		return false, err
	}
	names, err := ParseSnapshots(data)
	if err != nil {
		return false, fmt.Errorf("не удалось проверить состояние питания: %w", err)
	}
	for _, line := range names {
		candidate := strings.Trim(strings.TrimSpace(line), `"`)
		if !filepath.IsAbs(candidate) || !strings.EqualFold(filepath.Ext(candidate), ".vmx") {
			return false, errors.New("недопустимый ответ списка запущенных ВМ")
		}
		real, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			return false, errors.New("не удалось проверить конфигурацию запущенной ВМ")
		}
		if filepath.Clean(real) == path || (runtime.GOOS == "windows" && strings.EqualFold(filepath.Clean(real), path)) {
			return true, nil
		}
	}

	return false, nil
}

// ParseSnapshots checks the count, but does not depend on the heading language.
func ParseSnapshots(data []byte) ([]string, error) {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		return nil, errors.New("пустой список снимков")
	}
	_, countText, ok := strings.Cut(strings.TrimSpace(lines[0]), ":")
	if !ok {
		return nil, errors.New("неизвестный формат списка снимков")
	}
	count, err := strconv.Atoi(strings.TrimSpace(countText))
	if err != nil || count < 0 || count > 10000 {
		return nil, errors.New("недопустимое количество снимков")
	}
	names := []string{}
	seen := map[string]bool{}
	for _, line := range lines[1:] {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		if seen[name] {
			return nil, errors.New("неоднозначные имена снимков")
		}
		seen[name] = true
		names = append(names, name)
	}
	if len(names) != count {
		return nil, errors.New("список снимков неполон; операция отменена")
	}
	return names, nil
}

func (c *Controller) snapshots(ctx context.Context, path string) ([]Snapshot, error) {
	data, err := c.command(ctx, "listSnapshots", path)
	if err != nil {
		return nil, err
	}
	names, err := ParseSnapshots(data)
	if err != nil {
		return nil, err
	}
	result := []Snapshot{}
	for _, name := range names {
		result = append(result, Snapshot{name, c.hasReceipt(path, name)})
	}
	return result, nil
}

func (c *Controller) inspect(ctx context.Context, path string) (Report, error) {
	path, props, err := validateVMX(path)
	if err != nil {
		return Report{}, err
	}
	running, err := c.running(ctx, path)
	if err != nil {
		return Report{}, err
	}
	snapshots, err := c.snapshots(ctx, path)
	if err != nil {
		return Report{}, err
	}
	checks := Audit(props)
	checks[len(checks)-1] = checkVirtualDisks(path, props)
	rep := Report{Running: running, Suspended: props["checkpoint.vmstate"] != "", Checks: checks, Snapshots: snapshots, Tools: "ВМ выключена", GuestExecution: strings.Contains(props["guestos"], "windows"), Notice: "Запуск анализа включит эту ВМ, проверит вход через VMware Tools и выполнит файл внутри гостевой Windows. Отчёт сохраняется на основном ПК."}
	// A live connection may differ from startConnected in the file. Do not
	// describe persisted settings as verification of runtime containment.
	if running {
		rep.Tools = "Не удалось проверить VMware Tools"
		if out, err := c.command(ctx, "checkToolsState", path); err == nil {
			switch strings.ToLower(strings.TrimSpace(string(out))) {
			case "running":
				rep.Tools = "VMware Tools работают"
			case "installed":
				rep.Tools = "VMware Tools установлены; гостевой вход проверяется перед запуском"
			case "unknown":
				rep.Tools = "Состояние VMware Tools неизвестно"
			}
		}
		rep.Notice = "Сохранённые настройки не подтверждают текущее подключение устройств. При запуске анализа гостевая Windows будет штатно выключена и включена заново. Для подготовки и операций со снимками выключите ВМ вручную."
	}
	if !running && rep.Suspended {
		rep.Tools = "ВМ приостановлена"
		rep.Notice = "В VMX найдено сохранённое состояние памяти. Штатно завершите работу гостевой ОС перед операциями со снимками."
	}
	rep.ConfigurationPass = true
	for _, ch := range rep.Checks {
		if !ch.OK {
			rep.ConfigurationPass = false
		}
	}
	return rep, nil
}

func (c *Controller) Inspect(ctx context.Context, path string) (Report, error) {
	if !c.mu.TryLock() {
		return Report{}, ErrBusy
	}
	defer c.mu.Unlock()
	return c.inspect(ctx, path)
}

func (c *Controller) requireOff(ctx context.Context, path string) (string, error) {
	real, props, err := validateVMX(path)
	if err != nil {
		return "", err
	}
	if props["checkpoint.vmstate"] != "" {
		return "", errors.New("ВМ приостановлена: требуется штатное завершение работы гостевой ОС")
	}
	running, err := c.running(ctx, real)
	if err != nil {
		return "", err
	}
	if running {
		return "", errors.New("сначала штатно выключите Windows внутри ВМ; принудительного выключения не будет")
	}
	return real, nil
}

func (c *Controller) CreateBaseline(ctx context.Context, path string) (Report, error) {
	if !c.mu.TryLock() {
		return Report{}, ErrBusy
	}
	defer c.mu.Unlock()
	real, err := c.requireOff(ctx, path)
	if err != nil {
		return Report{}, err
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return Report{}, err
	}
	name := "mega-baseline-" + hex.EncodeToString(random[:])
	// Validate the local receipt store before making an irreversible external call.
	if c.stateDir == "" {
		return Report{}, errors.New("каталог подтверждений снимков не настроен")
	}
	if err := os.MkdirAll(c.stateDir, 0700); err != nil {
		return Report{}, err
	}
	if _, err := c.command(ctx, "snapshot", real, name); err != nil {
		return Report{}, err
	}
	snapshots, err := c.snapshots(ctx, real)
	if err != nil {
		return Report{}, fmt.Errorf("проверьте снимки в VMware: %w", err)
	}
	found := false
	for _, s := range snapshots {
		if s.Name == name {
			found = true
		}
	}
	if !found {
		return Report{}, errors.New("VMware не подтвердила создание снимка")
	}
	// Recheck power state before recording a powered-off baseline. Never
	// operate this VM simultaneously from another VMware window/client.
	if _, err := c.requireOff(ctx, real); err != nil {
		return Report{}, fmt.Errorf("состояние ВМ изменилось во время создания снимка; подтверждение не сохранено: %w", err)
	}
	if err := c.saveReceipt(real, name); err != nil {
		return Report{}, fmt.Errorf("снимок создан, но подтверждение не сохранено: %w", err)
	}
	rep, err := c.inspect(ctx, real)
	rep.LastSnapshot = name
	return rep, err
}

func (c *Controller) RestoreBaseline(ctx context.Context, path, name, confirmation string) (Report, error) {
	if !c.mu.TryLock() {
		return Report{}, ErrBusy
	}
	defer c.mu.Unlock()
	if confirmation != name || !managedName.MatchString(name) {
		return Report{}, errors.New("для восстановления введите точное имя снимка")
	}
	real, err := c.requireOff(ctx, path)
	if err != nil {
		return Report{}, err
	}
	if !c.hasReceipt(real, name) {
		return Report{}, errors.New("нет подтверждения, что снимок создан этим инструментом при выключенной ВМ")
	}
	snapshots, err := c.snapshots(ctx, real)
	if err != nil {
		return Report{}, err
	}
	found := false
	for _, s := range snapshots {
		if s.Name == name {
			found = true
		}
	}
	if !found {
		return Report{}, errors.New("снимок больше не существует")
	}
	if _, err := c.command(ctx, "revertToSnapshot", real, name); err != nil {
		return Report{}, err
	}
	rep, err := c.inspect(ctx, real)
	if err != nil {
		return rep, err
	}
	if rep.Running || rep.Suspended {
		return rep, errors.New("после восстановления ВМ включена или приостановлена; состояние требует ручной проверки")
	}
	rep.LastSnapshot = name
	return rep, nil
}

type receipt struct {
	VMX        string `json:"vmx"`
	Snapshot   string `json:"snapshot"`
	PoweredOff bool   `json:"poweredOff"`
	Version    int    `json:"version"`
}

func (c *Controller) receiptPath(path, name string) string {
	sum := sha256.Sum256([]byte(path + "\x00" + name))
	return filepath.Join(c.stateDir, hex.EncodeToString(sum[:])+".json")
}
func (c *Controller) saveReceipt(path, name string) error {
	data, err := json.Marshal(receipt{path, name, true, 1})
	if err != nil {
		return err
	}
	// A unique snapshot gets a unique receipt; never overwrite another baseline.
	f, err := os.OpenFile(c.receiptPath(path, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		os.Remove(c.receiptPath(path, name))
		return writeErr
	}
	if closeErr != nil {
		os.Remove(c.receiptPath(path, name))
		return closeErr
	}
	return nil
}
func (c *Controller) hasReceipt(path, name string) bool {
	if c.stateDir == "" || !managedName.MatchString(name) {
		return false
	}
	f, err := os.Open(c.receiptPath(path, name))
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 4096 {
		return false
	}
	dec := json.NewDecoder(io.LimitReader(f, 4097))
	dec.DisallowUnknownFields()
	var record receipt
	if err := dec.Decode(&record); err != nil {
		return false
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return false
	}
	return record.Version == 1 && record.PoweredOff && record.VMX == path && record.Snapshot == name
}
