package vmware

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/sandbox"
)

type ExecutionRequest struct {
	VMX           string
	Name          string
	Username      string `json:"-"`
	Password      string `json:"-"`
	CollectorPath string
	SamplePath    string
	OutputDir     string
	Duration      time.Duration
	MemoryMB      int
	CPUCores      int
	Interactive   bool
	Args          string
	ConsoleReady  func(*Console) `json:"-"`
}

func ValidateCredentials(username, password string) error {
	if strings.TrimSpace(username) == "" || len(username) > 256 || strings.ContainsAny(username, "\x00\r\n") {
		return errors.New("укажите корректное имя пользователя гостевой Windows")
	}
	if password == "" {
		return errors.New("VMware не принимает пустой пароль гостевой Windows. Введите пароль выбранной учётной записи или загрузите логин и пароль из файла")
	}
	if len(password) > 1024 || strings.ContainsAny(password, "\x00\r\n") {
		return errors.New("недопустимый пароль гостевой Windows")
	}
	return nil
}

// RunSession never starts the sample with a host process API. Only vmrun is
// executed locally; the exact host-owned collector and upload go into the VM.
func (c *Controller) RunSession(ctx context.Context, req ExecutionRequest, emit func(Event)) (report *sandbox.Report, runErr error) {
	if !c.mu.TryLock() {
		return nil, ErrBusy
	}
	defer c.mu.Unlock()
	if emit == nil {
		emit = func(Event) {}
	}
	if err := ValidateCredentials(req.Username, req.Password); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := validateExecutionVMX(req.VMX)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(req.SamplePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 512<<20 {
		return nil, errors.New("образец должен быть обычным файлом не более 512 МиБ")
	}
	collector, err := os.Open(req.CollectorPath)
	if err != nil {
		return nil, fmt.Errorf("гостевой сборщик недоступен: %w", err)
	}
	var magic [2]byte
	_, err = collector.Read(magic[:])
	collector.Close()
	if err != nil || string(magic[:]) != "MZ" {
		return nil, errors.New("для гостевой Windows требуется Windows-сборка analyzer.exe")
	}
	sha, err := fileSHA256(req.SamplePath)
	if err != nil {
		return nil, err
	}
	var token [12]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(token[:])
	guest := GuestRequest{Version: 1, ID: id, Extension: strings.ToLower(filepath.Ext(req.SamplePath)), SampleName: filepath.Base(req.SamplePath), SHA256: sha, DurationSeconds: int64(req.Duration / time.Second), MemoryMB: req.MemoryMB, CPUCores: req.CPUCores, Args: req.Args}
	if req.Duration < 0 {
		return nil, errors.New("длительность не может быть отрицательной")
	}
	if err := guest.validate(); err != nil {
		return nil, err
	}
	output, err := filepath.Abs(req.OutputDir)
	if err != nil {
		return nil, err
	}
	sessionID := "vmware-" + time.Now().UTC().Format("20060102-150405") + "-" + id
	hostDir := filepath.Join(output, "sandbox", sessionID)
	if err := os.MkdirAll(hostDir, 0700); err != nil {
		return nil, err
	}
	transferDir, err := os.MkdirTemp(hostDir, ".transfer-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(transferDir)
	guestDir := `C:\Users\Public\mega-session-` + id
	guestPath := func(name string) string { return guestDir + `\` + name }
	report = &sandbox.Report{
		SessionID: sessionID, InputType: "windows-executable", TargetOriginal: req.SamplePath,
		TargetCopied: guestPath(strings.ReplaceAll(guest.sampleRelativePath(), "/", `\`)), OutputRoot: output, SessionDir: hostDir,
		JSONPath: filepath.Join(hostDir, "sandbox_report.json"), MarkdownPath: filepath.Join(hostDir, "sandbox_report.md"),
		StartedAt: time.Now().UTC(), SHA256: sha, NetworkMode: "not_applied",
		VMware: &sandbox.VMwareSessionInfo{Name: req.Name, GuestSessionDir: guestDir, Transport: "VMware Tools", Incomplete: true},
	}
	if err := sandbox.PersistReport(report); err != nil {
		return report, err
	}
	emit(Event{Type: "report", Details: sessionID, SHA256: sha})
	emit(Event{Type: "metadata", Process: filepath.Base(req.SamplePath), SHA256: sha})
	guestCommand := func(commandCtx context.Context, command string, args ...string) ([]byte, error) {
		fixed := []string{"-gu", req.Username, "-gp", req.Password, command, path}
		return c.command(commandCtx, append(fixed, args...)...)
	}
	copyTo := func(copyCtx context.Context, local, remote string) error {
		_, err := guestCommand(copyCtx, "CopyFileFromHostToGuest", local, remote)
		return err
	}
	copyFrom := func(copyCtx context.Context, name string, limit int64) ([]byte, error) {
		local := filepath.Join(transferDir, name)
		return downloadGuestFile(copyCtx, local, limit, func(downloadCtx context.Context) error {
			_, err := guestCommand(downloadCtx, "CopyFileFromGuestToHost", guestPath(name), local)
			return err
		})
	}
	var heartbeat uint64
	control := func(controlCtx context.Context, stop bool) error {
		heartbeat++
		value := fmt.Sprintf("%s|%d", id, heartbeat)
		if stop {
			value = id + "|stop"
		}
		local := filepath.Join(transferDir, "control.txt")
		if err := os.WriteFile(local, []byte(value), 0600); err != nil {
			return err
		}
		return copyTo(controlCtx, local, guestPath("control.txt"))
	}
	started, launched, finished := false, false, false
	var console *Console
	collected, guestFailed := false, false
	var seq uint64
	journal, err := os.OpenFile(filepath.Join(hostDir, "events.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return report, err
	}
	defer journal.Close()
	live, err := newLiveReport(report)
	if err != nil {
		return report, err
	}
	defer live.Close()
	drain := func(drainCtx context.Context) error {
		data, err := copyFrom(drainCtx, "events.jsonl", guestEventLimit)
		if err != nil {
			return err
		}
		err = consumeGuestEvents(data, id, &seq, func(record guestEvent, line []byte) error {
			if _, err := journal.Write(append(line, '\n')); err != nil {
				return err
			}
			if err := journal.Sync(); err != nil {
				return err
			}
			if err := live.Observe(record.Event); err != nil {
				return err
			}
			emit(record.Event)
			return nil
		})
		return errors.Join(err, live.Flush())
	}
	collectResult := func(resultCtx context.Context) error {
		data, err := copyFrom(resultCtx, "result.json", guestReportLimit)
		if err != nil {
			return err
		}
		var result guestResult
		if err := decodeJSON(data, &result); err != nil || result.ID != id {
			return errors.New("недопустимый отчёт гостевой сессии")
		}
		if result.Report != nil {
			if result.Report.SHA256 != "" && result.Report.SHA256 != sha {
				return errors.New("отчёт относится к другому образцу")
			}
			guestReport := result.Report
			// Guest paths are data, never destinations for host writes/downloads.
			guestReport.SessionID, guestReport.OutputRoot, guestReport.SessionDir = sessionID, output, hostDir
			guestReport.JSONPath, guestReport.MarkdownPath = report.JSONPath, report.MarkdownPath
			guestReport.TargetOriginal, guestReport.SHA256, guestReport.VMware = req.SamplePath, sha, report.VMware
			guestReport.TargetCopied = report.TargetCopied
			guestReport.StdoutPath, guestReport.StderrPath, guestReport.ActivityPath = "", "", report.ActivityPath
			// The live journal is already durable on the host, even if a final
			// artifact transfer fails after the report arrives.
			if guestReport.ActivityCount < report.ActivityCount {
				guestReport.ActivityCount = report.ActivityCount
			}
			if guestReport.EffectiveConfig != nil {
				guestReport.EffectiveConfig.OutputDir = output
			}
			report = guestReport
		}
		for _, artifact := range []struct {
			name string
			path *string
		}{{"stdout.log", &report.StdoutPath}, {"stderr.log", &report.StderrPath}, {"activity.jsonl", &report.ActivityPath}} {
			if data, err := copyFrom(resultCtx, artifact.name, guestEventLimit); err == nil {
				local := filepath.Join(hostDir, artifact.name)
				if err := os.WriteFile(local, data, 0600); err == nil {
					*artifact.path = local
				}
			}
		}
		if result.Error != "" {
			guestFailed = true
			return errors.New(result.Error)
		}
		if result.Report == nil {
			return errors.New("гостевой сборщик не вернул отчёт")
		}
		collected = true
		return nil
	}
	defer func() {
		if console != nil {
			console.close()
		}
		// Stop uses its own context after a user cancellation. The guest also
		// has a lease, so loss of this host process cannot leave an endless run.
		cleanup, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		guestOff := false
		if started {
			active, err := c.running(cleanup, path)
			guestOff = err == nil && !active
		}
		if launched && !finished && guestOff && !errors.Is(runErr, context.Canceled) {
			runErr = &sandbox.ExecutionError{Code: "guest_powered_off", Stage: "observation", Cause: errors.New("Гостевая Windows выключилась до завершения сбора. Полученные события сохранены на основном ПК; итоговый отчёт неполный.")}
		}
		if launched && !finished && !guestOff {
			emit(Event{Type: "status", Stage: "stopping", Details: "Останавливаю гостевой процесс и забираю доступный отчёт"})
			_ = control(cleanup, true)
			deadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) && cleanup.Err() == nil {
				data, err := copyFrom(cleanup, "state.json", 16<<10)
				var state guestState
				if err == nil && decodeJSON(data, &state) == nil && state.ID == id && state.Done {
					_ = drain(cleanup)
					if err := collectResult(cleanup); err != nil {
						report.Warnings = append(report.Warnings, err.Error())
					}
					finished = true
					break
				}
				if sleepContext(cleanup, time.Second) != nil {
					break
				}
			}
		}
		if started && !guestOff {
			emit(Event{Type: "status", Details: "Завершаю работу гостевой Windows"})
			_, stopErr := c.command(cleanup, "stop", path, "soft")
			active, stateErr := c.running(cleanup, path)
			for stateErr == nil && active && cleanup.Err() == nil {
				if err := sleepContext(cleanup, time.Second); err != nil {
					break
				}
				active, stateErr = c.running(cleanup, path)
			}
			report.VMware.PoweredOff = stateErr == nil && !active
			if !report.VMware.PoweredOff {
				report.Warnings = append(report.Warnings, "Не удалось подтвердить выключение ВМ; проверьте её состояние в VMware.")
				runErr = errors.Join(runErr, stopErr, stateErr, errors.New("выключение гостевой Windows не подтверждено"))
			}
		}
		if guestOff {
			report.VMware.PoweredOff = true
		}
		if console != nil {
			restoreCtx, cancelRestore := context.WithTimeout(context.Background(), 15*time.Second)
			if err := c.restoreConsole(restoreCtx, console); err != nil {
				report.Warnings = append(report.Warnings, err.Error())
			}
			cancelRestore()
		}
		report.VMware.Incomplete = !finished || !collected || guestFailed || (started && !report.VMware.PoweredOff) || (runErr != nil && !errors.Is(runErr, context.Canceled))
		if report.VMware.Incomplete {
			report.CompletionReason = "interrupted"
			report.Warnings = append(report.Warnings, "Неполный сбор: сохранены только события, полученные до потери связи или остановки сборщика. Отсутствие обнаружений не означает безопасность образца.")
		} else if errors.Is(runErr, context.Canceled) {
			report.CompletionReason = "stopped"
		}
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			report.ExecutionError = sandbox.DescribeFailure(runErr)
			if !report.Executed {
				report.ExecutionSkipReason = runErr.Error()
			}
		}
		if report.FinishedAt.IsZero() {
			report.FinishedAt = time.Now().UTC()
			report.DurationMS = report.FinishedAt.Sub(report.StartedAt).Milliseconds()
		}
		runErr = errors.Join(runErr, sandbox.PersistReport(report))
		emit(Event{Type: "report", Details: sessionID, SHA256: sha, CompletionReason: report.CompletionReason})
	}()
	if err := c.powerOffForSession(ctx, path, req.Username, req.Password, emit); err != nil {
		return report, err
	}
	// VMware may rewrite the VMX during shutdown. Recheck the powered-off
	// configuration before booting so its saved device settings take effect.
	if _, err := c.requireOff(ctx, path); err != nil {
		return report, err
	}
	if _, err := validateExecutionVMX(path); err != nil {
		return report, err
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if req.ConsoleReady != nil {
		console, err = c.prepareConsole(ctx, path)
		if err != nil {
			return report, fmt.Errorf("подключить живую консоль VMware: %w", err)
		}
		req.ConsoleReady(console)
		// Release the reserved loopback port immediately before VMware binds it.
		console.reservation.Close()
	}
	setup, cancelSetup := context.WithTimeout(ctx, 3*time.Minute)
	defer cancelSetup()
	emit(Event{Type: "status", Details: "Включаю выбранную VMware и ожидаю VMware Tools"})
	if _, err := c.command(setup, "start", path, "nogui"); err != nil {
		return report, fmt.Errorf("включить ВМ: %w", err)
	}
	started = true
	var readinessErr error
	for {
		tools, err := c.command(setup, "checkToolsState", path)
		state := strings.ToLower(strings.TrimSpace(string(tools)))
		// Workstation reports "installed" even with a live Tools service.
		// Only a successful guest operation confirms both readiness and login.
		if err == nil && (state == "running" || state == "installed") {
			_, readinessErr = guestCommand(setup, "listProcessesInGuest")
			if readinessErr == nil {
				emit(Event{Type: "status", Details: "Вход в гостевую Windows выполнен: " + req.Username})
				break
			}
			if !guestToolsStarting(readinessErr) {
				if strings.Contains(strings.ToLower(readinessErr.Error()), "empty passwords") {
					return report, fmt.Errorf("VMware не разрешает вход с пустым паролем. Укажите отдельную гостевую учётную запись с паролем: %w", readinessErr)
				}
				return report, fmt.Errorf("вход в гостевую Windows под пользователем %q не выполнен: %w. Имя и пароль должны относиться к одной гостевой учётной записи; используйте пароль Windows, не PIN-код", req.Username, readinessErr)
			}
		} else if err != nil {
			readinessErr = err
		}
		if err := sleepContext(setup, 2*time.Second); err != nil {
			if ctx.Err() != nil {
				return report, ctx.Err()
			}
			return report, fmt.Errorf("VMware Tools не готовы к гостевым операциям; проверьте службу Tools в гостевой Windows: %w", errors.Join(err, readinessErr))
		}
	}
	if _, err := guestCommand(setup, "createDirectoryInGuest", guestDir); err != nil {
		return report, fmt.Errorf("создать каталог гостевой сессии: %w", err)
	}
	if _, err := guestCommand(setup, "createDirectoryInGuest", guestPath("input")); err != nil {
		return report, fmt.Errorf("создать каталог образца: %w", err)
	}
	requestPath := filepath.Join(transferDir, "request.json")
	if err := atomicJSON(requestPath, guest, 16<<10); err != nil {
		return report, err
	}
	emit(Event{Type: "status", Details: "Передаю сборщик и образец через VMware Tools"})
	for _, item := range []struct{ local, remote string }{{req.CollectorPath, "collector.exe"}, {requestPath, "request.json"}, {req.SamplePath, strings.ReplaceAll(guest.sampleRelativePath(), "/", `\`)}} {
		if err := copyTo(setup, item.local, guestPath(item.remote)); err != nil {
			return report, fmt.Errorf("передача %s в гостя: %w", item.remote, err)
		}
	}
	if err := control(setup, false); err != nil {
		return report, err
	}
	// Interactive mode is explicit; never silently fall back to a hidden session
	// or execution on the host. VMware requires the same user to be logged in.
	launchArgs := []string{"-noWait"}
	if req.Interactive {
		launchArgs = append(launchArgs, "-interactive")
		emit(Event{Type: "status", Details: "Ожидаю входа на рабочий стол гостевой Windows (до 90 секунд). Откройте Screen и войдите под выбранной учётной записью"})
		desktopCtx, cancelDesktop := context.WithTimeout(setup, 90*time.Second)
		var userMismatchNotified bool
		desktopErr := waitForGuestDesktop(desktopCtx, func(probeCtx context.Context) error {
			// Harmless fixed command, only in the guest. Never probe with the
			// sample or retry a possibly started collector.
			_, err := guestCommand(probeCtx, "runProgramInGuest", "-noWait", "-interactive", `C:\Windows\System32\cmd.exe`, "/c", "exit", "0")
			if err != nil {
				msg := err.Error()
				if strings.Contains(strings.ToLower(msg), "does not match the user currently logged in") && !userMismatchNotified {
					userMismatchNotified = true
					emit(Event{Type: "status", Details: fmt.Sprintf("Внимание: на экране Windows выполнен вход под другим пользователем (не %q). Войдите на экране под %q", req.Username, req.Username)})
				}
			}
			return err
		}, 2*time.Second)
		cancelDesktop()
		if desktopErr != nil {
			return report, fmt.Errorf("рабочий стол гостевой Windows не готов; образец не запущен: %w", desktopErr)
		}
	}
	launchArgs = append(launchArgs, guestPath("collector.exe"), "--vmware-guest-session", guestDir)
	if _, err := guestCommand(setup, "runProgramInGuest", launchArgs...); err != nil {
		if req.Interactive {
			return report, fmt.Errorf("видимый запуск не удался: войдите в гостевую Windows под выбранной учётной записью; автоматического фонового запуска нет: %w", err)
		}
		return report, fmt.Errorf("запустить гостевой сборщик: %w", err)
	}
	launched = true
	cancelSetup()
	lastState := time.Now()
	for {
		if err := control(ctx, false); err != nil {
			return report, fmt.Errorf("связь с гостем: %w", err)
		}
		data, err := copyFrom(ctx, "state.json", 16<<10)
		if err == nil {
			var state guestState
			if err := decodeJSON(data, &state); err != nil || state.Version != 1 || state.ID != id || state.PID <= 0 {
				return report, errors.New("гостевой сборщик вернул некорректное состояние")
			}
			lastState = time.Now()
			if err := drain(ctx); err != nil {
				return report, fmt.Errorf("журнал гостя: %w", err)
			}
			if state.Done {
				finished = true
				if err := collectResult(ctx); err != nil {
					return report, err
				}
				if state.Truncated {
					report.Warnings = append(report.Warnings, "Поток событий достиг лимита 8 МиБ; отчёт содержит итог наблюдения.")
				}
				return report, nil
			}
		} else if time.Since(lastState) > 30*time.Second {
			return report, fmt.Errorf("состояние гостевого сборщика недоступно: %w", err)
		}
		if err := sleepContext(ctx, 2*time.Second); err != nil {
			return report, err
		}
	}
}

func validateExecutionVMX(path string) (string, error) {
	path, props, err := validateVMX(path)
	if err != nil {
		return "", err
	}
	if props["checkpoint.vmstate"] != "" {
		return "", errors.New("ВМ приостановлена: требуется штатное завершение работы гостевой ОС")
	}
	if !strings.Contains(props["guestos"], "windows") {
		return "", errors.New("выбранная ВМ не является поддерживаемой гостевой Windows")
	}
	checks := Audit(props)
	checks[len(checks)-1] = checkVirtualDisks(path, props)
	for _, check := range checks {
		if !check.OK {
			return "", fmt.Errorf("сначала подготовьте выключенную ВМ: %s", check.Message)
		}
	}
	return path, nil
}

func (c *Controller) powerOffForSession(ctx context.Context, path, username, password string, emit func(Event)) error {
	shutdown, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	active, err := c.running(shutdown, path)
	if err != nil || !active {
		return err
	}
	// Reject a bad guest login before changing the power state of a running VM.
	if _, err := c.command(shutdown, "-gu", username, "-gp", password, "listProcessesInGuest", path); err != nil {
		return fmt.Errorf("проверьте VMware Tools и вход под пользователем %q; перезапуск ВМ не начат: %w", username, err)
	}
	emit(Event{Type: "status", Details: "Штатно выключаю гостевую Windows перед новой сессией"})
	if _, err := c.command(shutdown, "stop", path, "soft"); err != nil {
		return fmt.Errorf("не удалось штатно выключить гостевую Windows; проверьте ВМ в VMware: %w", err)
	}
	for {
		active, err = c.running(shutdown, path)
		if err != nil {
			return fmt.Errorf("выключение ВМ перед запуском не подтверждено: %w", err)
		}
		if !active {
			return nil
		}
		if err := sleepContext(shutdown, time.Second); err != nil {
			return fmt.Errorf("гостевая Windows не завершила работу; запуск отменён: %w", err)
		}
	}
}

func guestToolsStarting(err error) bool {
	message := strings.ToLower(err.Error())
	for _, transient := range []string{"tools are not running", "guest operating system is not running", "guest operations agent could not be contacted", "guest agent could not be contacted"} {
		if strings.Contains(message, transient) {
			return true
		}
	}
	return false
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func downloadGuestFile(ctx context.Context, destination string, limit int64, download func(context.Context) error) ([]byte, error) {
	// The guest controls file contents, not the host destination. Cancel a
	// growing transfer instead of waiting for an arbitrarily large guest file.
	if err := os.Remove(destination); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	downloadCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-downloadCtx.Done():
				return
			case <-ticker.C:
				if info, err := os.Stat(destination); err == nil && info.Size() > limit {
					cancel()
					return
				}
			}
		}
	}()
	if err := download(downloadCtx); err != nil {
		return nil, err
	}
	return readBounded(destination, limit)
}

func consumeGuestEvents(data []byte, id string, seq *uint64, consume func(guestEvent, []byte) error) error {
	for _, line := range bytes.SplitAfter(data, []byte{'\n'}) {
		// A copy racing the guest append may end at an incomplete last line.
		if len(line) == 0 || line[len(line)-1] != '\n' {
			continue
		}
		line = bytes.TrimSuffix(line, []byte{'\n'})
		if len(line) > 64<<10 {
			return errors.New("событие гостя превышает лимит")
		}
		var record guestEvent
		if err := decodeJSON(line, &record); err != nil || record.ID != id || record.Seq == 0 {
			return errors.New("недопустимое событие гостевой сессии")
		}
		if record.Seq <= *seq {
			continue
		}
		if record.Seq != *seq+1 {
			return errors.New("потеряна последовательность событий гостя")
		}
		switch record.Event.Type {
		case "status", "process", "network", "activity", "log":
		default:
			return errors.New("неподдерживаемый тип события гостя")
		}
		if err := consume(record, line); err != nil {
			return err
		}
		*seq = record.Seq
	}
	return nil
}

// waitForGuestDesktop retries only a harmless guest probe, never sample launch.
func waitForGuestDesktop(ctx context.Context, probe func(context.Context) error, interval time.Duration) error {
	var last error
	for {
		if err := ctx.Err(); err != nil { return errors.Join(err, last) }
		if last = probe(ctx); last == nil { return nil }
		if err := sleepContext(ctx, interval); err != nil { return errors.Join(err, last) }
	}
}
