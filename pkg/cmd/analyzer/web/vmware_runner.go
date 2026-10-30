package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"mega-analyzer/pkg/internal/sandbox"
	"mega-analyzer/pkg/internal/vmware"
)

func (s *Server) vmwareExecutionRequest(id, username, password, sample string, args []string) (*vmware.ExecutionRequest, error) {
	username = strings.TrimSpace(username)
	if err := vmware.ValidateCredentials(username, password); err != nil {
		return nil, err
	}
	discover := s.vmwareDiscover
	if discover == nil {
		discover = detectVMwareVMs
	}
	var selected *vmEntry
	for _, entry := range discover() {
		if entry.ID == id && (entry.Running || entry.Registered) {
			copy := entry
			selected = &copy
			break
		}
	}
	if selected == nil {
		return nil, errors.New("выбранная ВМ больше не найдена в библиотеке VMware; обновите список")
	}
	if !strings.Contains(strings.ToLower(selected.OSType), "windows") {
		return nil, errors.New("для анализа файлов поддерживается гостевая Windows")
	}
	req := &vmware.ExecutionRequest{VMX: selected.ConfigPath, Name: selected.Name, Username: username, Password: password, CollectorPath: s.exe, SamplePath: sample, MemoryMB: 512, CPUCores: 2, Interactive: true}
	for i := 0; i < len(args); i += 2 {
		if i+1 >= len(args) {
			return nil, errors.New("неполный параметр гостевой сессии")
		}
		switch args[i] {
		case "-sandbox-duration":
			n, err := strconv.ParseInt(args[i+1], 10, 64)
			if err != nil {
				return nil, err
			}
			req.Duration = time.Duration(n) * time.Second
		case "-sandbox-memory":
			req.MemoryMB, _ = strconv.Atoi(args[i+1])
		case "-sandbox-cpu-cores":
			req.CPUCores, _ = strconv.Atoi(args[i+1])
		case "-sandbox-args":
			req.Args = args[i+1]
		case "-sandbox-desktop":
			if args[i+1] != "background" && args[i+1] != "interactive" {
				return nil, errors.New("неизвестный режим рабочего стола")
			}
			req.Interactive = args[i+1] == "interactive"
		case "-sandbox-profile":
			if args[i+1] != "basic" {
				return nil, errors.New("для VMware доступен базовый профиль наблюдения")
			}
		default:
			return nil, fmt.Errorf("параметр %s не поддерживается VMware", args[i])
		}
	}
	return req, nil
}

func (s *Server) runVMwareAnalysis(job *scanJob, req vmware.ExecutionRequest) {
	defer job.cleanupUpload()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	job.mu.Lock()
	job.cancel = cancel
	stopped := job.stopped
	job.mu.Unlock()
	if stopped {
		job.finish(130)
		return
	}
	// Credentials stay inside the running session closure. Clear the callback
	// on completion; concurrent captures are bounded and canceled with the job.
	var screenMu sync.Mutex
	var cachedScreen []byte
	var screenAt time.Time
	vmx, username, password, outputDir := req.VMX, req.Username, req.Password, req.OutputDir
	job.mu.Lock()
	job.vmwareScreen = func(requestCtx context.Context) ([]byte, error) {
		if !screenMu.TryLock() {
			return nil, vmware.ErrBusy
		}
		defer screenMu.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if cachedScreen != nil && time.Since(screenAt) < 2*time.Second {
			return cachedScreen, nil
		}
		captureCtx, stop := context.WithCancel(requestCtx)
		defer stop()
		unlink := context.AfterFunc(ctx, stop)
		defer unlink()
		frame, err := s.vmwareManager().CaptureScreen(captureCtx, vmx, username, password, outputDir)
		if err != nil {
			return nil, err
		}
		cachedScreen, screenAt = frame, time.Now()
		return frame, nil
	}
	job.mu.Unlock()
	defer func() {
		cancel()
		job.mu.Lock()
		job.vmwareScreen = nil
		job.vmwareConsole = nil
		job.mu.Unlock()
	}()
	req.ConsoleReady = func(console *vmware.Console) {
		job.mu.Lock()
		job.vmwareConsole = console
		job.mu.Unlock()
	}
	emit := func(event vmware.Event) {
		if event.Timestamp == "" {
			event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
		}
		if encoded, err := json.Marshal(event); err == nil {
			job.broadcast(string(encoded))
		}
	}
	defer func() {
		if recover() != nil {
			emit(vmware.Event{Type: "error", Code: "vmware_internal", Stage: "execution", Details: "Внутренняя ошибка VMware-сессии; проверьте состояние гостевой Windows"})
			job.finish(1)
		}
	}()
	_, err := s.vmwareManager().RunSession(ctx, req, emit)
	req.Password = ""
	if err != nil {
		if errors.Is(err, context.Canceled) {
			job.finish(130)
			return
		}
		failure := sandbox.DescribeFailure(err)
		emit(vmware.Event{Type: "error", Code: failure.Code, Stage: failure.Stage, Details: failure.Message})
		job.finish(1)
		return
	}
	emit(vmware.Event{Type: "status", Details: "Анализ в VMware завершён; отчёт сохранён на основном ПК"})
	job.finish(0)
}
