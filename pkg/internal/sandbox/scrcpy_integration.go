package sandbox

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"mega-analyzer/pkg/logger"
)

// ScrcpyConfig определяет конфигурацию для scrcpy
type ScrcpyConfig struct {
	Enabled        bool
	Serial         string
	MaxSize        int
	VideoBitrate   string
	AudioBitrate   string
	MaxFPS         int
	StayAwake      bool
	TurnScreenOff  bool
	ShowTouches    bool
	RecordingPath  string
	LogPath        string
	Timeout        time.Duration
	AdditionalArgs []string
}

// ScrcpyManager управляет интеграцией с scrcpy
type ScrcpyManager struct {
	config     *ScrcpyConfig
	cmd        *exec.Cmd
	cancel     context.CancelFunc
	ctx        context.Context
	mu         sync.Mutex
	running    bool
	recordFile *os.File
	logFile    *os.File
	eventChan  chan ScrcpyEvent
}

// ScrcpyEvent представляет событие от scrcpy
type ScrcpyEvent struct {
	Type      string // "screen_update", "touch", "key", "error", "started", "stopped"
	Timestamp time.Time
	Data      map[string]interface{}
}

// NewScrcpyManager создает новый менеджер scrcpy
func NewScrcpyManager(config *ScrcpyConfig) *ScrcpyManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &ScrcpyManager{
		config:    config,
		ctx:       ctx,
		cancel:    cancel,
		eventChan: make(chan ScrcpyEvent, 100),
	}
}

// Start запускает scrcpy
func (sm *ScrcpyManager) Start() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.running {
		return fmt.Errorf("scrcpy is already running")
	}

	if !sm.config.Enabled {
		logger.Info("scrcpy is disabled in configuration")
		return nil
	}

	// Проверяем наличие scrcpy
	if _, err := exec.LookPath("scrcpy"); err != nil {
		return fmt.Errorf("scrcpy not found in PATH: %w", err)
	}

	// Строим аргументы команды
	args := sm.buildScrcpyArgs()

	sm.cmd = exec.CommandContext(sm.ctx, "scrcpy", args...)

	// Настраиваем вывод и логирование
	if sm.config.LogPath != "" {
		logFile, err := os.OpenFile(sm.config.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		sm.logFile = logFile
		sm.cmd.Stdout = logFile
		sm.cmd.Stderr = logFile
	}

	// Запускаем процесс
	if err := sm.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start scrcpy: %w", err)
	}

	sm.running = true
	logger.Info("scrcpy started successfully",
		"serial", sm.config.Serial,
		"max_size", sm.config.MaxSize,
		"video_bitrate", sm.config.VideoBitrate,
	)

	// Отправляем событие запуска (не блокируясь, чтобы не держать sm.mu при заполненном канале)
	select {
	case sm.eventChan <- ScrcpyEvent{
		Type:      "started",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"serial": sm.config.Serial,
		},
	}:
	default:
		logger.Warn("scrcpy event channel full, dropping 'started' event")
	}

	// Запускаем горутину для отслеживания процесса
	go sm.watchProcess()

	return nil
}

// Stop останавливает scrcpy
func (sm *ScrcpyManager) Stop() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.running {
		return nil
	}

	sm.cancel()

	if sm.cmd != nil && sm.cmd.Process != nil {
		if err := sm.cmd.Process.Kill(); err != nil {
			logger.Error("failed to kill scrcpy process", "error", err)
		}
	}

	// Закрываем файлы логирования и записи
	if sm.logFile != nil {
		sm.logFile.Close()
	}
	if sm.recordFile != nil {
		sm.recordFile.Close()
	}

	sm.running = false
	logger.Info("scrcpy stopped")

	// Отправляем событие остановки (не блокируясь, чтобы не держать sm.mu при заполненном канале)
	select {
	case sm.eventChan <- ScrcpyEvent{
		Type:      "stopped",
		Timestamp: time.Now(),
	}:
	default:
		logger.Warn("scrcpy event channel full, dropping 'stopped' event")
	}

	return nil
}

// IsRunning возвращает статус работы scrcpy
func (sm *ScrcpyManager) IsRunning() bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.running
}

// buildScrcpyArgs строит аргументы для scrcpy
func (sm *ScrcpyManager) buildScrcpyArgs() []string {
	args := []string{
		"--serial", sm.config.Serial,
		"--max-size", fmt.Sprintf("%d", sm.config.MaxSize),
		"--video-bit-rate", sm.config.VideoBitrate,
		"--max-fps", fmt.Sprintf("%d", sm.config.MaxFPS),
	}

	if sm.config.AudioBitrate != "" {
		args = append(args, "--audio-bit-rate", sm.config.AudioBitrate)
	}

	if sm.config.StayAwake {
		args = append(args, "--stay-awake")
	}

	if sm.config.TurnScreenOff {
		args = append(args, "--turn-screen-off")
	}

	if sm.config.ShowTouches {
		args = append(args, "--show-touches")
	}

	if sm.config.RecordingPath != "" {
		args = append(args, "--record", sm.config.RecordingPath)
	}

	// Добавляем дополнительные аргументы
	args = append(args, sm.config.AdditionalArgs...)

	return args
}

// watchProcess отслеживает процесс scrcpy
func (sm *ScrcpyManager) watchProcess() {
	if sm.cmd == nil {
		return
	}

	err := sm.cmd.Wait()
	sm.mu.Lock()
	sm.running = false
	sm.mu.Unlock()

	if err != nil {
		logger.Error("scrcpy process exited with error", "error", err)
		sm.eventChan <- ScrcpyEvent{
			Type:      "error",
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}
}

// GetEventChannel возвращает канал событий
func (sm *ScrcpyManager) GetEventChannel() <-chan ScrcpyEvent {
	return sm.eventChan
}

// TakeScreenshot захватывает скриншот с устройства
func (sm *ScrcpyManager) TakeScreenshot(outputPath string) error {
	cmd := exec.CommandContext(sm.ctx, "adb", "-s", sm.config.Serial, "shell", "screencap", "-p", "/sdcard/screenshot.png")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to take screenshot: %w", err)
	}

	// Копируем скриншот с устройства
	pullCmd := exec.CommandContext(sm.ctx, "adb", "-s", sm.config.Serial, "pull", "/sdcard/screenshot.png", outputPath)
	if err := pullCmd.Run(); err != nil {
		return fmt.Errorf("failed to pull screenshot: %w", err)
	}

	return nil
}

// StartRecording запускает запись экрана
func (sm *ScrcpyManager) StartRecording(outputPath string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.running {
		return fmt.Errorf("scrcpy is not running")
	}

	// scrcpy only accepts --record at process launch; it cannot be enabled
	// on an already-running process.
	if sm.config.RecordingPath == "" {
		return fmt.Errorf("recording must be configured before Start(); restart scrcpy with RecordingPath set to %q", outputPath)
	}
	if sm.config.RecordingPath != outputPath {
		return fmt.Errorf("scrcpy is already recording to %q; cannot switch to %q without restarting", sm.config.RecordingPath, outputPath)
	}

	return nil
}

// StopRecording останавливает запись экрана
func (sm *ScrcpyManager) StopRecording() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.running {
		return fmt.Errorf("scrcpy is not running")
	}

	logger.Info("Recording stopped")
	return nil
}

// InjectTouch инжектирует касание на экран
func (sm *ScrcpyManager) InjectTouch(x, y int) error {
	cmd := exec.CommandContext(sm.ctx, "adb", "-s", sm.config.Serial, "shell", "input", "tap", fmt.Sprintf("%d", x), fmt.Sprintf("%d", y))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to inject touch: %w", err)
	}

	sm.eventChan <- ScrcpyEvent{
		Type:      "touch",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"x": x,
			"y": y,
		},
	}

	return nil
}

// InjectKey инжектирует нажатие клавиши
func (sm *ScrcpyManager) InjectKey(keyCode string) error {
	cmd := exec.CommandContext(sm.ctx, "adb", "-s", sm.config.Serial, "shell", "input", "keyevent", keyCode)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to inject key: %w", err)
	}

	sm.eventChan <- ScrcpyEvent{
		Type:      "key",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"key_code": keyCode,
		},
	}

	return nil
}

// InjectText инжектирует текст
func (sm *ScrcpyManager) InjectText(text string) error {
	// adb concatenates all arguments after "shell" into a single command line
	// executed by the device's shell, so text must be single-quoted to
	// prevent shell metacharacters (e.g. `;`, `$()`, `` ` ``) from being
	// interpreted on the device.
	quoted := "'" + strings.ReplaceAll(text, "'", `'\''`) + "'"
	cmd := exec.CommandContext(sm.ctx, "adb", "-s", sm.config.Serial, "shell", "input text "+quoted)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to inject text: %w", err)
	}

	return nil
}

// GetLogcatStream возвращает поток logcat
func (sm *ScrcpyManager) GetLogcatStream(ctx context.Context) (<-chan string, error) {
	logcatChan := make(chan string, 100)

	cmd := exec.CommandContext(ctx, "adb", "-s", sm.config.Serial, "logcat")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get logcat stdout: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start logcat: %w", err)
	}

	go func() {
		defer close(logcatChan)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case logcatChan <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil {
			logger.Error("error reading logcat stdout", "error", err)
		}
	}()

	return logcatChan, nil
}

// GetDeviceInfo возвращает информацию об устройстве
func (sm *ScrcpyManager) GetDeviceInfo() (map[string]string, error) {
	info := make(map[string]string)

	// Получаем модель устройства
	cmd := exec.CommandContext(sm.ctx, "adb", "-s", sm.config.Serial, "shell", "getprop", "ro.product.model")
	output, err := cmd.Output()
	if err == nil {
		info["model"] = string(output)
	}

	// Получаем версию Android
	cmd = exec.CommandContext(sm.ctx, "adb", "-s", sm.config.Serial, "shell", "getprop", "ro.build.version.release")
	output, err = cmd.Output()
	if err == nil {
		info["android_version"] = string(output)
	}

	// Получаем уровень API
	cmd = exec.CommandContext(sm.ctx, "adb", "-s", sm.config.Serial, "shell", "getprop", "ro.build.version.sdk")
	output, err = cmd.Output()
	if err == nil {
		info["api_level"] = string(output)
	}

	return info, nil
}

// SyncWithMITM синхронизирует события scrcpy с MITM-захватами
func (sm *ScrcpyManager) SyncWithMITM(mitm *MITMCapture) error {
	if mitm == nil {
		return fmt.Errorf("MITM capture is nil")
	}

	logger.Info("Synchronizing scrcpy events with MITM captures")

	// Здесь можно добавить логику синхронизации временных меток
	// и корреляции событий между scrcpy и MITM-захватами

	return nil
}

// MITMCapture представляет MITM-захват для синхронизации
type MITMCapture struct {
	Timestamp time.Time
	Direction string // "request" или "response"
	Data      []byte
}
