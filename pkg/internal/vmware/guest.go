package vmware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"mega-analyzer/pkg/internal/sandbox"
)

const guestEventLimit = 8 << 20
const guestReportLimit = 16 << 20
const guestLease = 60 * time.Second

var sessionTokenPattern = regexp.MustCompile(`^[0-9a-f]{24}$`)

// GuestRequest contains execution settings, never host login credentials.
type GuestRequest struct {
	Version         int    `json:"version"`
	ID              string `json:"id"`
	Extension       string `json:"extension"`
	SampleName      string `json:"sample_name,omitempty"`
	SHA256          string `json:"sha256"`
	DurationSeconds int64  `json:"duration_seconds"`
	MemoryMB        int    `json:"memory_mb"`
	CPUCores        int    `json:"cpu_cores"`
	Args            string `json:"args"`
}

type Event struct {
	Type             string `json:"type"`
	Timestamp        string `json:"timestamp,omitempty"`
	PID              int    `json:"pid,omitempty"`
	PPID             int    `json:"ppid,omitempty"`
	Process          string `json:"process,omitempty"`
	Details          string `json:"details,omitempty"`
	Code             string `json:"code,omitempty"`
	Stage            string `json:"stage,omitempty"`
	EventID          string `json:"event_id,omitempty"`
	Source           string `json:"source,omitempty"`
	Attribution      string `json:"attribution,omitempty"`
	Category         string `json:"category,omitempty"`
	Action           string `json:"action,omitempty"`
	Object           string `json:"object,omitempty"`
	SHA256           string `json:"sha256,omitempty"`
	CompletionReason string `json:"completion_reason,omitempty"`
	Protocol         string `json:"protocol,omitempty"`
	LocalAddr        string `json:"local_addr,omitempty"`
	RemoteAddr       string `json:"remote_addr,omitempty"`
	State            string `json:"state,omitempty"`
}

type guestEvent struct {
	ID    string `json:"id"`
	Seq   uint64 `json:"seq"`
	Event Event  `json:"event"`
}

type guestState struct {
	Version   int    `json:"version"`
	ID        string `json:"id"`
	PID       int    `json:"pid"`
	Done      bool   `json:"done"`
	Truncated bool   `json:"truncated"`
	Error     string `json:"error,omitempty"`
}

type guestResult struct {
	ID     string          `json:"id"`
	Report *sandbox.Report `json:"report"`
	Error  string          `json:"error,omitempty"`
}

func (r GuestRequest) validate() error {
	if r.Version != 1 || !sessionTokenPattern.MatchString(r.ID) || !WindowsSampleExtension(r.Extension) {
		return errors.New("недопустимое задание гостевого сборщика")
	}
	if r.SampleName != "" && (!validSampleName(r.SampleName) || !strings.EqualFold(filepath.Ext(r.SampleName), r.Extension)) {
		return errors.New("недопустимое имя образца")
	}
	if len(r.SHA256) != 64 {
		return errors.New("не задан SHA-256 образца")
	}
	if _, err := hex.DecodeString(r.SHA256); err != nil {
		return errors.New("недопустимый SHA-256 образца")
	}
	if r.DurationSeconds < 0 || r.DurationSeconds > int64((1<<63-1)/time.Second) || (r.DurationSeconds > 0 && r.DurationSeconds < 5) {
		return errors.New("длительность должна быть 0 или не менее 5 секунд")
	}
	if r.MemoryMB < 128 || r.MemoryMB > 131072 || r.CPUCores < 1 || r.CPUCores > 1024 || len(r.Args) > 4096 || strings.ContainsAny(r.Args, "\x00\r\n") {
		return errors.New("недопустимые параметры исполнения")
	}
	return nil
}

// Names are data, never commands or paths. Restrict Windows reserved names,
// alternate streams and separators even when requests are checked on Linux.
var sampleNamePattern = regexp.MustCompile(`^[\pL\pN][\pL\pN ._()@+\-]{0,179}$`)
var reservedSampleName = regexp.MustCompile(`(?i)^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$`)

func validSampleName(name string) bool {
	stem, _, _ := strings.Cut(name, ".")
	return sampleNamePattern.MatchString(name) && !strings.HasSuffix(name, " ") &&
		!strings.HasSuffix(name, ".") && !reservedSampleName.MatchString(strings.TrimSpace(stem))
}

func (r GuestRequest) sampleRelativePath() string {
	if r.SampleName == "" {
		return "sample" + r.Extension // Compatibility with old saved guest requests.
	}
	return "input/" + r.SampleName
}

func WindowsSampleExtension(ext string) bool {
	switch strings.ToLower(ext) {
	case ".exe", ".com", ".bat", ".cmd", ".ps1":
		return true
	}
	return false
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("файл отсутствует, не является обычным файлом или превышает лимит")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if len(data) > int(limit) {
		return nil, errors.New("файл превышает лимит")
	}
	return data, err
}

func decodeJSON(data []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("ожидался один JSON-объект")
	}
	return nil
}

func atomicJSON(path string, value any, limit int) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > limit {
		return errors.New("отчёт превышает лимит передачи")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".mega-json-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// RunGuest is entered only through vmrun inside the guest. The sandbox entry
// point also checks VMware hardware; invoking this mode on the host cannot
// silently execute the sample there.
func RunGuest(ctx context.Context, dir string) error {
	return runGuest(ctx, dir, sandbox.RunVMwareGuest, guestLease)
}

func runGuest(parent context.Context, dir string, run func(context.Context, sandbox.Config) (*sandbox.Report, error), lease time.Duration) error {
	if err := parent.Err(); err != nil {
		return err
	}
	if !filepath.IsAbs(dir) {
		return errors.New("требуется абсолютный каталог гостевой сессии")
	}
	data, err := readBounded(filepath.Join(dir, "request.json"), 16<<10)
	if err != nil {
		return err
	}
	var request GuestRequest
	if err := decodeJSON(data, &request); err != nil {
		return err
	}
	if err := request.validate(); err != nil {
		return err
	}
	if filepath.Base(filepath.Clean(dir)) != "mega-session-"+request.ID {
		return errors.New("каталог не соответствует идентификатору сессии")
	}
	state := guestState{Version: 1, ID: request.ID, PID: os.Getpid()}
	statePath := filepath.Join(dir, "state.json")
	if err := atomicJSON(statePath, state, 16<<10); err != nil {
		return err
	}
	journal, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer journal.Close()
	var mu sync.Mutex
	var seq uint64
	var size int
	var journalErr error
	emit := func(event Event) {
		mu.Lock()
		defer mu.Unlock()
		if state.Truncated || journalErr != nil {
			return
		}
		if event.Timestamp == "" {
			event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
		}
		encoded, err := json.Marshal(guestEvent{request.ID, seq + 1, event})
		if err != nil || len(encoded) > 64<<10 || size+len(encoded)+1 > guestEventLimit {
			state.Truncated = true
			return
		}
		_, journalErr = journal.Write(append(encoded, '\n'))
		if journalErr == nil {
			journalErr = journal.Sync()
		}
		size += len(encoded) + 1
		seq++
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	controlDone := make(chan struct{})
	var controlErr error
	go func() {
		defer close(controlDone)
		interval := time.Second
		if lease < 3*time.Second {
			interval = lease / 4
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		last, previous := time.Now(), ""
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				control, err := readBounded(filepath.Join(dir, "control.txt"), 256)
				value := string(control)
				if err == nil && strings.HasPrefix(value, request.ID+"|") {
					if value == request.ID+"|stop" {
						cancel()
						return
					}
					if value != previous {
						previous, last = value, time.Now()
					}
				}
				mu.Lock()
				_ = atomicJSON(statePath, state, 16<<10)
				mu.Unlock()
				if time.Since(last) >= lease {
					controlErr = errors.New("связь с анализатором потеряна; гостевой процесс остановлен")
					cancel()
					return
				}
			}
		}
	}()
	target := filepath.Join(dir, filepath.FromSlash(request.sampleRelativePath()))
	var report *sandbox.Report
	hash, err := fileSHA256(target)
	if err == nil && hash != request.SHA256 {
		err = errors.New("SHA-256 переданного образца не совпадает; запуск отменён")
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		emit(Event{Type: "status", Details: "Гостевой сборщик запущен; подготовка наблюдения"})
		report, err = run(ctx, sandbox.Config{
			TargetPath: target, OutputDir: filepath.Join(dir, "reports"), RawArgs: request.Args,
			Duration: time.Duration(request.DurationSeconds) * time.Second, MaxMemoryMB: request.MemoryMB,
			MaxCPUCores: request.CPUCores, MonitorEvery: time.Second, SandboxProfile: "basic",
			OnObserving: func() {
				emit(Event{Type: "status", Stage: "observing", Details: "Наблюдение в гостевой Windows начато"})
			},
			OnProcess: func(p sandbox.ObservedProcess) {
				emit(Event{Type: "process", PID: p.PID, PPID: p.ParentPID, Process: p.Name, Details: p.CommandLine})
			},
			OnConnection: func(c sandbox.ObservedConnection) {
				emit(Event{Type: "network", PID: c.PID, Protocol: c.Protocol, LocalAddr: c.LocalAddr, RemoteAddr: c.RemoteAddr, State: c.State, Details: c.Protocol + " -> " + c.RemoteAddr + " (" + c.State + ")"})
			},
			OnActivity: func(a sandbox.ActivityEvent) {
				emit(Event{Type: "activity", Timestamp: a.ObservedAt.Format(time.RFC3339Nano), EventID: a.ID, PID: a.PID, Process: a.Process, Source: a.Source, Attribution: a.Attribution, Category: a.Category, Action: a.Action, Object: a.Object, Details: a.Details})
			},
			LogSink: func(line string) { emit(Event{Type: "log", Details: line}) },
		})
	}
	cancel()
	<-controlDone
	err = errors.Join(err, controlErr, journalErr)
	if report != nil {
		for _, log := range []struct{ from, to string }{{report.StdoutPath, "stdout.log"}, {report.StderrPath, "stderr.log"}, {report.ActivityPath, "activity.jsonl"}} {
			if log.from == "" {
				continue
			}
			if contents, readErr := readBounded(log.from, guestEventLimit); readErr == nil {
				_ = os.WriteFile(filepath.Join(dir, log.to), contents, 0600)
			}
		}
	}
	result := guestResult{ID: request.ID, Report: report}
	if err != nil {
		result.Error = err.Error()
	}
	if persistErr := atomicJSON(filepath.Join(dir, "result.json"), result, guestReportLimit); persistErr != nil {
		err = errors.Join(err, persistErr)
	}
	state.Done = true
	if err != nil {
		state.Error = err.Error()
	}
	if stateErr := atomicJSON(statePath, state, 16<<10); stateErr != nil {
		err = errors.Join(err, stateErr)
	}
	return err
}
