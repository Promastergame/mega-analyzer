package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/vmware"
)

func vmwareToolPath() string {
	return findTool("vmrun", `${ProgramFiles(x86)}\VMware\VMware Workstation\vmrun.exe`, `${ProgramFiles}\VMware\VMware Workstation\vmrun.exe`, "/usr/bin/vmrun", "/Applications/VMware Fusion.app/Contents/Library/vmrun")
}
func (s *Server) vmwareManager() *vmware.Controller {
	s.vmwareOnce.Do(func() {
		if s.vmwareControl != nil {
			return
		}
		var runner vmware.Runner
		if tool := vmwareToolPath(); tool != "" {
			runner = vmware.ExecRunner(tool)
		}
		dir := ""
		if base, err := os.UserConfigDir(); err == nil {
			dir = filepath.Join(base, "mega-analyzer", "vmware-baselines")
		}
		s.vmwareControl = vmware.New(runner, dir)
	})
	return s.vmwareControl
}

// handleVMware accepts a detected VM id and a fixed management operation.
// Guest credentials are accepted only by the analysis job, never this API.
func (s *Server) handleVMware(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fail := func(code int, msg string) {
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]string{"error": msg})
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		fail(http.StatusMethodNotAllowed, "требуется POST-запрос")
		return
	}
	if strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])) != "application/json" {
		fail(http.StatusUnsupportedMediaType, "требуется application/json")
		return
	}
	var req struct {
		ID           string `json:"id"`
		Action       string `json:"action"`
		Snapshot     string `json:"snapshot,omitempty"`
		Confirmation string `json:"confirmation,omitempty"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		fail(http.StatusBadRequest, "некорректный запрос VMware")
		return
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		fail(http.StatusBadRequest, "ожидался один JSON-объект")
		return
	}
	switch req.Action {
	case "inspect", "prepare", "create-baseline", "restore-baseline":
	default:
		fail(http.StatusBadRequest, "эта операция VMware не поддерживается")
		return
	}
	if len(req.ID) > 128 || !strings.HasPrefix(req.ID, "vmware:") {
		fail(http.StatusBadRequest, "выберите обнаруженную ВМ VMware")
		return
	}
	if req.Action == "create-baseline" && req.Confirmation != "СОЗДАТЬ СНИМОК" {
		fail(http.StatusBadRequest, "не подтверждено создание снимка")
		return
	}
	// Bound rediscovery too: vmrun/list and inventory files remain host-owned.
	discover := s.vmwareDiscover
	if discover == nil {
		discover = detectVMwareVMs
	}
	var selected *vmEntry
	for _, vm := range discover() {
		if vm.ID == req.ID && (vm.Running || vm.Registered) {
			copy := vm
			selected = &copy
			break
		}
	}
	if selected == nil {
		fail(http.StatusNotFound, "ВМ больше не найдена в библиотеке VMware; обновите список")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	manager := s.vmwareManager()
	var report vmware.Report
	var err error
	switch req.Action {
	case "inspect":
		report, err = manager.Inspect(ctx, selected.ConfigPath)
	case "prepare":
		report, err = manager.Prepare(ctx, selected.ConfigPath)
	case "create-baseline":
		report, err = manager.CreateBaseline(ctx, selected.ConfigPath)
	case "restore-baseline":
		report, err = manager.RestoreBaseline(ctx, selected.ConfigPath, req.Snapshot, req.Confirmation)
	}
	if err != nil {
		code := http.StatusUnprocessableEntity
		if errors.Is(err, vmware.ErrBusy) {
			code = http.StatusConflict
		}
		if errors.Is(err, context.DeadlineExceeded) {
			code = http.StatusGatewayTimeout
		}
		fail(code, err.Error())
		return
	}
	json.NewEncoder(w).Encode(report)
}
