package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/vmware"
)

func vmwareTestServer(t *testing.T) (*Server, vmEntry, *[]string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Lab.vmx")
	if err := os.WriteFile(path, []byte("config.version = \"8\"\nvirtualHW.version = \"20\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var names []string
	var calls []string
	runner := func(ctx context.Context, args ...string) ([]byte, error) {
		calls = append(calls, args[0])
		switch args[0] {
		case "list":
			return []byte("Total running VMs: 0\n"), nil
		case "listSnapshots":
			return []byte(fmt.Sprintf("Total snapshots: %d\n%s", len(names), strings.Join(names, "\n"))), nil
		case "snapshot":
			names = append(names, args[2])
			return nil, nil
		case "revertToSnapshot":
			return nil, nil
		default:
			return nil, fmt.Errorf("unexpected operation %v", args)
		}
	}
	vm := vmEntry{ID: "vmware:fixture", Name: "Lab", Registered: true, ConfigPath: path}
	s, err := New(Options{Host: "127.0.0.1", Port: 7474, Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	s.vmwareControl = vmware.New(runner, t.TempDir())
	s.vmwareDiscover = func() []vmEntry { return []vmEntry{vm} }
	return s, vm, &calls
}

func vmwareRequest(s *Server, method, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:7474/api/vmware", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-MA-Token", "test-token")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	return w
}

func TestVMwareProtectedAPIAndBaselineLifecycle(t *testing.T) {
	s, vm, calls := vmwareTestServer(t)
	request := func(action, name, confirmation string) vmware.Report {
		t.Helper()
		b, _ := json.Marshal(map[string]string{"id": vm.ID, "action": action, "snapshot": name, "confirmation": confirmation})
		w := vmwareRequest(s, "POST", string(b), nil)
		if w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		var report vmware.Report
		if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if w.Header().Get("Cache-Control") != "no-store" || report.GuestExecution {
			t.Fatal("unsafe capabilities/cache")
		}
		return report
	}
	request("inspect", "", "")
	created := request("create-baseline", "", "СОЗДАТЬ СНИМОК")
	if created.LastSnapshot == "" {
		t.Fatal("missing snapshot")
	}
	request("restore-baseline", created.LastSnapshot, created.LastSnapshot)
	for _, call := range *calls {
		if strings.Contains(strings.ToLower(call), "inguest") {
			t.Fatalf("guest execution attempted: %s", call)
		}
	}
}

func TestVMwareRejectsUntrustedRequests(t *testing.T) {
	s, vm, calls := vmwareTestServer(t)
	good := `{"id":"` + vm.ID + `","action":"inspect"}`
	for _, tt := range []struct {
		name, method, body string
		headers            map[string]string
		status             int
	}{
		{"method", "GET", "", nil, 405}, {"content type", "POST", good, map[string]string{"Content-Type": "text/plain"}, 415},
		{"malformed", "POST", "{", nil, 400}, {"unknown field", "POST", `{"id":"vmware:fixture","action":"inspect","path":"/etc/passwd"}`, nil, 400},
		{"trailing object", "POST", good + ` {}`, nil, 400}, {"wrong provider", "POST", `{"id":"vbox:x","action":"inspect"}`, nil, 400},
		{"execute", "POST", `{"id":"vmware:fixture","action":"runProgramInGuest"}`, nil, 400},
		{"unconfirmed snapshot", "POST", `{"id":"vmware:fixture","action":"create-baseline"}`, nil, 400},
		{"stale id", "POST", `{"id":"vmware:other","action":"inspect"}`, nil, 404},
		{"cross origin", "POST", good, map[string]string{"Origin": "https://evil.invalid"}, 403},
		{"cross site", "POST", good, map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"missing token", "POST", good, map[string]string{"X-MA-Token": ""}, 401},
		{"oversized", "POST", `{"id":"` + strings.Repeat("x", 9000) + `","action":"inspect"}`, nil, 400},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := len(*calls)
			w := vmwareRequest(s, tt.method, tt.body, tt.headers)
			if w.Code != tt.status {
				t.Fatalf("code=%d body=%s want=%d", w.Code, w.Body, tt.status)
			}
			if len(*calls) != before {
				t.Fatal("rejected request reached vmrun")
			}
		})
	}
	s.vmwareDiscover = func() []vmEntry { copy := vm; copy.Registered = false; return []vmEntry{copy} }
	if w := vmwareRequest(s, "POST", good, nil); w.Code != 404 {
		t.Fatalf("stale VM accepted: %s", w.Body)
	}
}

func TestVMwarePanelIsHonestAndNoHostFallback(t *testing.T) {
	for _, text := range []string{`id="vmwarePanel"`, `/api/vmware`, `function updateVMwarePanel`, `credentials:"same-origin"`, `report.running`, `vmwareExecutionReady`, `id="vmwareUser"`, `id="vmwarePassword"`, `generation!==vmwarePanelGeneration`} {
		if !strings.Contains(webUIHTML, text) {
			t.Errorf("missing UI guard %q", text)
		}
	}
	if strings.Contains(webUIHTML, "no guest execution or snapshot/restore adapter is implemented") {
		t.Fatal("old blanket detection-only message remains")
	}
	if _, err := validateSandboxRequest("host:host", "yes", "sample.exe", "windows", nil); err == nil {
		t.Fatal("native host execution became available")
	}
	if _, err := validateSandboxRequest("vmware:fixture", "yes", "sample.exe", "windows", []string{"-sandbox-allow-host-execution"}); err == nil {
		t.Fatal("VMware target accepted a host-execution override")
	}
}

func TestVMwareInvalidReceiptAndCommandFailureAPI(t *testing.T) {
	s, vm, _ := vmwareTestServer(t)
	for _, body := range []string{
		`{"id":"` + vm.ID + `","action":"restore-baseline","snapshot":"x","confirmation":"x"}`,
		`{"id":"` + vm.ID + `","action":"restore-baseline","snapshot":"mega-baseline-000000000000000000000000","confirmation":"mega-baseline-000000000000000000000000"}`,
	} {
		w := vmwareRequest(s, "POST", body, nil)
		if w.Code != 422 {
			t.Fatalf("code=%d %s", w.Code, w.Body)
		}
	}
	s.vmwareControl = vmware.New(nil, t.TempDir())
	w := vmwareRequest(s, "POST", `{"id":"`+vm.ID+`","action":"inspect"}`, nil)
	if w.Code != 422 || !bytes.Contains(w.Body.Bytes(), []byte("vmrun")) {
		t.Fatalf("missing tool=%d %s", w.Code, w.Body)
	}
}
