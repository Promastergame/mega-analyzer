package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func vmFixture(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name+".vmx")
	if err := os.WriteFile(p, []byte("config.version = \"8\"\nvirtualHW.version = \"20\"\nguestOS = \"windows9-64\"\ndisplayName = \"Research VM\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestSandboxReliabilityVMwareRejectsHeadingsAndMissingFiles(t *testing.T) {
	d := t.TempDir()
	missing := filepath.Join(d, "deleted.vmx")
	text := "Total running VMs: 0\nВсего запущенных виртуальных машин: 0\nVMware Workstation 17\nWarning: configuration unavailable\n" + missing
	got := collectVMwareVMs(text, nil, nil)
	if got == nil || len(got) != 0 {
		t.Fatalf("phantom guests: %#v", got)
	}
	inv := filepath.Join(d, "inventory.vmls")
	os.WriteFile(inv, []byte("index0.filename = \""+missing+"\"\n"), 0600)
	if got := collectVMwareVMs("", []string{inv}, nil); len(got) != 0 {
		t.Fatalf("stale inventory guest: %#v", got)
	}
}
func TestSandboxReliabilityVMwareRequiresRealDefinition(t *testing.T) {
	d := t.TempDir()
	junk := filepath.Join(d, "junk.vmx")
	os.WriteFile(junk, []byte("displayName = \"not a VM\""), 0600)
	folder := filepath.Join(d, "folder.vmx")
	os.Mkdir(folder, 0700)
	got := collectVMwareVMs(junk+"\n"+folder+"\nError: "+junk, nil, []string{d})
	if len(got) != 0 {
		t.Fatalf("non-VM accepted: %#v", got)
	}
}
func TestSandboxReliabilityVMwareDeduplicatesRealGuests(t *testing.T) {
	d := t.TempDir()
	vm := vmFixture(t, d, "machine")
	inv := filepath.Join(d, "inventory.vmls")
	os.WriteFile(inv, []byte("index0.filename = \""+vm+"\"\nindex1.filename = \""+vm+"\"\n"), 0600)
	got := collectVMwareVMs("Всего запущенных виртуальных машин: 1\n"+vm+"\n", []string{inv}, []string{d})
	if len(got) != 1 || !got[0].Running || got[0].Name != "Research VM" || got[0].OSType != "windows9-64" || !strings.HasPrefix(got[0].ID, "vmware:") {
		t.Fatalf("bad guests: %#v", got)
	}
	os.Remove(vm)
	if got := collectVMwareVMs(vm, []string{inv}, []string{d}); len(got) != 0 {
		t.Fatalf("deleted guest remained: %#v", got)
	}
}
func TestSandboxReliabilityReportAssociation(t *testing.T) {
	j := newScanJob("job", "", t.TempDir())
	j.broadcast(`{"type":"report","details":"20260905_123456_12345678"}`)
	if j.sandboxSession != "20260905_123456_12345678" {
		t.Fatalf("session = %q", j.sandboxSession)
	}
	j.broadcast(`{"type":"report","details":"../../other"}`)
	if j.sandboxSession != "20260905_123456_12345678" {
		t.Fatal("path traversal session accepted")
	}
	j.broadcast(`{"type":"stdout","details":"old-session"}`)
	if j.sandboxSession != "20260905_123456_12345678" {
		t.Fatal("stdout was treated as a report")
	}
}

func TestSandboxReliabilityNoStaleReport(t *testing.T) {
	out := t.TempDir()
	for _, id := range []string{"older_session", "current_session"} {
		dir := filepath.Join(out, "sandbox", id)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "sandbox_report.json"), []byte(`{"session_id":"`+id+`"}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	job := newScanJob("isolated_report_test", "", out)
	jobsMu.Lock()
	jobs[job.id] = job
	jobsMu.Unlock()
	t.Cleanup(func() { jobsMu.Lock(); delete(jobs, job.id); jobsMu.Unlock() })
	server := &Server{}
	read := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		server.handleSandbox(w, httptest.NewRequest("GET", "/api/sandbox/"+job.id, nil))
		return w
	}
	if w := read(); w.Code != http.StatusNotFound {
		t.Fatalf("unassociated prior report leaked: %d %s", w.Code, w.Body.String())
	}
	job.broadcast(`{"type":"report","details":"current_session"}`)
	if w := read(); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "current_session") {
		t.Fatalf("wrong report: %d %s", w.Code, w.Body.String())
	}
}

func TestVMwareInventoryConfigKeyMarksRegistered(t *testing.T) {
	d := t.TempDir()
	vm := vmFixture(t, d, "machine")
	// Real VMware Workstation libraries list guests as vmlistN.config.
	inv := filepath.Join(d, "inventory.vmls")
	os.WriteFile(inv, []byte("vmlist1.config = \""+vm+"\"\n"), 0600)
	got := collectVMwareVMs("", []string{inv}, nil)
	if len(got) != 1 || !got[0].Registered || got[0].Running {
		t.Fatalf("library VM not marked registered: %#v", got)
	}
}

func TestVMwareStrayConfigFileIsNotRegistered(t *testing.T) {
	d := t.TempDir()
	vmFixture(t, d, "leftover")
	got := collectVMwareVMs("", nil, []string{d})
	if len(got) != 1 || got[0].Registered {
		t.Fatalf("stray config reported as registered: %#v", got)
	}
}
