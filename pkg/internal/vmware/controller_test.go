package vmware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func fixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Lab VM.vmx")
	text := `config.version = "8"
virtualHW.version = "20"
Ethernet0.present = "TRUE"
ethernet0.startConnected = "FALSE"
isolation.tools.hgfs.disable = "TRUE"
isolation.tools.copy.disable = "TRUE"
isolation.tools.paste.disable = "TRUE"
isolation.tools.dnd.disable = "TRUE"
usb.present = "FALSE"
ehci.present = "FALSE"
usb_xhci.present = "FALSE"
`
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

type fakeVMware struct {
	path            string
	active          bool
	names           []string
	calls           [][]string
	fail            string
	badList         bool
	powerOnSnapshot bool
}

func (f *fakeVMware) run(ctx context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.fail == args[0] {
		return nil, errors.New("injected " + f.fail)
	}
	switch args[0] {
	case "list":
		if f.badList {
			return []byte("непонятный ответ"), nil
		}
		if f.active {
			return []byte("Всего ВМ: 1\n" + f.path + "\n"), nil
		}
		return []byte("Total running VMs: 0\n"), nil
	case "listSnapshots":
		return []byte(fmt.Sprintf("Всего снимков: %d\n%s", len(f.names), strings.Join(f.names, "\n"))), nil
	case "snapshot":
		if args[1] != f.path {
			return nil, errors.New("wrong VM")
		}
		f.names = append(f.names, args[2])
		if f.powerOnSnapshot {
			f.active = true
		}
		return nil, nil
	case "revertToSnapshot":
		if args[1] != f.path {
			return nil, errors.New("wrong VM")
		}
		return nil, nil
	case "checkToolsState":
		return []byte("running\n"), nil
	default:
		return nil, fmt.Errorf("forbidden operation %v", args)
	}
}

func TestBaselineLifecyclePersistenceAndNoGuestExecution(t *testing.T) {
	path := fixture(t)
	fake := &fakeVMware{path: path}
	dir := t.TempDir()
	c := New(fake.run, dir)
	ctx := context.Background()
	report, err := c.Inspect(ctx, path)
	if err != nil || report.Running || report.GuestExecution || len(report.Checks) != 6 || report.ConfigurationPass {
		t.Fatalf("inspect=%+v %v", report, err)
	}
	report, err = c.CreateBaseline(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	name := report.LastSnapshot
	if !managedName.MatchString(name) || len(report.Snapshots) != 1 || !report.Snapshots[0].Restorable {
		t.Fatalf("baseline=%+v", report)
	}
	// Local receipts survive restarting the analyzer; a foreign VM cannot reuse one.
	restarted := New(fake.run, dir)
	if !restarted.hasReceipt(path, name) || restarted.hasReceipt(path+".other", name) {
		t.Fatal("receipt binding")
	}
	report, err = restarted.RestoreBaseline(ctx, path, name, name)
	if err != nil || report.LastSnapshot != name || report.Running {
		t.Fatalf("restore=%+v %v", report, err)
	}
	for _, args := range fake.calls {
		switch args[0] {
		case "list", "listSnapshots", "snapshot", "revertToSnapshot":
		default:
			t.Fatalf("unexpected command %v", args)
		}
	}
	fake.active = true
	report, err = c.Inspect(ctx, path)
	if err != nil || !report.Running || report.Tools != "VMware Tools работают" || !strings.Contains(report.Notice, "не подтверждают") {
		t.Fatalf("live=%+v %v", report, err)
	}
	if _, err = c.CreateBaseline(ctx, path); err == nil {
		t.Fatal("snapshot of running VM allowed")
	}
	if _, err = c.RestoreBaseline(ctx, path, name, name); err == nil {
		t.Fatal("restore of running VM allowed")
	}
}

func TestAuditFailsClosedAndDoesNotClaimIsolation(t *testing.T) {
	_, props, err := validateVMX(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	checks := Audit(props)
	for _, ch := range checks {
		if ch.Key == "disks" {
			if ch.OK {
				t.Fatal("physical disk safety guessed")
			}
			continue
		}
		if !ch.OK {
			t.Errorf("expected setting check pass: %+v", ch)
		}
	}
	for _, tt := range []struct{ key, value, check string }{
		{"ethernet0.startconnected", "true", "network"}, {"ethernet1.present", "true", "network"}, {"ethernet2.connectiontype", "nat", "network"},
		{"isolation.tools.hgfs.disable", "false", "folders"}, {"sharedfolder0.enabled", "true", "folders"}, {"isolation.tools.copy.disable", "false", "clipboard"},
		{"isolation.tools.paste.disable", "false", "clipboard"}, {"isolation.tools.dnd.disable", "false", "dragdrop"}, {"usb.present", "true", "usb"}, {"usb.autoconnect.device0", "path:x", "usb"},
		{"scsi0:0.devicetype", "rawDisk", "disks"}, {"scsi0:0.filename", `\\.\physicaldrive0`, "disks"},
	} {
		t.Run(tt.key, func(t *testing.T) {
			p := map[string]string{}
			for k, v := range props {
				p[k] = v
			}
			p[tt.key] = strings.ToLower(tt.value)
			for _, ch := range Audit(p) {
				if ch.Key == tt.check && ch.OK {
					t.Fatalf("unsafe setting accepted: %s", tt.key)
				}
			}
		})
	}
	p := map[string]string{"ethernet0.present": "false", "ethernet0.startconnected": "true"}
	if !Audit(p)[0].OK {
		t.Fatal("absent NIC is not connected")
	}
}

func TestStrictVMXValidation(t *testing.T) {
	path := fixture(t)
	for _, bad := range []string{"relative.vmx", path + "\n", strings.TrimSuffix(path, ".vmx") + ".txt"} {
		if _, _, err := validateVMX(bad); err == nil {
			t.Errorf("invalid path %q accepted", bad)
		}
	}
	for _, text := range []string{"config.version = 0", "config.version = 8\nbroken", "config.version = 8\nConfig.Version = 8", "config.version = 8\n = true", "config.version = 8\nkey = \"broken"} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := validateVMX(path); err == nil {
			t.Errorf("ambiguous VMX %q accepted", text)
		}
	}
	if err := os.WriteFile(path, []byte("\ufeff# comment\n\nconfig.version = 8\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := validateVMX(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, (2<<20)+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := validateVMX(path); err == nil {
		t.Fatal("large VMX accepted")
	}
}

func TestSnapshotListParsing(t *testing.T) {
	for _, tt := range []struct {
		data string
		want []string
	}{
		{"Total snapshots: 0\n", []string{}}, {"Всего снимков: 2\nСнимок 1\nСнимок 2\n", []string{"Снимок 1", "Снимок 2"}},
	} {
		got, err := ParseSnapshots([]byte(tt.data))
		if err != nil || !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("snapshots=%v %v", got, err)
		}
	}
	for _, s := range []string{"", "Error: no snapshots", "Total: -1", "Total: 10001", "Total: 1", "Total: 2\nx\nx", "Total: 0\nUnexpected"} {
		if _, err := ParseSnapshots([]byte(s)); err == nil {
			t.Errorf("bad list %q accepted", s)
		}
	}
}

func TestOperationErrorsAndPowerChanges(t *testing.T) {
	path := fixture(t)
	ctx := context.Background()
	if _, err := New(nil, t.TempDir()).Inspect(ctx, path); err == nil {
		t.Fatal("missing vmrun accepted")
	}
	for _, command := range []string{"list", "listSnapshots", "snapshot"} {
		fake := &fakeVMware{path: path, fail: command}
		if _, err := New(fake.run, t.TempDir()).CreateBaseline(ctx, path); err == nil {
			t.Errorf("%s error swallowed", command)
		}
	}
	fake := &fakeVMware{path: path, badList: true}
	if _, err := New(fake.run, t.TempDir()).CreateBaseline(ctx, path); err == nil {
		t.Fatal("unknown power state accepted")
	}
	fake = &fakeVMware{path: path}
	if _, err := New(fake.run, "").CreateBaseline(ctx, path); err == nil {
		t.Fatal("missing receipt storage accepted")
	}
	fake = &fakeVMware{path: path, powerOnSnapshot: true}
	c := New(fake.run, t.TempDir())
	if _, err := c.CreateBaseline(ctx, path); err == nil {
		t.Fatal("concurrent power-on accepted")
	}
	if len(fake.names) != 1 || c.hasReceipt(path, fake.names[0]) {
		t.Fatal("unverified baseline got a receipt")
	}
	fake = &fakeVMware{path: path}
	c = New(fake.run, t.TempDir())
	report, err := c.CreateBaseline(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	name := report.LastSnapshot
	if _, err = c.RestoreBaseline(ctx, path, name, "yes"); err == nil {
		t.Fatal("missing exact confirmation accepted")
	}
	if _, err = c.RestoreBaseline(ctx, path, "../../other", "../../other"); err == nil {
		t.Fatal("invalid snapshot name accepted")
	}
	other := "mega-baseline-000000000000000000000000"
	if _, err = c.RestoreBaseline(ctx, path, other, other); err == nil {
		t.Fatal("foreign snapshot allowed")
	}
	fake.fail = "revertToSnapshot"
	if _, err = c.RestoreBaseline(ctx, path, name, name); err == nil {
		t.Fatal("restore failure swallowed")
	}
	fake.fail = ""
	fake.names = nil
	if _, err = c.RestoreBaseline(ctx, path, name, name); err == nil {
		t.Fatal("missing snapshot allowed")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = c.Inspect(canceled, path); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
}

func TestBusyAndCanceledInspect(t *testing.T) {
	path := fixture(t)
	entered := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var once sync.Once
	c := New(func(ctx context.Context, args ...string) ([]byte, error) {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		return nil, ctx.Err()
	}, t.TempDir())
	done := make(chan error, 1)
	go func() { _, err := c.Inspect(ctx, path); done <- err }()
	<-entered
	if _, err := c.Inspect(context.Background(), path); !errors.Is(err, ErrBusy) {
		t.Fatalf("busy inspect=%v", err)
	}
	if _, err := c.CreateBaseline(context.Background(), path); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if _, err := c.RestoreBaseline(context.Background(), path, "x", "x"); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestReceiptTamperingAndBoundedOutput(t *testing.T) {
	path := fixture(t)
	name := "mega-baseline-000000000000000000000000"
	dir := t.TempDir()
	c := New(nil, dir)
	for _, record := range []any{receipt{path, name, true, 2}, receipt{path, name, false, 1}, receipt{path + "other", name, true, 1}, map[string]any{"unknown": true}} {
		b, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(c.receiptPath(path, name), b, 0600); err != nil {
			t.Fatal(err)
		}
		if c.hasReceipt(path, name) {
			t.Fatalf("tampered receipt accepted: %s", b)
		}
	}
	if err := os.WriteFile(c.receiptPath(path, name), []byte(`{} {}`), 0600); err != nil {
		t.Fatal(err)
	}
	if c.hasReceipt(path, name) {
		t.Fatal("trailing JSON accepted")
	}
	if err := os.WriteFile(c.receiptPath(path, name), make([]byte, 5000), 0600); err != nil {
		t.Fatal(err)
	}
	if c.hasReceipt(path, name) {
		t.Fatal("oversized receipt")
	}
	if err := c.saveReceipt(path, name); err == nil {
		t.Fatal("receipt overwritten")
	}
	b := &boundedOutput{}
	n, err := b.Write(make([]byte, (1<<20)+100))
	if err != nil || n != (1<<20)+100 || len(b.Bytes()) != 1<<20 || !b.overflow {
		t.Fatal("output was not bounded")
	}
	if _, err := ExecRunner(filepath.Join(t.TempDir(), "missing-vmrun"))(context.Background(), "list"); err == nil {
		t.Fatal("exec error swallowed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ExecRunner("missing")(ctx, "list"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestSuspendedVMNeverTreatedAsPoweredOff(t *testing.T) {
	path := fixture(t)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.WriteString("checkpoint.vmState = \"Lab VM.vmss\"\n")
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeVMware{path: path}
	c := New(fake.run, t.TempDir())
	rep, err := c.Inspect(context.Background(), path)
	if err != nil || !rep.Suspended || rep.Running {
		t.Fatalf("inspect=%+v %v", rep, err)
	}
	if _, err := c.CreateBaseline(context.Background(), path); err == nil {
		t.Fatal("suspended baseline allowed")
	}
	name := "mega-baseline-0123456789abcdef01234567"
	if _, err := c.RestoreBaseline(context.Background(), path, name, name); err == nil {
		t.Fatal("suspended restore allowed")
	}
	for _, call := range fake.calls {
		if call[0] == "snapshot" || call[0] == "revertToSnapshot" {
			t.Fatal(call)
		}
	}
}

func TestNetworkStartDisconnectedWithoutPresentIsUnknown(t *testing.T) {
	checks := Audit(map[string]string{"ethernet0.startconnected": "false"})
	if checks[0].Key != "network" || checks[0].OK {
		t.Fatalf("unknown network presence accepted: %+v", checks[0])
	}
}
