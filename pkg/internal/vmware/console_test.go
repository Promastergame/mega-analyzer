package vmware

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestConsoleSettingsAreLoopbackAndRestoredAfterSession(t *testing.T) {
	fake, req := hostExecutionFixture(t)
	original, _ := os.ReadFile(req.VMX)
	original = append(original, []byte("\nRemoteDisplay.vnc.enabled = \"FALSE\"\n")...)
	os.WriteFile(req.VMX, original, 0600)
	var console *Console
	req.ConsoleReady = func(v *Console) {
		console = v
		_, props, err := validateVMX(req.VMX)
		if err != nil || props["remotedisplay.vnc.ip"] != "127.0.0.1" || props["remotedisplay.vnc.enabled"] != "true" || len(v.Password()) != 8 || !strings.HasPrefix(v.address, "127.0.0.1:") {
			t.Fatal("console configuration is not loopback-only")
		}
		if !strings.Contains(string(mustReadConsoleVMX(t, req.VMX)), v.Password()) {
			t.Fatal("console password was not configured")
		}
	}
	result, err := New(fake.run, t.TempDir()).RunSession(context.Background(), req, nil)
	if err != nil || result == nil || !result.Executed || console == nil {
		t.Fatalf("console session: %+v, %v", result, err)
	}
	data := string(mustReadConsoleVMX(t, req.VMX))
	if strings.Contains(data, console.Password()) || strings.Contains(data, "RemoteDisplay.vnc.port") || !strings.Contains(data, `RemoteDisplay.vnc.enabled = "FALSE"`) {
		t.Fatal("session console settings not restored")
	}
	if console.ctx.Err() == nil {
		t.Fatal("console lifetime outlived its session")
	}
}

func mustReadConsoleVMX(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestConsoleRestorationPreservesUnrelatedVMwareChanges(t *testing.T) {
	path := executionFixture(t)
	fake := &fakeVMware{path: path}
	manager := New(fake.run, t.TempDir())
	v, err := manager.prepareConsole(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer v.close()
	file, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	file.WriteString("\ngui.lastPoweredViewMode = \"windowed\"\n")
	file.Close()
	if err := manager.restoreConsole(context.Background(), v); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mustReadConsoleVMX(t, path)), "gui.lastPoweredViewMode") {
		t.Fatal("restoration lost changes unrelated to the console")
	}
	fake.active = true
	if _, err := manager.prepareConsole(context.Background(), path); err == nil {
		t.Fatal("running VM configuration was modified")
	}
}

func TestConsoleAllowsOneClientAndStopsWithSession(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v := &Console{address: listener.Addr().String(), ctx: ctx}
	client, err := v.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if _, err := v.Open(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal("concurrent control was allowed")
	}
	if _, err := peer.Write([]byte("RFB 003.008\n")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 12)
	if _, err := io.ReadFull(client, data); err != nil || string(data) != "RFB 003.008\n" {
		t.Fatal("console bytes not received", err)
	}
	cancel()
	client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(data); err == nil {
		t.Fatal("session cancellation left console connected")
	}
}
