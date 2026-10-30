package vmware

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRunningVMRestartsBeforeSampleTransfer(t *testing.T) {
	fake, req := hostExecutionFixture(t)
	fake.host.active = true
	var operations []string
	shutdownPending := 0
	runner := func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "list" && shutdownPending > 0 {
			shutdownPending--
			fake.host.active = shutdownPending > 0
		}
		if args[0] == "start" && fake.host.active {
			t.Fatal("started before power-off was confirmed")
		}
		command := args[0]
		if command == "-gu" {
			command = args[4]
		}
		if command == "stop" || command == "start" || command == "CopyFileFromHostToGuest" || command == "listProcessesInGuest" {
			operations = append(operations, command)
		}
		data, err := fake.run(ctx, args...)
		if command == "stop" && len(operations) == 2 {
			shutdownPending, fake.host.active = 2, true
		}
		return data, err
	}
	result, err := New(runner, t.TempDir()).RunSession(context.Background(), req, nil)
	if err != nil || result == nil || !result.Executed || result.VMware.Incomplete || !result.VMware.PoweredOff {
		t.Fatalf("restart result: %+v, %v", result, err)
	}
	want := []string{"listProcessesInGuest", "stop", "start", "listProcessesInGuest", "CopyFileFromHostToGuest"}
	if len(operations) < len(want) || !reflect.DeepEqual(operations[:len(want)], want) {
		t.Fatalf("unsafe operation order: %v", operations)
	}
}

func TestRunningVMPreflightFailureDoesNotChangePower(t *testing.T) {
	for _, failure := range []string{"credentials", "login", "sample", "collector", "duration", "configuration", "suspended"} {
		t.Run(failure, func(t *testing.T) {
			fake, req := hostExecutionFixture(t)
			fake.host.active = true
			switch failure {
			case "credentials":
				req.Password = ""
			case "login":
				fake.denyLogin = true
			case "sample":
				req.SamplePath += ".missing"
			case "collector":
				req.CollectorPath += ".missing"
			case "duration":
				req.Duration = -time.Second
			case "configuration":
				changeRestartVMX(t, req.VMX, false)
			case "suspended":
				changeRestartVMX(t, req.VMX, true)
			}
			_, err := New(fake.run, t.TempDir()).RunSession(context.Background(), req, nil)
			if err == nil || !fake.host.active {
				t.Fatalf("preflight failure changed guest power: %v", err)
			}
			for _, command := range fake.commands {
				if command == "stop" || command == "start" || command == "CopyFileFromHostToGuest" || command == "runProgramInGuest" {
					t.Fatalf("preflight failure reached %s", command)
				}
			}
		})
	}
}

func TestRunningVMShutdownFailureDoesNotBootOrTransfer(t *testing.T) {
	for _, failure := range []string{"stop-error", "stays-running", "cancelled", "configuration-changed", "suspended"} {
		t.Run(failure, func(t *testing.T) {
			fake, req := hostExecutionFixture(t)
			fake.host.active = true
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stopCount := 0
			runner := func(commandCtx context.Context, args ...string) ([]byte, error) {
				if args[0] != "stop" {
					return fake.run(commandCtx, args...)
				}
				stopCount++
				if len(args) != 3 || args[2] != "soft" {
					t.Fatalf("unexpected power command: %v", args)
				}
				switch failure {
				case "stop-error":
					return nil, errors.New("soft shutdown failed")
				case "stays-running":
					time.AfterFunc(30*time.Millisecond, cancel)
					return nil, nil
				case "cancelled":
					cancel()
				case "configuration-changed":
					changeRestartVMX(t, req.VMX, false)
				case "suspended":
					changeRestartVMX(t, req.VMX, true)
				}
				return fake.run(commandCtx, args...)
			}
			result, err := New(runner, t.TempDir()).RunSession(ctx, req, nil)
			if err == nil || result == nil || result.Executed || stopCount != 1 {
				t.Fatalf("shutdown failure ignored: %+v, %v, stops=%d", result, err, stopCount)
			}
			if (failure == "cancelled" || failure == "stays-running") && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
			for _, command := range fake.commands {
				if command == "start" || command == "CopyFileFromHostToGuest" || command == "runProgramInGuest" {
					t.Fatalf("shutdown failure reached %s", command)
				}
			}
		})
	}
}

func changeRestartVMX(t *testing.T, path string, suspended bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if suspended {
		text += "\ncheckpoint.vmState = \"memory.vmss\"\n"
	} else {
		text = strings.Replace(text, "ethernet0.startConnected = \"FALSE\"", "ethernet0.startConnected = \"TRUE\"", 1)
	}
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}
