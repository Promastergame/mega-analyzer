package web

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDynamicTargetValidation(t *testing.T) {
	cases := []struct {
		name, target, consent, file, host string
		args                              []string
		ok                                bool
	}{
		{"no consent", "host:host", "", "app.exe", "windows", nil, false},
		{"linux host", "host:host", "yes", "app.exe", "linux", nil, false},
		{"windows args blocked", "host:host", "yes", "app.exe", "windows", []string{"-sandbox-args", `--folder C:\Program Files\Lab`, "-sandbox-profile", "basic"}, false},
		{"unknown option", "host:host", "yes", "app.exe", "windows", []string{"-sandbox-mitm"}, false},
		{"unsupported profile", "host:host", "yes", "app.exe", "windows", []string{"-sandbox-profile", "forensic"}, false},
		{"no device network isolation", "device:phone-A", "yes", "app.apk", "windows", nil, false},
		{"tcp device", "device:192.0.2.1:5555", "yes", "app.apks", "windows", []string{"-sandbox-allow-net", "-sandbox-device", "192.0.2.1:5555"}, true},
		{"mismatched identity", "device:phone-A", "yes", "app.apk", "windows", []string{"-sandbox-allow-net", "-sandbox-device", "phone-B"}, false},
		{"device memory not supported", "device:phone-A", "yes", "app.apk", "windows", []string{"-sandbox-allow-net", "-sandbox-memory", "1024"}, false},
		{"unsupported format", "device:phone-A", "yes", "app.dex", "windows", []string{"-sandbox-allow-net"}, false},
		{"no vm adapter", "vbox:lab", "yes", "app.exe", "windows", nil, false},
		{"incomplete flag", "host:host", "yes", "app.exe", "windows", []string{"-sandbox-duration"}, false},
		{"no deadline", "device:phone-A", "yes", "app.apk", "windows", []string{"-sandbox-allow-net", "-sandbox-duration", "0"}, true},
		{"three hours", "device:phone-A", "yes", "app.apk", "windows", []string{"-sandbox-allow-net", "-sandbox-duration", "10800"}, true},
		{"short duration", "host:host", "yes", "app.exe", "windows", []string{"-sandbox-duration", "4"}, false},
		{"negative duration", "host:host", "yes", "app.exe", "windows", []string{"-sandbox-duration", "-1"}, false},
		{"overflow duration", "host:host", "yes", "app.exe", "windows", []string{"-sandbox-duration", "9223372037"}, false},
		{"duplicate flag", "host:host", "yes", "app.exe", "windows", []string{"-sandbox-allow-net", "-sandbox-allow-net"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, e := validateSandboxRequest(c.target, c.consent, c.file, c.host, c.args)
			if (e == nil) != c.ok {
				t.Fatal(e)
			}
		})
	}
}
func TestDynamicLiveDeviceIsJobBound(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX ADB fixture")
	}
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "adb"), []byte("#!/bin/sh\nprintf 'List of devices attached\\nphone-A device model:PhoneA\\nphone-B device model:PhoneB\\n'\n"), 0755); e != nil {
		t.Fatal(e)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ANDROID_HOME", "")
	t.Setenv("ANDROID_SDK_ROOT", "")

	j := newScanJob("bound-test", "", t.TempDir())
	j.broadcast(`{"type":"device","details":"phone-B"}`)
	jobsMu.Lock()
	jobs[j.id] = j
	jobsMu.Unlock()
	defer func() { jobsMu.Lock(); delete(jobs, j.id); jobsMu.Unlock() }()
	r := httptest.NewRequest("GET", "/api/live/status?job=bound-test&serial=phone-A", nil)
	if s := RequestDeviceSerial(r); s != "phone-B" {
		t.Fatal(s)
	}
	j.finish(0)
	if s := RequestDeviceSerial(r); s != "" {
		t.Fatal("finished job selected", s)
	}
}
func TestDynamicUIHasNoPhantomTarget(t *testing.T) {
	if strings.Contains(webUIHTML, `label:"Android emulator"`) {
		t.Fatal("phantom row remains")
	}
	for _, s := range []string{"/api/host", "Dynamic analysis", "sandbox-target", "sandbox-consent", "sbxObservationStartTime", "resultSerial!==sbxRunSerial"} {
		if !strings.Contains(webUIHTML, s) {
			t.Fatal("missing", s)
		}
	}
}
func TestSandboxNetworkToggleExists(t *testing.T) {
	for _, s := range []string{`id="sbxNetToggle"`, `id="sbxNetToggleState"`, `syncNetToggle`, `sbxAllowNet`} {
		if !strings.Contains(webUIHTML, s) {
			t.Fatal("missing", s)
		}
	}
}
func TestSandboxProcessSelectionCanBeCleared(t *testing.T) {
	for _, s := range []string{
		`sbxSelectedPid`,
		`function deselectSandboxProcess()`,
		`if(sbxSelectedPid===pid){deselectSandboxProcess();return;}`,
		`sbx-detail-close`,
		`onclick="deselectSandboxProcess()"`,
	} {
		if !strings.Contains(webUIHTML, s) {
			t.Fatal("missing", s)
		}
	}
}
func TestSandboxAndroidOnlyNoteExists(t *testing.T) {
	for _, s := range []string{`id="sbxAndroidOnlyNote"`, `Android-only options`, `show("sbxAndroidOnlyNote",!android)`} {
		if !strings.Contains(webUIHTML, s) {
			t.Fatal("missing", s)
		}
	}
}
func TestFridaHostTerminalExists(t *testing.T) {
	for _, s := range []string{`fridaURL`, `host=1`, `syncFridaToolbar`, `id="fridaStartBtn"`, `id="fridaRepackBtn"`, `Local frida`, `sample process auto-selected`} {
		if !strings.Contains(webUIHTML, s) {
			t.Fatal("missing", s)
		}
	}
}
func TestSandboxViewportAndStopReasonExist(t *testing.T) {
	for _, s := range []string{
		`id="sbxViewOutputBtn"`, `id="sbxViewScreenBtn"`, `switchSbxView`, `syncSbxView`,
		`sbxStopReason`, `STOPPED`, `Stopped by you`,
		`id="sbxResizeHandle"`, `sbxResetRows`, `sbxApplySavedRows`,
		`bluescreen this PC`,
	} {
		if !strings.Contains(webUIHTML, s) {
			t.Fatal("missing", s)
		}
	}
}
