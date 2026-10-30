package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestFridaReplArgs(t *testing.T) {
	if got := fridaReplArgs(true, "1234"); !reflect.DeepEqual(got, []string{"-p", "1234"}) {
		t.Fatalf("host args = %q", got)
	}
	if got := fridaReplArgs(false, "1234"); !reflect.DeepEqual(got, []string{"-U", "-p", "1234"}) {
		t.Fatalf("device args = %q", got)
	}
}

func TestParseFridaPsTable(t *testing.T) {
	out := "PID  Name\n---  ----\n1234 TgWsProxy_windows.exe\nnotapid broken\n5678 explorer.exe\n42\n"
	got := parseFridaPsTable(out)
	want := []fridaProc{{PID: 1234, Name: "TgWsProxy_windows.exe"}, {PID: 5678, Name: "explorer.exe"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
}

// writeFridaFixture drops an executable fake frida/frida-ps onto PATH.
func writeFridaFixture(t *testing.T, dir, name, body string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		name += ".bat"
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("@echo off\r\n"+body+"\r\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
}

func TestFridaHostProcessesListsLocal(t *testing.T) {
	dir := t.TempDir()
	rows := "echo PID  Name\necho ---  ----\necho 1234 TgWsProxy_windows.exe\necho 5678 explorer.exe"
	if runtime.GOOS == "windows" {
		rows = "echo PID  Name\r\necho ---  ----\r\necho 1234 TgWsProxy_windows.exe\r\necho 5678 explorer.exe"
	}
	writeFridaFixture(t, dir, "frida-ps", rows)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	w := httptest.NewRecorder()
	handleFridaProcesses(w, httptest.NewRequest("GET", "/api/live/frida/processes?host=1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", w.Code, w.Body.String())
	}
	var got []fridaProc
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := []fridaProc{{PID: 1234, Name: "TgWsProxy_windows.exe"}, {PID: 5678, Name: "explorer.exe"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
}

func TestFridaHostStartChecksCLI(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)

	w := httptest.NewRecorder()
	handleFridaStart(w, httptest.NewRequest("POST", "/api/live/frida/start?host=1", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("without CLI: code = %d, body = %s", w.Code, w.Body.String())
	}

	writeFridaFixture(t, dir, "frida", "exit 0")
	w = httptest.NewRecorder()
	handleFridaStart(w, httptest.NewRequest("POST", "/api/live/frida/start?host=1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("with CLI: code = %d, body = %s", w.Code, w.Body.String())
	}
}
