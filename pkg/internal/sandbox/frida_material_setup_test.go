package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFridaMaterialScriptsRespectUserOverride(t *testing.T) {
	dir := t.TempDir()
	path, err := fridaWriteScript(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "emitCryptoKey") || !strings.Contains(string(data), "Cipher.init.overloads") {
		t.Fatalf("default key hooks missing: %v", err)
	}
	custom := filepath.Join(dir, "custom.js")
	if err := os.WriteFile(custom, []byte("// analyst instrumentation"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := fridaWriteScript(dir, custom)
	if err != nil || got != custom {
		t.Fatalf("custom script overridden: %q %v", got, err)
	}
	got, err = fridaWriteWindowsScript(dir, custom, nil)
	if err != nil || got != custom {
		t.Fatalf("Windows custom script overridden: %q %v", got, err)
	}
	for _, write := range []func(string, string) (string, error){fridaWriteScript, func(dir, file string) (string, error) { return fridaWriteWindowsScript(dir, file, nil) }} {
		if _, err := write(dir, filepath.Join(dir, "missing.js")); err == nil {
			t.Fatal("accepted missing override")
		}
		if _, err := write(filepath.Join(dir, "missing"), ""); err == nil {
			t.Fatal("ignored materialisation error")
		}
	}
	path, err = fridaWriteWindowsScript(dir, "", []string{CategoryCrypto})
	if err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil || !strings.HasPrefix(string(data), `var __MEGA_ENABLED_CATEGORIES = ["Crypto"];`) || !strings.Contains(string(data), "BCryptImportKey") {
		t.Fatalf("category/script mismatch: %v", err)
	}
}

func TestFridaServerSelectionMatchesABIAndVersion(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MEGA_FRIDA_SERVER_DIR", dir)
	files := []string{
		"frida-server-999.1.0-android-x86", "frida-server-999.2.0-android-x86", "frida-server-999.3.0-android-x86_64",
		"frida-server-999.4.0-android-x86.xz", "frida-server-999.5.0-android-x86.gz",
		"frida-server-999.1.0-windows-x86.exe", "frida-server-999.2.0-windows-x86.exe", "frida-server-999.3.0-windows-x86_64.exe",
		"frida-server-999.4.0-windows-x86.exe.zip",
	}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "frida-server-999.9.0-android-x86"), 0700); err != nil {
		t.Fatal(err)
	}
	path, version := fridaServerForArch("x86")
	if path != filepath.Join(dir, files[1]) || version != "999.2.0" {
		t.Fatalf("Android ABI/version selection: %s %s", path, version)
	}
	path, version, mismatch := fridaWindowsServerForArch("386")
	if path != filepath.Join(dir, files[6]) || version != "999.2.0" || len(mismatch) == 0 {
		t.Fatalf("Windows selection: %s %s %v", path, version, mismatch)
	}
	if path, _ := fridaServerForArch(""); path != "" {
		t.Fatal("empty arch selected binary")
	}
	if path, _, _ := fridaWindowsServerForArch("unsupported"); path != "" {
		t.Fatal("unsupported arch selected binary")
	}
}

func TestFridaAndroidABIsAndFilenameBoundaries(t *testing.T) {
	for input, want := range map[string]string{"arm64-v8a": "arm64", "arm64": "arm64", "armeabi-v7a": "arm", "armeabi": "arm", "arm": "arm", "x86": "x86", "x86_64": "x86_64", "mips": ""} {
		if got := fridaArchForABI(" " + input + " "); got != want {
			t.Fatalf("%s: %s", input, got)
		}
	}
	for _, name := range []string{"frida-server-1-android-x86_64", "frida-server-1-android-x86other", "frida-server-1-android-x86A", "frida-server-1-android-x861", "frida-server-1-windows-x86"} {
		if fridaNameMatchesArch(name, "x86") {
			t.Fatalf("wrong ABI accepted: %s", name)
		}
	}
	if !fridaNameMatchesArch("frida-server-1-android-x86.xz", "x86") {
		t.Fatal("archive boundary not recognised")
	}
	if fridaVersionFromName("broken") != "" || fridaMajorMinor(" 17 ") != "17" || fridaMajorMinor("17.2.1") != "17.2" {
		t.Fatal("version parsing")
	}
}
