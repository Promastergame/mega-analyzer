package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestAdminCLIOnlyWeb(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		valid bool
	}{
		{"web", []string{"-web", "-admin"}, true}, {"long", []string{"--web", "--admin=true", "--web-port", "8080"}, true},
		{"disabled", []string{"-admin=false", "-t", "пример.apk"}, true}, {"alone", []string{"-admin"}, false},
		{"api", []string{"-api", "-admin"}, false}, {"webscan", []string{"-web-scan", "-admin"}, false},
		{"sandbox", []string{"-sandbox", "-admin", "-t", "x.exe"}, false}, {"mixed", []string{"-web", "-admin", "-sandbox-stream"}, false},
		{"editor", []string{"-web", "-admin", "-edit"}, false}, {"target", []string{"-web", "-admin", "пример.apk"}, false},
		{"zeroport", []string{"-web", "-admin", "-web-port", "0"}, false}, {"largeport", []string{"-web", "-admin", "-web-port", "65536"}, false},
		{"internal", []string{"-admin-reexec"}, false}, {"relativecwd", []string{"-web", "-admin", "-admin-reexec", "-admin-cwd", "relative"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, e := NewCLIParser().Parse(tc.args)
			if (e == nil) != tc.valid {
				t.Fatalf("opts=%+v err=%v", o, e)
			}
			if e == nil && o.Admin && !o.NoProfile {
				t.Fatal("profile still enabled")
			}
		})
	}
}
func TestAdminNoImplicitProfileElevation(t *testing.T) {
	oldE, oldR := fsExists, fsReadFile
	defer func() { fsExists, fsReadFile = oldE, oldR }()
	reads := 0
	fsExists = func(string) bool { return true }
	fsReadFile = func(string) (string, error) { reads++; return "-web -admin", nil }
	if _, e := NewCLIParser().Parse([]string{"-web"}); e == nil || !strings.Contains(e.Error(), "command line") {
		t.Fatalf("implicit elevation: %v", e)
	}
	reads = 0
	if _, e := NewCLIParser().Parse([]string{"-web", "-admin"}); e != nil {
		t.Fatal(e)
	}
	if reads != 0 {
		t.Fatal("admin read a profile")
	}
	reads = 0
	fsReadFile = func(string) (string, error) { reads++; return "# benign UTF-8 профиль", nil }
	o, e := NewCLIParser().Parse([]string{"-o", "-admin", "-web"})
	if e != nil || o.Admin || reads == 0 {
		t.Fatalf("-admin as a value is not a flag: %+v %v %d", o, e, reads)
	}
}
func TestUTF8FlagsBOMAndCyrillic(t *testing.T) {
	a, e := parseFlagsFile("\uFEFF# UTF-8\r\n-target 'папка с пробелом/пример.apk'\r\n-ml-patch-min-tier имба\r\n")
	if e != nil {
		t.Fatal(e)
	}
	o, e := NewCLIParser().Parse(append([]string{"-no-profile"}, a...))
	if e != nil || o.Target != "папка с пробелом/пример.apk" || !utf8.ValidString(o.MLPatchMinTier) {
		t.Fatalf("Unicode changed: %+v %v", o, e)
	}
	if _, e := parseFlagsFile(string([]byte{0xff, 0xfe, '-', 0})); e == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}
func TestAdminCanonicalRestart(t *testing.T) {
	cwd := filepath.Join(t.TempDir(), "Рабочая папка & данные")
	o := &CLIOptions{Web: true, Admin: true, WebPort: 7475}
	child, e := NewCLIParser().Parse(adminRestartArgs(o, cwd))
	if e != nil {
		t.Fatal(e)
	}
	if !child.Web || !child.Admin || !child.adminRelaunched || !child.NoProfile || child.adminCWD != cwd || child.WebPort != 7475 {
		t.Fatalf("restart lost data: %+v", child)
	}
	if child.WebToken != "" {
		t.Fatal("fresh secret must be child-generated, not in argv")
	}
}
func TestAdminStateMachineNoRealElevation(t *testing.T) {
	t.Setenv("MEGA_ANALYZER_HOST", "")
	for _, tc := range []struct {
		name             string
		elevated, child  bool
		queryErr         error
		restarts, serves int
		fail             bool
	}{
		{"already-root", true, false, nil, 0, 1, false}, {"request", false, false, nil, 1, 0, false}, {"failed-child", false, true, nil, 0, 0, true}, {"query-error", false, false, errors.New("test"), 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, s := 0, 0
			o := &CLIOptions{Web: true, Admin: true, WebPort: 7474, adminRelaunched: tc.child}
			e := runAdminWebWith(o, func() (bool, error) { return tc.elevated, tc.queryErr }, func(exe string, args []string, cwd string) error {
				n++
				if !filepath.IsAbs(exe) || !filepath.IsAbs(cwd) || !reflect.DeepEqual(args, adminRestartArgs(o, cwd)) {
					t.Error("invalid restart")
				}
				return nil
			}, func(*CLIOptions) error { s++; return nil })
			if (e != nil) != tc.fail || n != tc.restarts || s != tc.serves {
				t.Fatalf("error=%v restart=%d serve=%d", e, n, s)
			}
		})
	}
	if e := runAdminWebWith(&CLIOptions{Admin: true}, nil, nil, nil); e == nil {
		t.Fatal("invalid mode")
	}
	if e := runAdminWebWith(&CLIOptions{Web: true, Admin: true}, nil, nil, nil); e == nil {
		t.Fatal("invalid port")
	}
	if e := runAdminWebWith(&CLIOptions{Web: true, Admin: true, WebPort: 7474, Version: true}, nil, nil, nil); e != nil {
		t.Fatal(e)
	}
}
func TestAdminHostAndToken(t *testing.T) {
	for _, h := range []string{"", "127.0.0.1", "localhost", "LOCALHOST", "::1", "127.1.2.3"} {
		if e := validateAdminHost(h); e != nil {
			t.Error(e)
		}
	}
	for _, h := range []string{"0.0.0.0", "::", "192.168.1.2", "evil.example", "127.0.0.1.evil.example", "127.0.0.1:7474"} {
		if e := validateAdminHost(h); e == nil {
			t.Errorf("accepted %s", h)
		}
	}
	for _, v := range []string{"", strings.Repeat("ab_-01", 8)} {
		if e := validateAdminToken(v); e != nil {
			t.Error(e)
		}
	}
	for _, v := range []string{"short", strings.Repeat("Ж", 32), strings.Repeat("a", 31) + "&", strings.Repeat("a", 257)} {
		if e := validateAdminToken(v); e == nil {
			t.Fatal("invalid token accepted")
		}
	}
}
func TestWindowsAdminQuoting(t *testing.T) {
	for _, tc := range []struct{ arg, want string }{{"", `""`}, {"a b", `"a b"`}, {`a"b`, `"a\"b"`}, {`C:\Рабочая папка\`, `"C:\Рабочая папка\\"`}, {`x&y%PATH%$z`, `"x&y%PATH%$z"`}} {
		if g := quoteWindowsArg(tc.arg); g != tc.want {
			t.Errorf("%q -> %q, want %q", tc.arg, g, tc.want)
		}
	}
	p, e := windowsAdminParameters([]string{"-web", "путь с пробелом", "🙂"})
	if e != nil || !utf8.ValidString(p) || !strings.Contains(p, "путь с пробелом") {
		t.Fatalf("%q %v", p, e)
	}
	if _, e := windowsAdminParameters([]string{"x\x00y"}); e == nil {
		t.Fatal("NUL accepted")
	}
	if _, e := androidAdminCommand("/x", []string{"x\x00y"}); e == nil {
		t.Fatal("NUL accepted")
	}
}
func TestAdminArgHelper(t *testing.T) {
	if os.Getenv("MEGA_ADMIN_TEST_ARGV") != "1" {
		return
	}
	for i, a := range os.Args {
		if a == "--" {
			_ = json.NewEncoder(os.Stdout).Encode(os.Args[i+1:])
			os.Exit(0)
		}
	}
	os.Exit(2)
}
func TestAndroidAdminShellRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test")
	}
	sh, e := exec.LookPath("sh")
	if e != nil {
		t.Skip("no sh")
	}
	marker := filepath.Join(t.TempDir(), "must-not-exist")
	want := []string{"папка с пробелом/🙂", "it's literal", "", "line1\nline2", "$(touch " + marker + ")", "; touch " + marker + ";", "a\\b"}
	args := append([]string{"-test.run=^TestAdminArgHelper$", "--"}, want...)
	command, e := androidAdminCommand(os.Args[0], args)
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(sh, "-c", command)
	cmd.Env = append(os.Environ(), "MEGA_ADMIN_TEST_ARGV=1")
	out, e := cmd.Output()
	if e != nil {
		t.Fatal(e)
	}
	var got []string
	if e := json.Unmarshal(out, &got); e != nil {
		t.Fatalf("%q: %v", out, e)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%#v != %#v", got, want)
	}
	if _, e := os.Stat(marker); !os.IsNotExist(e) {
		t.Fatal("shell interpolation executed")
	}
}
