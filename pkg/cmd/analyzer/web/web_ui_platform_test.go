package web

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The environment picker used to derive its whole identity from runtime.GOOS,
// which called an Android tablet running Termux a Linux desktop. describeHost
// reads nothing from the machine, so these tests pin the labelling rules and
// run identically on CI and on the phone.

func TestDescribeHostAndroidUsesModelAndVersion(t *testing.T) {
	h := describeHost(hostInfo{
		OS: "linux", Arch: "arm64", Android: true, Termux: true,
		Model: "SM-X510", Vendor: "samsung", Release: "14", SDK: "34",
	})

	if h.Label != "Samsung SM-X510 (this device)" {
		t.Errorf("label = %q", h.Label)
	}
	if h.Family != "android" || h.Icon != "android" {
		t.Errorf("family/icon = %q/%q, want android/android", h.Family, h.Icon)
	}
	for _, want := range []string{"Android 14", "API 34", "Termux", "arm64"} {
		if !strings.Contains(h.Sub, want) {
			t.Errorf("sub %q is missing %q", h.Sub, want)
		}
	}
	// GOOS has to survive untouched: other code still switches on it.
	if h.OS != "linux" {
		t.Errorf("OS = %q, want the original GOOS", h.OS)
	}
}

func TestDescribeHostAndroidFallsBackWithoutModel(t *testing.T) {
	h := describeHost(hostInfo{OS: "linux", Arch: "arm", Android: true})

	if h.Label != "Android device (this device)" {
		t.Errorf("label = %q", h.Label)
	}
	if h.Family != "android" {
		t.Errorf("family = %q, want android", h.Family)
	}
	// A blank getprop must not turn into "Android " or "API ".
	if strings.Contains(h.Sub, "Android ") || strings.Contains(h.Sub, "API ") {
		t.Errorf("sub %q invented a version it was never given", h.Sub)
	}
	if h.Sub != "arm" {
		t.Errorf("sub = %q, want just the arch", h.Sub)
	}
}

// Android wins over the distro name: Termux sitting on an Android system image
// must not introduce itself as whatever /etc/os-release happens to say.
func TestDescribeHostAndroidBeatsDistro(t *testing.T) {
	h := describeHost(hostInfo{
		OS: "linux", Arch: "arm64", Android: true,
		Model: "Pixel 8", Distro: "Debian GNU/Linux 12",
	})
	if !strings.HasPrefix(h.Label, "Pixel 8") {
		t.Errorf("label = %q, want the device model to win", h.Label)
	}
	if h.Family != "android" {
		t.Errorf("family = %q, want android", h.Family)
	}
}

func TestDescribeHostNonAndroidPlatforms(t *testing.T) {
	cases := []struct {
		name  string
		in    hostInfo
		label string
		fam   string
		ico   string
	}{
		{"windows", hostInfo{OS: "windows", Arch: "amd64"}, "Windows (this machine)", "windows", "win"},
		{"darwin", hostInfo{OS: "darwin", Arch: "arm64"}, "macOS (this machine)", "macos", "macos"},
		{"bare linux", hostInfo{OS: "linux", Arch: "amd64"}, "Linux (this machine)", "linux", "linux"},
		{"distro linux", hostInfo{OS: "linux", Arch: "arm64", Distro: "Arch Linux ARM"}, "Arch Linux ARM (this machine)", "linux", "linux"},
		{"unknown goos", hostInfo{OS: "plan9", Arch: "386"}, "plan9 host", "any", "other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := describeHost(tc.in)
			if got.Label != tc.label {
				t.Errorf("label = %q, want %q", got.Label, tc.label)
			}
			if got.Family != tc.fam {
				t.Errorf("family = %q, want %q", got.Family, tc.fam)
			}
			if got.Icon != tc.ico {
				t.Errorf("icon = %q, want %q", got.Icon, tc.ico)
			}
			if got.Sub != tc.in.Arch {
				t.Errorf("sub = %q, want the arch %q", got.Sub, tc.in.Arch)
			}
		})
	}
}

func TestVendorPrefixAvoidsDuplication(t *testing.T) {
	cases := []struct{ vendor, model, want string }{
		{"samsung", "SM-X510", "Samsung SM-X510"},
		{"Google", "Google Pixel 8", "Google Pixel 8"},
		{"Xiaomi", "Xiaomi 13T Pro", "Xiaomi 13T Pro"},
		{"OnePlus", "LE2123", "OnePlus LE2123"},
		{"ASUS", "AI2201", "ASUS AI2201"},
		{"samsung", "samsung", "samsung"},
		{"", "SM-X510", "SM-X510"},
		{"samsung", "", ""},
		{"  samsung  ", "  SM-X510  ", "Samsung SM-X510"},
	}
	for _, tc := range cases {
		if got := vendorPrefix(tc.vendor, tc.model); got != tc.want {
			t.Errorf("vendorPrefix(%q, %q) = %q, want %q", tc.vendor, tc.model, got, tc.want)
		}
	}
}

func TestReadPropFileParsesAndSkipsNoise(t *testing.T) {
	path := filepath.Join(t.TempDir(), "build.prop")
	body := strings.Join([]string{
		"# begin build properties",
		"",
		"ro.product.model=SM-X510",
		"  ro.product.manufacturer = samsung  ",
		"ro.build.version.release=14",
		"malformed-line-without-a-separator",
		"# ro.product.model=COMMENTED-OUT",
		"ro.build.version.sdk=34",
		"ro.unrelated=ignored",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := readPropFile(path, "ro.product.model", "ro.product.manufacturer",
		"ro.build.version.release", "ro.build.version.sdk")

	want := map[string]string{
		"ro.product.model":         "SM-X510",
		"ro.product.manufacturer":  "samsung",
		"ro.build.version.release": "14",
		"ro.build.version.sdk":     "34",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d keys, want %d: %v", len(got), len(want), got)
	}
}

// A missing file is the normal case on every non-Android machine, so it has to
// be an empty map rather than a nil one: callers index the result directly.
func TestReadPropFileMissingFileIsEmptyNotNil(t *testing.T) {
	got := readPropFile(filepath.Join(t.TempDir(), "absent"), "ro.product.model")
	if got == nil {
		t.Fatal("returned a nil map")
	}
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

func TestOsReleasePrettyNameStripsQuotesAndFallsThrough(t *testing.T) {
	dir := t.TempDir()
	absent := filepath.Join(dir, "absent")

	quoted := filepath.Join(dir, "quoted")
	if err := os.WriteFile(quoted, []byte("NAME=Arch\nPRETTY_NAME=\"Arch Linux ARM\"\nID=archarm\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// An unreadable earlier path is skipped, not fatal.
	if got := osReleasePrettyName(absent, quoted); got != "Arch Linux ARM" {
		t.Errorf("got %q, want %q", got, "Arch Linux ARM")
	}

	bare := filepath.Join(dir, "bare")
	if err := os.WriteFile(bare, []byte("PRETTY_NAME=Debian GNU/Linux 12 (bookworm)\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := osReleasePrettyName(bare); got != "Debian GNU/Linux 12 (bookworm)" {
		t.Errorf("got %q", got)
	}

	// A blank PRETTY_NAME must fall back to the generic label, not to " (this
	// machine)" with nothing in front of it.
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("PRETTY_NAME=\"\"\nID=weird\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := osReleasePrettyName(empty); got != "" {
		t.Errorf("got %q, want empty", got)
	}
	if got := osReleasePrettyName(absent); got != "" {
		t.Errorf("got %q, want empty when nothing is readable", got)
	}
	if got := describeHost(hostInfo{OS: "linux", Arch: "arm64"}).Label; got != "Linux (this machine)" {
		t.Errorf("empty distro produced %q", got)
	}
}

func TestHostPayloadKeepsLegacyKeys(t *testing.T) {
	w := describeHost(hostInfo{OS: "windows", Arch: "amd64"}).payload()
	if w["os"] != "windows" || w["arch"] != "amd64" || w["canRunNative"] != true {
		t.Errorf("legacy keys changed meaning: %v", w)
	}

	a := describeHost(hostInfo{
		OS: "linux", Arch: "arm64", Android: true,
		Model: "SM-X510", Vendor: "samsung",
	}).payload()
	if a["canRunNative"] != false {
		t.Error("an Android host must not claim native Windows detonation")
	}
	if a["os"] != "linux" {
		t.Errorf("os = %v, want the untouched GOOS", a["os"])
	}
	if a["android"] != true || a["model"] != "SM-X510" {
		t.Errorf("android facts missing: %v", a)
	}
	for _, k := range []string{"os", "arch", "canRunNative", "android", "termux",
		"model", "vendor", "release", "sdk", "distro", "label", "sub", "icon", "family"} {
		if _, ok := a[k]; !ok {
			t.Errorf("payload is missing key %q; the SPA reads it", k)
		}
	}
}

// hostPlatform shells out to getprop, so it must answer from cache after the
// first call, and it must never contradict the runtime it was built for.
func TestHostPlatformIsCachedAndConsistent(t *testing.T) {
	first := hostPlatform()
	second := hostPlatform()
	if first != second {
		t.Errorf("not cached: %+v vs %+v", first, second)
	}
	if first.OS != runtime.GOOS || first.Arch != runtime.GOARCH {
		t.Errorf("got %s/%s, want %s/%s", first.OS, first.Arch, runtime.GOOS, runtime.GOARCH)
	}
	if first.Label == "" || first.Icon == "" || first.Family == "" {
		t.Errorf("picker fields must never be empty: %+v", first)
	}
	if first.Android && first.Family != "android" {
		t.Errorf("android host got family %q", first.Family)
	}
	if runtime.GOOS != "linux" && first.Android {
		t.Error("android detected off Linux")
	}
}

// The old "Linux" glyph was a featureless blob that read as a lightbulb.
func TestLinuxIconIsARecognisablePenguin(t *testing.T) {
	const marker = "  linux:'<svg"
	i := strings.Index(webUIHTML, marker)
	if i < 0 {
		t.Fatal("linux entry missing from OS_ICONS")
	}
	end := strings.Index(webUIHTML[i:], "',")
	if end < 0 {
		t.Fatal("unterminated linux icon entry")
	}
	icon := webUIHTML[i : i+end]

	if strings.Contains(icon, "M12 2c2 0 3 2 3 5 0 2 1 3 2 5s2 4 1 6-3 2-6 2") {
		t.Error("still the old placeholder blob")
	}
	// evenodd is what punches the eyes and beak out of the body. Without it the
	// silhouette collapses back into a solid lump.
	if !strings.Contains(icon, "evenodd") {
		t.Error("icon lost its fill-rule; the facial cut-outs will not render")
	}
	if n := strings.Count(icon, "z"); n < 4 {
		t.Errorf("found %d closed subpaths, want a body plus two eyes and a beak", n)
	}
}

// describeHost hands the SPA a bare icon key, so every key it can emit must
// exist in OS_ICONS or the picker renders the fallback question mark.
func TestEveryIconKeyDescribeHostEmitsExists(t *testing.T) {
	emitted := map[string]bool{}
	for _, h := range []hostInfo{
		{OS: "windows"}, {OS: "darwin"}, {OS: "linux"},
		{OS: "linux", Android: true}, {OS: "plan9"},
	} {
		emitted[describeHost(h).Icon] = true
	}
	if len(emitted) != 5 {
		t.Errorf("expected five distinct icon keys, got %v", emitted)
	}
	for key := range emitted {
		if !strings.Contains(webUIHTML, "  "+key+":'<svg") {
			t.Errorf("OS_ICONS has no %q entry", key)
		}
	}
}

// The host row is the machine serving the page, so it is always "detected".
// Local execution is blocked even when the host is Windows.
func TestHostRowIsAlwaysDetectedButNotAlwaysRunnable(t *testing.T) {
	if !strings.Contains(webUIHTML, "compatible:(fam===\"any\"||fam===hFam),runnable:hRun,detected:true,") {
		t.Error("host row no longer reports itself as detected")
	}
	if !strings.Contains(webUIHTML, "var hRun=false;") || !strings.Contains(webUIHTML, "Execution on this PC is blocked.") {
		t.Error("host execution must stay blocked in the web picker")
	}
	// refreshBtn is the single gate on the Run button.
	if !strings.Contains(webUIHTML, "if(curMode===\"sandbox\")ok=ok&&!!curTarget&&curTarget.runnable;") {
		t.Error("refreshBtn no longer gates the Run button on runnable")
	}
}
