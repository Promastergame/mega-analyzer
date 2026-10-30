// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// hostInfo describes the machine the analyzer itself runs on.
//
// runtime.GOOS alone is not enough. Under Termux, and inside an Arch Linux ARM
// chroot on a phone, Go reports plain "linux" because that really is the kernel
// it is talking to. The environment picker then announced "Linux (this machine)"
// on what is actually an Android tablet: technically defensible, practically
// useless. Android publishes everything needed to say so properly, so we look
// for it instead of stopping at GOOS.
type hostInfo struct {
	Hostname string
	CPUCount int
	OS       string // runtime.GOOS, passed through untouched
	Arch     string // runtime.GOARCH, passed through untouched
	Android  bool
	Termux   bool
	Model    string // "SM-X510", "Pixel 8"
	Vendor   string // "samsung", "Google"
	Release  string // Android version, e.g. "14"
	SDK      string // API level, e.g. "34"
	Distro   string // PRETTY_NAME from /etc/os-release on non-Android Linux
	Label    string // headline the picker shows
	Sub      string // second line under the headline
	Icon     string // key into the OS_ICONS map in the SPA
	Family   string // windows | linux | macos | android | any
}

// androidSystemMarkers only exist on an Android system image. Probing files
// rather than environment variables keeps the answer right when the analyzer is
// started from a chroot, a service manager, or anything else that hands over an
// empty environment.
var androidSystemMarkers = []string{
	"/system/build.prop",
	"/system/bin/app_process",
	"/system/framework/framework.jar",
}

func looksLikeAndroid() bool {
	for _, p := range androidSystemMarkers {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return true
		}
	}
	// Termux exports PREFIX inside its own app sandbox; nothing else does.
	if strings.Contains(os.Getenv("PREFIX"), "com.termux") {
		return true
	}
	// ANDROID_ROOT is set to /system by the platform itself. ANDROID_HOME and
	// ANDROID_SDK_ROOT are deliberately not consulted: they only mean "the SDK is
	// installed", which is true on plenty of Linux and macOS desktops.
	// A random ANDROID_ROOT directory (SDKs included) is not an Android OS.
	// Only actual platform markers / the Termux app prefix above count.
	return false
}

// androidProp reads one Android system property. One process per key is slower
// than parsing a full dump, but it is also the only form that degrades well: a
// missing or restricted getprop then fails per key instead of taking every
// lookup down with it. The timeout matters because getprop can hang outright on
// a wedged property service.
func androidProp(key string) string {
	bin, err := exec.LookPath("getprop")
	if err != nil {
		if st, sErr := os.Stat("/system/bin/getprop"); sErr != nil || st.IsDir() {
			return ""
		}
		bin = "/system/bin/getprop"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// readPropFile pulls specific keys out of a key=value property file. Hardened
// ROMs and most chroots have no usable getprop on PATH, but /system/build.prop
// has been world-readable on every Android build shipped so far.
func readPropFile(path string, keys ...string) map[string]string {
	found := make(map[string]string, len(keys))
	f, err := os.Open(path)
	if err != nil {
		return found
	}
	defer f.Close()

	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if k = strings.TrimSpace(k); want[k] {
			found[k] = strings.TrimSpace(v)
		}
	}
	return found
}

// osReleasePrettyName reads PRETTY_NAME so an Arch Linux ARM chroot introduces
// itself as "Arch Linux ARM" rather than a generic "Linux".
func osReleasePrettyName(paths ...string) string {
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "PRETTY_NAME=") {
				continue
			}
			v := strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"'")
			if v = strings.TrimSpace(v); v != "" {
				return v
			}
		}
	}
	return ""
}

// vendorPrefix joins a manufacturer onto a model without the duplicates that
// plague naive concatenation: "samsung" + "SM-X510" should read "Samsung
// SM-X510", but "Google" + "Google Pixel 8" must not become "Google Google
// Pixel 8".
func vendorPrefix(vendor, model string) string {
	vendor, model = strings.TrimSpace(vendor), strings.TrimSpace(model)
	if vendor == "" || model == "" {
		return model
	}
	lv, lm := strings.ToLower(vendor), strings.ToLower(model)
	if lv == lm || strings.HasPrefix(lm, lv) {
		return model
	}
	// Only fix casing on an all-lowercase vendor string like "samsung"; leave
	// "OnePlus" and "ASUS" exactly as the ROM spelled them.
	if vendor == lv {
		r := []rune(vendor)
		vendor = strings.ToUpper(string(r[0])) + string(r[1:])
	}
	return vendor + " " + model
}

// describeHost turns raw platform facts into the strings the picker renders. It
// takes everything as arguments and reads nothing from the machine, so the
// labelling rules stay testable without an Android device.
func describeHost(h hostInfo) hostInfo {
	switch {
	case h.Android:
		h.Family, h.Icon = "android", "android"
		name := vendorPrefix(h.Vendor, h.Model)
		if name == "" {
			name = "Android device"
		}
		h.Label = name + " (this device)"
		var parts []string
		if h.Release != "" {
			parts = append(parts, "Android "+h.Release)
		}
		if h.SDK != "" {
			parts = append(parts, "API "+h.SDK)
		}
		if h.Termux {
			parts = append(parts, "Termux")
		}
		if h.Arch != "" {
			parts = append(parts, h.Arch)
		}
		h.Sub = strings.Join(parts, " · ")
	case h.OS == "windows":
		h.Family, h.Icon = "windows", "win"
		h.Label, h.Sub = "Windows (this machine)", h.Arch
	case h.OS == "darwin":
		h.Family, h.Icon = "macos", "macos"
		h.Label, h.Sub = "macOS (this machine)", h.Arch
	case h.OS == "linux":
		h.Family, h.Icon = "linux", "linux"
		name := strings.TrimSpace(h.Distro)
		if name == "" {
			name = "Linux"
		}
		h.Label, h.Sub = name+" (this machine)", h.Arch
	default:
		h.Family, h.Icon = "any", "other"
		h.Label, h.Sub = h.OS+" host", h.Arch
	}
	return h
}

func detectHostPlatform() hostInfo {
	hostname, _ := os.Hostname()
	h := hostInfo{OS: runtime.GOOS, Arch: runtime.GOARCH, Hostname: hostname, CPUCount: runtime.NumCPU()}
	if runtime.GOOS == "linux" {
		if looksLikeAndroid() {
			h.Android = true
			h.Termux = strings.Contains(os.Getenv("PREFIX"), "com.termux")
			h.Model = androidProp("ro.product.model")
			h.Vendor = androidProp("ro.product.manufacturer")
			h.Release = androidProp("ro.build.version.release")
			h.SDK = androidProp("ro.build.version.sdk")
			if h.Model == "" || h.Release == "" {
				fb := readPropFile("/system/build.prop",
					"ro.product.model", "ro.product.manufacturer",
					"ro.build.version.release", "ro.build.version.sdk")
				if h.Model == "" {
					h.Model = fb["ro.product.model"]
				}
				if h.Vendor == "" {
					h.Vendor = fb["ro.product.manufacturer"]
				}
				if h.Release == "" {
					h.Release = fb["ro.build.version.release"]
				}
				if h.SDK == "" {
					h.SDK = fb["ro.build.version.sdk"]
				}
			}
		} else {
			h.Distro = osReleasePrettyName("/etc/os-release", "/usr/lib/os-release")
		}
	}
	return describeHost(h)
}

var (
	hostPlatformOnce sync.Once
	hostPlatformInfo hostInfo
)

// hostPlatform detects the host once per process. The UI polls /api/env, and a
// cold detection shells out to getprop four times.
func hostPlatform() hostInfo {
	hostPlatformOnce.Do(func() { hostPlatformInfo = detectHostPlatform() })
	return hostPlatformInfo
}

// payload is the JSON the SPA consumes. The three original keys keep their exact
// former meaning — os stays runtime.GOOS so nothing that switches on it changes
// behaviour — and the Android facts arrive alongside them.
func (h hostInfo) payload() map[string]any {
	return map[string]any{
		"hostname":     h.Hostname,
		"cpuCount":     h.CPUCount,
		"os":           h.OS,
		"arch":         h.Arch,
		"canRunNative": h.OS == "windows",
		"android":      h.Android,
		"termux":       h.Termux,
		"model":        h.Model,
		"vendor":       h.Vendor,
		"release":      h.Release,
		"sdk":          h.SDK,
		"distro":       h.Distro,
		"label":        h.Label,
		"sub":          h.Sub,
		"icon":         h.Icon,
		"family":       h.Family,
	}
}
