package androidsdk

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// Toolchain describes an optional Android SDK installation discovered on the host.
type Toolchain struct {
	Detected          bool
	Root              string
	Source            string
	BuildToolsVersion string
	ADB               string
	AAPT2             string
	APKAnalyzer       string
	APKSigner         string
	ZIPAlign          string
	Emulator          string
	AVDManager        string
}

// Detect discovers an Android SDK installation from environment variables and common locations.
func Detect() Toolchain {
	root, source := detectRoot()
	if root == "" {
		return detectFromPATH()
	}
	return DetectFromRoot(root, source)
}

// DetectFromRoot inspects a specific SDK root.
func DetectFromRoot(root, source string) Toolchain {
	root = strings.TrimSpace(root)
	if root == "" {
		return Toolchain{}
	}
	root = filepath.Clean(root)
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return Toolchain{}
	}

	tc := Toolchain{
		Detected: true,
		Root:     root,
		Source:   source,
	}

	tc.ADB = firstExisting(
		filepath.Join(root, "platform-tools", exeName("adb")),
		filepath.Join(root, "platform-tools", "adb"),
	)
	tc.Emulator = firstExisting(
		filepath.Join(root, "emulator", exeName("emulator")),
		filepath.Join(root, "emulator", "emulator"),
	)
	tc.AVDManager = firstExisting(cmdlineToolCandidates(root, "avdmanager")...)
	tc.APKAnalyzer = firstExisting(cmdlineToolCandidates(root, "apkanalyzer")...)

	if version, dir := latestBuildTools(root); version != "" && dir != "" {
		tc.BuildToolsVersion = version
		tc.AAPT2 = firstExisting(
			filepath.Join(dir, exeName("aapt2")),
			filepath.Join(dir, "aapt2"),
		)
		tc.ZIPAlign = firstExisting(
			filepath.Join(dir, exeName("zipalign")),
			filepath.Join(dir, "zipalign"),
		)
		tc.APKSigner = firstExisting(
			filepath.Join(dir, exeName("apksigner")),
			filepath.Join(dir, "apksigner"),
			filepath.Join(dir, "apksigner.bat"),
		)
	}

	tc.Detected = tc.ADB != "" || tc.Emulator != "" || tc.AAPT2 != "" || tc.APKAnalyzer != "" || tc.AVDManager != "" || tc.APKSigner != "" || tc.ZIPAlign != ""
	return tc
}

func detectRoot() (string, string) {
	seen := make(map[string]struct{})
	type candidate struct {
		path   string
		source string
	}

	candidates := make([]candidate, 0, 8)
	add := func(path, source string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		key := strings.ToLower(path)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		candidates = append(candidates, candidate{path: path, source: source})
	}

	add(os.Getenv("ANDROID_SDK_ROOT"), "ANDROID_SDK_ROOT")
	add(os.Getenv("ANDROID_HOME"), "ANDROID_HOME")

	home, _ := os.UserHomeDir()
	localAppData := os.Getenv("LOCALAPPDATA")

	switch runtime.GOOS {
	case "windows":
		add(filepath.Join(localAppData, "Android", "Sdk"), "LOCALAPPDATA")
		add(filepath.Join(home, "AppData", "Local", "Android", "Sdk"), "USERPROFILE")
	case "darwin":
		add(filepath.Join(home, "Library", "Android", "sdk"), "HOME")
		add(filepath.Join(home, "Android", "Sdk"), "HOME")
	default:
		add(filepath.Join(home, "Android", "Sdk"), "HOME")
		add("/opt/android-sdk", "system")
		add("/usr/lib/android-sdk", "system")
	}

	for _, candidate := range candidates {
		if info, err := os.Stat(candidate.path); err == nil && info.IsDir() {
			if tc := DetectFromRoot(candidate.path, candidate.source); tc.Detected {
				return candidate.path, candidate.source
			}
		}
	}
	return "", ""
}

func detectFromPATH() Toolchain {
	tc := Toolchain{
		ADB:         lookPath(exeName("adb"), "adb"),
		AAPT2:       lookPath(exeName("aapt2"), "aapt2"),
		APKAnalyzer: lookPath(exeName("apkanalyzer"), "apkanalyzer"),
		APKSigner:   lookPath(exeName("apksigner"), "apksigner", "apksigner.bat"),
		ZIPAlign:    lookPath(exeName("zipalign"), "zipalign"),
		Emulator:    lookPath(exeName("emulator"), "emulator"),
		AVDManager:  lookPath(exeName("avdmanager"), "avdmanager", "avdmanager.bat"),
		Source:      "PATH",
	}
	tc.Detected = tc.ADB != "" || tc.AAPT2 != "" || tc.APKAnalyzer != "" || tc.ZIPAlign != "" || tc.Emulator != ""
	return tc
}

func cmdlineToolCandidates(root, tool string) []string {
	var candidates []string
	latest := filepath.Join(root, "cmdline-tools", "latest", "bin")
	candidates = append(candidates,
		filepath.Join(latest, exeName(tool)),
		filepath.Join(latest, tool),
		filepath.Join(latest, tool+".bat"),
	)

	entries, err := os.ReadDir(filepath.Join(root, "cmdline-tools"))
	if err == nil {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			if strings.EqualFold(name, "latest") {
				continue
			}
			names = append(names, name)
		}
		sort.Slice(names, func(i, j int) bool { return compareVersion(names[i], names[j]) > 0 })
		for _, name := range names {
			dir := filepath.Join(root, "cmdline-tools", name, "bin")
			candidates = append(candidates,
				filepath.Join(dir, exeName(tool)),
				filepath.Join(dir, tool),
				filepath.Join(dir, tool+".bat"),
			)
		}
	}

	toolsBin := filepath.Join(root, "tools", "bin")
	candidates = append(candidates,
		filepath.Join(toolsBin, exeName(tool)),
		filepath.Join(toolsBin, tool),
		filepath.Join(toolsBin, tool+".bat"),
	)
	return candidates
}

func latestBuildTools(root string) (string, string) {
	dir := filepath.Join(root, "build-tools")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", ""
	}

	versions := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			versions = append(versions, entry.Name())
		}
	}
	if len(versions) == 0 {
		return "", ""
	}

	sort.Slice(versions, func(i, j int) bool { return compareVersion(versions[i], versions[j]) > 0 })
	version := versions[0]
	return version, filepath.Join(dir, version)
}

func compareVersion(left, right string) int {
	lparts := splitVersion(left)
	rparts := splitVersion(right)
	maxLen := len(lparts)
	if len(rparts) > maxLen {
		maxLen = len(rparts)
	}
	for i := 0; i < maxLen; i++ {
		li := 0
		ri := 0
		if i < len(lparts) {
			li = lparts[i]
		}
		if i < len(rparts) {
			ri = rparts[i]
		}
		switch {
		case li > ri:
			return 1
		case li < ri:
			return -1
		}
	}
	lpre := isPrerelease(left)
	rpre := isPrerelease(right)
	switch {
	case lpre && !rpre:
		return -1
	case !lpre && rpre:
		return 1
	}
	return strings.Compare(left, right)
}

func splitVersion(raw string) []int {
	cut := len(raw)
	for i, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			cut = i
			break
		}
	}
	raw = raw[:cut]
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return !(r >= '0' && r <= '9')
	})
	if len(fields) == 0 {
		return []int{0}
	}
	out := make([]int, 0, len(fields))
	for _, field := range fields {
		n, err := strconv.Atoi(field)
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return []int{0}
	}
	return out
}

func isPrerelease(raw string) bool {
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

func exeName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}

func firstExisting(paths ...string) string {
	for _, path := range paths {
		if path == "" {
			continue
		}
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func lookPath(names ...string) string {
	for _, name := range names {
		if name == "" {
			continue
		}
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}
