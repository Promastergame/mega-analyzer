package apkloader

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// exeSuffix is the platform executable suffix (".exe" on Windows, empty
// elsewhere) so binary lookups work on Linux/macOS too. See plan §2.
func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// Aapt2Config holds the path to aapt2 binary.
type Aapt2Config struct {
	Aapt2Path string // e.g. "aapt2" or full path to aapt2.exe
}

// DefaultAapt2Config tries to find aapt2 in PATH or Android SDK.
func DefaultAapt2Config() Aapt2Config {
	cfg := Aapt2Config{}
	if Standalone() {
		return cfg
	}

	// 1. Try local project tools directory and executable path
	localCandidates := []string{
		"bin/tools/aapt2",
		"tools/windows/aapt2",
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		localCandidates = append(localCandidates,
			filepath.Join(exeDir, "tools", "aapt2"),
			filepath.Join(exeDir, "tools", "windows", "aapt2"),
			filepath.Join(exeDir, "bin", "tools", "aapt2"),
			filepath.Join(exeDir, "..", "tools", "windows", "aapt2"),
			filepath.Join(exeDir, "..", "bin", "tools", "aapt2"),
		)
	}

	checkExists := func(paths []string) string {
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				return p
			}
			if suf := exeSuffix(); suf != "" {
				if _, err := os.Stat(p + suf); err == nil {
					return p + suf
				}
			}
		}
		return ""
	}

	if found := checkExists(localCandidates); found != "" {
		cfg.Aapt2Path = found
		return cfg
	}

	// 2. Try $PATH
	if p, err := exec.LookPath("aapt2"); err == nil {
		cfg.Aapt2Path = p
		return cfg
	}

	// 2. Try SDK directories
	var sdkPaths []string
	for _, env := range []string{"ANDROID_HOME", "ANDROID_SDK_ROOT"} {
		if sdk := os.Getenv(env); sdk != "" {
			sdkPaths = append(sdkPaths, sdk)
		}
	}
	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		sdkPaths = append(sdkPaths, filepath.Join(localAppData, "Android", "Sdk"))
	}

	for _, sdk := range sdkPaths {
		// First check exact known paths
		candidates := []string{
			filepath.Join(sdk, "build-tools", "latest", "aapt2"),
			filepath.Join(sdk, "build-tools", "aapt2"),
		}

		if found := checkExists(candidates); found != "" {
			cfg.Aapt2Path = found
			return cfg
		}

		// Search inside build-tools subdirectories (e.g. build-tools/36.0.0/aapt2)
		if dirs, err := os.ReadDir(filepath.Join(sdk, "build-tools")); err == nil {
			// Iterate backwards to prefer newer versions if sorted, though ReadDir is lexically sorted
			for i := len(dirs) - 1; i >= 0; i-- {
				d := dirs[i]
				if d.IsDir() {
					cand := filepath.Join(sdk, "build-tools", d.Name(), "aapt2")
					if found := checkExists([]string{cand}); found != "" {
						cfg.Aapt2Path = found
						return cfg
					}
				}
			}
		}
	}

	// 3. Fall back to the aapt2 embedded in this binary.
	if p := locateEmbeddedAapt2(); p != "" {
		cfg.Aapt2Path = p
	}
	return cfg
}

// Available reports whether aapt2 was found.
func (c Aapt2Config) Available() bool { return c.Aapt2Path != "" }

// CompileResources runs `aapt2 compile` on a res/ directory, producing
// a flat intermediate zip archive in outZip.
func (c Aapt2Config) CompileResources(resDir, outZip string, legacy bool) error {
	if !c.Available() {
		return ErrAapt2NotFound
	}

	if err := os.MkdirAll(filepath.Dir(outZip), 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(outZip), err)
	}
	os.Remove(outZip) // Ensure we overwrite

	cmd := exec.Command(c.Aapt2Path, "compile",
		"--dir", resDir,
		"-o", outZip,
		"--no-crunch",
	)
	if legacy {
		cmd.Args = append(cmd.Args, "--legacy")
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(out))
		if text != "" {
			return diagnosticsError("aapt2_compile", ParseAapt2Output("aapt2_compile", text))
		}
		return fmt.Errorf("aapt2 compile failed: %w", err)
	}
	return nil
}

// LinkResources runs `aapt2 link` to build resources.arsc, AndroidManifest.xml,
// and produce the final APK (or an intermediate zip for later merging).
func (c Aapt2Config) LinkResources(manifestPath, compiledResZip, outApk string, options Aapt2LinkOptions) error {
	if !c.Available() {
		return ErrAapt2NotFound
	}

	cmd := exec.Command(c.Aapt2Path, "link",
		"-o", outApk,
		"--manifest", manifestPath,
	)

	if len(options.FrameworkAPKs) > 0 {
		for _, f := range options.FrameworkAPKs {
			cmd.Args = append(cmd.Args, "-I", f)
		}
	} else if options.FrameworkAPK != "" {
		cmd.Args = append(cmd.Args, "-I", options.FrameworkAPK)
	}

	if options.MinSDK > 0 {
		cmd.Args = append(cmd.Args, "--min-sdk-version", fmt.Sprintf("%d", options.MinSDK))
	}
	if options.TargetSDK > 0 {
		cmd.Args = append(cmd.Args, "--target-sdk-version", fmt.Sprintf("%d", options.TargetSDK))
	}
	if options.VersionCode > 0 {
		cmd.Args = append(cmd.Args, "--version-code", fmt.Sprintf("%d", options.VersionCode))
	}
	if options.VersionName != "" {
		cmd.Args = append(cmd.Args, "--version-name", options.VersionName)
	}

	if options.PackageName != "" {
		cmd.Args = append(cmd.Args, "--package-id", options.PackageName)
	}

	// Add RE-specific strict-avoidance flags
	cmd.Args = append(cmd.Args,
		"--no-auto-version",
		"--no-version-vectors",
		"--no-version-transitions",
		"--no-resource-deduping",
		"--no-compile-sdk-metadata",
		"--warn-manifest-validation",
	)

	// Add compiled zip file directly (avoids CLI character limits)
	if compiledResZip != "" {
		cmd.Args = append(cmd.Args, compiledResZip)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(out))
		if text != "" {
			return diagnosticsError("aapt2_link", ParseAapt2Output("aapt2_link", text))
		}
		return fmt.Errorf("aapt2 link failed: %w", err)
	}
	return nil
}

// Aapt2LinkOptions controls the aapt2 link invocation.
type Aapt2LinkOptions struct {
	ManifestPath   string
	CompiledResZip string
	FrameworkAPK   string   // fallback for backward compatibility
	FrameworkAPKs  []string // paths to framework APKs (e.g., android.jar, 1.apk)
	MinSDK         int
	TargetSDK      int
	VersionCode    int
	VersionName    string
	PackageName    string // e.g. "0x7f" for app package
}

// ErrAapt2NotFound is returned when aapt2 binary is not available.
var ErrAapt2NotFound = fmt.Errorf("aapt2 not found; install Android build-tools or set ANDROID_HOME")
