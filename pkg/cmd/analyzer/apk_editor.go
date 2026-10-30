package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// FindAPKEditorBinary returns the absolute path to the apk-editor executable,
// searching local output directories, the sibling apk-editor repository, and PATH.
func FindAPKEditorBinary() (string, error) {
	cwd, _ := os.Getwd()
	execPath, _ := os.Executable()
	return findAPKEditorBinary(cwd, execPath, os.Getenv("APK_EDITOR_EXE"))
}

func findAPKEditorBinary(cwd, execPath, override string) (string, error) {
	exeName := "apk-editor"
	if runtime.GOOS == "windows" {
		exeName = "apk-editor.exe"
	}

	isFile := func(path string) bool {
		info, err := os.Stat(path)
		return err == nil && info.Mode().IsRegular()
	}
	if override != "" {
		if !isFile(override) {
			return "", fmt.Errorf("APK_EDITOR_EXE does not point to an editor executable: %s", override)
		}
		return filepath.Abs(override)
	}

	candidates := []string{}
	if cwd != "" {
		candidates = append(candidates, filepath.Join(cwd, "bin", exeName))
	}
	if execPath != "" {
		dir := filepath.Dir(execPath)
		candidates = append(candidates, filepath.Join(dir, exeName), filepath.Join(dir, "..", "bin", exeName))
	}
	// Support analyzer.exe at the repository root or in bin/, regardless of cwd.
	for _, base := range []string{cwd, filepath.Dir(execPath)} {
		if base == "" || base == "." {
			continue
		}
		for range 2 {
			sibling := filepath.Join(base, "..", "apk-editor")
			for _, output := range []string{"bin", "zig-out/bin", "."} {
				candidates = append(candidates, filepath.Join(sibling, output, exeName))
			}
			base = filepath.Dir(base)
		}
	}
	for _, path := range candidates {
		if isFile(path) {
			return filepath.Abs(path)
		}
	}
	if p, err := exec.LookPath(exeName); err == nil {
		return filepath.Abs(p)
	}

	return "", fmt.Errorf("apk-editor binary not found: build the separate apk-editor repository with zig build, or set APK_EDITOR_EXE")
}

// LaunchAPKEditor opens targetPath (Smali folder or APK) in the native Zig APK Patch Editor.
// If patchesPath is provided and valid, it passes --patches <patches.json>.
func LaunchAPKEditor(targetPath string, patchesPath string) error {
	binPath, err := FindAPKEditorBinary()
	if err != nil {
		return err
	}

	args := []string{}
	if targetPath != "" {
		args = append(args, targetPath)
	}

	if patchesPath != "" {
		if _, err := os.Stat(patchesPath); err == nil {
			args = append(args, "--patches", patchesPath)
		}
	}

	cmd := exec.Command(binPath, args...)
	cmd.Dir = filepath.Dir(binPath)

	setDetachedProcess(cmd)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start APK Patch Editor: %w", err)
	}

	return nil
}
