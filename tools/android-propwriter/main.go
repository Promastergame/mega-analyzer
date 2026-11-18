// android-propwriter is a root-only, AVD-only property writer. It changes
// existing property areas without invoking init triggers; unset properties
// use Android's ordinary setprop service. It does not change system images.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var errNotFound = errors.New("property not found")
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func main() {
	args := os.Args[1:]
	if len(args) == 1 && args[0] == "--version" {
		fmt.Println("MegaAnalyzer AVD property writer 1")
		return
	}
	if len(args) > 0 && args[0] == "-n" {
		args = args[1:]
	}
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: android-propwriter [-n] <property> <value>")
		os.Exit(2)
	}
	if err := apply(args[0], args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func apply(key, value string) error {
	if os.Geteuid() != 0 {
		return errors.New("a root ADB shell is required")
	}
	if !keyPattern.MatchString(key) || strings.Contains(key, "..") || strings.HasPrefix(key, ".") || strings.HasSuffix(key, ".") {
		return errors.New("invalid property key")
	}
	if !strings.HasPrefix(key, "ro.") {
		return errors.New("only read-only identity/environment properties are supported")
	}
	if strings.ContainsAny(value, "\x00\r\n") || len(value) > 91 {
		return errors.New("this writer requires a single-line value of at most 91 bytes")
	}
	// These remain kernel/device artifacts even after identity properties change.
	qemu := false
	for _, path := range []string{"/dev/qemu_pipe", "/dev/goldfish_pipe", "/dev/socket/qemud"} {
		if _, err := os.Stat(path); err == nil {
			qemu = true
			break
		}
	}
	if !qemu {
		return errors.New("refusing property writes: no Android emulator device artifact found")
	}
	paths, err := propertyFiles("/dev/__properties__")
	if err != nil {
		return err
	}
	for _, path := range paths {
		err = writeProperty(path, key, value)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errNotFound) {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	// Absence already satisfies an empty desired value. Otherwise let Android
	// create a new property rather than editing the property trie ourselves.
	if value == "" {
		return nil
	}
	output, err := exec.Command("/system/bin/setprop", key, value).CombinedOutput()
	if err != nil {
		return fmt.Errorf("create property: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func propertyFiles(root string) ([]string, error) {
	st, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return []string{root}, nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, entry := range entries {
		// Context-area names are stable on Android 7+; omit index/serial files.
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "u:object_r:") {
			paths = append(paths, filepath.Join(root, entry.Name()))
		}
	}
	return paths, nil
}
