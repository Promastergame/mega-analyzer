package androidsdk

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectFromRootFindsLatestBuildTools(t *testing.T) {
	root := t.TempDir()

	mustMkdirAll(t, filepath.Join(root, "platform-tools"))
	mustWriteFile(t, filepath.Join(root, "platform-tools", exeName("adb")))

	mustMkdirAll(t, filepath.Join(root, "build-tools", "34.0.0"))
	mustWriteFile(t, filepath.Join(root, "build-tools", "34.0.0", exeName("aapt2")))

	mustMkdirAll(t, filepath.Join(root, "build-tools", "36.0.0"))
	mustWriteFile(t, filepath.Join(root, "build-tools", "36.0.0", exeName("aapt2")))
	mustWriteFile(t, filepath.Join(root, "build-tools", "36.0.0", exeName("zipalign")))
	mustWriteFile(t, filepath.Join(root, "build-tools", "36.0.0", "apksigner.bat"))

	mustMkdirAll(t, filepath.Join(root, "cmdline-tools", "latest", "bin"))
	mustWriteFile(t, filepath.Join(root, "cmdline-tools", "latest", "bin", "avdmanager.bat"))

	tc := DetectFromRoot(root, "test")
	if !tc.Detected {
		t.Fatal("expected toolchain to be detected")
	}
	if tc.BuildToolsVersion != "36.0.0" {
		t.Fatalf("BuildToolsVersion = %q, want 36.0.0", tc.BuildToolsVersion)
	}
	if tc.AAPT2 == "" || filepath.Base(tc.AAPT2) != exeName("aapt2") {
		t.Fatalf("AAPT2 = %q, want detected executable", tc.AAPT2)
	}
	if tc.ZIPAlign == "" || filepath.Base(tc.ZIPAlign) != exeName("zipalign") {
		t.Fatalf("ZIPAlign = %q, want detected executable", tc.ZIPAlign)
	}
	if tc.AVDManager == "" {
		t.Fatal("expected avdmanager to be detected")
	}
}

func TestCompareVersion(t *testing.T) {
	tests := []struct {
		name     string
		left     string
		right    string
		expected int // 1 for left > right, -1 for left < right, 0 for equal
	}{
		{
			name:     "36.0.0 > 35.0.0",
			left:     "36.0.0",
			right:    "35.0.0",
			expected: 1,
		},
		{
			name:     "34.0.0-rc1 < 34.0.0",
			left:     "34.0.0-rc1",
			right:    "34.0.0",
			expected: -1,
		},
		{
			name:     "equal versions",
			left:     "30.0.0",
			right:    "30.0.0",
			expected: 0,
		},
		{
			name:     "major version difference",
			left:     "35.0.0",
			right:    "34.0.0",
			expected: 1,
		},
		{
			name:     "minor version difference",
			left:     "34.1.0",
			right:    "34.0.0",
			expected: 1,
		},
		{
			name:     "patch version difference",
			left:     "34.0.1",
			right:    "34.0.0",
			expected: 1,
		},
		{
			name:     "prerelease vs stable",
			left:     "35.0.0-beta",
			right:    "35.0.0",
			expected: -1,
		},
		{
			name:     "stable vs prerelease",
			left:     "35.0.0",
			right:    "35.0.0-alpha",
			expected: 1,
		},
		{
			name:     "different length versions",
			left:     "34.0.0.1",
			right:    "34.0.0",
			expected: 1,
		},
		{
			name:     "single digit versions",
			left:     "9",
			right:    "8",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareVersion(tt.left, tt.right)
			if (result > 0 && tt.expected <= 0) || (result < 0 && tt.expected >= 0) || (result == 0 && tt.expected != 0) {
				t.Errorf("compareVersion(%q, %q) = %d, want %d", tt.left, tt.right, result, tt.expected)
			}
		})
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("stub"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func TestDetect(t *testing.T) {
	// Test that Detect() doesn't panic
	tc := Detect()
	// We can't make strong assertions about the result since it depends on the host environment
	// but we can verify the function runs without error
	_ = tc.Detected
	_ = tc.Root
	_ = tc.Source
}

func TestDetectFromRootInvalidPath(t *testing.T) {
	tests := []struct {
		name string
		root string
	}{
		{
			name: "non-existent path",
			root: "/nonexistent/path/to/sdk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := DetectFromRoot(tt.root, "test")
			if tc.Detected {
				t.Error("expected toolchain not to be detected for invalid path")
			}
		})
	}
}

func TestDetectFromRootFileInsteadOfDirectory(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "notadir")
	mustWriteFile(t, filePath)

	tc := DetectFromRoot(filePath, "test")
	if tc.Detected {
		t.Error("expected toolchain not to be detected when root is a file")
	}
}

func TestDetectFromRootEmptySDK(t *testing.T) {
	root := t.TempDir()

	tc := DetectFromRoot(root, "test")
	if tc.Detected {
		t.Error("an empty directory must not be reported as an installed SDK")
	}
	if tc.Root != root {
		t.Errorf("Root = %q, want %q", tc.Root, root)
	}
	if tc.Source != "test" {
		t.Errorf("Source = %q, want %q", tc.Source, "test")
	}
	// All tools should be empty
	if tc.ADB != "" {
		t.Error("ADB should be empty for empty SDK")
	}
	if tc.AAPT2 != "" {
		t.Error("AAPT2 should be empty for empty SDK")
	}
}

func TestDetectFromRootWithPlatformTools(t *testing.T) {
	root := t.TempDir()

	mustMkdirAll(t, filepath.Join(root, "platform-tools"))
	mustWriteFile(t, filepath.Join(root, "platform-tools", exeName("adb")))

	tc := DetectFromRoot(root, "test")
	if !tc.Detected {
		t.Fatal("expected toolchain to be detected")
	}
	if tc.ADB == "" {
		t.Error("ADB should be detected")
	}
}

func TestDetectFromRootWithEmulator(t *testing.T) {
	root := t.TempDir()

	mustMkdirAll(t, filepath.Join(root, "emulator"))
	mustWriteFile(t, filepath.Join(root, "emulator", exeName("emulator")))

	tc := DetectFromRoot(root, "test")
	if !tc.Detected {
		t.Fatal("expected toolchain to be detected")
	}
	if tc.Emulator == "" {
		t.Error("Emulator should be detected")
	}
}

func TestDetectFromRootWithCmdlineTools(t *testing.T) {
	root := t.TempDir()

	mustMkdirAll(t, filepath.Join(root, "cmdline-tools", "latest", "bin"))
	mustWriteFile(t, filepath.Join(root, "cmdline-tools", "latest", "bin", exeName("avdmanager")))
	mustWriteFile(t, filepath.Join(root, "cmdline-tools", "latest", "bin", exeName("apkanalyzer")))

	tc := DetectFromRoot(root, "test")
	if !tc.Detected {
		t.Fatal("expected toolchain to be detected")
	}
	if tc.AVDManager == "" {
		t.Error("AVDManager should be detected")
	}
	if tc.APKAnalyzer == "" {
		t.Error("APKAnalyzer should be detected")
	}
}

func TestDetectFromRootWithVersionedCmdlineTools(t *testing.T) {
	root := t.TempDir()

	// Create multiple versions
	mustMkdirAll(t, filepath.Join(root, "cmdline-tools", "8.0", "bin"))
	mustWriteFile(t, filepath.Join(root, "cmdline-tools", "8.0", "bin", exeName("avdmanager")))

	mustMkdirAll(t, filepath.Join(root, "cmdline-tools", "9.0", "bin"))
	mustWriteFile(t, filepath.Join(root, "cmdline-tools", "9.0", "bin", exeName("avdmanager")))

	tc := DetectFromRoot(root, "test")
	if !tc.Detected {
		t.Fatal("expected toolchain to be detected")
	}
	if tc.AVDManager == "" {
		t.Error("AVDManager should be detected from versioned cmdline-tools")
	}
}

func TestDetectFromRootWithOldToolsDir(t *testing.T) {
	root := t.TempDir()

	mustMkdirAll(t, filepath.Join(root, "tools", "bin"))
	mustWriteFile(t, filepath.Join(root, "tools", "bin", exeName("avdmanager")))

	tc := DetectFromRoot(root, "test")
	if !tc.Detected {
		t.Fatal("expected toolchain to be detected")
	}
	if tc.AVDManager == "" {
		t.Error("AVDManager should be detected from tools/bin")
	}
}

func TestDetectFromRootMultipleBuildToolsVersions(t *testing.T) {
	root := t.TempDir()

	versions := []string{"30.0.0", "31.0.0", "33.0.0", "34.0.0", "35.0.0"}
	for _, version := range versions {
		mustMkdirAll(t, filepath.Join(root, "build-tools", version))
		mustWriteFile(t, filepath.Join(root, "build-tools", version, exeName("aapt2")))
	}

	tc := DetectFromRoot(root, "test")
	if !tc.Detected {
		t.Fatal("expected toolchain to be detected")
	}
	if tc.BuildToolsVersion != "35.0.0" {
		t.Errorf("BuildToolsVersion = %q, want 35.0.0", tc.BuildToolsVersion)
	}
}

func TestSplitVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected []int
	}{
		{
			name:     "simple version",
			version:  "34.0.0",
			expected: []int{34, 0, 0},
		},
		{
			name:     "version with prerelease",
			version:  "34.0.0-rc1",
			expected: []int{34, 0, 0},
		},
		{
			name:     "version with dots and dashes",
			version:  "34.0.0-beta.1",
			expected: []int{34, 0, 0},
		},
		{
			name:     "single digit",
			version:  "9",
			expected: []int{9},
		},
		{
			name:     "version with letters",
			version:  "34a",
			expected: []int{34},
		},
		{
			name:     "empty version",
			version:  "",
			expected: []int{0},
		},
		{
			name:     "non-numeric version",
			version:  "abc",
			expected: []int{0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitVersion(tt.version)
			if len(result) != len(tt.expected) {
				t.Errorf("splitVersion(%q) length = %d, want %d", tt.version, len(result), len(tt.expected))
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("splitVersion(%q)[%d] = %d, want %d", tt.version, i, result[i], tt.expected[i])
				}
			}
		})
	}
}

func TestIsPrerelease(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected bool
	}{
		{
			name:     "stable version",
			version:  "34.0.0",
			expected: false,
		},
		{
			name:     "rc version",
			version:  "34.0.0-rc1",
			expected: true,
		},
		{
			name:     "beta version",
			version:  "34.0.0-beta",
			expected: true,
		},
		{
			name:     "alpha version",
			version:  "34.0.0-alpha",
			expected: true,
		},
		{
			name:     "version with letters",
			version:  "34a",
			expected: true,
		},
		{
			name:     "numeric only",
			version:  "123",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPrerelease(tt.version)
			if result != tt.expected {
				t.Errorf("isPrerelease(%q) = %v, want %v", tt.version, result, tt.expected)
			}
		})
	}
}

func TestExeName(t *testing.T) {
	tests := []struct {
		name     string
		base     string
		expected string
	}{
		{
			name:     "adb",
			base:     "adb",
			expected: exeName("adb"),
		},
		{
			name:     "aapt2",
			base:     "aapt2",
			expected: exeName("aapt2"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := exeName(tt.base)
			// On Windows, should have .exe extension
			// On Unix, should be unchanged
			if result == "" {
				t.Error("exeName should not return empty string")
			}
		})
	}
}

func TestFirstExisting(t *testing.T) {
	tempDir := t.TempDir()

	existingFile := filepath.Join(tempDir, "exists.txt")
	mustWriteFile(t, existingFile)

	tests := []struct {
		name     string
		paths    []string
		expected string
	}{
		{
			name:     "first path exists",
			paths:    []string{existingFile, "/nonexistent"},
			expected: existingFile,
		},
		{
			name:     "second path exists",
			paths:    []string{"/nonexistent", existingFile},
			expected: existingFile,
		},
		{
			name:     "no paths exist",
			paths:    []string{"/nonexistent1", "/nonexistent2"},
			expected: "",
		},
		{
			name:     "empty paths",
			paths:    []string{"", ""},
			expected: "",
		},
		{
			name:     "directory should be skipped",
			paths:    []string{tempDir, existingFile},
			expected: existingFile,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := firstExisting(tt.paths...)
			if result != tt.expected {
				t.Errorf("firstExisting() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestLatestBuildTools(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name            string
		setup           func() string
		expectedVersion string
		expectEmpty     bool
	}{
		{
			name: "multiple versions",
			setup: func() string {
				root := filepath.Join(tempDir, "sdk1")
				versions := []string{"30.0.0", "31.0.0", "33.0.0"}
				for _, v := range versions {
					mustMkdirAll(t, filepath.Join(root, "build-tools", v))
				}
				return root
			},
			expectedVersion: "33.0.0",
			expectEmpty:     false,
		},
		{
			name: "single version",
			setup: func() string {
				root := filepath.Join(tempDir, "sdk2")
				mustMkdirAll(t, filepath.Join(root, "build-tools", "34.0.0"))
				return root
			},
			expectedVersion: "34.0.0",
			expectEmpty:     false,
		},
		{
			name: "no build-tools directory",
			setup: func() string {
				root := filepath.Join(tempDir, "sdk3")
				mustMkdirAll(t, root)
				return root
			},
			expectedVersion: "",
			expectEmpty:     true,
		},
		{
			name: "empty build-tools directory",
			setup: func() string {
				root := filepath.Join(tempDir, "sdk4")
				mustMkdirAll(t, filepath.Join(root, "build-tools"))
				return root
			},
			expectedVersion: "",
			expectEmpty:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := tt.setup()
			version, dir := latestBuildTools(root)

			if tt.expectEmpty {
				if version != "" || dir != "" {
					t.Errorf("latestBuildTools() = (%q, %q), want empty", version, dir)
				}
			} else {
				if version != tt.expectedVersion {
					t.Errorf("latestBuildTools() version = %q, want %q", version, tt.expectedVersion)
				}
				if dir == "" {
					t.Error("latestBuildTools() dir should not be empty")
				}
			}
		})
	}
}

func TestCmdlineToolCandidates(t *testing.T) {
	tempDir := t.TempDir()

	root := filepath.Join(tempDir, "sdk")
	mustMkdirAll(t, filepath.Join(root, "cmdline-tools", "latest", "bin"))
	mustMkdirAll(t, filepath.Join(root, "cmdline-tools", "9.0", "bin"))
	mustMkdirAll(t, filepath.Join(root, "cmdline-tools", "8.0", "bin"))
	mustMkdirAll(t, filepath.Join(root, "tools", "bin"))

	candidates := cmdlineToolCandidates(root, "avdmanager")

	if len(candidates) == 0 {
		t.Fatal("cmdlineToolCandidates should return candidates")
	}

	// Should include latest, versioned, and tools/bin paths
	hasLatest := false
	hasVersioned := false
	hasTools := false

	for _, candidate := range candidates {
		if strings.Contains(candidate, "latest") {
			hasLatest = true
		}
		if strings.Contains(candidate, "9.0") || strings.Contains(candidate, "8.0") {
			hasVersioned = true
		}
		if strings.Contains(candidate, filepath.Join("tools", "bin")) {
			hasTools = true
		}
	}

	if !hasLatest {
		t.Error("candidates should include latest path")
	}
	if !hasVersioned {
		t.Error("candidates should include versioned paths")
	}
	if !hasTools {
		t.Error("candidates should include tools/bin path")
	}
}

func TestDetectFromPATH(t *testing.T) {
	// Test that detectFromPATH doesn't panic
	tc := detectFromPATH()
	// We can't make strong assertions since it depends on PATH
	// but we can verify the function runs
	if tc.Source != "PATH" {
		t.Errorf("Source = %q, want %q", tc.Source, "PATH")
	}
}

// Benchmark tests
func BenchmarkDetectFromRoot(b *testing.B) {
	root := b.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "platform-tools"), 0o755); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "platform-tools", exeName("adb")), []byte("stub"), 0o644); err != nil {
		b.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "build-tools", "34.0.0"), 0o755); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "build-tools", "34.0.0", exeName("aapt2")), []byte("stub"), 0o644); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectFromRoot(root, "test")
	}
}

func BenchmarkCompareVersion(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compareVersion("36.0.0", "35.0.0")
	}
}

func BenchmarkSplitVersion(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		splitVersion("34.0.0-rc1")
	}
}
