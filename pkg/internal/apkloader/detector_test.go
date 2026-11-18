package apkloader

import (
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/testutil"
)

func TestDetectInputType(t *testing.T) {
	tempDir := testutil.TempDir(t)

	tests := []struct {
		name     string
		setup    func() string
		expected InputType
		wantErr  bool
	}{
		{
			name: "APK file",
			setup: func() string {
				path := filepath.Join(tempDir, "test.apk")
				f, _ := os.Create(path)
				f.Write(magicZIP)
				f.Close()
				return path
			},
			expected: InputTypeAPKFile,
			wantErr:  false,
		},
		{
			name: "DEX file by magic",
			setup: func() string {
				path := filepath.Join(tempDir, "classes.dex")
				f, _ := os.Create(path)
				f.Write(magicDEX)
				f.Close()
				return path
			},
			expected: InputTypeDEXFile,
			wantErr:  false,
		},
		{
			name: "ODEX file by magic",
			setup: func() string {
				path := filepath.Join(tempDir, "classes.odex")
				f, _ := os.Create(path)
				f.Write(magicODEX)
				f.Close()
				return path
			},
			expected: InputTypeDEXFile,
			wantErr:  false,
		},
		{
			name: "VDEX file by magic",
			setup: func() string {
				path := filepath.Join(tempDir, "classes.vdex")
				f, _ := os.Create(path)
				f.Write(magicVDEX)
				f.Close()
				return path
			},
			expected: InputTypeDEXFile,
			wantErr:  false,
		},
		{
			name: "ART file by magic",
			setup: func() string {
				path := filepath.Join(tempDir, "boot.art")
				f, _ := os.Create(path)
				f.Write(magicART)
				f.Close()
				return path
			},
			expected: InputTypeDEXFile,
			wantErr:  false,
		},
		{
			name: "ZIP archive",
			setup: func() string {
				path := filepath.Join(tempDir, "archive.zip")
				f, _ := os.Create(path)
				f.Write(magicZIP)
				f.Close()
				return path
			},
			expected: InputTypeArchiveFile,
			wantErr:  false,
		},
		{
			name: "XAPK file",
			setup: func() string {
				path := filepath.Join(tempDir, "app.xapk")
				f, _ := os.Create(path)
				f.Write(magicZIP)
				f.Close()
				return path
			},
			expected: InputTypeAPKFile,
			wantErr:  false,
		},
		{
			name: "APKS file",
			setup: func() string {
				path := filepath.Join(tempDir, "bundle.apks")
				f, _ := os.Create(path)
				f.Write(magicZIP)
				f.Close()
				return path
			},
			expected: InputTypeAPKFile,
			wantErr:  false,
		},
		{
			name: "OBB file",
			setup: func() string {
				path := filepath.Join(tempDir, "main.obb")
				f, _ := os.Create(path)
				f.Write(magicZIP)
				f.Close()
				return path
			},
			expected: InputTypeArchiveFile,
			wantErr:  false,
		},
		{
			name: "IPA file",
			setup: func() string {
				path := filepath.Join(tempDir, "app.ipa")
				f, _ := os.Create(path)
				f.Write(magicZIP)
				f.Close()
				return path
			},
			expected: InputTypeArchiveFile,
			wantErr:  false,
		},
		{
			name: "patch file",
			setup: func() string {
				path := filepath.Join(tempDir, "changes.patch")
				f, _ := os.Create(path)
				f.WriteString("diff --git a/file.txt b/file.txt")
				f.Close()
				return path
			},
			expected: InputTypePatchFile,
			wantErr:  false,
		},
		{
			name: "diff file",
			setup: func() string {
				path := filepath.Join(tempDir, "changes.diff")
				f, _ := os.Create(path)
				f.WriteString("--- a/file.txt\n+++ b/file.txt")
				f.Close()
				return path
			},
			expected: InputTypePatchFile,
			wantErr:  false,
		},
		{
			name: "smali folder",
			setup: func() string {
				dir := filepath.Join(tempDir, "decompiled")
				smaliDir := filepath.Join(dir, "smali")
				os.MkdirAll(smaliDir, 0755)
				f, _ := os.Create(filepath.Join(smaliDir, "Test.smali"))
				f.WriteString(".class public LTest;")
				f.Close()
				return dir
			},
			expected: InputTypeSmaliFolder,
			wantErr:  false,
		},
		{
			name: "cache folder with dalvik-cache",
			setup: func() string {
				dir := filepath.Join(tempDir, "cache_test")
				cacheDir := filepath.Join(dir, "dalvik-cache")
				os.MkdirAll(cacheDir, 0755)
				return dir
			},
			expected: InputTypeCacheFolder,
			wantErr:  false,
		},
		{
			name: "cache folder with oat",
			setup: func() string {
				dir := filepath.Join(tempDir, "cache_oat")
				oatDir := filepath.Join(dir, "oat")
				os.MkdirAll(oatDir, 0755)
				return dir
			},
			expected: InputTypeCacheFolder,
			wantErr:  false,
		},
		{
			name: "cache folder with vdex file",
			setup: func() string {
				dir := filepath.Join(tempDir, "cache_vdex")
				os.MkdirAll(dir, 0755)
				f, _ := os.Create(filepath.Join(dir, "base.vdex"))
				f.Close()
				return dir
			},
			expected: InputTypeCacheFolder,
			wantErr:  false,
		},
		{
			name: "non-existent path",
			setup: func() string {
				return filepath.Join(tempDir, "nonexistent")
			},
			expected: InputTypeUnknown,
			wantErr:  true,
		},
		{
			name: "unknown file type",
			setup: func() string {
				path := filepath.Join(tempDir, "unknown.txt")
				f, _ := os.Create(path)
				f.WriteString("random content")
				f.Close()
				return path
			},
			expected: InputTypeUnknown,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup()
			result, err := DetectInputType(path)

			if (err != nil) != tt.wantErr {
				t.Errorf("DetectInputType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if result != tt.expected {
				t.Errorf("DetectInputType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetectByMagic(t *testing.T) {
	tempDir := testutil.TempDir(t)

	tests := []struct {
		name     string
		magic    []byte
		expected InputType
	}{
		{
			name:     "DEX magic",
			magic:    magicDEX,
			expected: InputTypeDEXFile,
		},
		{
			name:     "ODEX magic",
			magic:    magicODEX,
			expected: InputTypeDEXFile,
		},
		{
			name:     "VDEX magic",
			magic:    magicVDEX,
			expected: InputTypeDEXFile,
		},
		{
			name:     "ART magic",
			magic:    magicART,
			expected: InputTypeDEXFile,
		},
		{
			name:     "ZIP magic",
			magic:    magicZIP,
			expected: InputTypeArchiveFile,
		},
		{
			name:     "unknown magic",
			magic:    []byte{'X', 'Y', 'Z', 'W'},
			expected: InputTypeUnknown,
		},
		{
			name:     "short file",
			magic:    []byte{'A', 'B'},
			expected: InputTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(tempDir, tt.name)
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			f.Write(tt.magic)
			f.Close()

			result, err := detectByMagic(path)
			if err != nil && tt.expected != InputTypeUnknown {
				t.Errorf("detectByMagic() error = %v", err)
			}

			if result != tt.expected {
				t.Errorf("detectByMagic() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestNormalizeArchiveType(t *testing.T) {
	tests := []struct {
		name      string
		pathLower string
		detected  InputType
		expected  InputType
	}{
		{
			name:      "APK archive",
			pathLower: "app.apk",
			detected:  InputTypeArchiveFile,
			expected:  InputTypeAPKFile,
		},
		{
			name:      "XAPK archive",
			pathLower: "app.xapk",
			detected:  InputTypeArchiveFile,
			expected:  InputTypeAPKFile,
		},
		{
			name:      "APKS archive",
			pathLower: "bundle.apks",
			detected:  InputTypeArchiveFile,
			expected:  InputTypeAPKFile,
		},
		{
			name:      "ZIP archive",
			pathLower: "data.zip",
			detected:  InputTypeArchiveFile,
			expected:  InputTypeArchiveFile,
		},
		{
			name:      "DEX file unchanged",
			pathLower: "classes.dex",
			detected:  InputTypeDEXFile,
			expected:  InputTypeDEXFile,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeArchiveType(tt.pathLower, tt.detected)
			if result != tt.expected {
				t.Errorf("normalizeArchiveType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestHasSmaliFiles(t *testing.T) {
	tempDir := testutil.TempDir(t)

	tests := []struct {
		name     string
		setup    func() string
		expected bool
	}{
		{
			name: "directory with smali folder",
			setup: func() string {
				dir := filepath.Join(tempDir, "with_smali")
				smaliDir := filepath.Join(dir, "smali")
				os.MkdirAll(smaliDir, 0755)
				return dir
			},
			expected: true,
		},
		{
			name: "directory with smali_classes2",
			setup: func() string {
				dir := filepath.Join(tempDir, "with_smali2")
				smaliDir := filepath.Join(dir, "smali_classes2")
				os.MkdirAll(smaliDir, 0755)
				return dir
			},
			expected: true,
		},
		{
			name: "directory with .smali file",
			setup: func() string {
				dir := filepath.Join(tempDir, "with_smali_file")
				os.MkdirAll(dir, 0755)
				f, _ := os.Create(filepath.Join(dir, "Test.smali"))
				f.Close()
				return dir
			},
			expected: true,
		},
		{
			name: "directory without smali",
			setup: func() string {
				dir := filepath.Join(tempDir, "no_smali")
				os.MkdirAll(dir, 0755)
				f, _ := os.Create(filepath.Join(dir, "test.txt"))
				f.Close()
				return dir
			},
			expected: false,
		},
		{
			name: "empty directory",
			setup: func() string {
				dir := filepath.Join(tempDir, "empty")
				os.MkdirAll(dir, 0755)
				return dir
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.setup()
			result := hasSmaliFiles(dir)
			if result != tt.expected {
				t.Errorf("hasSmaliFiles() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestHasCacheArtifacts(t *testing.T) {
	tempDir := testutil.TempDir(t)

	tests := []struct {
		name     string
		setup    func() string
		expected bool
	}{
		{
			name: "directory with dalvik-cache",
			setup: func() string {
				dir := filepath.Join(tempDir, "cache1")
				cacheDir := filepath.Join(dir, "dalvik-cache")
				os.MkdirAll(cacheDir, 0755)
				return dir
			},
			expected: true,
		},
		{
			name: "directory with code_cache",
			setup: func() string {
				dir := filepath.Join(tempDir, "cache2")
				cacheDir := filepath.Join(dir, "code_cache")
				os.MkdirAll(cacheDir, 0755)
				return dir
			},
			expected: true,
		},
		{
			name: "directory with oat",
			setup: func() string {
				dir := filepath.Join(tempDir, "cache3")
				oatDir := filepath.Join(dir, "oat")
				os.MkdirAll(oatDir, 0755)
				return dir
			},
			expected: true,
		},
		{
			name: "directory with .vdex file",
			setup: func() string {
				dir := filepath.Join(tempDir, "cache4")
				os.MkdirAll(dir, 0755)
				f, _ := os.Create(filepath.Join(dir, "base.vdex"))
				f.Close()
				return dir
			},
			expected: true,
		},
		{
			name: "directory with .odex file",
			setup: func() string {
				dir := filepath.Join(tempDir, "cache5")
				os.MkdirAll(dir, 0755)
				f, _ := os.Create(filepath.Join(dir, "base.odex"))
				f.Close()
				return dir
			},
			expected: true,
		},
		{
			name: "directory with .oat file",
			setup: func() string {
				dir := filepath.Join(tempDir, "cache6")
				os.MkdirAll(dir, 0755)
				f, _ := os.Create(filepath.Join(dir, "base.oat"))
				f.Close()
				return dir
			},
			expected: true,
		},
		{
			name: "directory with .art file",
			setup: func() string {
				dir := filepath.Join(tempDir, "cache7")
				os.MkdirAll(dir, 0755)
				f, _ := os.Create(filepath.Join(dir, "boot.art"))
				f.Close()
				return dir
			},
			expected: true,
		},
		{
			name: "directory without cache artifacts",
			setup: func() string {
				dir := filepath.Join(tempDir, "no_cache")
				os.MkdirAll(dir, 0755)
				f, _ := os.Create(filepath.Join(dir, "test.txt"))
				f.Close()
				return dir
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.setup()
			result := hasCacheArtifacts(dir, 0)
			if result != tt.expected {
				t.Errorf("hasCacheArtifacts() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsCachePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "path with dalvik-cache",
			path:     "/data/dalvik-cache/arm/base.dex",
			expected: true,
		},
		{
			name:     "path with code_cache",
			path:     "/data/app/com.example/code_cache/classes.dex",
			expected: true,
		},
		{
			name:     "path with oat",
			path:     "/system/framework/oat/arm64/services.odex",
			expected: true,
		},
		{
			name:     "path with odex",
			path:     "/system/app/Settings/odex/arm/Settings.odex",
			expected: true,
		},
		{
			name:     "regular path",
			path:     "/data/app/com.example/base.apk",
			expected: false,
		},
		{
			name:     "Windows path with cache",
			path:     "C:\\data\\dalvik-cache\\arm\\base.dex",
			expected: true,
		},
		{
			name:     "case insensitive",
			path:     "/data/DALVIK-CACHE/arm/base.dex",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCachePath(tt.path)
			if result != tt.expected {
				t.Errorf("isCachePath(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestIsCacheExtension(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		expected bool
	}{
		{
			name:     "vdex extension",
			filename: "base.vdex",
			expected: true,
		},
		{
			name:     "odex extension",
			filename: "classes.odex",
			expected: true,
		},
		{
			name:     "oat extension",
			filename: "boot.oat",
			expected: true,
		},
		{
			name:     "art extension",
			filename: "boot.art",
			expected: true,
		},
		{
			name:     "prof extension",
			filename: "primary.prof",
			expected: true,
		},
		{
			name:     "dex extension",
			filename: "classes.dex",
			expected: false,
		},
		{
			name:     "apk extension",
			filename: "base.apk",
			expected: false,
		},
		{
			name:     "case insensitive",
			filename: "base.VDEX",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCacheExtension(tt.filename)
			if result != tt.expected {
				t.Errorf("isCacheExtension(%q) = %v, want %v", tt.filename, result, tt.expected)
			}
		})
	}
}

func TestDetectDirectory(t *testing.T) {
	tempDir := testutil.TempDir(t)

	tests := []struct {
		name     string
		setup    func() string
		expected InputType
		wantErr  bool
	}{
		{
			name: "smali directory",
			setup: func() string {
				dir := filepath.Join(tempDir, "smali_dir")
				smaliDir := filepath.Join(dir, "smali")
				os.MkdirAll(smaliDir, 0755)
				f, _ := os.Create(filepath.Join(smaliDir, "Test.smali"))
				f.Close()
				return dir
			},
			expected: InputTypeSmaliFolder,
			wantErr:  false,
		},
		{
			name: "cache directory",
			setup: func() string {
				dir := filepath.Join(tempDir, "cache_dir")
				cacheDir := filepath.Join(dir, "dalvik-cache")
				os.MkdirAll(cacheDir, 0755)
				return dir
			},
			expected: InputTypeCacheFolder,
			wantErr:  false,
		},
		{
			name: "unknown directory",
			setup: func() string {
				dir := filepath.Join(tempDir, "unknown_dir")
				os.MkdirAll(dir, 0755)
				return dir
			},
			expected: InputTypeUnknown,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.setup()
			result, err := detectDirectory(dir)

			if (err != nil) != tt.wantErr {
				t.Errorf("detectDirectory() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if result != tt.expected {
				t.Errorf("detectDirectory() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetectFile(t *testing.T) {
	tempDir := testutil.TempDir(t)

	tests := []struct {
		name     string
		setup    func() string
		expected InputType
		wantErr  bool
	}{
		{
			name: "APK by extension",
			setup: func() string {
				path := filepath.Join(tempDir, "app.apk")
				f, _ := os.Create(path)
				f.WriteString("not a real apk")
				f.Close()
				return path
			},
			expected: InputTypeAPKFile,
			wantErr:  false,
		},
		{
			name: "AAB by extension",
			setup: func() string {
				path := filepath.Join(tempDir, "app.aab")
				f, _ := os.Create(path)
				f.WriteString("not a real aab")
				f.Close()
				return path
			},
			expected: InputTypeAPKFile,
			wantErr:  false,
		},
		{
			name: "DEX by extension",
			setup: func() string {
				path := filepath.Join(tempDir, "classes.dex")
				f, _ := os.Create(path)
				f.WriteString("not a real dex")
				f.Close()
				return path
			},
			expected: InputTypeDEXFile,
			wantErr:  false,
		},
		{
			name: "unknown file",
			setup: func() string {
				path := filepath.Join(tempDir, "unknown.xyz")
				f, _ := os.Create(path)
				f.WriteString("unknown content")
				f.Close()
				return path
			},
			expected: InputTypeUnknown,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup()
			result, err := detectFile(path)

			if (err != nil) != tt.wantErr {
				t.Errorf("detectFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if result != tt.expected {
				t.Errorf("detectFile() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Benchmark tests
func BenchmarkDetectInputType(b *testing.B) {
	tempDir := b.TempDir()
	path := filepath.Join(tempDir, "test.apk")
	f, _ := os.Create(path)
	f.Write(magicZIP)
	f.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectInputType(path)
	}
}

func BenchmarkHasSmaliFiles(b *testing.B) {
	tempDir := b.TempDir()
	smaliDir := filepath.Join(tempDir, "smali")
	os.MkdirAll(smaliDir, 0755)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasSmaliFiles(tempDir)
	}
}

func BenchmarkIsCachePath(b *testing.B) {
	path := "/data/dalvik-cache/arm/base.dex"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isCachePath(path)
	}
}
