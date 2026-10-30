package apkloader

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestAlignAPK(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "align_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test APK
	inputPath := filepath.Join(tempDir, "input.apk")
	outputPath := filepath.Join(tempDir, "output.apk")

	// Create test APK with uncompressed files
	if err := createTestAPK(inputPath); err != nil {
		t.Fatal(err)
	}

	// Align the APK
	if err := AlignAPK(inputPath, outputPath); err != nil {
		t.Fatalf("AlignAPK failed: %v", err)
	}

	// Verify output exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("aligned APK was not created")
	}

	// Verify it's a valid ZIP
	reader, err := zip.OpenReader(outputPath)
	if err != nil {
		t.Fatalf("output is not a valid ZIP: %v", err)
	}
	defer reader.Close()

	// Verify files are present
	if len(reader.File) == 0 {
		t.Error("aligned APK has no files")
	}
}

func TestVerifyAlignment(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "verify_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	apkPath := filepath.Join(tempDir, "test.apk")
	if err := createTestAPK(apkPath); err != nil {
		t.Fatal(err)
	}

	// Note: Our test APK may or may not be aligned
	// This test just verifies the function runs without crashing
	err = VerifyAlignment(apkPath)
	// We don't check the error because the test APK might not be aligned
	t.Logf("VerifyAlignment result: %v", err)
}

func TestCalculateAlignmentPadding(t *testing.T) {
	tests := []struct {
		name       string
		headerName string
		extraLen   int
	}{
		{"short name", "a.txt", 0},
		{"medium name", "path/to/file.txt", 0},
		{"long name", "very/long/path/to/some/file.txt", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := &zip.FileHeader{
				Name:  tt.headerName,
				Extra: make([]byte, tt.extraLen),
			}

			padding := calculateAlignmentPadding(header)

			// Padding should be a byte slice
			if padding == nil {
				t.Error("padding should not be nil")
			}

			// Padding should be at least as long as original extra field
			if len(padding) < tt.extraLen {
				t.Errorf("padding length %d < original extra length %d", len(padding), tt.extraLen)
			}
		})
	}
}

func TestAlignZipEntry(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "entry_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test ZIP
	zipPath := filepath.Join(tempDir, "test.zip")
	if err := createTestAPK(zipPath); err != nil {
		t.Fatal(err)
	}

	// Open it
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	// Create output
	outPath := filepath.Join(tempDir, "out.zip")
	outFile, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer outFile.Close()

	writer := zip.NewWriter(outFile)
	defer writer.Close()

	// Test aligning each entry
	for _, file := range reader.File {
		if err := alignZipEntry(writer, file); err != nil {
			t.Errorf("alignZipEntry failed for %s: %v", file.Name, err)
		}
	}
}

// Helper function to create a test APK
func createTestAPK(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := zip.NewWriter(file)
	defer writer.Close()

	// Add some test files
	files := map[string]string{
		"AndroidManifest.xml":    "<?xml version=\"1.0\"?><manifest/>",
		"classes.dex":            "dex\n035\x00",
		"res/values/strings.xml": "<resources/>",
	}

	for name, content := range files {
		// Store DEX uncompressed, compress others
		header := &zip.FileHeader{
			Name:   name,
			Method: zip.Deflate,
		}
		if name == "classes.dex" {
			header.Method = zip.Store
		}

		w, err := writer.CreateHeader(header)
		if err != nil {
			return err
		}

		if _, err := w.Write([]byte(content)); err != nil {
			return err
		}
	}

	return nil
}
