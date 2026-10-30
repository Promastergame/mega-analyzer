package apkloader

import (
	"archive/zip"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/androidsdk"
)

const (
	// alignmentBoundary is the 4-byte boundary for ZIP alignment
	alignmentBoundary = 4
)

// AlignAPK aligns stored files in an APK: 16 KiB pages for uncompressed
// native libraries, 4-byte boundaries for other stored entries. The
// official tool is preferred when it proves sufficient; when its output
// fails native verification (notably pre-16K binaries aligning .so to 4 KiB
// only) the built-in fallback rewrites the output.
func AlignAPK(inputPath, outputPath string) error {
	if err := tryOfficialZipAlign(inputPath, outputPath); err == nil {
		if verr := VerifyAlignment(outputPath); verr == nil {
			return nil
		}
	}
	return alignAPKNative(inputPath, outputPath)
}

func alignAPKNative(inputPath, outputPath string) error {
	// Open input APK
	reader, err := zip.OpenReader(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input APK: %w", err)
	}
	defer reader.Close()

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Create ZIP writer
	writer := zip.NewWriter(outFile)
	defer writer.Close()

	// Process each file
	for _, file := range reader.File {
		if err := alignZipEntry(writer, file); err != nil {
			return fmt.Errorf("failed to align %s: %w", file.Name, err)
		}
	}

	return nil
}

func findZipAlignExecutable() string {
	candidates := []string{
		"bin/tools/zipalign.exe",
		"tools/windows/zipalign.exe",
		"bin/tools/zipalign",
		"tools/windows/zipalign",
	}

	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "tools", "zipalign.exe"),
			filepath.Join(exeDir, "tools", "windows", "zipalign.exe"),
			filepath.Join(exeDir, "bin", "tools", "zipalign.exe"),
			filepath.Join(exeDir, "..", "tools", "windows", "zipalign.exe"),
			filepath.Join(exeDir, "..", "bin", "tools", "zipalign.exe"),
		)
	}

	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}

	tc := androidsdk.Detect()
	if tc.ZIPAlign != "" {
		return tc.ZIPAlign
	}

	if p, err := exec.LookPath("zipalign"); err == nil {
		return p
	}

	return ""
}

func tryOfficialZipAlign(inputPath, outputPath string) error {
	if Standalone() {
		return fmt.Errorf("%s", StandaloneReason("zipalign"))
	}
	bin := findZipAlignExecutable()
	if bin == "" {
		return fmt.Errorf("official zipalign not available")
	}

	cmd := exec.Command(bin, "-f", "-p", "4", inputPath, outputPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(output))
		if text == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, text)
	}
	return nil
}

// alignWriterOffsets tracks the write offset per *zip.Writer so the fallback
// aligner can compute data alignment from the true file position instead of
// only the local header size. Go's zip.Writer does not expose its position.
var alignWriterOffsets sync.Map // map[*zip.Writer]int64

func alignWriterOffset(w *zip.Writer) int64 {
	if v, ok := alignWriterOffsets.Load(w); ok {
		if n, ok := v.(int64); ok {
			return n
		}
	}
	return 0
}

func alignWriterAdvance(w *zip.Writer, n int64) {
	cur := alignWriterOffset(w)
	alignWriterOffsets.Store(w, cur+n)
}

// alignZipEntry aligns a single ZIP entry
func alignZipEntry(w *zip.Writer, file *zip.File) error {
	offset := alignWriterOffset(w)
	newOffset, err := alignZipEntryAt(w, file, offset)
	if err != nil {
		return err
	}
	alignWriterOffsets.Store(w, newOffset)
	return nil
}

// alignZipEntryAt writes one entry assuming the writer is at absolute offset
// off and returns the offset after the entry. Exported logic is kept small so
// AlignAPK and direct callers share the same alignment math.
func alignZipEntryAt(w *zip.Writer, file *zip.File, off int64) (int64, error) {
	// Directory entries carry no payload: copy verbatim, never pad.
	if strings.HasSuffix(file.Name, "/") {
		if _, err := w.CreateRaw(&file.FileHeader); err != nil {
			return off, err
		}
		headerSize := int64(30 + len(file.Name) + len(file.FileHeader.Extra))
		return off + headerSize, nil
	}
	// For compressed files (Deflate), preserve the exact compressed bytes via CreateRaw
	if file.Method == zip.Deflate {
		rc, err := file.OpenRaw()
		if err != nil {
			return off, err
		}
		if closer, ok := rc.(io.Closer); ok {
			defer closer.Close()
		}

		header := file.FileHeader
		headerSize := int64(30 + len(header.Name) + len(header.Extra))
		raw, err := w.CreateRaw(&file.FileHeader)
		if err != nil {
			return off, err
		}
		n, err := io.Copy(raw, rc)
		if err != nil {
			return off, err
		}
		// Compressed size is the on-disk payload; fall back to copied bytes.
		payload := int64(file.CompressedSize64)
		if payload == 0 {
			payload = n
		}
		return off + headerSize + payload, nil
	}

	// For uncompressed (Store) files, calculate padding from the true file
	// offset and write via CreateRaw. CreateHeader would let Go's zip writer
	// inject its own extra fields (UTF-8/timestamp, data descriptor), which
	// breaks the offset math: observed 45 instead of 36 for a 1-byte entry.
	// CreateRaw writes the header exactly as given, so alignment holds.
	rc, err := file.Open()
	if err != nil {
		return off, err
	}
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return off, err
	}

	header := file.FileHeader
	header.Method = zip.Store
	header.Flags &^= 1 << 3 // clear data-descriptor bit; sizes are known
	header.Flags &^= 1 << 11 // clear UTF-8 flag to avoid automatic extra
	header.Extra = calculateAlignmentPaddingAt(&header, off)
	header.CRC32 = crc32.ChecksumIEEE(data)
	header.UncompressedSize64 = uint64(len(data))
	header.CompressedSize64 = uint64(len(data))
	header.UncompressedSize = uint32(len(data))
	header.CompressedSize = uint32(len(data))
	// Drop fields that force Go to emit extra blocks.
	header.ModifiedTime = 0
	header.ModifiedDate = 0
	header.ExternalAttrs = 0
	header.CreatorVersion = 20

	raw, err := w.CreateRaw(&header)
	if err != nil {
		return off, err
	}
	if _, err := raw.Write(data); err != nil {
		return off, err
	}
	headerSize := int64(30 + len(header.Name) + len(header.Extra))
	return off + headerSize + int64(len(data)), nil
}

// alignmentForEntry returns the required data alignment for a stored entry:
// 16 KiB pages for uncompressed native libraries (Android 15 requirement),
// 4-byte boundaries for everything else.
func alignmentForEntry(name string) int64 {
	low := strings.ToLower(name)
	if strings.HasPrefix(low, "lib/") && strings.HasSuffix(low, ".so") {
		return soPageAlign
	}
	return alignmentBoundary
}

// calculateAlignmentPadding calculates the padding needed for 4-byte alignment
// assuming the entry starts at offset 0 (legacy wrapper).
func calculateAlignmentPadding(header *zip.FileHeader) []byte {
	return calculateAlignmentPaddingAt(header, 0)
}

// calculateAlignmentPaddingAt computes alignment padding from the true file
// offset so consecutive stored entries stay aligned. The data starts at
// off + 30 + len(name) + len(extra); we append one extra field (ID+size+pad)
// when needed so the total header size aligns the payload. The extra field
// uses the standard zipalign header ID 0xD935.
func calculateAlignmentPaddingAt(header *zip.FileHeader, off int64) []byte {
	align := alignmentForEntry(header.Name)
	headerSize := off + 30 + int64(len(header.Name)) + int64(len(header.Extra))

	// Calculate padding needed to align to the boundary. The extra field
	// itself costs 4 bytes, which is a multiple of 4 but not of 16 KiB, so
	// for page alignment solve (headerSize + 4 + pad) % align == 0.
	var padding int64
	if align == alignmentBoundary {
		padding = (align - headerSize%align) % align
	} else {
		padding = (align - (headerSize+4)%align) % align
	}

	if padding == 0 {
		return header.Extra
	}

	paddingExtra := make([]byte, 4+padding)
	paddingExtra[0] = 0x35 // standard zipalign alignment header ID 0xD935
	paddingExtra[1] = 0xD9
	paddingExtra[2] = byte(padding & 0xFF)
	paddingExtra[3] = byte((padding >> 8) & 0xFF)

	// Combine existing extra field with padding
	result := make([]byte, len(header.Extra)+len(paddingExtra))
	copy(result, header.Extra)
	copy(result[len(header.Extra):], paddingExtra)

	return result
}

// VerifyAlignment checks if an APK is properly aligned: 16 KiB pages for
// uncompressed .so libraries, 4-byte boundaries for other stored files.
func VerifyAlignment(apkPath string) error {
	reader, err := zip.OpenReader(apkPath)
	if err != nil {
		return fmt.Errorf("failed to open APK: %w", err)
	}
	defer reader.Close()

	for _, file := range reader.File {
		// Directories have no payload to align.
		if strings.HasSuffix(file.Name, "/") {
			continue
		}
		// Only check uncompressed files
		if file.Method != zip.Store {
			continue
		}

		offset, err := file.DataOffset()
		if err != nil {
			return fmt.Errorf("failed to get data offset for %s: %w", file.Name, err)
		}

		if align := alignmentForEntry(file.Name); offset%align != 0 {
			return fmt.Errorf("file %s is not aligned (offset: %d, want %d-byte alignment)", file.Name, offset, align)
		}
	}

	return nil
}
