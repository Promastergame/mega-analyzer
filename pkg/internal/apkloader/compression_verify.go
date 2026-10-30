package apkloader

import (
	"archive/zip"
	"fmt"
	"hash/crc32"
	"io"
	"path/filepath"
	"strings"
)

// VerifyAPKCompression audits final APK ZIP entries for Android runtime-safe
// compression. It also streams every file to force CRC/size verification so
// corrupted archives fail with a precise diagnostic instead of a vague install
// or rebuild error later.
func VerifyAPKCompression(apkPath string, meta *APKMeta) []Diagnostic {
	r, err := zip.OpenReader(apkPath)
	if err != nil { return []Diagnostic{{Code:"APK_ZIP_OPEN_FAILED", Severity:DiagError, Stage:"apk_compression", Path:apkPath, Message:err.Error()}} }
	defer r.Close()
	var diags []Diagnostic
	seen := map[string]bool{}
	for _, f := range r.File {
		name := filepath.ToSlash(f.Name)
		if seen[name] { diags = append(diags, Diagnostic{Code:"APK_ZIP_DUPLICATE_ENTRY", Severity:DiagError, Stage:"apk_compression", Path:name, Message:"duplicate ZIP entry"}) }
		seen[name] = true
		if f.Method != zip.Store && f.Method != zip.Deflate { diags = append(diags, Diagnostic{Code:"APK_ZIP_UNSUPPORTED_METHOD", Severity:DiagError, Stage:"apk_compression", Path:name, Message:fmt.Sprintf("unsupported ZIP compression method %d", f.Method), Hint:"APK entries should normally use STORE or DEFLATE"}) }
		wantStore := shouldStoreAPKEntry(name, meta)
		if wantStore && f.Method == zip.Deflate { diags = append(diags, Diagnostic{Code:"APK_ZIP_BAD_COMPRESSION", Severity:DiagWarn, Stage:"apk_compression", Path:name, Message:"entry is deflated but should be stored for Android runtime performance", Hint:"force STORE for resources.arsc, media, and doNotCompress extensions"}) }
		if !wantStore && f.Method == zip.Store && f.UncompressedSize64 > 32*1024 { diags = append(diags, Diagnostic{Code:"APK_ZIP_INEFFICIENT_STORE", Severity:DiagWarn, Stage:"apk_compression", Path:name, Message:"large compressible-looking entry is stored", Hint:"use DEFLATE unless the original APK metadata marks this extension as doNotCompress"}) }
		if d := verifyZipEntryPayload(f); d != nil { diags = append(diags, *d) }
	}
	return diags
}

func shouldStoreAPKEntry(name string, meta *APKMeta) bool {
	base := filepath.Base(name)
	lower := strings.ToLower(name)
	if base == "resources.arsc" || strings.HasSuffix(lower, ".9.png") { return true }
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(lower)), ".")
	if ext != "dex" && ext != "so" && noCompressExts[ext] { return true } // dex/so may be deflated; only doNotCompress metadata forces STORE
	if meta != nil { for _, e := range meta.DoNotCompress { if strings.TrimPrefix(strings.ToLower(strings.TrimSpace(e)), ".") == ext { return true } } }
	return false
}

func verifyZipEntryPayload(f *zip.File) *Diagnostic {
	rc, err := f.Open()
	if err != nil { return &Diagnostic{Code:"APK_ZIP_ENTRY_OPEN_FAILED", Severity:DiagError, Stage:"apk_compression", Path:f.Name, Message:err.Error()} }
	defer rc.Close()
	h := crc32.NewIEEE()
	n, err := io.Copy(h, rc)
	if err != nil { return &Diagnostic{Code:"APK_ZIP_CRC_MISMATCH", Severity:DiagError, Stage:"apk_compression", Path:f.Name, Message:err.Error(), Hint:"rebuild the APK; the ZIP central directory and payload disagree"} }
	if uint64(n) != f.UncompressedSize64 { return &Diagnostic{Code:"APK_ZIP_SIZE_MISMATCH", Severity:DiagError, Stage:"apk_compression", Path:f.Name, Message:fmt.Sprintf("read %d bytes, central directory declares %d", n, f.UncompressedSize64)} }
	if h.Sum32() != f.CRC32 { return &Diagnostic{Code:"APK_ZIP_CRC_MISMATCH", Severity:DiagError, Stage:"apk_compression", Path:f.Name, Message:"CRC32 mismatch", Hint:"rebuild the APK; entry payload is corrupted"} }
	return nil
}
