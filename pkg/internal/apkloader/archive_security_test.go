package apkloader

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"mega-analyzer/pkg/internal/boundedfile"
	"mega-analyzer/pkg/internal/testutil"
	"mega-analyzer/pkg/internal/types"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func securityZIP(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func runSecurityZIP(t *testing.T, data []byte, dest string) (*Extractor, error) {
	t.Helper()
	path := filepath.Join(testutil.TempDir(t), "input.apk")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	e := NewExtractor()
	return e, e.extractZipSafe(context.Background(), path, dest)
}

func TestArchiveTraversalAlertsAndSafeExtraction(t *testing.T) {
	dest := filepath.Join(testutil.TempDir(t), "output")
	bad := []string{"../outside", "a/../inside", `a\..\outside`, `C:\outside`, "asset.svg:stream"}
	// Root-relative and repeated-slash names are packer duplicates, not
	// traversal: they normalize onto the plain root file names and extract
	// inside the destination root (Info-ZIP semantics).
	normalized := []string{"/absolute", "//AndroidManifest.xml", "/classes.dex", `\\server\share\file`, `a//b.txt`}
	entries := map[string]string{"assets/normal.svg": "<svg/>"}
	for _, name := range bad {
		entries[name] = "ignored"
	}
	for _, name := range normalized {
		entries[name] = "duplicate"
	}
	e, err := runSecurityZIP(t, securityZIP(t, entries), dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Findings) != len(bad) {
		t.Fatalf("blocked entries missing from report: %+v", e.Findings)
	}
	for _, f := range e.Findings {
		if f.Severity != types.SeverityCritical || !strings.Contains(f.Reason, "ARCHIVE_PATH_TRAVERSAL") {
			t.Fatalf("bad alert: %+v", f)
		}
	}
	if data, err := os.ReadFile(filepath.Join(dest, "assets", "normal.svg")); err != nil || string(data) != "<svg/>" {
		t.Fatal("safe file lost", err)
	}
	for _, name := range []string{"absolute", "AndroidManifest.xml", "classes.dex", filepath.Join("server", "share", "file"), filepath.Join("a", "b.txt")} {
		if _, err := os.Stat(filepath.Join(dest, filepath.FromSlash(name))); err != nil {
			t.Fatalf("normalized entry %q was not extracted: %v", name, err)
		}
	}
	files := 0
	filepath.WalkDir(dest, func(_ string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			files++
		}
		return err
	})
	if files != 1+len(normalized) {
		t.Fatalf("unexpected extracted file count: %d", files)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "outside")); !os.IsNotExist(err) {
		t.Fatal("entry escaped extraction root")
	}
}

func TestArchiveJunkEntryNameSkippedWithoutFinding(t *testing.T) {
	dest := testutil.TempDir(t)
	e, err := runSecurityZIP(t, securityZIP(t, map[string]string{`\`: "junk", "res/ok.txt": "ok"}), dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Findings) != 0 {
		t.Fatalf("junk entry name reported as traversal: %+v", e.Findings)
	}
	if data, err := os.ReadFile(filepath.Join(dest, "res", "ok.txt")); err != nil || string(data) != "ok" {
		t.Fatal("safe file lost", err)
	}
}

func TestArchiveRejectsMaliciousMetadataBeforeWriting(t *testing.T) {
	for _, tc := range []struct {
		name  string
		patch func([]byte, int)
		want  error
	}{
		{"unsupported compression", func(b []byte, pos int) { binary.LittleEndian.PutUint16(b[pos+10:], 99) }, zip.ErrAlgorithm},
		{"oversized XML", func(b []byte, pos int) { binary.LittleEndian.PutUint32(b[pos+24:], maxXMLBytes+1) }, errZipBomb},
		{"impossible declared size", func(b []byte, pos int) { binary.LittleEndian.PutUint32(b[pos+24:], 1) }, zip.ErrFormat},
		{"checksum", func(b []byte, pos int) { b[pos+16] ^= 0xff }, zip.ErrChecksum},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := securityZIP(t, map[string]string{"res/xml/test.xml": "<xml>some content</xml>"})
			pos := bytes.Index(data, []byte{'P', 'K', 1, 2})
			tc.patch(data, pos)
			dest := testutil.TempDir(t)
			e, err := runSecurityZIP(t, data, dest)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if len(e.Findings) != 1 {
				t.Fatalf("error not recorded as finding: %+v", e.Findings)
			}
			entries, err := os.ReadDir(dest)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range entries {
				if !d.IsDir() {
					t.Fatalf("partial file remains: %s", d.Name())
				}
			}
			if _, err := os.Stat(filepath.Join(dest, "res", "xml", "test.xml")); !os.IsNotExist(err) {
				t.Fatal("invalid entry was committed")
			}
		})
	}
}

func TestArchiveActualByteBudgetAndCancellation(t *testing.T) {
	data := securityZIP(t, map[string]string{"payload.bin": strings.Repeat("A", 4096)})
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	for _, cancel := range []bool{false, true} {
		dest := testutil.TempDir(t)
		if err := os.WriteFile(filepath.Join(dest, "existing"), []byte("original"), 0600); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dest)
		if err != nil {
			t.Fatal(err)
		}
		ctx, stop := context.WithCancel(context.Background())
		if cancel {
			stop()
		}
		var budget atomic.Int64
		budget.Store(32)
		_, err = extractZipFile(ctx, root, r.File[0], "existing", make([]byte, 256), &budget)
		stop()
		root.Close()
		want := errZipBomb
		if cancel {
			want = context.Canceled
		}
		if !errors.Is(err, want) {
			t.Fatalf("budget/cancellation failed: %v", err)
		}
		if b, _ := os.ReadFile(filepath.Join(dest, "existing")); string(b) != "original" {
			t.Fatal("failed extraction replaced existing file")
		}
		entries, _ := os.ReadDir(dest)
		if len(entries) != 1 {
			t.Fatal("temporary file was not removed")
		}
	}
}

func TestArchiveRootRejectsExistingSymlinkEscape(t *testing.T) {
	dest, outside := testutil.TempDir(t), testutil.TempDir(t)
	if err := os.Symlink(outside, filepath.Join(dest, "assets")); err != nil {
		t.Skip("symlinks unavailable: ", err)
	}
	_, err := runSecurityZIP(t, securityZIP(t, map[string]string{"assets/ignored.txt": "ignored"}), dest)
	if err == nil {
		t.Fatal("pre-existing symlink escape accepted")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatal("file written outside root")
	}
}

func TestArchiveSymlinkEntriesBlocked(t *testing.T) {
	var data bytes.Buffer
	w := zip.NewWriter(&data)
	h := &zip.FileHeader{Name: "assets/link"}
	h.SetMode(os.ModeSymlink | 0777)
	f, err := w.CreateHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("../../outside"))
	w.Close()
	e, err := runSecurityZIP(t, data.Bytes(), testutil.TempDir(t))
	if err != nil || len(e.Findings) != 1 || !strings.Contains(e.Findings[0].Reason, "ARCHIVE_SYMLINK") {
		t.Fatalf("symlink not flagged: %v %+v", err, e.Findings)
	}
}

func TestResourceDecodeBoundedBeforeAllocation(t *testing.T) {
	path := filepath.Join(testutil.TempDir(t), "oversized.xml")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxXMLBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := decodeAndSaveManifest(path); !errors.Is(err, boundedfile.ErrLimit) {
		t.Fatalf("manifest read unbounded: %v", err)
	}
	if err := decodeAndSaveAXML(path); !errors.Is(err, boundedfile.ErrLimit) {
		t.Fatalf("resource XML read unbounded: %v", err)
	}
}

// Packers plant a stripped decoy manifest at a rooted name ("/AndroidManifest.xml")
// ahead of the real entry so naive path normalization hands the canonical name
// to the decoy. The exact-name entry — the one Android's installer reads — must
// win the collision and keep its content.
func TestArchiveExactNameWinsPackerDecoyCollision(t *testing.T) {
	dest := testutil.TempDir(t)
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	decoy, real := "<manifest decoy/>", "<manifest real with-permissions/>"
	// Decoy first: central-directory order must not decide the winner.
	for _, e := range []struct{ name, body string }{
		{"/AndroidManifest.xml", decoy},
		{"AndroidManifest.xml", real},
	} {
		f, err := w.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	e, err := runSecurityZIP(t, buf.Bytes(), dest)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(dest, "AndroidManifest.xml")); err != nil || string(data) != real {
		t.Fatalf("canonical entry content lost to decoy: %q (%v)", string(data), err)
	}
	for _, f := range e.Findings {
		if strings.Contains(f.Reason, "ARCHIVE_PATH_TRAVERSAL") {
			t.Fatalf("rooted decoy reported as traversal: %+v", f)
		}
	}
}
