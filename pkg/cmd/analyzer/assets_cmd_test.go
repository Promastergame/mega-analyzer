package main

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/ml/assetscan"
)

// ── helpers ────────────────────────────────────────────────────────────

func assetsTestPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, color.RGBA{R: uint8(x * 16), G: 0x40, B: uint8(y * 16), A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	return buf.Bytes()
}

func assetsWriteTemp(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", p, err)
	}
	return p
}

// assetsCaptureStdout swaps os.Stdout for a pipe. runAssetScan prints the human
// report with fmt.Print, which resolves os.Stdout at call time, so reassigning
// it here is enough - and it keeps the test output readable.
func assetsCaptureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	defer func() {
		os.Stdout = old
		_ = r.Close()
	}()
	fn()
	_ = w.Close()
	return <-done
}

// ── flags ───────────────────────────────────────────────────────────────

func TestAssetScanFlagsAreAllRegistered(t *testing.T) {
	opts, err := NewCLIParser().Parse([]string{
		"-assets", "game.apk",
		"-assets-out", "out/dir",
		"-assets-open",
		"-assets-json",
		"-assets-deep",
		"-assets-all",
		"-assets-max-mb", "8",
		"-assets-max-dim", "128",
		"-assets-max-previews", "4",
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if opts.AssetScan != "game.apk" || opts.AssetsOut != "out/dir" {
		t.Fatalf("paths = %q, %q", opts.AssetScan, opts.AssetsOut)
	}
	if !opts.AssetsOpen || !opts.AssetsJSON || !opts.AssetsDeep || !opts.AssetsAll {
		t.Fatalf("boolean flags = open %v json %v deep %v all %v",
			opts.AssetsOpen, opts.AssetsJSON, opts.AssetsDeep, opts.AssetsAll)
	}
	if opts.AssetsMaxMB != 8 || opts.AssetsMaxDim != 128 || opts.AssetsMaxPrev != 4 {
		t.Fatalf("numeric flags = %d, %d, %d",
			opts.AssetsMaxMB, opts.AssetsMaxDim, opts.AssetsMaxPrev)
	}
}

func TestAssetScanFlagDefaultsAreUsable(t *testing.T) {
	opts, err := NewCLIParser().Parse(nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// An unset -assets must leave the flag inert: runner.go dispatches on it
	// being non-empty, so a stray default would hijack every other command.
	if opts.AssetScan != "" {
		t.Fatalf("AssetScan defaults to %q, want empty", opts.AssetScan)
	}
	if opts.AssetsMaxMB != 64 || opts.AssetsMaxDim != 512 || opts.AssetsMaxPrev != 256 {
		t.Fatalf("defaults = %d MB, %d px, %d previews",
			opts.AssetsMaxMB, opts.AssetsMaxDim, opts.AssetsMaxPrev)
	}
	if opts.AssetsOpen || opts.AssetsJSON || opts.AssetsDeep || opts.AssetsAll {
		t.Fatalf("a boolean asset flag defaults to true")
	}
}

func TestAssetScanIsListedInTheUsageText(t *testing.T) {
	// The usage block is the only discovery path for these flags, so an
	// unlisted flag is an unusable one.
	var buf bytes.Buffer
	p := NewCLIParser()
	if _, err := p.Parse(nil); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	p.fs.SetOutput(&buf)
	p.fs.PrintDefaults()
	out := buf.String()
	for _, flagName := range []string{
		"assets", "assets-out", "assets-open", "assets-json",
		"assets-deep", "assets-all", "assets-max-mb",
		"assets-max-dim", "assets-max-previews",
	} {
		if !strings.Contains(out, "-"+flagName+" ") && !strings.Contains(out, "-"+flagName+"\n") {
			t.Fatalf("flag -%s is missing from the flag set output", flagName)
		}
	}
}

// ── preview directory ──────────────────────────────────────────────────────

func TestDefaultPreviewDirSitsNextToTheTarget(t *testing.T) {
	dir := t.TempDir()

	if got, want := defaultPreviewDir(filepath.Join(dir, "game.apk")),
		filepath.Join(dir, "game-assets"); got != want {
		t.Fatalf("apk target -> %q, want %q", got, want)
	}
	// A directory target has no extension to strip.
	if got, want := defaultPreviewDir(filepath.Join(dir, "raw")),
		filepath.Join(dir, "raw-assets"); got != want {
		t.Fatalf("directory target -> %q, want %q", got, want)
	}
	// Two different targets must never share a preview directory, otherwise a
	// second scan silently overwrites the first one's PNGs.
	if defaultPreviewDir(filepath.Join(dir, "a.apk")) == defaultPreviewDir(filepath.Join(dir, "b.apk")) {
		t.Fatalf("two targets collided on one preview directory")
	}
}

func TestDefaultPreviewDirIsAlwaysAbsoluteAndNamed(t *testing.T) {
	if got := defaultPreviewDir("game.apk"); !filepath.IsAbs(got) {
		t.Fatalf("a relative target produced a relative dir: %q", got)
	}
	// filepath.Ext(".hidden") is the whole name, so stripping it leaves
	// nothing; the fallback keeps the path from becoming a bare "-assets".
	dir := t.TempDir()
	if got, want := defaultPreviewDir(filepath.Join(dir, ".hidden")),
		filepath.Join(dir, "target-assets"); got != want {
		t.Fatalf("dotfile target -> %q, want %q", got, want)
	}
}

// ── running the command ────────────────────────────────────────────────────

func TestRunAssetScanRejectsAMissingTarget(t *testing.T) {
	err := runAssetScan(&CLIOptions{AssetScan: filepath.Join(t.TempDir(), "nope.apk")})
	if err == nil {
		t.Fatalf("scanning a missing target succeeded")
	}
	if !strings.Contains(err.Error(), "cannot read") {
		t.Fatalf("error = %v, want it to name the unreadable path", err)
	}
}

func TestRunAssetScanWritesTheIndexBesideThePreviews(t *testing.T) {
	src := t.TempDir()
	assetsWriteTemp(t, src, "logo.png", assetsTestPNG(t, 16, 16))
	out := filepath.Join(t.TempDir(), "previews")

	text := assetsCaptureStdout(t, func() {
		if err := runAssetScan(&CLIOptions{AssetScan: src, AssetsOut: out}); err != nil {
			t.Errorf("runAssetScan: %v", err)
		}
	})
	if !strings.Contains(text, "asset scan") {
		t.Fatalf("human report was not printed:\n%s", text)
	}

	index := filepath.Join(out, assetIndexName)
	blob, err := os.ReadFile(index)
	if err != nil {
		t.Fatalf("index was not written: %v", err)
	}

	var rep assetscan.Report
	if err := json.Unmarshal(blob, &rep); err != nil {
		t.Fatalf("index is not valid JSON: %v", err)
	}
	if rep.PreviewDir != out {
		t.Fatalf("index previewDir = %q, want %q", rep.PreviewDir, out)
	}
	if len(rep.Items) == 0 {
		t.Fatalf("index lists no items")
	}
	if !bytes.HasSuffix(blob, []byte("\n")) {
		t.Fatalf("index does not end in a newline")
	}

	// Every preview the index names must actually exist, or the editor opens
	// on a broken gallery.
	seen := 0
	for _, it := range rep.Items {
		for _, p := range it.Previews {
			if _, err := os.Stat(p.Path); err != nil {
				t.Fatalf("index names a preview that is not on disk: %v", err)
			}
			if filepath.Dir(p.Path) != out {
				t.Fatalf("preview %q is not inside the preview dir %q", p.Path, out)
			}
			seen++
		}
	}
	if seen == 0 {
		t.Fatalf("no previews were rendered for a plain PNG")
	}
}

func TestRunAssetScanJSONOnlyTouchesNothingOnDisk(t *testing.T) {
	src := t.TempDir()
	assetsWriteTemp(t, src, "logo.png", assetsTestPNG(t, 8, 8))

	out := assetsCaptureStdout(t, func() {
		if err := runAssetScan(&CLIOptions{AssetScan: src, AssetsJSON: true}); err != nil {
			t.Errorf("runAssetScan: %v", err)
		}
	})

	// -assets-json on its own is for piping into another program; it must not
	// scatter PNGs into the user's tree as a side effect.
	if _, err := os.Stat(defaultPreviewDir(src)); err == nil {
		t.Fatalf("-assets-json created %s", defaultPreviewDir(src))
	}

	var rep assetscan.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("stdout is not a single JSON document: %v\n%s", err, out)
	}
	if rep.Target != src {
		t.Fatalf("report target = %q, want %q", rep.Target, src)
	}
	if rep.PreviewDir != "" {
		t.Fatalf("previewDir = %q, want empty when nothing was rendered", rep.PreviewDir)
	}
	// Nothing but JSON may reach stdout, or the editor's parse fails.
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Fatalf("stdout does not start with the JSON document:\n%s", out)
	}
	if strings.Contains(out, "asset scan") {
		t.Fatalf("the human report leaked into the JSON stream:\n%s", out)
	}
}

func TestRunAssetScanHonoursTheSizeAndPreviewCaps(t *testing.T) {
	src := t.TempDir()
	for _, name := range []string{"a.png", "b.png", "c.png"} {
		assetsWriteTemp(t, src, name, assetsTestPNG(t, 8, 8))
	}
	out := filepath.Join(t.TempDir(), "previews")

	_ = assetsCaptureStdout(t, func() {
		if err := runAssetScan(&CLIOptions{
			AssetScan:     src,
			AssetsOut:     out,
			AssetsMaxMB:   1,
			AssetsMaxDim:  32,
			AssetsMaxPrev: 1,
		}); err != nil {
			t.Errorf("runAssetScan: %v", err)
		}
	})

	blob, err := os.ReadFile(filepath.Join(out, assetIndexName))
	if err != nil {
		t.Fatalf("index was not written: %v", err)
	}
	var rep assetscan.Report
	if err := json.Unmarshal(blob, &rep); err != nil {
		t.Fatalf("index is not valid JSON: %v", err)
	}

	total := 0
	for _, it := range rep.Items {
		for _, p := range it.Previews {
			total++
			if p.Width > 32 || p.Height > 32 {
				t.Fatalf("-assets-max-dim 32 produced a %dx%d preview", p.Width, p.Height)
			}
		}
	}
	if total > 1 {
		t.Fatalf("-assets-max-previews 1 produced %d previews", total)
	}
}

// ── handing off to the editor ───────────────────────────────────────────────

func TestOpenAssetPreviewsNeedsSomewhereToPoint(t *testing.T) {
	err := openAssetPreviews(&assetscan.Report{}, true)
	if err == nil {
		t.Fatalf("opening an empty preview dir succeeded")
	}
	if !strings.Contains(err.Error(), "-assets-out") {
		t.Fatalf("error = %v, want it to suggest -assets-out", err)
	}
}

func TestAssetsOpenSurvivesAMissingEditorBinary(t *testing.T) {
	// The PNGs and the index are already on disk by the time the editor is
	// launched, so a missing GUI binary is a warning, never a failed scan.
	// This is the normal case on Android and Linux ARM, where the Win32 editor
	// cannot be built at all.
	src := t.TempDir()
	assetsWriteTemp(t, src, "logo.png", assetsTestPNG(t, 8, 8))
	out := filepath.Join(t.TempDir(), "previews")

	_ = assetsCaptureStdout(t, func() {
		if err := runAssetScan(&CLIOptions{
			AssetScan:  src,
			AssetsOut:  out,
			AssetsOpen: true,
		}); err != nil {
			t.Errorf("a missing editor binary failed the whole scan: %v", err)
		}
	})

	if _, err := os.Stat(filepath.Join(out, assetIndexName)); err != nil {
		t.Fatalf("index missing after -assets-open: %v", err)
	}
}

func TestAssetIndexNameMatchesTheZigReader(t *testing.T) {
	// src/logic/assetscan.zig hardcodes this name as index_file_name. The two
	// sides have no shared header, so the constant is pinned here instead.
	if assetIndexName != "assets.json" {
		t.Fatalf("assetIndexName = %q; update src/logic/assetscan.zig to match", assetIndexName)
	}
}
