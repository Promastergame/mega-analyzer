// patch-apk performs deterministic ZIP-entry replacement for APK/XAPK files.
// It is intentionally content-agnostic: callers explicitly provide every
// archive path and replacement file instead of relying on developer paths.
package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

type options struct {
	input           string
	output          string
	replacements    map[string]string
	deletions       map[string]bool
	stripSignatures bool
	allowAdd        bool
	dryRun          bool
}

func main() {
	var replaceSpecs, deleteSpecs multiFlag
	input := flag.String("in", "", "input APK/XAPK/ZIP")
	output := flag.String("out", "", "output APK/XAPK/ZIP")
	flag.Var(&replaceSpecs, "replace", "replace archive/path=local/file (repeatable)")
	flag.Var(&deleteSpecs, "delete", "delete archive/path (repeatable)")
	strip := flag.Bool("strip-signatures", true, "remove invalidated META-INF v1 signatures")
	allowAdd := flag.Bool("allow-add", false, "allow -replace to add a missing archive entry")
	dryRun := flag.Bool("dry-run", false, "validate and print the patch plan without writing")
	flag.Parse()

	opts, err := parseOptions(*input, *output, replaceSpecs, deleteSpecs, *strip, *allowAdd, *dryRun)
	if err != nil {
		fmt.Fprintln(os.Stderr, "patch-apk:", err)
		flag.Usage()
		os.Exit(2)
	}
	if err := patchArchive(opts); err != nil {
		fmt.Fprintln(os.Stderr, "patch-apk:", err)
		os.Exit(1)
	}
}

func parseOptions(input, output string, replaceSpecs, deleteSpecs []string, strip, allowAdd, dryRun bool) (options, error) {
	opts := options{
		input: input, output: output, replacements: make(map[string]string),
		deletions: make(map[string]bool), stripSignatures: strip,
		allowAdd: allowAdd, dryRun: dryRun,
	}
	if input == "" { return opts, fmt.Errorf("-in is required") }
	if output == "" && !dryRun { return opts, fmt.Errorf("-out is required unless -dry-run is used") }
	if output != "" {
		inAbs, _ := filepath.Abs(input)
		outAbs, _ := filepath.Abs(output)
		if inAbs == outAbs { return opts, fmt.Errorf("input and output must be different paths") }
	}
	for _, spec := range replaceSpecs {
		archivePath, localPath, ok := strings.Cut(spec, "=")
		if !ok || archivePath == "" || localPath == "" { return opts, fmt.Errorf("invalid -replace %q; want archive/path=local/file", spec) }
		archivePath, err := cleanArchivePath(archivePath)
		if err != nil { return opts, err }
		if _, exists := opts.replacements[archivePath]; exists { return opts, fmt.Errorf("duplicate replacement for %s", archivePath) }
		info, err := os.Stat(localPath)
		if err != nil { return opts, fmt.Errorf("replacement %s: %w", localPath, err) }
		if !info.Mode().IsRegular() { return opts, fmt.Errorf("replacement is not a regular file: %s", localPath) }
		opts.replacements[archivePath] = localPath
	}
	for _, raw := range deleteSpecs {
		clean, err := cleanArchivePath(raw)
		if err != nil { return opts, err }
		if _, replaced := opts.replacements[clean]; replaced { return opts, fmt.Errorf("entry is both replaced and deleted: %s", clean) }
		opts.deletions[clean] = true
	}
	if len(opts.replacements) == 0 && len(opts.deletions) == 0 { return opts, fmt.Errorf("at least one -replace or -delete is required") }
	return opts, nil
}

func cleanArchivePath(raw string) (string, error) {
	raw = strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/")
	clean := path.Clean(raw)
	if raw == "" || clean == "." || strings.HasPrefix(clean, "/") || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, ":") || strings.ContainsRune(clean, '\x00') {
		return "", fmt.Errorf("unsafe archive path: %q", raw)
	}
	return clean, nil
}

func patchArchive(opts options) error {
	reader, err := zip.OpenReader(opts.input)
	if err != nil { return fmt.Errorf("open input: %w", err) }
	defer reader.Close()

	present := make(map[string]bool, len(reader.File))
	for _, f := range reader.File {
		clean, err := cleanArchivePath(f.Name)
		if err != nil { return fmt.Errorf("input contains %w", err) }
		if present[clean] { return fmt.Errorf("input contains duplicate entry %s", clean) }
		present[clean] = true
	}
	for entry := range opts.replacements {
		if !present[entry] && !opts.allowAdd { return fmt.Errorf("replacement target is missing: %s (use -allow-add)", entry) }
	}
	for entry := range opts.deletions {
		if !present[entry] { return fmt.Errorf("delete target is missing: %s", entry) }
	}
	if opts.dryRun {
		printPlan(opts)
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(opts.output), 0755); err != nil { return fmt.Errorf("create output directory: %w", err) }
	tmp, err := os.CreateTemp(filepath.Dir(opts.output), ".patch-apk-*")
	if err != nil { return fmt.Errorf("create temporary output: %w", err) }
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	zw := zip.NewWriter(tmp)

	written := make(map[string]bool)
	for _, f := range reader.File {
		name, _ := cleanArchivePath(f.Name)
		if opts.deletions[name] || (opts.stripSignatures && isV1Signature(name)) { continue }
		if local, ok := opts.replacements[name]; ok {
			if err := writeReplacement(zw, &f.FileHeader, name, local); err != nil { return closeWithError(zw, tmp, err) }
			written[name] = true
			continue
		}
		if err := copyEntry(zw, f); err != nil { return closeWithError(zw, tmp, err) }
		written[name] = true
	}
	for entry, local := range opts.replacements {
		if written[entry] { continue }
		header := zip.FileHeader{Name: entry, Method: zip.Deflate}
		if err := writeReplacement(zw, &header, entry, local); err != nil { return closeWithError(zw, tmp, err) }
	}
	if err := zw.Close(); err != nil { tmp.Close(); return fmt.Errorf("close ZIP writer: %w", err) }
	if err := tmp.Sync(); err != nil { tmp.Close(); return fmt.Errorf("sync output: %w", err) }
	if err := tmp.Close(); err != nil { return fmt.Errorf("close output: %w", err) }
	if err := os.Rename(tmpPath, opts.output); err != nil { return fmt.Errorf("publish output: %w", err) }
	fmt.Printf("Patched archive written to %s\n", opts.output)
	return nil
}

func writeReplacement(zw *zip.Writer, source *zip.FileHeader, name, local string) error {
	data, err := os.Open(local)
	if err != nil { return fmt.Errorf("open replacement %s: %w", local, err) }
	defer data.Close()
	h := *source
	h.Name = name
	h.CRC32, h.CompressedSize, h.CompressedSize64, h.UncompressedSize, h.UncompressedSize64 = 0, 0, 0, 0, 0
	h.Flags &^= 0x8
	if h.Method != zip.Store && h.Method != zip.Deflate { h.Method = zip.Deflate }
	writer, err := zw.CreateHeader(&h)
	if err != nil { return fmt.Errorf("create replacement entry %s: %w", name, err) }
	if _, err := io.Copy(writer, data); err != nil { return fmt.Errorf("write replacement entry %s: %w", name, err) }
	return nil
}

func copyEntry(zw *zip.Writer, source *zip.File) error {
	reader, err := source.Open()
	if err != nil { return fmt.Errorf("open entry %s: %w", source.Name, err) }
	defer reader.Close()
	h := source.FileHeader
	h.CRC32, h.CompressedSize, h.CompressedSize64, h.UncompressedSize, h.UncompressedSize64 = 0, 0, 0, 0, 0
	h.Flags &^= 0x8
	writer, err := zw.CreateHeader(&h)
	if err != nil { return fmt.Errorf("create entry %s: %w", source.Name, err) }
	if _, err := io.Copy(writer, reader); err != nil { return fmt.Errorf("copy entry %s: %w", source.Name, err) }
	return nil
}

func isV1Signature(name string) bool {
	upper := strings.ToUpper(name)
	if !strings.HasPrefix(upper, "META-INF/") { return false }
	base := path.Base(upper)
	return base == "MANIFEST.MF" || strings.HasSuffix(base, ".SF") || strings.HasSuffix(base, ".RSA") || strings.HasSuffix(base, ".DSA") || strings.HasSuffix(base, ".EC")
}

func closeWithError(zw *zip.Writer, file *os.File, cause error) error {
	_ = zw.Close()
	_ = file.Close()
	return cause
}

func printPlan(opts options) {
	entries := make([]string, 0, len(opts.replacements)+len(opts.deletions))
	for entry, local := range opts.replacements { entries = append(entries, "REPLACE "+entry+" <- "+local) }
	for entry := range opts.deletions { entries = append(entries, "DELETE  "+entry) }
	sort.Strings(entries)
	for _, entry := range entries { fmt.Println(entry) }
	if opts.stripSignatures { fmt.Println("DELETE  META-INF signature files (automatic)") }
}
