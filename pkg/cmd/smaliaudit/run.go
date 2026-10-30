// Package smaliaudit provides an offline, read-only APK/DEX/smali audit command.
// It never installs, executes, rebuilds, signs or patches an Android application.
package smaliaudit

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/internal/apkloader/axml"
	"mega-analyzer/pkg/ml"
)

const maxDEXBytes int64 = 128 << 20
const maxManifestBytes int64 = 8 << 20
const maxArchiveEntries = 100000

type Options struct {
	Input  string
	Config ml.SmaliAuditConfig
}
type DEXInventory struct {
	Name           string   `json:"name"`
	SHA256         string   `json:"sha256"`
	Bytes          int      `json:"bytes"`
	Classes        int      `json:"classes"`
	DefinedMethods int      `json:"defined_methods"`
	Warnings       []string `json:"warnings,omitempty"`
}
type NativeInventory struct {
	Name  string `json:"name"`
	Bytes uint64 `json:"bytes"`
}
type Report struct {
	Tool            string               `json:"tool"`
	GoVersion       string               `json:"go_version"`
	Input           string               `json:"input"`
	SHA256          string               `json:"sha256,omitempty"`
	DurationMS      int64                `json:"duration_ms"`
	DEX             []DEXInventory       `json:"dex"`
	NativeLibraries []NativeInventory    `json:"native_libraries"`
	Manifest        *axml.Manifest       `json:"manifest,omitempty"`
	Audit           *ml.SmaliAuditReport `json:"audit"`
}

// Run reads user input into bounded memory and invokes pkg/ml's audit chain.
// ZIP members are never extracted to paths controlled by the APK.
func Run(ctx context.Context, options Options) (*Report, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if options.Input == "" {
		return nil, fmt.Errorf("an input APK, DEX, smali file or directory is required")
	}
	cfg := options.Config
	defaults := ml.DefaultSmaliAuditConfig()
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaults.Timeout
	}
	if cfg.MaxTotalBytes <= 0 {
		cfg.MaxTotalBytes = defaults.MaxTotalBytes
	}
	if cfg.MaxFileBytes <= 0 {
		cfg.MaxFileBytes = defaults.MaxFileBytes
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = defaults.MaxFiles
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	started := time.Now()
	info, err := os.Lstat(options.Input)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("input symlinks are not accepted")
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("input must be a regular file or directory")
	}
	report := &Report{Tool: "Mega-Analyzer smali-audit v1", GoVersion: runtime.Version(), Input: filepath.Base(options.Input), DEX: []DEXInventory{}, NativeLibraries: []NativeInventory{}}
	files := []ml.SmaliAuditFile{}
	diagnostics := []string{}
	var totalSmali int64
	addSmali := func(name string, data []byte) bool {
		if len(files) >= cfg.MaxFiles {
			diagnostics = appendLimited(diagnostics, "Input file budget reached.")
			return false
		}
		if int64(len(data)) > cfg.MaxFileBytes {
			diagnostics = appendLimited(diagnostics, "Oversized smali class skipped: "+name)
			return true
		}
		if int64(len(data)) > cfg.MaxTotalBytes-totalSmali {
			diagnostics = appendLimited(diagnostics, "Expanded smali byte budget reached.")
			return false
		}
		files = append(files, ml.SmaliAuditFile{Path: name, Content: data})
		totalSmali += int64(len(data))
		return true
	}
	decodeDEX := func(name string, data []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		parser, err := apkloader.ParseDEXBytesContext(ctx, data)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		defer parser.Close()
		sum := sha256.Sum256(data)
		entry := DEXInventory{Name: name, SHA256: hex.EncodeToString(sum[:]), Bytes: len(data), Classes: len(parser.GetClasses())}
		classes := append([]*apkloader.ClassDef(nil), parser.GetClasses()...)
		sort.Slice(classes, func(i, j int) bool { return classes[i].ClassName < classes[j].ClassName })
		for _, class := range classes {
			entry.DefinedMethods += len(class.DirectMethods) + len(class.VirtualMethods)
		}
		for _, class := range classes {
			if err := ctx.Err(); err != nil {
				diagnostics = appendLimited(diagnostics, "DEX rendering cancelled: "+err.Error())
				break
			}
			descriptor := class.ClassName
			// This is a virtual evidence path, not a disk destination. Reject malformed
			// descriptors anyway so SARIF links cannot escape the evidence tree.
			if !strings.HasPrefix(descriptor, "L") || !strings.HasSuffix(descriptor, ";") {
				diagnostics = appendLimited(diagnostics, "Invalid class descriptor in "+name)
				continue
			}
			relative := descriptor[1:len(descriptor)-1] + ".smali"
			if !safeMemberPath(relative) {
				diagnostics = appendLimited(diagnostics, "Unsafe class descriptor in "+name)
				continue
			}
			content := apkloader.GenerateSmaliClass(class, parser)
			if !addSmali(path.Join("dex", strings.TrimSuffix(name, ".dex"), relative), content) {
				break
			}
		}
		entry.Warnings = parser.GetWarnings()
		if len(entry.Warnings) > 0 {
			diagnostics = appendLimited(diagnostics, fmt.Sprintf("%s: %d DEX parser warning(s); inspect dex[].warnings.", name, len(entry.Warnings)))
		}
		report.DEX = append(report.DEX, entry)
		return nil
	}
	if info.IsDir() {
		err = filepath.WalkDir(options.Input, func(filename string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				diagnostics = appendLimited(diagnostics, "Skipped symlink in smali input.")
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(filename), ".smali") {
				return nil
			}
			if len(files) >= cfg.MaxFiles {
				diagnostics = appendLimited(diagnostics, "Input file budget reached.")
				return fs.SkipAll
			}
			data, err := readBoundedFile(filename, cfg.MaxFileBytes)
			if err != nil {
				diagnostics = appendLimited(diagnostics, filepath.Base(filename)+": "+err.Error())
				return nil
			}
			relative, err := filepath.Rel(options.Input, filename)
			if err != nil {
				return err
			}
			if !addSmali(filepath.ToSlash(relative), data) {
				return fs.SkipAll
			}
			return nil
		})
		if err != nil {
			diagnostics = appendLimited(diagnostics, "Directory read was incomplete: "+err.Error())
		}
	} else {
		hash, err := hashFile(ctx, options.Input)
		if err != nil {
			return nil, err
		}
		report.SHA256 = hash
		switch strings.ToLower(filepath.Ext(options.Input)) {
		case ".smali":
			data, e := readBoundedFile(options.Input, cfg.MaxFileBytes)
			if e != nil {
				return nil, e
			}
			addSmali(filepath.Base(options.Input), data)
		case ".dex":
			data, e := readBoundedFile(options.Input, maxDEXBytes)
			if e != nil {
				return nil, e
			}
			if e = decodeDEX(filepath.Base(options.Input), data); e != nil {
				return nil, e
			}
		case ".apk", ".zip":
			archive, e := zip.OpenReader(options.Input)
			if e != nil {
				return nil, e
			}
			defer archive.Close()
			if len(archive.File) > maxArchiveEntries {
				return nil, fmt.Errorf("archive has too many entries")
			}
			members := append([]*zip.File(nil), archive.File...)
			sort.SliceStable(members, func(i, j int) bool { return members[i].Name < members[j].Name })
			seen := map[string]bool{}
			var dexTotal int64
			for _, member := range members {
				if err := ctx.Err(); err != nil {
					diagnostics = appendLimited(diagnostics, "APK reading cancelled: "+err.Error())
					break
				}
				if !safeMemberPath(member.Name) || member.Mode()&os.ModeSymlink != 0 {
					diagnostics = appendLimited(diagnostics, "Unsafe archive entry ignored.")
					continue
				}
				if seen[member.Name] {
					diagnostics = appendLimited(diagnostics, "Duplicate archive entry: "+member.Name)
					continue
				}
				seen[member.Name] = true
				if strings.HasPrefix(member.Name, "lib/") && strings.HasSuffix(member.Name, ".so") {
					report.NativeLibraries = append(report.NativeLibraries, NativeInventory{Name: member.Name, Bytes: member.UncompressedSize64})
				}
				if member.Name == "AndroidManifest.xml" {
					data, e := readZipMember(member, maxManifestBytes)
					if e != nil {
						diagnostics = appendLimited(diagnostics, "Manifest read: "+e.Error())
						continue
					}
					if axml.IsBinaryXML(data) {
						report.Manifest, e = axml.Decode(data)
					} else {
						report.Manifest, e = axml.DecodePlainXML(data)
					}
					if e != nil {
						diagnostics = appendLimited(diagnostics, "Manifest parse: "+e.Error())
					}
					continue
				}
				// DEX assets are inspected too; they may be dynamically loaded rather
				// than installed as classes.dex. No runtime reachability is assumed.
				if !strings.HasSuffix(strings.ToLower(member.Name), ".dex") {
					continue
				}
				if member.UncompressedSize64 > uint64(maxDEXBytes) || member.UncompressedSize64 > uint64(2*maxDEXBytes-dexTotal) {
					diagnostics = appendLimited(diagnostics, "DEX byte budget reached: "+member.Name)
					continue
				}
				data, e := readZipMember(member, maxDEXBytes)
				if e != nil {
					diagnostics = appendLimited(diagnostics, member.Name+": "+e.Error())
					continue
				}
				dexTotal += int64(len(data))
				if e = decodeDEX(member.Name, data); e != nil {
					diagnostics = appendLimited(diagnostics, e.Error())
				}
			}
			if report.Manifest == nil {
				diagnostics = appendLimited(diagnostics, "No readable AndroidManifest.xml; app/package context is unavailable.")
			}
		default:
			return nil, fmt.Errorf("supported inputs: .apk, .zip with DEX, .dex, .smali or smali directory")
		}
	}
	if cfg.AppPackage == "" && report.Manifest != nil {
		cfg.AppPackage = report.Manifest.Package
	}
	report.Audit = ml.NewSmaliAuditChain(cfg).Analyze(ctx, files)
	if len(diagnostics) > 0 {
		report.Audit.AnalysisComplete = false
		report.Audit.Verdict = "incomplete_review_required"
		report.Audit.Diagnostics = append(report.Audit.Diagnostics, diagnostics...)
	}
	if len(report.NativeLibraries) > 0 {
		report.Audit.Limitations = append(report.Audit.Limitations, fmt.Sprintf("%d native libraries were inventoried but their machine code was not analyzed.", len(report.NativeLibraries)))
	}
	report.DurationMS = time.Since(started).Milliseconds()
	return report, nil
}

func safeMemberPath(name string) bool {
	if name == "" || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") || strings.Contains(name, ":") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return false
		}
	}
	return path.Clean(name) != "."
}
func appendLimited(list []string, message string) []string {
	if len(list) < 100 {
		return append(list, message)
	}
	return list
}
func readZipMember(member *zip.File, limit int64) ([]byte, error) {
	if member.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("entry exceeds %d-byte limit", limit)
	}
	reader, err := member.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return readBounded(reader, limit)
}
func readBoundedFile(filename string, limit int64) ([]byte, error) {
	reader, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	info, err := reader.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("file exceeds %d-byte limit", limit)
	}
	return readBounded(reader, limit)
}
func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("expanded data exceeds %d-byte limit", limit)
	}
	return data, nil
}
func hashFile(ctx context.Context, filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hash := sha256.New()
	buf := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, e := f.Read(buf)
		if n > 0 {
			hash.Write(buf[:n])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", e
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// WriteJSON uses a same-directory temporary file and atomic rename. It never
// truncates an existing report if encoding/writing fails.
func WriteJSON(filename string, value any) error {
	directory := filepath.Dir(filename)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(directory, ".smali-audit-*.tmp")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(value); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(temp, filename)
}
