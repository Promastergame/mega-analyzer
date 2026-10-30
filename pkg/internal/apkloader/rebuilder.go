package apkloader

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"mega-analyzer/pkg/internal/apkloader/axml"
)

// APKMeta holds package metadata written during decode (apktool-compatible).
type APKMeta struct {
	Package       string   `json:"package,omitempty"`
	VersionCode   int      `json:"versionCode,omitempty"`
	VersionName   string   `json:"versionName,omitempty"`
	MinSDK        int      `json:"minSdk,omitempty"`
	TargetSDK     int      `json:"targetSdk,omitempty"`
	Tool          string   `json:"tool,omitempty"`
	Format        string   `json:"format,omitempty"`
	DoNotCompress []string `json:"doNotCompress,omitempty"` // extensions stored uncompressed in original APK
	UnknownFiles  []string `json:"unknownFiles,omitempty"`  // files outside res/, assets/, smali/, dex, manifest
}

// BuildOptions controls how an APK is rebuilt (apktool-style build).
type BuildOptions struct {
	SourceDir                 string
	OutputPath                string
	IncludeSignature          bool
	IncludeAlignment          bool
	CopyOriginal              bool // copy original/META-INF back into the APK
	CompressionMode           CompressionMode
	LargeFileSpoolThreshold   int64
	NoSmaliIncremental        bool // set true to force full smali→dex rebuild (default: incremental on)
	PreserveOriginalSignature bool // experimental: keep original META-INF/signing blocks, skip re-sign
	// Signing key material (passwords resolved from these fields or the
	// ANALYZER_KEYSTORE_PASS / ANALYZER_KEY_PASS environment; never flags
	// for secrets, never logged). Empty = debug-key flow, honestly labeled.
	SigningKeystore  string
	SigningKeyAlias  string
	SigningStorePass string
	SigningKeyPass   string
}

// APKRebuilder handles rebuilding APK files from extracted directories
type APKRebuilder struct {
	SourceDir                 string
	OutputPath                string
	IncludeSignature          bool
	IncludeAlignment          bool
	CopyOriginal              bool
	CompressionMode           CompressionMode
	LargeFileSpoolThreshold   int64
	SmaliIncremental          bool
	PreserveOriginalSignature bool
	SigningKeystore           string
	SigningKeyAlias           string
	SigningStorePass          string
	SigningKeyPass            string
	Warnings                  []string
	Diagnostics               []Diagnostic
	meta                      *APKMeta

	// Tool overrides (when empty, auto-detect is used)
	SmaliCfg SmaliToolConfig
	Aapt2Cfg Aapt2Config
	UseSmali bool // when false, skip smali assembly even if tools found
	UseAapt2 bool // when false, skip aapt2 even if found
}

// FileEntry represents a file to be included in the APK
type FileEntry struct {
	RelativePath   string
	FullPath       string
	Info           os.FileInfo
	ShouldCompress bool
}

// NewAPKRebuilder creates a new APK rebuilder
func NewAPKRebuilder(sourceDir string) *APKRebuilder {
	r := &APKRebuilder{
		SourceDir:        sourceDir,
		IncludeSignature: true,
		IncludeAlignment: true,
		SmaliIncremental: true,
		Warnings:         make([]string, 0),
		Diagnostics:      make([]Diagnostic, 0),
		UseSmali:         true,
		UseAapt2:         true,
	}
	r.loadMeta()
	return r
}

// NewAPKRebuilderWithOptions creates a rebuilder with explicit options.
func NewAPKRebuilderWithOptions(opts BuildOptions) *APKRebuilder {
	r := &APKRebuilder{
		SourceDir:                 opts.SourceDir,
		OutputPath:                opts.OutputPath,
		IncludeSignature:          opts.IncludeSignature,
		IncludeAlignment:          opts.IncludeAlignment,
		CopyOriginal:              opts.CopyOriginal,
		CompressionMode:           opts.CompressionMode,
		LargeFileSpoolThreshold:   opts.LargeFileSpoolThreshold,
		SmaliIncremental:          !opts.NoSmaliIncremental,
		PreserveOriginalSignature: opts.PreserveOriginalSignature,
		SigningKeystore:           opts.SigningKeystore,
		SigningKeyAlias:           opts.SigningKeyAlias,
		SigningStorePass:          opts.SigningStorePass,
		SigningKeyPass:            opts.SigningKeyPass,
		Warnings:                  make([]string, 0),
		Diagnostics:               make([]Diagnostic, 0),
		UseSmali:                  true,
		UseAapt2:                  true,
	}
	r.loadMeta()
	return r
}

// loadMeta reads omnisec-meta.json from the source directory if present.
func (r *APKRebuilder) loadMeta() {
	metaPath := filepath.Join(r.SourceDir, "omnisec-meta.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return
	}
	var m APKMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return
	}
	r.meta = &m
}

// GetMeta returns the decoded package metadata (may be nil).
func (r *APKRebuilder) GetMeta() *APKMeta { return r.meta }

// Rebuild rebuilds an APK or XAPK from the source directory.
// When aapt2 and smali tools are available it follows the Apktool
// round-trip pipeline: smali→dex, aapt2 compile→link, zip→align→sign.
// When target is XAPK, it packages the signed inner APK, manifest.json and OBB assets into a standard XAPK archive.
func (r *APKRebuilder) Rebuild(ctx context.Context, outputPath string) error {
	r.OutputPath = outputPath
	r.Warnings = r.Warnings[:0]
	r.Diagnostics = r.Diagnostics[:0]
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}
	staged, err := os.CreateTemp(filepath.Dir(outputPath), ".mega-analyzer-build-*"+filepath.Ext(outputPath))
	if err != nil {
		return err
	}
	stagedPath := staged.Name()
	if err := staged.Close(); err != nil {
		os.Remove(stagedPath)
		return err
	}
	defer os.Remove(stagedPath)
	if err := r.rebuildArtifact(ctx, stagedPath); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(stagedPath, outputPath); err != nil {
		return &LoaderError{Op: "publish_apk", err: err}
	}
	for i := range r.Diagnostics {
		if r.Diagnostics[i].Path == stagedPath {
			r.Diagnostics[i].Path = outputPath
		}
	}
	return nil
}

func (r *APKRebuilder) rebuildArtifact(ctx context.Context, outputPath string) error {
	isXAPK := strings.HasSuffix(strings.ToLower(outputPath), ".xapk")
	if !isXAPK {
		if _, err := os.Stat(filepath.Join(r.SourceDir, "manifest.json")); err == nil {
			if _, err2 := os.Stat(filepath.Join(r.SourceDir, "Android")); err2 == nil {
				isXAPK = true
			}
		}
	}

	targetApk := outputPath
	if isXAPK {
		tempInner, err := os.CreateTemp("", "rebuilt_inner_*.apk")
		if err != nil {
			return err
		}
		targetApk = tempInner.Name()
		tempInner.Close()
		defer os.Remove(targetApk)
	}

	// Patch edited resource and manifest values before any aapt2 compilation.
	if err := r.syncAndPatchResources(); err != nil {
		return &LoaderError{Op: "native_resources", err: err}
	}

	// ── Phase 1: assemble smali → dex (optional) ──
	// Fill only the missing fields: replacing the whole config silently
	// discards an explicit -smali-jar/-smali-api/-smali-jobs override.
	smaliCfg := r.SmaliCfg
	if smaliCfg.SmaliJar == "" || smaliCfg.JavaBinary == "" {
		def := DefaultSmaliConfig()
		if smaliCfg.SmaliJar == "" {
			smaliCfg.SmaliJar = def.SmaliJar
		}
		if smaliCfg.JavaBinary == "" {
			smaliCfg.JavaBinary = def.JavaBinary
		}
		if smaliCfg.BaksmaliJar == "" {
			smaliCfg.BaksmaliJar = def.BaksmaliJar
		}
	}
	// When the API level was not pinned explicitly, match the newest dex
	// version present in the tree: rebuilding a 037/038/039 tree with the
	// tool default (035) produces a mixed-version APK that ART rejects with
	// IncompatibleClassChangeError on interface-heavy code (Compose).
	if smaliCfg.APILevel <= 0 {
		if detected := DetectTreeAPILevel(r.SourceDir); detected > 0 {
			smaliCfg.APILevel = detected
			r.warn("smali api auto-detected: --api %d (matches tree dex version)", detected)
		}
	}
	if r.UseSmali && smaliDirsPresent(r.SourceDir) && !smaliFilesPresent(r.SourceDir) {
		r.warn("smali directories contain no .smali files: the existing classes.dex is packaged as-is")
	}
	if r.UseSmali && smaliDirsPresent(r.SourceDir) && smaliFilesPresent(r.SourceDir) {
		changed, unknown, _ := SmaliTreeChanged(r.SourceDir)
		// The native Go assembler is always available; smali.jar/Java only
		// matters for constructs it cannot represent yet.
		haveAssembler := true
		javaAssembler := smaliCfg.SmaliJar != "" && smaliCfg.JavaBinary != ""
		_ = javaAssembler
		switch {
		case len(changed) == 0 && len(unknown) == 0:
			// Smali is byte-identical to what was decoded: the original dex
			// files are already correct. No preflight, no assembler, no Java.
			r.warn("smali unchanged since decode: reusing original dex files (no assembler needed)")
		case !haveAssembler && len(changed) == 0:
			// No decode snapshot to compare with (tree not produced by this
			// tool): keep the historical behaviour and package the existing dex.
			r.warn("smali tool not found and no decode snapshot: the existing classes.dex is packaged as-is; " +
				"edited .smali files (if any) are NOT included. Pass -smali-jar <path> to assemble them.")
		case !haveAssembler:
			return &LoaderError{Op: "smali_assemble", err: fmt.Errorf(
				"smali was edited in %s but no assembler is available; the edits would be silently dropped. "+
					"Pass -smali-jar <path> (needs Java), or revert the smali edits", strings.Join(changed, ", "))}
		default:
			preDiags := ValidateSmaliTree(r.SourceDir)
			r.addDiagnostics(preDiags...)
			if err := diagnosticsError("smali_preflight", preDiags); err != nil {
				return &LoaderError{Op: "smali_preflight", err: err}
			}
			if dexPaths, warns, err := BuildDEXFromSmaliContextWithWarnings(ctx, r.SourceDir, smaliCfg, SmaliBuildOptions{MaxWorkers: 4, Incremental: r.SmaliIncremental}); err == nil {
				for _, p := range dexPaths {
					r.warn("smali assembled: %s", filepath.Base(p))
				}
				for _, wmsg := range warns {
					r.warn("smali: %s", wmsg)
				}
			} else {
				return &LoaderError{Op: "smali_assemble", err: err}
			}
		}
	}

	// ── Phase 2: aapt2 resource pipeline (optional) ──
	aapt2 := r.Aapt2Cfg
	if aapt2.Aapt2Path == "" {
		aapt2 = DefaultAapt2Config()
	}
	resDir := filepath.Join(r.SourceDir, "res")
	manifestPath := filepath.Join(r.SourceDir, "AndroidManifest.xml")
	buildDir := filepath.Join(r.SourceDir, "build")
	compiledZip := filepath.Join(buildDir, "compiled.zip")
	linkedApk := filepath.Join(buildDir, "linked.apk")

	var useAapt2 bool
	var nativeCompileErr error
	// The native resource decoder does not export every resource type
	// (attr, id, styleable, drawable aliases ...), so recompiling its XML with
	// aapt2 would drop resources. Binary resources stay authoritative there and
	// string edits are patched into resources.arsc directly (no aapt2 needed).
	nativeResources := fileExists(filepath.Join(r.SourceDir, "resources.arsc.json")) || fileExists(filepath.Join(r.SourceDir, "resources.arsc"))
	// Fresh text projects have no compiled resources to overlay. Compile a
	// complete resource APK in Go first, including manifest, IDs and ARSC.
	if !nativeResources && !fileExists(manifestPath+".bin") && fileExists(manifestPath) {
		if manifest, err := os.ReadFile(manifestPath); err == nil && !axml.IsBinaryXML(manifest) {
			if err := r.compileNativeResources(ctx, linkedApk); err == nil {
				useAapt2 = true // both compilers produce the same linked ZIP contract
				r.warn("resources compiled natively: no aapt2 or android.jar required")
			} else if !r.UseAapt2 || !aapt2.Available() {
				return &LoaderError{Op: "native_resources", err: err}
			} else {
				nativeCompileErr = err
				r.warn("native resources unsupported, using enabled aapt2 compatibility backend: %v", err)
			}
		}
	}
	if r.UseAapt2 && nativeResources && aapt2.Available() {
		r.warn("aapt2 skipped: resources were decoded natively; binary resources are authoritative")
	}
	if !useAapt2 && r.UseAapt2 && !nativeResources && aapt2.Available() {
		_, hasRes := os.Stat(resDir)
		_, hasManifest := os.Stat(manifestPath)
		if hasRes == nil && hasManifest == nil {
			if err := aapt2.CompileResources(resDir, compiledZip, true); err == nil {
				opts := Aapt2LinkOptions{
					ManifestPath:   manifestPath,
					CompiledResZip: compiledZip,
					FrameworkAPKs:  r.frameworkAPKs(),
					MinSDK:         r.metaOrZero(func(m *APKMeta) int { return m.MinSDK }),
					TargetSDK:      r.metaOrZero(func(m *APKMeta) int { return m.TargetSDK }),
					VersionCode:    r.metaOrZero(func(m *APKMeta) int { return m.VersionCode }),
					VersionName:    r.metaOrString(func(m *APKMeta) string { return m.VersionName }),
					PackageName:    r.metaOrString(func(m *APKMeta) string { return m.Package }),
				}
				if err := aapt2.LinkResources(manifestPath, compiledZip, linkedApk, opts); err == nil {
					useAapt2 = true
					r.warn("aapt2 link produced intermediate APK")
				} else {
					return &LoaderError{Op: "aapt2_link", err: err}
				}
			} else {
				return &LoaderError{Op: "aapt2_compile", err: err}
			}
		}
	}
	if nativeCompileErr != nil && !useAapt2 {
		return &LoaderError{Op: "native_resources", err: nativeCompileErr}
	}

	// ── Phase 3: collect files ──
	files, err := r.collectFiles(ctx)
	if err != nil {
		return &LoaderError{Op: "collect_files", err: err}
	}

	if len(files) == 0 && !useAapt2 {
		return &LoaderError{Op: "rebuild", err: fmt.Errorf("no files found in source directory")}
	}

	// ── Phase 4: create APK ──
	if useAapt2 {
		// Merge aapt2-linked APK (contains arsc, manifest, compiled res)
		// with everything else (assets, lib, dex, original, …).
		if err := r.createMergedZipArchive(ctx, files, linkedApk, targetApk); err != nil {
			return &LoaderError{Op: "create_merged_zip", err: err}
		}
	} else {
		if err := r.createZipArchive(ctx, files, targetApk); err != nil {
			return &LoaderError{Op: "create_zip", err: err}
		}
	}

	if diags := VerifyAPKCompression(targetApk, r.meta); len(diags) > 0 {
		r.addDiagnostics(diags...)
		if err := diagnosticsError("apk_compression", diags); err != nil {
			return &LoaderError{Op: "apk_compression", err: err}
		}
	}

	// ── Phase 5: align ──
	if r.IncludeAlignment {
		alignedPath := targetApk + ".aligned"
		if err := AlignAPK(targetApk, alignedPath); err != nil {
			return &LoaderError{Op: "align", err: err}
		} else {
			os.Remove(targetApk)
			if err := os.Rename(alignedPath, targetApk); err != nil {
				return &LoaderError{Op: "rename_aligned", err: err}
			}
			if err := VerifyAlignment(targetApk); err != nil {
				d := Diagnostic{Code: "APK_ALIGN_VERIFY_FAILED", Severity: DiagWarn, Stage: "align", Path: targetApk, Message: err.Error(), Hint: "fallback aligner could not prove alignment; official zipalign is recommended"}
				r.addDiagnostics(d)
			}
		}
	}

	// ── Phase 6: sign (v1+v2+v3) ──
	if r.PreserveOriginalSignature {
		d := Diagnostic{Code: "APK_ORIGINAL_SIGNATURE_PRESERVED_EXPERIMENTAL", Severity: DiagWarn, Stage: "sign", Path: targetApk, Message: "original signature files/signing block were preserved without re-signing; this only remains valid when signed bytes did not change", Hint: "use for experiments only; any changed APK entry invalidates real Android signatures"}
		r.addDiagnostics(d)
	} else if r.IncludeSignature {
		if err := r.signAndVerify(targetApk); err != nil {
			return err
		}
	}

	// ── Phase 7: package XAPK container (if applicable) ──
	if isXAPK {
		r.warn("packaging final XAPK container...")
		if err := r.createXAPKArchive(ctx, targetApk, outputPath); err != nil {
			return &LoaderError{Op: "create_xapk", err: err}
		}
	}

	return nil
}

// signAndVerify signs targetApk with the configured key material and then
// proves the result cryptographically. Fail-closed: a user key that does
// not match the original signer is a hard error; a debug key is allowed
// but loudly labeled, never silently passed off as the original.
func (r *APKRebuilder) signAndVerify(targetApk string) error {
	outcome, err := SignAPKWithConfig(targetApk, SignConfig{
		KeystorePath: r.SigningKeystore,
		KeyAlias:     r.SigningKeyAlias,
		StorePass:    r.SigningStorePass,
		KeyPass:      r.SigningKeyPass,
		MinSDK:       uint32(r.metaOrZero(func(m *APKMeta) int { return m.MinSDK })),
	})
	if err != nil {
		return &LoaderError{Op: "sign", err: err}
	}
	userKey := r.SigningKeystore != "" && !outcome.DebugKey
	switch outcome.Method {
	case SignMethodApkSigner:
		if verr := VerifySignature(targetApk); verr != nil {
			d := Diagnostic{Code: "APK_SIGNATURE_VERIFY_FAILED", Severity: DiagError, Stage: "sign", Path: targetApk, Message: verr.Error(), Hint: "re-sign the APK or inspect META-INF signature entries"}
			r.addDiagnostics(d)
			return &LoaderError{Op: "verify_signature", err: d}
		}
		r.addDiagnostics(Diagnostic{Code: "APK_SIGNED_APKSIGNER_VERIFIED", Severity: DiagInfo, Stage: "sign", Path: targetApk, Message: fmt.Sprintf("signed with user keystore via apksigner and verified; signer SHA-256 %s", shortFP(outcome.SignerSHA256))})
	default:
		fp, verr := VerifyV1SignatureOffline(targetApk)
		if verr != nil {
			d := Diagnostic{Code: "APK_SIGNATURE_VERIFY_FAILED", Severity: DiagError, Stage: "sign", Path: targetApk, Message: verr.Error(), Hint: "the built-in signer produced output it cannot prove; inspect META-INF"}
			r.addDiagnostics(d)
			return &LoaderError{Op: "verify_signature", err: d}
		}
		if v2out, verr := VerifyV2V3Offline(targetApk); verr != nil || !v2out.V2 || !v2out.V3 {
			msg := "v2/v3 block missing"
			if verr != nil {
				msg = verr.Error()
			}
			d := Diagnostic{Code: "APK_SIGNATURE_VERIFY_FAILED", Severity: DiagError, Stage: "sign", Path: targetApk, Message: "v2/v3 verification: " + msg, Hint: "the built-in signer produced output it cannot prove; inspect the APK Signing Block"}
			r.addDiagnostics(d)
			return &LoaderError{Op: "verify_signature", err: d}
		} else if v2out.SignerSHA256 != fp {
			d := Diagnostic{Code: "APK_SIGNATURE_VERIFY_FAILED", Severity: DiagError, Stage: "sign", Path: targetApk, Message: "v1 and v2/v3 signers differ; refusing a half-signed APK"}
			r.addDiagnostics(d)
			return &LoaderError{Op: "verify_signature", err: d}
		}
		outcome.SignerSHA256 = fp
		note := "self-signed debug key (v1+v2+v3): Android installs it as an unknown publisher, stores reject it"
		if outcome.Note != "" {
			note += "; " + outcome.Note
		}
		r.addDiagnostics(Diagnostic{Code: "APK_SIGNED_DEBUG_UNVERIFIED", Severity: DiagWarn, Stage: "sign", Path: targetApk, Message: fmt.Sprintf("signed with generated debug key, cryptographically self-consistent; signer SHA-256 %s; %s", shortFP(fp), note), Hint: "pass --ks <keystore> with ANALYZER_KEYSTORE_PASS set to sign with your own key"})
	}
	if outcome.SignerSHA256 == "" {
		r.addDiagnostics(Diagnostic{Code: "APK_SIGNER_FP_UNKNOWN", Severity: DiagInfo, Stage: "sign", Path: targetApk, Message: "signer fingerprint could not be extracted; original-signer match not checked"})
		return nil
	}
	// Compare against the original signer when the source tree still
	// carries signature material.
	origFPs := originalSignerFingerprints(r.SourceDir)
	if len(origFPs) == 0 {
		r.addDiagnostics(Diagnostic{Code: "APK_ORIGINAL_SIGNER_UNKNOWN", Severity: DiagInfo, Stage: "sign", Path: targetApk, Message: "source tree carries no original signature block; signer match not checked", Hint: "decode with META-INF preserved to enable the check"})
		return nil
	}
	for _, ofp := range origFPs {
		if ofp == outcome.SignerSHA256 {
			r.addDiagnostics(Diagnostic{Code: "APK_SIGNER_MATCHES_ORIGINAL", Severity: DiagInfo, Stage: "sign", Path: targetApk, Message: fmt.Sprintf("signer SHA-256 %s matches the original", shortFP(ofp))})
			return nil
		}
	}
	if userKey {
		d := Diagnostic{Code: "APK_SIGNER_MISMATCH_ORIGINAL", Severity: DiagError, Stage: "sign", Path: targetApk, Message: fmt.Sprintf("signer SHA-256 %s does not match original %s; refusing to ship a silently re-keyed APK", shortFP(outcome.SignerSHA256), shortFP(origFPs[0])), Hint: "point --ks at the original keystore (or its backup); for Play App Signing use the upload key"}
		r.addDiagnostics(d)
		return &LoaderError{Op: "verify_signer_match", err: d}
	}
	r.addDiagnostics(Diagnostic{Code: "APK_SIGNER_DIFFERS_FROM_ORIGINAL", Severity: DiagWarn, Stage: "sign", Path: targetApk, Message: fmt.Sprintf("debug signer SHA-256 %s differs from original %s (expected: a fresh debug key cannot match); updates over the original install will be rejected by Android", shortFP(outcome.SignerSHA256), shortFP(origFPs[0])), Hint: "pass --ks <original keystore> to keep the update path"})
	return nil
}

func shortFP(fp string) string {
	if len(fp) > 16 {
		return fp[:16] + "…"
	}
	return fp
}

// isSignatureFile checks if file is an old signature file that must be skipped and regenerated
func isSignatureFile(relPath string) bool {
	if !strings.HasPrefix(relPath, "META-INF/") {
		return false
	}
	upper := strings.ToUpper(relPath)
	return strings.HasSuffix(upper, ".SF") ||
		strings.HasSuffix(upper, ".RSA") ||
		strings.HasSuffix(upper, ".DSA") ||
		strings.HasSuffix(upper, ".EC") ||
		upper == "META-INF/MANIFEST.MF" ||
		strings.HasPrefix(upper, "META-INF/SIG-")
}

// stripDupSuffix removes disambiguation suffix added on case-insensitive filesystems (_dup1, _dup2, etc.)
func stripDupSuffix(relPath string) string {
	ext := filepath.Ext(relPath)
	base := strings.TrimSuffix(relPath, ext)
	// Check if base ends with _dup<digits>
	if idx := strings.LastIndex(base, "_dup"); idx >= 0 {
		digits := base[idx+4:]
		allDigits := true
		for _, r := range digits {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && len(digits) > 0 {
			return base[:idx] + ext
		}
	}
	return relPath
}

func (r *APKRebuilder) ensureBinaryXMLFile(path string, relPath string) (string, os.FileInfo) {
	binPath := path + ".bin"
	if binInfo, err := os.Stat(binPath); err == nil {
		return binPath, binInfo
	}

	// Direct file might already be binary
	if data, err := os.ReadFile(path); err == nil && axml.IsBinaryXML(data) {
		if info, err := os.Stat(path); err == nil {
			return path, info
		}
	}

	// Try recovering binary form from source APK in parent/source directory
	parentDir := filepath.Dir(r.SourceDir)
	baseName := filepath.Base(r.SourceDir)
	cleanName := strings.TrimPrefix(baseName, "decoded_")

	candidateApks := []string{
		filepath.Join(parentDir, cleanName),
		filepath.Join(parentDir, cleanName+".apk"),
		filepath.Join(parentDir, cleanName+".xapk"),
		filepath.Join(parentDir, strings.TrimSuffix(cleanName, ".apk")+".apk"),
		filepath.Join(parentDir, strings.TrimSuffix(cleanName, ".xapk")+".apk"),
	}

	for _, apkPath := range candidateApks {
		if zr, err := zip.OpenReader(apkPath); err == nil {
			for _, f := range zr.File {
				if filepath.ToSlash(f.Name) == filepath.ToSlash(relPath) {
					if rc, err := f.Open(); err == nil {
						data, err := io.ReadAll(rc)
						rc.Close()
						if err == nil && axml.IsBinaryXML(data) {
							if err := os.WriteFile(binPath, data, 0644); err == nil {
								zr.Close()
								if info, err := os.Stat(binPath); err == nil {
									return binPath, info
								}
							}
						}
					}
				}
			}
			zr.Close()
		}
	}

	if info, err := os.Stat(path); err == nil {
		return path, info
	}
	return path, nil
}

// CollectFiles is the exported wrapper for collectFiles
func (r *APKRebuilder) CollectFiles(ctx context.Context) ([]FileEntry, error) {
	return r.collectFiles(ctx)
}

// collectFiles scans the source directory and collects all files.
// When CopyOriginal is true the original/ subtree is hoisted to the APK root.
func (r *APKRebuilder) collectFiles(ctx context.Context) ([]FileEntry, error) {
	filesByPath := make(map[string]FileEntry)
	// resources.arsc.json marks a tree produced by the native decoder, whose
	// res/values*/ XML is only an export of resources.arsc.
	hasArsc := fileExists(filepath.Join(r.SourceDir, "resources.arsc")) && fileExists(filepath.Join(r.SourceDir, "resources.arsc.json"))
	addFile := func(entry FileEntry) {
		filesByPath[entry.RelativePath] = entry
	}

	err := filepath.Walk(r.SourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}
		if outputAbs, e := filepath.Abs(r.OutputPath); e == nil {
			if pathAbs, e := filepath.Abs(path); e == nil && strings.EqualFold(pathAbs, outputAbs) {
				return nil
			}
		}

		// Calculate relative path
		relPath, err := filepath.Rel(r.SourceDir, path)
		if err != nil {
			return err
		}
		// Skip apktool.yml
		if relPath == "apktool.yml" {
			return nil
		}

		// Convert to forward slashes for ZIP compatibility
		relPath = filepath.ToSlash(relPath)

		// Smali sources must never ship inside the APK: DEX is the runtime
		// artifact, smali is build input. Previously this exclusion only
		// applied after a fully successful assembly (smaliAssembled), so a
		// partially-failed build both lost the dex AND shipped 60k+ .smali
		// files, blowing past the 65535-entry ZIP limit and breaking every
		// downstream tool. Skip unconditionally. The same holds for .java
		// pseudocode sidecars emitted next to smali by JavaView decodes.
		if strings.HasPrefix(relPath, "smali/") || strings.HasPrefix(relPath, "smali_") ||
			strings.Contains(relPath, "/smali/") || relPath == "smali" || strings.HasSuffix(relPath, ".smali") {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(relPath), ".java") && (strings.Contains(relPath, "/smali/") || strings.HasPrefix(relPath, "smali/") || strings.HasPrefix(relPath, "smali_")) {
			return nil
		}

		// Skip the original/ subtree when walking normally — it is handled
		// separately so it lands at the APK root, not inside original/.
		if strings.HasPrefix(relPath, "original/") {
			return nil
		}

		// Skip metadata, decode cache, logs, and dumped json files
		if relPath == "omnisec-meta.json" || relPath == "apktool.yml" || relPath == "analyzer.log" ||
			strings.HasPrefix(relPath, ".mega-analyzer") ||
			strings.HasSuffix(relPath, ".arsc.json") || (strings.HasSuffix(relPath, ".json") && !strings.HasPrefix(relPath, "assets/")) {
			return nil
		}

		// Skip XAPK container files (manifest.json, icon.png, Android/ directory) from the inner APK
		if relPath == "manifest.json" || relPath == "icon.png" || strings.HasPrefix(relPath, "Android/") {
			return nil
		}

		// Skip old signature and META-INF files (they will be freshly signed by apksigner)
		if strings.HasPrefix(relPath, "META-INF/") && !r.PreserveOriginalSignature {
			return nil
		}

		// Skip build directory
		if strings.HasPrefix(relPath, "build/") || relPath == "build" {
			return nil
		}

		// res/values*/*.xml are the decoder's *text export* of resources.arsc
		// (public.xml, strings.xml, ...). aapt never ships them: the values live
		// in resources.arsc. Packing them only bloats the APK (~1.6 MB on NewPipe).
		if hasArsc && isExportedValuesXML(relPath) {
			return nil
		}

		// Restore original case-sensitive name by stripping Windows collision suffix (_dup1, _dup2, etc.)
		zipRelPath := stripDupSuffix(relPath)

		// Handle AXML fallback: substitute plain-text XML files with their original binary version (.bin)
		if strings.HasSuffix(strings.ToLower(zipRelPath), ".xml") {
			finalPath, finalInfo := r.ensureBinaryXMLFile(path, zipRelPath)
			if finalInfo != nil {
				// Honest fallback: if the text XML was edited after the binary
				// was produced/patched, structural edits (new elements,
				// reordered nodes) cannot be represented by string-patching
				// alone. Warn instead of silently reverting the user's edit.
				if finalPath != path {
					if textInfo, err := os.Stat(path); err == nil {
						if textInfo.ModTime().After(finalInfo.ModTime()) {
							r.warn("text XML %s is newer than its binary; packaging patched binary (string edits survive, structural edits need aapt2)", zipRelPath)
						}
					}
				}
				addFile(FileEntry{
					RelativePath:   zipRelPath, // Store as original .xml in the ZIP
					FullPath:       finalPath,
					Info:           finalInfo,
					ShouldCompress: r.shouldCompressFile(zipRelPath),
				})
				return nil
			}
		}

		// Prevent raw .bin from being packed directly into the APK
		if strings.HasSuffix(strings.ToLower(relPath), ".xml.bin") || relPath == "AndroidManifest.xml.bin" {
			return nil
		}

		// Determine compression strategy
		shouldCompress := r.shouldCompressFile(zipRelPath)

		addFile(FileEntry{
			RelativePath:   zipRelPath,
			FullPath:       path,
			Info:           info,
			ShouldCompress: shouldCompress,
		})

		return nil
	})

	if err != nil {
		return nil, err
	}

	// If copy-original is enabled, overlay files from original/ onto the root.
	if r.CopyOriginal {
		originalDir := filepath.Join(r.SourceDir, "original")
		if stat, err := os.Stat(originalDir); err == nil && stat.IsDir() {
			if err := filepath.Walk(originalDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				relPath, err := filepath.Rel(originalDir, path)
				if err != nil {
					return err
				}
				relPath = filepath.ToSlash(relPath)
				addFile(FileEntry{
					RelativePath:   relPath,
					FullPath:       path,
					Info:           info,
					ShouldCompress: r.shouldCompressFile(relPath),
				})
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}

	// Overlay unknown/ files onto the APK root (Apktool convention).
	unknownDir := filepath.Join(r.SourceDir, "unknown")
	if stat, err := os.Stat(unknownDir); err == nil && stat.IsDir() {
		if err := filepath.Walk(unknownDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			relPath, err := filepath.Rel(unknownDir, path)
			if err != nil {
				return err
			}
			relPath = filepath.ToSlash(relPath)
			addFile(FileEntry{
				RelativePath:   relPath,
				FullPath:       path,
				Info:           info,
				ShouldCompress: r.shouldCompressFile(relPath),
			})
			return nil
		}); err != nil {
			return nil, err
		}
	}

	paths := make([]string, 0, len(filesByPath))
	for path := range filesByPath {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	files := make([]FileEntry, 0, len(paths))
	for _, path := range paths {
		files = append(files, filesByPath[path])
	}
	return files, nil
}

// noCompressExts is the set of extensions that are already compressed media.
var noCompressExts = map[string]bool{
	"jpg": true, "jpeg": true, "png": true, "gif": true,
	"wav": true, "mp2": true, "mp3": true, "ogg": true, "aac": true,
	"mpg": true, "mpeg": true, "mid": true, "midi": true,
	"smf": true, "jet": true, "rtttl": true, "imy": true, "xmf": true,
	"mp4": true, "m4a": true, "m4v": true,
	"3gp": true, "3gpp": true, "3g2": true, "3gpp2": true,
	"amr": true, "awb": true, "wma": true, "wmv": true,
	"webm": true, "webp": true, "mkv": true,
}

// shouldCompressFile determines if a file should be compressed.
// Follows Android AAPT/Apktool specification:
// - resources.arsc is stored uncompressed (STORE) for runtime mmap
// - media files (png, jpg, mp3, etc.) and 9-patch are stored uncompressed (STORE)
// - bytecode, native libraries and extensions listed in metadata are stored
func (r *APKRebuilder) shouldCompressFile(relPath string) bool {
	if relPath == "resources.arsc" {
		return false
	}

	// Special 9.png suffix
	if strings.HasSuffix(relPath, ".9.png") {
		return false
	}

	ext := strings.ToLower(filepath.Ext(relPath))
	if ext != "" {
		ext = ext[1:] // strip leading dot
	}

	// dex is always deflated (apktool/aapt do the same, ~3x smaller); native
	// libraries are deflated too unless the app asked for them to be mapped
	// straight out of the APK (extractNativeLibs=false / listed in metadata).
	if ext == "so" && r.storeNativeLibs() {
		return false
	}
	if ext != "dex" && ext != "so" && noCompressExts[ext] {
		return false
	}
	if r.meta != nil {
		for _, configured := range r.meta.DoNotCompress {
			configured = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(configured)), ".")
			if configured == ext && ext != "dex" {
				return false
			}
		}
	}

	return true
}

// createZipArchive creates the ZIP archive with proper compression.
//
// Compression (DEFLATE) is the dominant cost when rebuilding a large APK, so
// entries are compressed concurrently across all CPUs and then written to the
// archive in their original order via CreateRaw. The single output ZIP writer
// stays single-threaded (it must), but the expensive deflate work fans out.
func (r *APKRebuilder) createZipArchive(ctx context.Context, files []FileEntry, outputPath string) error {
	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	zipWriter := zip.NewWriter(outFile)
	defer zipWriter.Close()

	// Pre-compress entries in parallel, preserving order.
	prepared := r.compressEntriesParallel(ctx, files, r.zipBuildConfig())

	for i, pe := range prepared {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if pe == nil {
			return fmt.Errorf("failed to prepare %s", files[i].RelativePath)
		}
		if err := writeRawZipEntry(zipWriter, pe); err != nil {
			r.warn("failed to write %s: %v", files[i].RelativePath, err)
			continue
		}
	}

	return nil
}

// preparedEntry holds an already-compressed (or stored) ZIP entry ready to be
// streamed into the archive with CreateRaw.
type preparedEntry struct {
	header   *zip.FileHeader
	body     []byte // compressed bytes (Deflate) or raw bytes (Store)
	bodyPath string // temp-spooled body for large entries
}

// compressEntriesParallel compresses every entry concurrently and returns the
// results in the same order as the input. A nil slot means that entry failed.
func (r *APKRebuilder) compressEntriesParallel(ctx context.Context, files []FileEntry, cfg zipBuildConfig) []*preparedEntry {
	out := make([]*preparedEntry, len(files))

	workers := runtime.NumCPU()
	if workers > 16 {
		workers = 16
	}
	if workers < 1 {
		workers = 1
	}

	var next int64 = -1
	total := int64(len(files))
	var wg sync.WaitGroup
	var warnMu sync.Mutex
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := atomic.AddInt64(&next, 1)
				if i >= total {
					return
				}
				if i&0x3F == 0 && ctx.Err() != nil {
					return
				}
				pe, err := prepareZipEntry(files[i], cfg)
				if err != nil {
					warnMu.Lock()
					r.warn("compress %s: %v", files[i].RelativePath, err)
					warnMu.Unlock()
					continue
				}
				out[i] = pe
			}
		}()
	}
	wg.Wait()
	return out
}

// prepareZipEntry reads a file and produces its compressed (or stored) form
// plus a fully-populated header (CRC32 + sizes), ready for CreateRaw.
func prepareZipEntry(entry FileEntry, cfg zipBuildConfig) (*preparedEntry, error) {
	if entry.ShouldCompress && shouldStoreForSpeed(entry.RelativePath, entry.Info.Size()) {
		entry.ShouldCompress = false
	}
	if entry.Info.Size() > cfg.spoolThreshold {
		return prepareZipEntrySpool(entry, cfg)
	}

	raw, err := os.ReadFile(entry.FullPath)
	if err != nil {
		return nil, err
	}

	header := &zip.FileHeader{
		Name:               entry.RelativePath,
		Modified:           entry.Info.ModTime(),
		CRC32:              crc32.ChecksumIEEE(raw),
		UncompressedSize64: uint64(len(raw)),
	}

	if !entry.ShouldCompress {
		header.Method = zip.Store
		header.CompressedSize64 = uint64(len(raw))
		return &preparedEntry{header: header, body: raw}, nil
	}

	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, cfg.mode.flateLevel())
	if err != nil {
		return nil, err
	}
	if _, err := fw.Write(raw); err != nil {
		_ = fw.Close()
		return nil, err
	}
	if err := fw.Close(); err != nil {
		return nil, err
	}
	header.Method = zip.Deflate
	header.CompressedSize64 = uint64(buf.Len())
	return &preparedEntry{header: header, body: buf.Bytes()}, nil
}

func prepareZipEntrySpool(entry FileEntry, cfg zipBuildConfig) (*preparedEntry, error) {
	src, err := os.Open(entry.FullPath)
	if err != nil {
		return nil, err
	}
	defer src.Close()

	tmp, err := os.CreateTemp("", "mega-zip-entry-*")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	hash := crc32.NewIEEE()
	counting := &countingWriter{w: tmp}
	w := io.MultiWriter(hash, counting)
	if entry.ShouldCompress {
		fw, err := flate.NewWriter(tmp, cfg.mode.flateLevel())
		if err != nil {
			return nil, err
		}
		w = io.MultiWriter(hash, fw)
		if _, err := io.Copy(w, src); err != nil {
			_ = fw.Close()
			return nil, err
		}
		if err := fw.Close(); err != nil {
			return nil, err
		}
		if fi, err := tmp.Stat(); err == nil {
			counting.n = fi.Size()
		}
	} else {
		if _, err := io.Copy(w, src); err != nil {
			return nil, err
		}
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	header := &zip.FileHeader{Name: entry.RelativePath, Modified: entry.Info.ModTime(), CRC32: hash.Sum32(), UncompressedSize64: uint64(entry.Info.Size()), CompressedSize64: uint64(counting.n)}
	if entry.ShouldCompress {
		header.Method = zip.Deflate
	} else {
		header.Method = zip.Store
	}
	cleanup = false
	return &preparedEntry{header: header, bodyPath: tmpPath}, nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n += int64(n)
	return n, err
}

// writeRawZipEntry streams a pre-compressed entry into the archive without
// re-compressing it.
func writeRawZipEntry(w *zip.Writer, pe *preparedEntry) error {
	raw, err := w.CreateRaw(pe.header)
	if err != nil {
		return err
	}
	if pe.bodyPath != "" {
		f, err := os.Open(pe.bodyPath)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(raw, f)
		_ = os.Remove(pe.bodyPath)
		return err
	}
	_, err = raw.Write(pe.body)
	return err
}

// writeZipEntry writes a single file entry to the ZIP archive (sequential path,
// still used by the merged-archive overlay).
func (r *APKRebuilder) writeZipEntry(w *zip.Writer, entry FileEntry) error {
	// Create ZIP file header
	header := &zip.FileHeader{
		Name:     entry.RelativePath,
		Method:   zip.Store, // Default to no compression
		Modified: entry.Info.ModTime(),
	}

	// Set compression method
	if entry.ShouldCompress {
		header.Method = zip.Deflate
	}

	// Open source file
	srcFile, err := os.Open(entry.FullPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	if !entry.ShouldCompress {
		hash := crc32.NewIEEE()
		size, err := io.Copy(hash, srcFile)
		if err != nil {
			return err
		}
		header.CRC32 = hash.Sum32()
		header.UncompressedSize64 = uint64(size)
		header.CompressedSize64 = uint64(size)
		if _, err := srcFile.Seek(0, 0); err != nil {
			return err
		}
	}

	// Create writer for this entry
	writer, err := w.CreateHeader(header)
	if err != nil {
		return err
	}

	// Copy file content
	_, err = io.Copy(writer, srcFile)
	return err
}

// createMergedZipArchive copies the aapt2-linked APK and overlays files
// from the source directory, skipping entries already produced by aapt2
// (res/, AndroidManifest.xml, resources.arsc).
func (r *APKRebuilder) createMergedZipArchive(ctx context.Context, files []FileEntry, linkedApk, outputPath string) error {
	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	zipWriter := zip.NewWriter(outFile)
	defer zipWriter.Close()

	// Copy everything from the aapt2-linked APK first
	reader, err := zip.OpenReader(linkedApk)
	if err != nil {
		return fmt.Errorf("open linked apk: %w", err)
	}
	defer reader.Close()

	seen := make(map[string]bool)
	for _, f := range reader.File {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		seen[f.Name] = true
		if err := copyZipEntry(zipWriter, f); err != nil {
			return fmt.Errorf("copy linked %s: %w", f.Name, err)
		}
	}

	// Overlay source files, skipping aapt2-managed entries
	for _, entry := range files {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip entries already in the linked APK
		if seen[entry.RelativePath] {
			continue
		}
		// Also skip raw res/ and manifest — aapt2 already compiled them
		if strings.HasPrefix(entry.RelativePath, "res/") ||
			entry.RelativePath == "AndroidManifest.xml" ||
			entry.RelativePath == "resources.arsc" {
			continue
		}
		pe, err := prepareZipEntry(entry, r.zipBuildConfig())
		if err != nil {
			return fmt.Errorf("prepare %s: %w", entry.RelativePath, err)
		}
		if err := writeRawZipEntry(zipWriter, pe); err != nil {
			return fmt.Errorf("write %s: %w", entry.RelativePath, err)
		}
	}

	if err := zipWriter.Close(); err != nil {
		return err
	}
	return outFile.Close()
}

// frameworkAPKs returns the paths to android.jar and other framework APKs for aapt2 -I.
// Tries ANDROID_HOME first, then falls back to a bundled placeholder.
func (r *APKRebuilder) frameworkAPKs() []string {
	var frameworks []string

	// Start with base android.jar
	baseJarFound := false
	var sdkPaths []string
	for _, env := range []string{"ANDROID_HOME", "ANDROID_SDK_ROOT"} {
		if sdk := os.Getenv(env); sdk != "" {
			sdkPaths = append(sdkPaths, sdk)
		}
	}
	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		sdkPaths = append(sdkPaths, filepath.Join(localAppData, "Android", "Sdk"))
	}

	for _, sdk := range sdkPaths {
		jar := filepath.Join(sdk, "platforms", "android-30", "android.jar")
		if _, err := os.Stat(jar); err == nil {
			frameworks = append(frameworks, jar)
			baseJarFound = true
			break
		}
		// try any installed platform
		if platforms, err := os.ReadDir(filepath.Join(sdk, "platforms")); err == nil {
			// Iterate backwards to prefer newer platforms
			for i := len(platforms) - 1; i >= 0; i-- {
				p := platforms[i]
				if p.IsDir() {
					jar = filepath.Join(sdk, "platforms", p.Name(), "android.jar")
					if _, err := os.Stat(jar); err == nil {
						frameworks = append(frameworks, jar)
						baseJarFound = true
						break
					}
				}
			}
		}
		if baseJarFound {
			break
		}
	}
	if !baseJarFound {
		frameworks = append(frameworks, "android.jar")
	}

	// Now search for extra framework APKs from usesFramework
	yamlPath := filepath.Join(r.SourceDir, "apktool.yml")
	ids, tag := parseApktoolYaml(yamlPath)

	// Framework search directories — Windows, Linux and macOS conventions so
	// apktool framework files resolve on every platform. See plan §2.
	var searchDirs []string
	if local := os.Getenv("LocalAppData"); local != "" {
		searchDirs = append(searchDirs, filepath.Join(local, "apktool", "framework"))
	}
	if profile := os.Getenv("USERPROFILE"); profile != "" {
		searchDirs = append(searchDirs, filepath.Join(profile, "apktool", "framework"))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		// Linux default (apktool uses ~/.local/share on XDG systems).
		searchDirs = append(searchDirs,
			filepath.Join(home, ".local", "share", "apktool", "framework"))
		// macOS default.
		searchDirs = append(searchDirs,
			filepath.Join(home, "Library", "apktool", "framework"))
		// Generic ~/apktool/framework fallback.
		searchDirs = append(searchDirs,
			filepath.Join(home, "apktool", "framework"))
	}

	// Local android.jar candidates (highest priority for modern APKs)
	jarCandidates := []string{
		"bin/tools/android.jar",
		"tools/windows/android.jar",
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		jarCandidates = append(jarCandidates,
			filepath.Join(exeDir, "tools", "android.jar"),
			filepath.Join(exeDir, "tools", "windows", "android.jar"),
			filepath.Join(exeDir, "bin", "tools", "android.jar"),
			filepath.Join(exeDir, "..", "tools", "windows", "android.jar"),
			filepath.Join(exeDir, "..", "bin", "tools", "android.jar"),
		)
	}
	for _, jc := range jarCandidates {
		if abs, err := filepath.Abs(jc); err == nil {
			if _, err := os.Stat(abs); err == nil {
				if !containsPath(frameworks, abs) {
					frameworks = append(frameworks, abs)
				}
				break
			}
		}
	}

	// If usesFramework ids are parsed, resolve them.
	// Otherwise, check if "1.apk" exists in searchDirs and append it just in case.
	if len(ids) > 0 {
		for _, id := range ids {
			found := false
			for _, dir := range searchDirs {
				// Try id-tag.apk if tag is specified
				if tag != "" {
					customPath := filepath.Join(dir, fmt.Sprintf("%d-%s.apk", id, tag))
					if _, err := os.Stat(customPath); err == nil {
						frameworks = append(frameworks, customPath)
						found = true
						break
					}
				}
				// Try standard id.apk
				stdPath := filepath.Join(dir, fmt.Sprintf("%d.apk", id))
				if _, err := os.Stat(stdPath); err == nil {
					frameworks = append(frameworks, stdPath)
					found = true
					break
				}
			}
			if !found {
				r.warn("framework apk for id %d not found in standard paths", id)
			}
		}
	} else {
		// Fallback: check if 1.apk is present
		for _, dir := range searchDirs {
			stdPath := filepath.Join(dir, "1.apk")
			if _, err := os.Stat(stdPath); err == nil {
				frameworks = append(frameworks, stdPath)
				break
			}
		}
	}

	return frameworks
}

func containsPath(paths []string, candidate string) bool {
	for _, path := range paths {
		if strings.EqualFold(filepath.Clean(path), filepath.Clean(candidate)) {
			return true
		}
	}
	return false
}

// parseApktoolYaml parses apktool.yml using a safe, zero-dependency, line-by-line custom parser.
func parseApktoolYaml(yamlPath string) ([]int, string) {
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		return nil, ""
	}

	var ids []int
	var tag string
	lines := strings.Split(string(data), "\n")
	inUsesFramework := false
	inIds := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " \t"))

		if strings.HasPrefix(trimmed, "usesFramework:") {
			inUsesFramework = true
			inIds = false
			continue
		}

		if inUsesFramework {
			if strings.HasPrefix(trimmed, "ids:") {
				inIds = true
				rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "ids:"))
				if strings.HasPrefix(rest, "[") && strings.HasSuffix(rest, "]") {
					arrStr := rest[1 : len(rest)-1]
					for _, part := range strings.Split(arrStr, ",") {
						var id int
						if _, err := fmt.Sscanf(strings.TrimSpace(part), "%d", &id); err == nil {
							ids = append(ids, id)
						}
					}
					inIds = false
				}
				continue
			}
			if strings.HasPrefix(trimmed, "tag:") {
				inIds = false
				tag = strings.TrimSpace(strings.TrimPrefix(trimmed, "tag:"))
				tag = strings.Trim(tag, "\"'")
				continue
			}

			if inIds && strings.HasPrefix(trimmed, "-") {
				valStr := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
				var id int
				if _, err := fmt.Sscanf(valStr, "%d", &id); err == nil {
					ids = append(ids, id)
				}
				continue
			}

			if indent == 0 && !strings.HasPrefix(trimmed, "usesFramework") {
				inUsesFramework = false
				inIds = false
			}
		}
	}
	return ids, tag
}

// metaOrZero extracts an int from meta or returns 0.
func (r *APKRebuilder) metaOrZero(fn func(*APKMeta) int) int {
	if r.meta == nil {
		return 0
	}
	return fn(r.meta)
}

// metaOrString extracts a string from meta or returns empty.
func (r *APKRebuilder) metaOrString(fn func(*APKMeta) string) string {
	if r.meta == nil {
		return ""
	}
	return fn(r.meta)
}

// warn adds a warning message
func (r *APKRebuilder) warn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	r.Warnings = append(r.Warnings, msg)
}

func (r *APKRebuilder) addDiagnostics(diags ...Diagnostic) {
	for _, d := range diags {
		r.Diagnostics = append(r.Diagnostics, d)
		if d.Severity == DiagWarn || d.Severity == DiagError || d.Severity == DiagFatal {
			r.warn("[%s] %s", d.Code, d.Error())
		}
	}
}

func (r *APKRebuilder) GetDiagnostics() []Diagnostic {
	return append([]Diagnostic(nil), r.Diagnostics...)
}

// smaliDirsPresent reports whether the source directory contains smali/ or
// smali_*/ directories (Apktool layout). Used to distinguish a plain-DEX
// rebuild from an edited decoded project where skipping assembly silently
// discards every smali edit.
func smaliDirsPresent(sourceDir string) bool {
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return false
	}
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		name := ent.Name()
		if name == "smali" || strings.HasPrefix(name, "smali_") {
			return true
		}
	}
	return false
}

// smaliFilesPresent reports whether any smali directory actually contains
// .smali sources. Directory stubs without sources (structure-only trees)
// skip assembly and package any existing DEX as-is.
func smaliFilesPresent(sourceDir string) bool {
	jobs, err := listSmaliJobs(sourceDir)
	if err != nil {
		return false
	}
	for _, job := range jobs {
		found := false
		_ = filepath.WalkDir(job.dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || found {
				return nil
			}
			if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".smali") {
				found = true
			}
			return nil
		})
		if found {
			return true
		}
	}
	return false
}

// GetWarnings returns all warnings
func (r *APKRebuilder) GetWarnings() []string {
	return r.Warnings
}

type xapkManifestMeta struct {
	PackageName string `json:"package_name"`
}

func (r *APKRebuilder) createXAPKArchive(ctx context.Context, innerApkPath string, outputPath string) error {
	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	zipWriter := zip.NewWriter(outFile)
	defer zipWriter.Close()

	// 1. Определяем имя внутреннего APK (например com.supercell.brawlstars.apk)
	innerApkName := "base.apk"
	manifestPath := filepath.Join(r.SourceDir, "manifest.json")
	if data, err := os.ReadFile(manifestPath); err == nil {
		var mf xapkManifestMeta
		if err := json.Unmarshal(data, &mf); err == nil && mf.PackageName != "" {
			innerApkName = mf.PackageName + ".apk"
		}
	} else if r.meta != nil && r.meta.Package != "" {
		innerApkName = r.meta.Package + ".apk"
	}

	// 2. Добавляем внутренний APK без повторного сжатия (STORE)
	if err := addFileToZip(zipWriter, innerApkPath, innerApkName, false); err != nil {
		return fmt.Errorf("failed to add inner APK to XAPK: %w", err)
	}

	// 3. Добавляем скорректированный manifest.json (чтобы XAPK Installer ссылался на единый собранный APK)
	if data, err := os.ReadFile(manifestPath); err == nil {
		var rawMap map[string]interface{}
		if err := json.Unmarshal(data, &rawMap); err == nil {
			rawMap["split_apks"] = []map[string]string{
				{"file": innerApkName, "id": "base"},
			}
			delete(rawMap, "split_configs")
			if fixedData, err := json.MarshalIndent(rawMap, "", "  "); err == nil {
				_ = addBytesToZip(zipWriter, fixedData, "manifest.json", false)
			} else {
				_ = addBytesToZip(zipWriter, data, "manifest.json", false)
			}
		} else {
			_ = addBytesToZip(zipWriter, data, "manifest.json", false)
		}
	}

	// 4. Добавляем icon.png
	iconPath := filepath.Join(r.SourceDir, "icon.png")
	if _, err := os.Stat(iconPath); err == nil {
		if err := addFileToZip(zipWriter, iconPath, "icon.png", false); err != nil {
			r.warn("failed to add icon.png to XAPK: %v", err)
		}
	}

	// 5. Добавляем папку Android/ (OBB файлы)
	androidDir := filepath.Join(r.SourceDir, "Android")
	if _, err := os.Stat(androidDir); err == nil {
		_ = filepath.Walk(androidDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(r.SourceDir, path)
			if err != nil {
				return nil
			}
			rel = filepath.ToSlash(rel)
			_ = addFileToZip(zipWriter, path, rel, false)
			return nil
		})
	}

	return nil
}

func addFileToZip(w *zip.Writer, srcPath, zipRelPath string, compress bool) error {
	info, err := os.Stat(srcPath)
	if err != nil {
		return err
	}
	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = filepath.ToSlash(zipRelPath)
	if compress {
		header.Method = zip.Deflate
	} else {
		header.Method = zip.Store
	}
	writer, err := w.CreateHeader(header)
	if err != nil {
		return err
	}
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(writer, f)
	return err
}

func addBytesToZip(w *zip.Writer, data []byte, zipRelPath string, compress bool) error {
	header := &zip.FileHeader{
		Name:   filepath.ToSlash(zipRelPath),
		Method: zip.Store,
	}
	if compress {
		header.Method = zip.Deflate
	}
	writer, err := w.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}

func (r *APKRebuilder) syncAndPatchResources() error {
	replacements := make(map[string]string)

	// 1. Check if manifest.json exists
	manifestPath := filepath.Join(r.SourceDir, "manifest.json")
	if data, err := os.ReadFile(manifestPath); err == nil {
		var m struct {
			Name        string `json:"name"`
			PackageName string `json:"package_name"`
			VersionName string `json:"version_name"`
		}
		if err := json.Unmarshal(data, &m); err == nil {
			if r.meta != nil {
				if r.meta.Package != "" && m.PackageName != "" && r.meta.Package != m.PackageName {
					replacements[r.meta.Package] = m.PackageName
				}
				if r.meta.VersionName != "" && m.VersionName != "" && r.meta.VersionName != m.VersionName {
					replacements[r.meta.VersionName] = m.VersionName
				}
			}
		}
	}

	// 2. Load the resource table once for overlay reference resolution
	//    and addressed string edits. Nil-safe: overlays work without it as
	//    long as no new @type/name references appear.
	var table *axml.ResourceTable
	if data, err := os.ReadFile(filepath.Join(r.SourceDir, "resources.arsc")); err == nil {
		if t, terr := axml.ParseARSC(data); terr == nil {
			table = t
		} else {
			r.warn("resources.arsc unreadable, reference resolution disabled: %v", terr)
		}
	}

	// 3. Re-encode edited text XML over its binary twin. The text is the
	//    user's intent; the .bin is what gets packaged.
	var resourceEdits []axml.ARSCEdit
	if fileExists(filepath.Join(r.SourceDir, "resources.arsc.json")) {
		var err error
		resourceEdits, err = r.collectNativeResourceEdits(table)
		if err != nil {
			return err
		}
	} else {
		resourceEdits = r.collectArscEdits()
	}
	if err := r.overlayTextXML("AndroidManifest.xml", table); err != nil {
		return err
	}
	if err := r.overlayResXML(table); err != nil {
		return err
	}

	// 4. Addressed resources.arsc string edits: one entry per changed
	//    <string>, sharing-safe (pool split instead of text collision).
	if edits := resourceEdits; len(edits) > 0 {
		arscPath := filepath.Join(r.SourceDir, "resources.arsc")
		if data, err := os.ReadFile(arscPath); err == nil {
			if patched, err := axml.PatchARSCEntries(data, edits); err == nil {
				if err := os.WriteFile(arscPath, patched, 0644); err == nil {
					r.warn("Applied %d addressed string updates to resources.arsc", len(edits))
				} else {
					return fmt.Errorf("resources.arsc write failed: %w", err)
				}
			} else {
				return fmt.Errorf("resources.arsc edit failed: %w", err)
			}
		}
	}

	if len(replacements) > 0 {
		if err := axml.PatchARSCAndAXMLFiles(r.SourceDir, replacements); err != nil {
			return err
		}
		r.warn("Applied %d string updates to resources.arsc and AndroidManifest.xml.bin", len(replacements))
	}
	return nil
}

// overlayTextXML re-encodes one text XML file over its .bin twin when the
// text differs semantically. rel is slash-separated (e.g.
// "AndroidManifest.xml"). Filesystem timestamps are not edit evidence:
// archive extraction, copies and coarse clocks can reorder them.
func (r *APKRebuilder) overlayTextXML(rel string, table *axml.ResourceTable) error {
	textPath := filepath.Join(r.SourceDir, filepath.FromSlash(rel))
	binPath := textPath + ".bin"
	_, terr := os.Stat(textPath)
	_, berr := os.Stat(binPath)
	if os.IsNotExist(terr) {
		return nil
	}
	if terr != nil {
		return terr
	}
	textData, err := os.ReadFile(textPath)
	if err != nil {
		return err
	}
	if axml.IsBinaryXML(textData) {
		return nil
	}
	if os.IsNotExist(berr) {
		// A fresh source project is compiled as a whole later. An existing
		// binary resource table, however, must never ship plain-text XML just
		// because its decoded .bin twin was omitted from a project ZIP.
		hasTable := fileExists(filepath.Join(r.SourceDir, "resources.arsc"))
		if !hasTable && !fileExists(filepath.Join(r.SourceDir, "AndroidManifest.xml.bin")) {
			return nil
		}
		if hasTable && table == nil {
			return fmt.Errorf("%s: original resource table is unreadable; cannot compile XML without its binary twin", rel)
		}
		if rel != "AndroidManifest.xml" && !tableReferencesResourceFile(table, rel) {
			return fmt.Errorf("%s: adding resource files to an existing resource table is not supported; restore its binary twin or build a fresh resource project", rel)
		}
		compiled, err := axml.CompileTextAXML(textData, table)
		if err != nil {
			return fmt.Errorf("%s: cannot compile XML without binary twin: %w", rel, err)
		}
		if err := os.WriteFile(binPath, compiled, 0644); err != nil {
			return err
		}
		r.warn("%s: compiled missing binary XML with existing resource IDs (no aapt2)", rel)
		return nil
	}
	if berr != nil {
		return berr
	}
	binData, err := os.ReadFile(binPath)
	if err != nil {
		return err
	}
	if axml.SameAXMLSemantics(binData, textData) {
		return nil
	}
	merged, err := axml.OverlayAXML(binData, textData, table)
	if err != nil {
		return fmt.Errorf("%s: cannot compile XML edit: %w", rel, err)
	}
	if err := os.WriteFile(binPath, merged, 0644); err != nil {
		return fmt.Errorf("%s: binary rewrite failed: %w", rel, err)
	}
	r.warn("%s: text edits re-encoded into binary (no aapt2)", rel)
	return nil
}

func tableReferencesResourceFile(table *axml.ResourceTable, rel string) bool {
	if table == nil {
		return false
	}
	for _, pkg := range table.Packages {
		for _, typ := range pkg.Types {
			for _, entry := range typ.Entries {
				for _, value := range entry.Values {
					if value.Value == rel {
						return true
					}
				}
			}
		}
	}
	return false
}

// overlayResXML re-encodes every edited res layout-style XML twin.
func (r *APKRebuilder) overlayResXML(table *axml.ResourceTable) error {
	resDir := filepath.Join(r.SourceDir, "res")
	entries, err := os.ReadDir(resDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, de := range entries {
		if !de.IsDir() {
			continue
		}
		name := de.Name()
		if name == "values" || strings.HasPrefix(name, "values-") || name == "raw" || strings.HasPrefix(name, "raw-") {
			continue // exports of resources.arsc, handled via entry edits
		}
		dir := filepath.Join(resDir, name)
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(strings.ToLower(f.Name()), ".xml") {
				continue
			}
			if err := r.overlayTextXML("res/"+name+"/"+f.Name(), table); err != nil {
				return err
			}
		}
	}
	return nil
}

// collectArscEdits walks every res/values*/strings.xml and returns one
// addressed edit per changed <string>, keyed by entry name and config so
// shared pool slots are split instead of colliding by text.
func (r *APKRebuilder) collectArscEdits() []axml.ARSCEdit {
	resDir := filepath.Join(r.SourceDir, "res")
	arscPath := filepath.Join(r.SourceDir, "resources.arsc")
	table, err := axml.ParseARSCFile(arscPath)
	if err != nil || table == nil {
		return nil
	}
	entries, err := os.ReadDir(resDir)
	if err != nil {
		return nil
	}
	var edits []axml.ARSCEdit
	for _, de := range entries {
		if !de.IsDir() {
			continue
		}
		name := de.Name()
		if name != "values" && !strings.HasPrefix(name, "values-") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(resDir, name, "strings.xml"))
		if err != nil {
			continue
		}
		folderCfg := configFromValuesFolder(name)
		for key, newVal := range parseStringsXml(data) {
			if newVal == "" {
				continue
			}
			oldVal, ok := arscStringValue(table, key, folderCfg)
			if !ok || oldVal == "" || oldVal == newVal {
				continue
			}
			edits = append(edits, axml.ARSCEdit{Type: "string", Name: key, Config: folderCfg, NewValue: newVal})
		}
	}
	return edits
}

// configFromValuesFolder maps a res/ folder name to the aapt config string
// used in resources.arsc: "values" → "default", "values-ru" → "ru",
// "values-en-rUS" → "en-rUS".
func configFromValuesFolder(folder string) string {
	if folder == "values" {
		return "default"
	}
	if strings.HasPrefix(folder, "values-") {
		return folder[len("values-"):]
	}
	return "default"
}

// arscStringValue returns the current resources.arsc value for a string
// resource named key under the given folder config. It prefers an exact
// config match, treats "default"/"" as equivalent for the default folder,
// and falls back to a language-prefix match (so a "ru" folder can line up
// with a "ru-v21" arsc config).
func arscStringValue(table *axml.ResourceTable, key, folderCfg string) (string, bool) {
	folderLang := folderCfg
	if i := strings.IndexByte(folderLang, '-'); i >= 0 {
		folderLang = folderLang[:i]
	}
	for _, pkg := range table.Packages {
		for _, typ := range pkg.Types {
			if typ.Name != "string" {
				continue
			}
			for _, ent := range typ.Entries {
				if ent.Name != key {
					continue
				}
				// Pass 1: exact config (with default/"" equivalence).
				for _, v := range ent.Values {
					c := v.Config
					if c == folderCfg || (folderCfg == "default" && (c == "" || c == "default")) {
						return v.Value, true
					}
				}
				// Pass 2: language-prefix fallback for locale folders.
				if folderLang != "" && folderLang != "default" {
					for _, v := range ent.Values {
						cl := v.Config
						if i := strings.IndexByte(cl, '-'); i >= 0 {
							cl = cl[:i]
						}
						if cl == folderLang {
							return v.Value, true
						}
					}
				}
			}
		}
	}
	return "", false
}

// parseStringsXml extracts name→resolved-text for every non-self-closing
// <string> element in a values/strings.xml file. Values are XML- and
// Android-unescaped so they match the resolved text stored in the arsc
// string pool.
func parseStringsXml(data []byte) map[string]string {
	out := make(map[string]string)
	s := string(data)
	i := 0
	for {
		p := strings.Index(s[i:], "<string")
		if p < 0 {
			break
		}
		p += i
		tagStart := p + len("<string")
		if tagStart >= len(s) {
			break
		}
		// Must be a <string ...> element, not <string-array>.
		next := s[tagStart]
		if next != ' ' && next != '\t' && next != '\n' && next != '\r' && next != '>' {
			i = tagStart
			continue
		}
		gt := strings.IndexByte(s[tagStart:], '>')
		if gt < 0 {
			break
		}
		openTag := s[p : tagStart+gt]  // "<string name=... "
		afterOpen := tagStart + gt + 1 // index just past '>'
		// Self-closing <string .../> carries no text.
		if strings.HasSuffix(strings.TrimSpace(openTag), "/") {
			i = afterOpen
			continue
		}
		name := extractAttr(openTag, "name")
		close := strings.Index(s[afterOpen:], "</string>")
		if close < 0 {
			break
		}
		raw := s[afterOpen : afterOpen+close]
		i = afterOpen + close + len("</string>")
		if name == "" {
			continue
		}
		out[name] = unescapeAndroidResString(raw)
	}
	return out
}

// extractAttr returns the value of attr="..." (or attr='...') within an
// opening tag, or "" if absent.
func extractAttr(tag, attr string) string {
	key := attr + "="
	idx := strings.Index(tag, key)
	if idx < 0 {
		return ""
	}
	rest := tag[idx+len(key):]
	if rest == "" {
		return ""
	}
	q := rest[0]
	if q != '"' && q != '\'' {
		return ""
	}
	rest = rest[1:]
	end := strings.IndexByte(rest, q)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// unescapeAndroidResString converts XML entities and the common Android
// resource escapes into the resolved characters stored in the arsc pool.
// Handles the frequent cases (&amp; &lt; &gt; &quot; &apos; &#nn; \' \" \\
// \n \t) and strips a single pair of enclosing quotes used to preserve
// whitespace. Full aapt fidelity is the aapt2 path's job; this covers the
// binary fallback well enough for real-world translation files.
func unescapeAndroidResString(s string) string {
	// A fully double-quoted value preserves its interior whitespace verbatim.
	// Detect this on the raw text so an escaped literal quote (&quot; / \")
	// is treated as content, not as a whitespace-preservation marker — which
	// mirrors aapt, where a bare " toggles quoting but an escaped one doesn't.
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}

	// XML entities.
	if strings.ContainsRune(s, '&') {
		var b strings.Builder
		for i := 0; i < len(s); {
			if s[i] == '&' {
				if semi := strings.IndexByte(s[i:], ';'); semi > 0 && semi <= 10 {
					ent := s[i+1 : i+semi]
					switch {
					case ent == "amp":
						b.WriteByte('&')
					case ent == "lt":
						b.WriteByte('<')
					case ent == "gt":
						b.WriteByte('>')
					case ent == "quot":
						b.WriteByte('"')
					case ent == "apos":
						b.WriteByte('\'')
					case strings.HasPrefix(ent, "#x") || strings.HasPrefix(ent, "#X"):
						if cp, ok := parseHexRune(ent[2:]); ok {
							b.WriteRune(cp)
						}
					case strings.HasPrefix(ent, "#"):
						if cp, ok := parseDecRune(ent[1:]); ok {
							b.WriteRune(cp)
						}
					default:
						b.WriteString(s[i : i+semi+1])
					}
					i += semi + 1
					continue
				}
			}
			b.WriteByte(s[i])
			i++
		}
		s = b.String()
	}

	// Android backslash escapes.
	if strings.ContainsRune(s, '\\') {
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			if s[i] == '\\' && i+1 < len(s) {
				switch s[i+1] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				case '\'':
					b.WriteByte('\'')
				case '"':
					b.WriteByte('"')
				case '\\':
					b.WriteByte('\\')
				case '@', '?':
					b.WriteByte(s[i+1])
				default:
					b.WriteByte(s[i+1])
				}
				i++
				continue
			}
			b.WriteByte(s[i])
		}
		s = b.String()
	}

	return s
}

func parseHexRune(h string) (rune, bool) {
	var v uint64
	if h == "" {
		return 0, false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return 0, false
		}
		v = v*16 + d
		if v > 0x10FFFF {
			return 0, false
		}
	}
	return rune(v), true
}

func parseDecRune(d string) (rune, bool) {
	var v uint64
	if d == "" {
		return 0, false
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + uint64(c-'0')
		if v > 0x10FFFF {
			return 0, false
		}
	}
	return rune(v), true
}

// storeNativeLibs reports whether .so files must stay uncompressed: the app
// opted into mapping libraries directly from the APK, or the original APK
// stored them (recorded in the decode metadata).
func (r *APKRebuilder) storeNativeLibs() bool {
	if r.meta != nil {
		for _, configured := range r.meta.DoNotCompress {
			if strings.TrimPrefix(strings.ToLower(strings.TrimSpace(configured)), ".") == "so" {
				return true
			}
		}
	}
	data, err := os.ReadFile(filepath.Join(r.SourceDir, "AndroidManifest.xml"))
	if err != nil {
		return false
	}
	s := string(data)
	return strings.Contains(s, `extractNativeLibs="false"`) || strings.Contains(s, `extractNativeLibs='false'`)
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// isExportedValuesXML matches res/values, res/values-xx, ... XML files.
func isExportedValuesXML(rel string) bool {
	if !strings.HasPrefix(rel, "res/values") || !strings.HasSuffix(strings.ToLower(rel), ".xml") {
		return false
	}
	rest := strings.TrimPrefix(rel, "res/")
	i := strings.IndexByte(rest, '/')
	if i < 0 || strings.Count(rest, "/") != 1 {
		return false
	}
	dir := rest[:i]
	return dir == "values" || strings.HasPrefix(dir, "values-")
}
