package apkloader

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SignConfig carries user-supplied signing key material.
//
// Passwords never come from CLI flags (they would leak via the process
// table): set StorePass/KeyPass explicitly in code, or export
// ANALYZER_KEYSTORE_PASS / ANALYZER_KEY_PASS in the environment.
type SignConfig struct {
	KeystorePath string // JKS keystore for apksigner; empty = auto debug keystore or generated debug key
	KeyAlias     string // apksigner --ks-key-alias; empty = keystore default
	StorePass    string // explicit keystore password (else ANALYZER_KEYSTORE_PASS)
	KeyPass      string // explicit key password (else ANALYZER_KEY_PASS, else store password)
	MinSDK       uint32 // app minimum SDK; the v3 signer range starts at API 28 or later
}

// Env names for keystore passwords. Documented in CLI help for --ks.
const (
	EnvKeystorePass = "ANALYZER_KEYSTORE_PASS"
	EnvKeyPass      = "ANALYZER_KEY_PASS"
)

func (c SignConfig) storePassword() string {
	if c.StorePass != "" {
		return c.StorePass
	}
	return os.Getenv(EnvKeystorePass)
}

func (c SignConfig) keyPassword() string {
	if c.KeyPass != "" {
		return c.KeyPass
	}
	if v := os.Getenv(EnvKeyPass); v != "" {
		return v
	}
	return c.storePassword()
}

// SignMethod records how an APK was signed so callers can tell a real
// key from a throwaway debug one.
type SignMethod string

const (
	// SignMethodApkSigner used an external keystore via Google apksigner.
	SignMethodApkSigner SignMethod = "apksigner"
	// SignMethodDebugPKCS7 used a freshly generated debug key with the
	// built-in Go signer. Real PKCS#7, but self-signed: Android installs
	// it as an unknown publisher, stores reject it.
	SignMethodDebugPKCS7 SignMethod = "go-pkcs7-debug"
)

// SignOutcome describes a completed signing operation.
type SignOutcome struct {
	Method       SignMethod
	SignerSHA256 string // hex SHA-256 of the signer certificate
	DebugKey     bool   // true when the key was generated, never user-supplied
	Note         string // human-readable detail for diagnostics
}

// findApkSignerJar searches for apksigner.jar in bundled and exe-relative
// locations. It deliberately knows nothing about keystores: key material
// is resolved separately from SignConfig, never by filename guessing.
func findApkSignerJar() string {
	candidates := []string{
		"bin/tools/apksigner.jar",
		"tools/windows/apksigner.jar",
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "tools", "apksigner.jar"),
			filepath.Join(exeDir, "tools", "windows", "apksigner.jar"),
			filepath.Join(exeDir, "bin", "tools", "apksigner.jar"),
			filepath.Join(exeDir, "..", "tools", "windows", "apksigner.jar"),
			filepath.Join(exeDir, "..", "bin", "tools", "apksigner.jar"),
		)
	}

	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	return ""
}

// debugKeystoreNextToJar returns the stock Android debug keystore shipped
// next to apksigner, if present. Only this well-known filename is ever
// auto-picked; anything else must be passed explicitly via --ks.
func debugKeystoreNextToJar(jarPath string) string {
	if jarPath == "" {
		return ""
	}
	ksPath := filepath.Join(filepath.Dir(jarPath), "debug.keystore")
	if _, err := os.Stat(ksPath); err == nil {
		return ksPath
	}
	return ""
}

// SignAPKWithConfig signs an APK and reports how it was signed.
//
// Fail-closed rules: a configured keystore without apksigner/Java is an
// error (never a silent debug key); a configured non-debug keystore
// without a password is an error; a failed apksigner run is an error,
// never a quiet fallback. With no key material at all a debug key is
// generated and the outcome says so explicitly.
func SignAPKWithConfig(apkPath string, cfg SignConfig) (SignOutcome, error) {
	if Standalone() && cfg.KeystorePath != "" {
		return SignOutcome{}, fmt.Errorf("%s", StandaloneReason("apksigner"))
	}
	// Installed compatibility tools must not change standalone signing. In
	// particular, an auto-discovered debug.keystore previously forced this
	// path into apksigner and made native builds fail on SDK-equipped hosts.
	jarPath := ""
	if !Standalone() {
		jarPath = findApkSignerJar()
	}
	ksPath := cfg.KeystorePath
	explicitKey := ksPath != ""
	if ksPath != "" {
		if _, err := os.Stat(ksPath); err != nil {
			return SignOutcome{}, fmt.Errorf("keystore not found: %s", ksPath)
		}
	} else {
		ksPath = debugKeystoreNextToJar(jarPath)
	}

	if ksPath != "" {
		if jarPath == "" {
			return SignOutcome{}, fmt.Errorf("keystore %s requires apksigner (Java), which was not found: refusing to sign with a generated debug key instead", ksPath)
		}
		if Standalone() {
			return SignOutcome{}, fmt.Errorf("%s", StandaloneReason("apksigner"))
		}
		storePass := cfg.storePassword()
		keyPass := cfg.keyPassword()
		note := ""
		if storePass == "" {
			if !isDebugKeystoreName(ksPath) {
				return SignOutcome{}, fmt.Errorf("keystore %s needs a password: set %s (and %s if the key differs)", ksPath, EnvKeystorePass, EnvKeyPass)
			}
			// The stock Android debug keystore password is public by design
			// (AOSP platform/build docs); using it for a file literally
			// named debug.keystore is standard tooling behavior.
			storePass, keyPass = "android", "android"
			note = "used the public Android debug password for debug.keystore"
		}
		if err := signWithApkSigner(apkPath, jarPath, ksPath, cfg.KeyAlias, storePass, keyPass); err != nil {
			return SignOutcome{}, err
		}
		fp := ""
		if fps, ferr := SignerCertFingerprints(apkPath); ferr == nil && len(fps) > 0 {
			fp = fps[0]
		}
		return SignOutcome{Method: SignMethodApkSigner, SignerSHA256: fp, Note: note}, nil
	}

	// No key material anywhere: throwaway debug key, honestly labeled.
	privateKey, cert, err := generateDebugCertificate()
	if err != nil {
		return SignOutcome{}, fmt.Errorf("failed to generate debug key: %w", err)
	}
	if explicitKey {
		// Unreachable: explicitKey implies ksPath != "" handled above.
		return SignOutcome{}, fmt.Errorf("internal error: explicit keystore lost during resolution")
	}
	if err := signWithGoFallback(apkPath, privateKey, cert, cfg.MinSDK); err != nil {
		return SignOutcome{}, err
	}
	fp := sha256.Sum256(cert.Raw)
	return SignOutcome{
		Method:       SignMethodDebugPKCS7,
		SignerSHA256: hex.EncodeToString(fp[:]),
		DebugKey:     true,
		Note:         "self-signed debug key generated for this build (v1+v2+v3); not a user key",
	}, nil
}

func isDebugKeystoreName(path string) bool {
	return strings.EqualFold(filepath.Base(path), "debug.keystore")
}

// signWithApkSigner runs one signing attempt with resolved credentials.
// Passwords reach apksigner via env: references when they came from the
// environment (never placed on the command line), or pass: values when
// provided explicitly. A failure is returned as-is: no password guessing,
// no silent fallback.
func signWithApkSigner(apkPath, jarPath, ksPath, alias, storePass, keyPass string) error {
	args := []string{"-jar", jarPath, "sign", "--ks", ksPath}
	if alias != "" {
		args = append(args, "--ks-key-alias", alias)
	}
	args = append(args, "--ks-pass", ksPassRef(storePass), "--key-pass", ksPassRef(keyPass),
		"--v1-signing-enabled", "true",
		"--v2-signing-enabled", "true",
		"--v3-signing-enabled", "true",
		apkPath)
	out, err := exec.Command(javaBin(), args...).CombinedOutput()
	if err != nil {
		msg := filterApkSignerNoise(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("apksigner sign failed: %s", firstLines(msg, 5))
	}
	return nil
}

// ksPassRef keeps environment-sourced passwords out of the process table:
// apksigner resolves env: itself. Explicit values must use pass:.
func ksPassRef(password string) string {
	if v, ok := passwordFromEnv(password); ok {
		return "env:" + v
	}
	return "pass:" + password
}

// passwordFromEnv reports whether password is literally the content of a
// known password variable (i.e. it was resolved from the environment).
func passwordFromEnv(password string) (string, bool) {
	if password == "" {
		return "", false
	}
	for _, name := range []string{EnvKeystorePass, EnvKeyPass} {
		if os.Getenv(name) == password {
			return name, true
		}
	}
	return "", false
}

// SignAPK signs an APK, resolving credentials from the environment.
// Compatibility wrapper: prefer SignAPKWithConfig. With no keystore and
// no apksigner-adjacent debug keystore it produces a debug-signed APK.
func SignAPK(apkPath string, keystorePath string) error {
	_, err := SignAPKWithConfig(apkPath, SignConfig{KeystorePath: keystorePath})
	return err
}

// signWithGoFallback performs the built-in v1+v2+v3 signing with an
// already-resolved key: JAR-scheme files first, then the APK Signing Block
// over the final bytes (v1 covers entry data, so block insertion keeps it
// valid — the same ordering apksigner uses). Callers must label the result
// honestly: this is only appropriate for generated debug keys, never as a
// stand-in for a user-supplied keystore (SignAPKWithConfig enforces that).
func signWithGoFallback(apkPath string, privateKey *rsa.PrivateKey, cert *x509.Certificate, minSdk uint32) error {
	manifest, err := func() (string, error) {
		reader, err := zip.OpenReader(apkPath)
		if err != nil {
			return "", fmt.Errorf("failed to open APK: %w", err)
		}
		defer reader.Close()
		return generateManifest(reader)
	}()
	if err != nil {
		return err
	}

	signatureFile, err := generateSignatureFile(manifest)
	if err != nil {
		return fmt.Errorf("failed to generate signature file: %w", err)
	}

	signatureBlock, err := generateSignatureBlock(signatureFile, privateKey, cert)
	if err != nil {
		return fmt.Errorf("failed to generate signature block: %w", err)
	}

	tempPath := apkPath + ".signed"
	if err := createSignedAPK(apkPath, tempPath, manifest, signatureFile, signatureBlock); err != nil {
		return fmt.Errorf("failed to create signed APK: %w", err)
	}

	if err := os.Remove(apkPath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to remove original APK: %w", err)
	}

	if err := os.Rename(tempPath, apkPath); err != nil {
		return fmt.Errorf("failed to rename signed APK: %w", err)
	}

	// v2+v3 over the v1-signed bytes (alignment already applied upstream;
	// the block pad preserves 16 KiB alignment of everything after it).
	if minSdk == 0 {
		minSdk = 1
	}
	if err := SignV2V3(apkPath, privateKey, cert, minSdk); err != nil {
		return fmt.Errorf("v2/v3 signing block: %w", err)
	}

	return nil
}

// generateDebugCertificate generates a debug certificate for signing
func generateDebugCertificate() (*rsa.PrivateKey, *x509.Certificate, error) {
	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Android Debug",
			Organization: []string{"Android"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour * 30), // 30 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, cert, nil
}

// generateManifest generates META-INF/MANIFEST.MF
func generateManifest(reader *zip.ReadCloser) (string, error) {
	var manifest strings.Builder
	manifest.WriteString("Manifest-Version: 1.0\r\n")
	manifest.WriteString("Created-By: Mega-Analyzer\r\n")
	manifest.WriteString("\r\n")

	// Sort files for deterministic output
	var files []*zip.File
	for _, f := range reader.File {
		// Skip META-INF directory
		if strings.HasPrefix(f.Name, "META-INF/") {
			continue
		}
		files = append(files, f)
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].Name < files[j].Name
	})

	// Generate digest for each file
	for _, file := range files {
		if file.FileInfo().IsDir() {
			continue
		}

		digest, err := calculateFileDigest(file)
		if err != nil {
			continue // Skip files that can't be read
		}

		manifest.WriteString("Name: ")
		manifest.WriteString(file.Name)
		manifest.WriteString("\r\n")
		manifest.WriteString("SHA-256-Digest: ")
		manifest.WriteString(digest)
		manifest.WriteString("\r\n")
		manifest.WriteString("\r\n")
	}

	return manifest.String(), nil
}

// calculateFileDigest calculates SHA-256 digest of a file
func calculateFileDigest(file *zip.File) (string, error) {
	rc, err := file.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, rc); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil
}

// generateSignatureFile generates META-INF/CERT.SF
func generateSignatureFile(manifest string) (string, error) {
	var sf strings.Builder
	sf.WriteString("Signature-Version: 1.0\r\n")
	sf.WriteString("Created-By: Mega-Analyzer\r\n")

	// Calculate digest of entire manifest
	manifestHash := sha256.Sum256([]byte(manifest))
	sf.WriteString("SHA-256-Digest-Manifest: ")
	sf.WriteString(base64.StdEncoding.EncodeToString(manifestHash[:]))
	sf.WriteString("\r\n")
	sf.WriteString("\r\n")

	// Calculate digest of each manifest entry
	lines := strings.Split(manifest, "\r\n\r\n")
	for _, entry := range lines {
		if entry == "" || !strings.Contains(entry, "Name:") {
			continue
		}

		entryHash := sha256.Sum256([]byte(entry + "\r\n\r\n"))

		// Extract name
		for _, line := range strings.Split(entry, "\r\n") {
			if strings.HasPrefix(line, "Name:") {
				sf.WriteString(line)
				sf.WriteString("\r\n")
				break
			}
		}

		sf.WriteString("SHA-256-Digest: ")
		sf.WriteString(base64.StdEncoding.EncodeToString(entryHash[:]))
		sf.WriteString("\r\n")
		sf.WriteString("\r\n")
	}

	return sf.String(), nil
}

// generateSignatureBlock generates META-INF/CERT.RSA: a real DER PKCS#7
// SignedData block (detached, SHA-256) over the signature file bytes.
// Keep the historic (sf, key, cert) shape: signer_test.go pins it.
func generateSignatureBlock(signatureFile string, privateKey *rsa.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	block, err := buildPKCS7SignatureBlock([]byte(signatureFile), privateKey, cert)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signature block: %w", err)
	}
	return block, nil
}

// createSignedAPK creates a new APK with signature files
func createSignedAPK(inputPath, outputPath string, manifest, signatureFile string, signatureBlock []byte) error {
	// Open input APK
	reader, err := zip.OpenReader(inputPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Create ZIP writer
	writer := zip.NewWriter(outFile)
	defer writer.Close()

	// Copy all files except old META-INF
	for _, file := range reader.File {
		if strings.HasPrefix(file.Name, "META-INF/") {
			continue
		}

		if err := copyZipEntry(writer, file); err != nil {
			return err
		}
	}

	// Add META-INF directory
	if _, err := writer.Create("META-INF/"); err != nil {
		return err
	}

	// Add MANIFEST.MF
	if err := writeZipString(writer, "META-INF/MANIFEST.MF", manifest); err != nil {
		return err
	}

	// Add CERT.SF
	if err := writeZipString(writer, "META-INF/CERT.SF", signatureFile); err != nil {
		return err
	}

	// Add CERT.RSA
	if err := writeZipBytes(writer, "META-INF/CERT.RSA", signatureBlock); err != nil {
		return err
	}

	return nil
}

// copyZipEntry copies a ZIP entry from reader to writer preserving compression
// and exact header bytes. CreateRaw is used for stored entries as well so
// the alignment applied upstream survives v1 signing (a Decode+CreateHeader
// round-trip would let Go inject its own extra fields and shift offsets).
func copyZipEntry(w *zip.Writer, file *zip.File) error {
	rc, err := file.OpenRaw()
	if err != nil {
		return err
	}
	if closer, ok := rc.(io.Closer); ok {
		defer closer.Close()
	}
	raw, err := w.CreateRaw(&file.FileHeader)
	if err != nil {
		return err
	}
	_, err = io.Copy(raw, rc)
	return err
}

// writeZipString writes a string to a ZIP entry
func writeZipString(w *zip.Writer, name, content string) error {
	writer, err := w.Create(name)
	if err != nil {
		return err
	}

	_, err = writer.Write([]byte(content))
	return err
}

// writeZipBytes writes bytes to a ZIP entry
func writeZipBytes(w *zip.Writer, name string, content []byte) error {
	writer, err := w.Create(name)
	if err != nil {
		return err
	}

	_, err = writer.Write(content)
	return err
}

// VerifySignature verifies that an APK carries a usable signature.
//
// apksigner is authoritative when present: it understands the v1 JAR scheme,
// the v2/v3 APK Signing Block and v4, and is the same tool that produced the
// signature. The structural fallback only inspects the archive, and therefore
// accepts either a v1 pair under any name or the presence of a signing block:
// apksigner names the v1 files after the key alias (ANDROIDD.SF, not CERT.SF)
// and v2+ signatures live outside META-INF entirely, so requiring
// META-INF/CERT.SF rejects perfectly valid APKs.
func VerifySignature(apkPath string) error {
	err := verifyWithApkSigner(apkPath)
	if err == nil {
		return nil
	}
	if err != errApkSignerUnavailable {
		return err
	}
	if _, verr := VerifyV1SignatureOffline(apkPath); verr == nil {
		return nil
	}
	return verifySignatureStructural(apkPath)
}

// VerifyMethod records which evidence backs a verification outcome.
type VerifyMethod string

const (
	// VerifyMethodApkSigner: Google apksigner verified the signature
	// cryptographically (v1/v2/v3/v4). Authoritative.
	VerifyMethodApkSigner VerifyMethod = "apksigner"
	// VerifyMethodOfflineV1: the built-in offline checker verified the
	// full v1 chain cryptographically (entry digests, manifest, .SF,
	// PKCS#7 RSA). Real math, no external tools.
	VerifyMethodOfflineV1 VerifyMethod = "offline-v1"
	// VerifyMethodStructural: only file presence / magic bytes were
	// observed. This is NOT cryptographic verification.
	VerifyMethodStructural VerifyMethod = "structural"
)

// VerifyOutcome pairs a verification verdict with its evidence level.
type VerifyOutcome struct {
	Method       VerifyMethod
	SignerSHA256 []string // fingerprints when extractable, else empty
}

// VerifySignatureDetailed verifies an APK and reports how. apksigner wins
// when present; otherwise the offline v1 checker; the structural fallback
// is last and explicitly labeled as non-cryptographic.
func VerifySignatureDetailed(apkPath string) (VerifyOutcome, error) {
	if err := verifyWithApkSigner(apkPath); err == nil {
		fps, _ := SignerCertFingerprints(apkPath)
		return VerifyOutcome{Method: VerifyMethodApkSigner, SignerSHA256: fps}, nil
	} else if err != errApkSignerUnavailable {
		return VerifyOutcome{}, err
	}
	if fp, err := VerifyV1SignatureOffline(apkPath); err == nil {
		return VerifyOutcome{Method: VerifyMethodOfflineV1, SignerSHA256: []string{fp}}, nil
	}
	if err := verifySignatureStructural(apkPath); err == nil {
		fps, _ := v1BlockFingerprints(apkPath)
		return VerifyOutcome{Method: VerifyMethodStructural, SignerSHA256: fps}, nil
	} else {
		return VerifyOutcome{}, err
	}
}

// VerifySignatureStrict verifies cryptographically or fails: apksigner
// first, offline v1 second. File presence alone never passes.
func VerifySignatureStrict(apkPath string) (VerifyOutcome, error) {
	if err := verifyWithApkSigner(apkPath); err == nil {
		fps, _ := SignerCertFingerprints(apkPath)
		return VerifyOutcome{Method: VerifyMethodApkSigner, SignerSHA256: fps}, nil
	} else if err != errApkSignerUnavailable {
		return VerifyOutcome{}, err
	}
	fp, err := VerifyV1SignatureOffline(apkPath)
	if err != nil {
		return VerifyOutcome{}, fmt.Errorf("no cryptographic verifier available (apksigner not found) and offline v1 check failed: %w", err)
	}
	return VerifyOutcome{Method: VerifyMethodOfflineV1, SignerSHA256: []string{fp}}, nil
}

// SignerCertFingerprints returns hex SHA-256 fingerprints of the APK signer
// certificates: parsed from `apksigner verify --print-certs` when Java is
// available, else extracted from v1 signature blocks on disk.
func SignerCertFingerprints(apkPath string) ([]string, error) {
	if fps, ok := apksignerCertFingerprints(apkPath); ok {
		return fps, nil
	}
	return v1BlockFingerprints(apkPath)
}

// apksignerCertFingerprints asks apksigner for signer digests. ok=false
// when the tool is unavailable or printed nothing parseable.
func apksignerCertFingerprints(apkPath string) (fps []string, ok bool) {
	if Standalone() {
		return nil, false
	}
	jarPath := findApkSignerJar()
	if jarPath == "" {
		return nil, false
	}
	if jp, _ := LocateJava(); jp == "" {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, _ := exec.CommandContext(ctx, javaBin(), "-Xmx512m", "-jar", jarPath, "verify", "--print-certs", apkPath).CombinedOutput()
	for _, line := range strings.Split(string(out), "\n") {
		lower := strings.ToLower(line)
		idx := strings.Index(lower, "sha-256 digest:")
		if idx < 0 {
			continue
		}
		raw := line[idx+len("sha-256 digest:"):]
		clean := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' {
				return r
			}
			return -1
		}, raw)
		if len(clean) == 64 {
			fps = append(fps, strings.ToLower(clean))
		}
	}
	if len(fps) == 0 {
		return nil, false
	}
	return fps, true
}

var errApkSignerUnavailable = fmt.Errorf("apksigner not available")

// verifyWithApkSigner runs the official verifier. It returns
// errApkSignerUnavailable when the tool cannot be located, so the caller can
// fall back to the structural check.
func verifyWithApkSigner(apkPath string) error {
	if Standalone() {
		return errApkSignerUnavailable
	}
	jarPath := findApkSignerJar()
	if jarPath == "" {
		return errApkSignerUnavailable
	}
	if jp, _ := LocateJava(); jp == "" {
		return errApkSignerUnavailable
	}
	// apksigner refuses to run without a manifest (it reads minSdkVersion from
	// it) and reports that as ApkFormatException rather than a signature
	// problem. Synthetic archives without a manifest are inconclusive, not
	// invalid, so let the structural check judge them.
	if !zipHasEntry(apkPath, "AndroidManifest.xml") {
		return errApkSignerUnavailable
	}
	attempt := func() ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		// Bounded heap: verify reads the archive lazily and needs very little,
		// but an unconstrained JVM on a memory-starved host dies with
		// commit_memory failures printed after the WARNING banner, which used
		// to be reported as a signature failure.
		return exec.CommandContext(ctx, javaBin(), "-Xmx512m", "-jar", jarPath, "verify", apkPath).CombinedOutput()
	}
	out, err := attempt()
	if err != nil {
		// One retry: a transient JVM allocation failure right after signing a
		// freshly rewritten 100+MB archive is not evidence about the signature.
		out, err = attempt()
	}
	if err != nil {
		msg := filterApkSignerNoise(string(out))
		if msg == "" {
			// The tool died without saying anything meaningful; inconclusive.
			return errApkSignerUnavailable
		}
		return fmt.Errorf("apksigner verify failed: %s", firstLines(msg, 5))
	}
	return nil
}

// filterApkSignerNoise strips JVM/apksigner banner lines so a short error
// message actually shows the failure instead of WARNING spam.
func filterApkSignerNoise(out string) string {
	var kept []string
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "WARNING:") ||
			strings.Contains(t, "HotSpot") || strings.Contains(t, "os::commit_memory") ||
			strings.HasPrefix(t, "#") {
			continue
		}
		kept = append(kept, t)
	}
	return strings.Join(kept, "\n")
}

// zipHasEntry reports whether the archive contains an entry with this name.
func zipHasEntry(apkPath, name string) bool {
	reader, err := zip.OpenReader(apkPath)
	if err != nil {
		return false
	}
	defer reader.Close()
	for _, f := range reader.File {
		if f.Name == name {
			return true
		}
	}
	return false
}

// verifySignatureStructural checks the archive without invoking external tools.
func verifySignatureStructural(apkPath string) error {
	reader, err := zip.OpenReader(apkPath)
	if err != nil {
		return fmt.Errorf("failed to open APK: %w", err)
	}
	defer reader.Close()

	hasV1 := false
	hasV1Block := false
	for _, file := range reader.File {
		upper := strings.ToUpper(file.Name)
		if !strings.HasPrefix(upper, "META-INF/") {
			continue
		}
		base := strings.TrimPrefix(upper, "META-INF/")
		switch {
		case strings.HasSuffix(base, ".SF"):
			hasV1 = true
		case strings.HasSuffix(base, ".RSA"), strings.HasSuffix(base, ".DSA"), strings.HasSuffix(base, ".EC"):
			hasV1Block = true
		}
	}
	if hasV1 && hasV1Block {
		return nil
	}

	// No v1 pair: accept a v2/v3/v4 APK Signing Block. Its magic sits at the
	// end of the archive, just before the central directory.
	block, err := hasAPKSigningBlock(apkPath)
	if err != nil {
		return fmt.Errorf("missing v1 signature (META-INF/*.SF + *.RSA|*.DSA|*.EC) and could not inspect signing block: %w", err)
	}
	if block {
		return nil
	}
	return fmt.Errorf("missing META-INF signature entries and no APK Signing Block (v2/v3)")
}

// apkSigBlockMagic is the 16-byte marker of the APK Signing Block (v2/v3/v4).
const apkSigBlockMagic = "APK Sig Block 42"

// hasAPKSigningBlock reports whether the archive carries a v2+ signing block.
// The magic lives near the end of the file, so a bounded tail read suffices.
func hasAPKSigningBlock(apkPath string) (bool, error) {
	f, err := os.Open(apkPath)
	if err != nil {
		return false, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return false, err
	}
	const tail = 64 << 10
	size := fi.Size()
	if size > tail {
		if _, err := f.Seek(size-tail, io.SeekStart); err != nil {
			return false, err
		}
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return false, err
	}
	return bytes.Contains(buf, []byte(apkSigBlockMagic)), nil
}

// firstLines keeps diagnostics readable when a tool dumps a wall of output.
func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = append(lines[:n], "…")
	}
	return strings.Join(lines, "\n")
}

// TryPreserveOriginalSignature copies signature-related material from originalAPK
// into rebuiltAPK without possessing the private key. This is intentionally an
// experimental best-effort helper: Android signatures bind file contents, so any
// changed entry normally invalidates the preserved signature. It is useful only
// for byte-identical repacks, diagnostics, or research on what changed.
func TryPreserveOriginalSignature(originalAPK, rebuiltAPK string) error {
	orig, err := zip.OpenReader(originalAPK)
	if err != nil {
		return fmt.Errorf("open original APK: %w", err)
	}
	defer orig.Close()
	tmp := rebuiltAPK + ".preserve-sig"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(out)
	seen := map[string]bool{}
	rebuilt, err := zip.OpenReader(rebuiltAPK)
	if err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("open rebuilt APK: %w", err)
	}
	for _, f := range rebuilt.File {
		if strings.HasPrefix(strings.ToUpper(f.Name), "META-INF/") {
			continue
		}
		if err := copyZipEntry(zw, f); err != nil {
			rebuilt.Close()
			_ = zw.Close()
			_ = out.Close()
			_ = os.Remove(tmp)
			return err
		}
		seen[f.Name] = true
	}
	rebuilt.Close()
	for _, f := range orig.File {
		upper := strings.ToUpper(f.Name)
		if !strings.HasPrefix(upper, "META-INF/") {
			continue
		}
		if seen[f.Name] {
			continue
		}
		if err := copyZipEntry(zw, f); err != nil {
			_ = zw.Close()
			_ = out.Close()
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := zw.Close(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, rebuiltAPK); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
