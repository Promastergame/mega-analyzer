package apkloader

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// This file finds (or, failing that, unpacks) the external tools the rebuild
// pipeline can use: Java, smali/baksmali and aapt2.
//
// Search order for every tool: explicit environment override -> files next to
// the executable / working directory -> system installs -> the copy embedded
// in this binary (extracted once into the per-user cache).

const (
	embeddedJarName = "mega-smali-tools.jar"
	smaliMainClass  = "com.android.tools.smali.smali.Main"
	baksmaliMain    = "com.android.tools.smali.baksmali.Main"
)

// ToolSource says where a located tool came from.
type ToolSource string

const (
	ToolMissing  ToolSource = "missing"
	ToolEnv      ToolSource = "environment"
	ToolLocal    ToolSource = "local"
	ToolSystem   ToolSource = "system"
	ToolEmbedded ToolSource = "embedded"
)

// ToolStatus describes one located tool for `-tools-info`.
type ToolStatus struct {
	Name    string
	Path    string
	Source  ToolSource
	Version string
}

func toolsCacheRoot() string {
	if d := os.Getenv("MEGA_TOOLS_DIR"); d != "" {
		return d
	}
	if d, err := os.UserCacheDir(); err == nil && d != "" {
		return filepath.Join(d, "mega-analyzer", "tools")
	}
	return filepath.Join(os.TempDir(), "mega-analyzer-tools")
}

func exeDir() string {
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		return filepath.Dir(exe)
	}
	return ""
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

func firstExisting(paths []string) string {
	for _, p := range paths {
		if p != "" && isFile(p) {
			return p
		}
	}
	return ""
}

// toolSearchDirs are the local folders where users typically drop tools.
func toolSearchDirs() []string {
	var dirs []string
	if e := exeDir(); e != "" {
		dirs = append(dirs, filepath.Join(e, "tools"), filepath.Join(e, "bin"), e, filepath.Join(e, "..", "tools"))
	}
	dirs = append(dirs, "tools", "bin", ".")
	dirs = append(dirs, filepath.Join(toolsCacheRoot(), "user"))
	return dirs
}

// extractBlob writes data once to <cache>/<group>-<hash>/<name> and returns the
// path. Concurrent processes are safe: the file is written to a temp name and
// renamed, and a size match on an existing file short-circuits.
func extractBlob(group, name string, data []byte, mode os.FileMode) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("%s is not embedded in this build", name)
	}
	sum := sha256.Sum256(data)
	dir := filepath.Join(toolsCacheRoot(), group+"-"+hex.EncodeToString(sum[:4]))
	path := filepath.Join(dir, name)
	if fi, err := os.Stat(path); err == nil && fi.Size() == int64(len(data)) {
		return path, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, name+".tmp*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	_ = os.Chmod(tmpName, mode)
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		if isFile(path) { // another process won the race
			return path, nil
		}
		return "", err
	}
	return path, nil
}

// ── smali / baksmali ────────────────────────────────────────────────────────

func locateJar(envNames []string, fileNames []string) (string, ToolSource) {
	for _, env := range envNames {
		if p := os.Getenv(env); p != "" && isFile(p) {
			return p, ToolEnv
		}
	}
	for _, dir := range toolSearchDirs() {
		for _, sub := range []string{"", "smali"} {
			for _, n := range fileNames {
				if p := filepath.Join(dir, sub, n); isFile(p) {
					return p, ToolLocal
				}
			}
		}
	}
	if len(embeddedSmaliTools) > 0 {
		if p, err := extractBlob("smali", embeddedJarName, embeddedSmaliTools, 0o644); err == nil {
			return p, ToolEmbedded
		}
	}
	return "", ToolMissing
}

// LocateSmaliJar returns the smali assembler jar.
func LocateSmaliJar() (string, ToolSource) {
	return locateJar([]string{"MEGA_SMALI_JAR", "SMALI_JAR"}, []string{"smali.jar"})
}

// LocateBaksmaliJar returns the baksmali disassembler jar.
func LocateBaksmaliJar() (string, ToolSource) {
	return locateJar([]string{"MEGA_BAKSMALI_JAR", "BAKSMALI_JAR"}, []string{"baksmali.jar"})
}

// jarInvocation returns the java arguments that run a smali-family jar. The
// embedded combined jar has no single Main-Class, so it is run with -cp.
func jarInvocation(jar, mainClass string) []string {
	if strings.HasPrefix(filepath.Base(jar), "mega-smali-tools") {
		return []string{"-cp", jar, mainClass}
	}
	return []string{"-jar", jar}
}

// ── Java ────────────────────────────────────────────────────────────────────

func javaExeName() string {
	if runtime.GOOS == "windows" {
		return "java.exe"
	}
	return "java"
}

var (
	javaOnce   sync.Once
	javaPath   string
	javaSource ToolSource
)

func javaWorks(path string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, path, "-version").Run() == nil
}

func wellKnownJavaHomes() []string {
	var homes []string
	switch runtime.GOOS {
	case "windows":
		for _, base := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LOCALAPPDATA")} {
			if base == "" {
				continue
			}
			for _, vendor := range []string{"Java", "Eclipse Adoptium", "Microsoft", "Amazon Corretto", "Zulu", "BellSoft", "Android\\Android Studio\\jbr", "Android\\Android Studio"} {
				root := filepath.Join(base, vendor)
				if isFile(filepath.Join(root, "bin", "java.exe")) {
					homes = append(homes, root)
				}
				if entries, err := os.ReadDir(root); err == nil {
					for i := len(entries) - 1; i >= 0; i-- {
						if entries[i].IsDir() {
							homes = append(homes, filepath.Join(root, entries[i].Name()))
						}
					}
				}
			}
		}
	case "darwin":
		if entries, err := os.ReadDir("/Library/Java/JavaVirtualMachines"); err == nil {
			for i := len(entries) - 1; i >= 0; i-- {
				homes = append(homes, filepath.Join("/Library/Java/JavaVirtualMachines", entries[i].Name(), "Contents", "Home"))
			}
		}
		homes = append(homes, "/Applications/Android Studio.app/Contents/jbr/Contents/Home")
	default:
		if entries, err := os.ReadDir("/usr/lib/jvm"); err == nil {
			for i := len(entries) - 1; i >= 0; i-- {
				homes = append(homes, filepath.Join("/usr/lib/jvm", entries[i].Name()))
			}
		}
		if p := os.Getenv("PREFIX"); p != "" { // Termux
			homes = append(homes, filepath.Join(p, "lib", "jvm"))
		}
	}
	return homes
}

// LocateJava finds a working Java runtime. It prefers what the user configured
// or installed and falls back to the runtime embedded in the binary.
func LocateJava() (string, ToolSource) {
	javaOnce.Do(func() {
		exe := javaExeName()
		var cands []struct {
			path string
			src  ToolSource
		}
		add := func(p string, s ToolSource) {
			cands = append(cands, struct {
				path string
				src  ToolSource
			}{p, s})
		}
		if p := os.Getenv("MEGA_JAVA"); p != "" {
			add(p, ToolEnv)
		}
		if e := exeDir(); e != "" {
			for _, sub := range []string{"jre", "runtime", filepath.Join("tools", "jre")} {
				add(filepath.Join(e, sub, "bin", exe), ToolLocal)
			}
		}
		add(filepath.Join(toolsCacheRoot(), "user", "jre", "bin", exe), ToolLocal)
		if jh := os.Getenv("JAVA_HOME"); jh != "" {
			add(filepath.Join(jh, "bin", exe), ToolSystem)
		}
		if p, err := exec.LookPath("java"); err == nil {
			add(p, ToolSystem)
		}
		for _, h := range wellKnownJavaHomes() {
			add(filepath.Join(h, "bin", exe), ToolSystem)
		}
		// MEGA_EMBEDDED_JRE_ONLY=1 ignores every Java except MEGA_JAVA and
		// the bundled runtime (useful to test a self-contained setup).
		if os.Getenv("MEGA_EMBEDDED_JRE_ONLY") == "1" && len(embeddedJRE) > 0 {
			cands = cands[:0]
		}
		for _, c := range cands {
			if isFile(c.path) && javaWorks(c.path) {
				javaPath, javaSource = c.path, c.src
				return
			}
		}
		if p, err := extractEmbeddedJRE(); err == nil && javaWorks(p) {
			javaPath, javaSource = p, ToolEmbedded
			return
		}
		javaSource = ToolMissing
	})
	return javaPath, javaSource
}

// extractEmbeddedJRE unpacks the embedded jlink runtime (built with
// -tags embedjre) into the cache and returns the java executable.
func extractEmbeddedJRE() (string, error) {
	if len(embeddedJRE) == 0 {
		return "", fmt.Errorf("no JRE embedded in this build")
	}
	sum := sha256.Sum256(embeddedJRE)
	root := toolsCacheRoot()
	dest := filepath.Join(root, "jre-"+hex.EncodeToString(sum[:4]))
	java := filepath.Join(dest, "bin", javaExeName())
	if isFile(java) && isFile(filepath.Join(dest, ".complete")) {
		return java, nil
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp(root, "jre-tmp-")
	if err != nil {
		return "", err
	}
	if err := untarGz(embeddedJRE, tmp); err != nil {
		os.RemoveAll(tmp)
		return "", err
	}
	_ = os.WriteFile(filepath.Join(tmp, ".complete"), []byte("ok"), 0o644)
	if err := os.Rename(tmp, dest); err != nil {
		os.RemoveAll(tmp)
		if isFile(java) {
			return java, nil
		}
		return "", err
	}
	return java, nil
}

func untarGz(data []byte, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	cleanDest := filepath.Clean(dest) + string(os.PathSeparator)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dest, filepath.FromSlash(h.Name))
		if !strings.HasPrefix(target+string(os.PathSeparator), cleanDest) {
			return fmt.Errorf("unsafe path in archive: %s", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(h.Mode) & 0o777
			if mode == 0 {
				mode = 0o644
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
	}
}

// ── aapt2 ───────────────────────────────────────────────────────────────────

// locateEmbeddedAapt2 unpacks the bundled aapt2 for this OS/arch, if any.
func locateEmbeddedAapt2() string {
	if len(embeddedAapt2) == 0 {
		return ""
	}
	p, err := extractBlob("aapt2", embeddedAapt2Name, embeddedAapt2, 0o755)
	if err != nil {
		return ""
	}
	return p
}

// ToolsReport describes every tool the rebuild pipeline can use.
func ToolsReport() []ToolStatus {
	var out []ToolStatus
	jp, js := LocateJava()
	out = append(out, ToolStatus{Name: "java", Path: jp, Source: js, Version: javaVersion(jp)})
	sp, ss := LocateSmaliJar()
	out = append(out, ToolStatus{Name: "smali", Path: sp, Source: ss})
	bp, bs := LocateBaksmaliJar()
	out = append(out, ToolStatus{Name: "baksmali", Path: bp, Source: bs})
	a := DefaultAapt2Config()
	src := ToolSystem
	if a.Aapt2Path == "" {
		src = ToolMissing
	} else if strings.HasPrefix(a.Aapt2Path, toolsCacheRoot()) {
		src = ToolEmbedded
	}
	out = append(out, ToolStatus{Name: "aapt2", Path: a.Aapt2Path, Source: src})
	sort.SliceStable(out, func(i, j int) bool { return false })
	return out
}

func javaVersion(path string) string {
	if path == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, _ := exec.CommandContext(ctx, path, "-version").CombinedOutput()
	line := strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
	return line
}

// ToolsCacheDir returns the directory bundled tools are unpacked into.
func ToolsCacheDir() string { return toolsCacheRoot() }

// javaBin returns the located java executable, or plain "java" when none was found.
func javaBin() string {
	if p, _ := LocateJava(); p != "" {
		return p
	}
	return "java"
}
