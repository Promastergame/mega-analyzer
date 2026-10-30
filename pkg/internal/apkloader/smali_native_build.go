package apkloader

// Native build driver: smali directory → DEX bytes, no external tools.
//
// assembleSmaliDirNative parses every .smali file in dir, interns all
// references, freezes pools into DEX order and writes one DEX file. Files
// that fail to parse produce user errors; genuinely unrepresentable
// constructs produce *nativeUnsupportedError so the caller can fall back to
// smali.jar (or report cleanly in standalone mode).

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// AssembleSmaliDirNative assembles one smali directory into DEX bytes.
// apiLevel selects the DEX version (0 = 035 default).
func AssembleSmaliDirNative(dir string, apiLevel int) (dex []byte, warnings []string, err error) {
	var paths []string
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".smali") {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if len(paths) == 0 {
		// Mirror smali.jar behavior: an empty smali directory is the Java
		// assembler's problem, not a native user error.
		return nil, nil, unsupported("no .smali files in %s", dir)
	}
	sort.Strings(paths)
	parsed := make([]*SmaliFile, 0, len(paths))
	for _, p := range paths {
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil, nil, rerr
		}
		rel, _ := filepath.Rel(dir, p)
		f, notes, perr := ParseSmaliFile(filepath.ToSlash(rel), string(data))
		if perr != nil {
			return nil, nil, perr
		}
		for _, n := range notes {
			warnings = append(warnings, fmt.Sprintf("%s:%d: %s", n.Path, n.Line, n.Text))
		}
		parsed = append(parsed, f)
	}
	return assembleParsed(parsed, warnings, apiLevel)
}

// AssembleSmaliText assembles a single in-memory .smali source.
func AssembleSmaliText(path, text string, apiLevel int) (dex []byte, warnings []string, err error) {
	f, notes, perr := ParseSmaliFile(path, text)
	if perr != nil {
		return nil, nil, perr
	}
	for _, n := range notes {
		warnings = append(warnings, fmt.Sprintf("%s:%d: %s", n.Path, n.Line, n.Text))
	}
	return assembleParsed([]*SmaliFile{f}, warnings, apiLevel)
}

func assembleParsed(parsed []*SmaliFile, warnings []string, apiLevel int) ([]byte, []string, error) {
	pools := newAsmPools()
	pools.typ("Ljava/lang/Object;")
	for _, f := range parsed {
		if perr := prescanClass(pools, f); perr != nil {
			if isUnsupported(perr) {
				return nil, warnings, perr
			}
			return nil, warnings, fmt.Errorf("%s: %v", f.Path, perr)
		}
	}
	pools.freeze()
	classes, cerr := collectClasses(pools, parsed)
	if cerr != nil {
		if isUnsupported(cerr) {
			return nil, warnings, cerr
		}
		return nil, warnings, cerr
	}
	minimumAPI := 0
	for _, file := range parsed {
		for _, method := range file.Methods {
			for _, line := range method.Lines {
				if line.parsed != nil && line.parsed.op >= 0xfa {
					required := 26
					if line.parsed.op >= 0xfe {
						required = 28
					}
					if required > minimumAPI {
						minimumAPI = required
					}
				}
			}
		}
	}
	if apiLevel == 0 {
		apiLevel = minimumAPI
	} else if apiLevel < minimumAPI {
		return nil, warnings, fmt.Errorf("instructions require Android API %d or newer (requested %d)", minimumAPI, apiLevel)
	}
	dexBytes, aerr := assembleDex(pools, classes, apiLevel)
	if aerr != nil {
		return nil, warnings, aerr
	}
	return dexBytes, warnings, nil
}

// tryNativeAssembleJobs attempts native assembly for every job, writing each
// output DEX next to its smali directory. It returns per-job results: built
// jobs were written natively; unsupported jobs may be tried with smali.jar.
func tryNativeAssembleJobs(jobs []smaliDirJob, apiLevel int) (built []smaliDirJob, unsupported []smaliDirJob, errs []string, warnings []string) {
	for _, job := range jobs {
		dex, warns, err := AssembleSmaliDirNative(job.dir, apiLevel)
		warnings = append(warnings, warns...)
		if err == nil {
			if werr := os.WriteFile(job.dexPath, dex, 0644); werr != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", job.name, werr))
				continue
			}
			built = append(built, job)
			continue
		}
		if isUnsupported(err) {
			unsupported = append(unsupported, job)
			warnings = append(warnings, fmt.Sprintf("%s: native assembler cannot represent tree (%v); trying smali.jar", job.name, err))
			continue
		}
		errs = append(errs, fmt.Sprintf("%s: %v", job.name, err))
	}
	return built, unsupported, errs, warnings
}
