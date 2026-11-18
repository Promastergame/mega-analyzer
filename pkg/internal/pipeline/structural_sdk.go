package pipeline

import (
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/logger"
)

// Structural SDK recognition.
//
// Path-prefix classification cannot see a library whose packages were renamed
// during obfuscation: renamed androidx lands in a package like "smali/z/" and
// scores as app code, which inflates hotspots and defeats SDK noise
// suppression. This pass fingerprints vendored obfuscated libraries by
// structure instead of by name and registers them with the filter so every
// downstream consumer (hotspot scoring, FP filter, SDK stats) sees library
// code.
//
// A package qualifies only when all of the following hold, which keeps
// obfuscated *malware* out of the library bucket:
//   - it contains enough classes (minStructuralLibClasses);
//   - the overwhelming majority of class names are obfuscated-shaped
//     (looksObfuscatedClassName);
//   - no class in it is registered as a manifest component;
//   - it is not the app package (or a child of it);
//   - none of its files produced a critical or malware-category match.

const (
	minStructuralLibClasses = 20
	minStructuralLibRatio   = 0.8
)

// markObfuscatedLibraryPackages runs after all files are processed and before
// hotspot scoring, so scoring and the FP filter observe the corrected
// classification.
func (p *Pipeline) markObfuscatedLibraryPackages() {
	if p.result == nil || p.filter == nil {
		return
	}

	appPackage := p.result.AppPackage
	components := p.manifestComponentNames()

	type pkgStat struct {
		files       []*types.FileAnalysis
		obfuscated  int
		suspicious  bool
		hasComp     bool
		hasNoSmali  bool
		nonObfNames []string
	}
	packages := make(map[string]*pkgStat)

	for _, fa := range p.result.Files {
		if fa == nil || fa.SmaliClass == nil {
			continue
		}
		pkg := fa.SmaliClass.PackageName
		if pkg == "" {
			pkg = smaliPackageOf(fa.Path)
		}
		if pkg == "" {
			continue
		}
		stat, ok := packages[pkg]
		if !ok {
			stat = &pkgStat{}
			packages[pkg] = stat
		}
		stat.files = append(stat.files, fa)

		simple := classSimpleName(fa.SmaliClass.Name)
		if looksObfuscatedClassName(simple) {
			stat.obfuscated++
		} else {
			stat.nonObfNames = append(stat.nonObfNames, simple)
		}
		if classMatchesComponent(fa.SmaliClass.Name, components, appPackage) {
			stat.hasComp = true
		}
		for _, m := range fa.Matches {
			if m.IsCritical || m.Category == types.CategoryMalware {
				stat.suspicious = true
				break
			}
		}
	}

	marked := make([]string, 0, 4)
	for pkg, stat := range packages {
		if stat.suspicious || stat.hasComp || len(stat.files) < minStructuralLibClasses {
			continue
		}
		if isAppPackageOrChild(pkg, appPackage) {
			continue
		}
		if float64(stat.obfuscated) < minStructuralLibRatio*float64(len(stat.files)) {
			continue
		}

		// Canonical prefix covers every multidex root: tryFastPath normalizes
		// smali_classesN/ back to smali/ before prefix matching.
		prefix := "smali/" + strings.ReplaceAll(pkg, ".", "/") + "/"
		p.filter.MarkStructuralLibrary(strings.ToLower(prefix))
		marked = append(marked, pkg)

		for _, fa := range stat.files {
			fa.IsAppCode = false
			fa.IsLibrary = true
			fa.SmaliClass.IsLibrary = true
			fa.SmaliClass.IsAppCode = false
			// Vulnerability findings inside reclassified library code
			// describe the library, not the app: a mutable PendingIntent in
			// a renamed androidx notification helper (inline replies) is the
			// platform-recommended pattern, scored 8-as-app only because the
			// structural pass had not reclassified the file when the
			// detector ran. Drop vulnerability/review matches here.
			kept := fa.Matches[:0]
			for _, m := range fa.Matches {
				switch m.Category {
				case types.CategoryPendingIntentVuln, types.CategoryPendingIntentReview:
					continue
				}
				kept = append(kept, m)
			}
			fa.Matches = kept
		}
	}

	if len(marked) > 0 {
		sort.Strings(marked)
		logger.Warn("structural SDK fingerprint: obfuscated library packages recognized",
			"count", len(marked), "packages", strings.Join(marked, ", "))
	}
}

// manifestComponentNames collects every class name the manifest registers
// (activities, services, receivers, providers), both as written and as
// simple names, so packages that own UI or OS entry points can be excluded.
func (p *Pipeline) manifestComponentNames() map[string]struct{} {
	names := make(map[string]struct{})
	for _, fa := range p.result.Files {
		if fa == nil || fa.XMLData == nil {
			continue
		}
		for _, group := range [][]string{
			fa.XMLData.Activities, fa.XMLData.Services,
			fa.XMLData.Receivers, fa.XMLData.Providers,
		} {
			for _, name := range group {
				if name == "" {
					continue
				}
				names[strings.TrimPrefix(name, ".")] = struct{}{}
				if dot := strings.LastIndexAny(name, ".$"); dot >= 0 && dot+1 < len(name) {
					names[name[dot+1:]] = struct{}{}
				}
			}
		}
	}
	return names
}

// classMatchesComponent reports whether a class name equals or extends a
// manifest-registered component (including inner classes of one).
func classMatchesComponent(className string, components map[string]struct{}, appPackage string) bool {
	if len(components) == 0 {
		return false
	}
	name := strings.TrimPrefix(className, "L")
	name = strings.TrimSuffix(name, ";")
	name = strings.ReplaceAll(name, "/", ".")
	candidates := []string{name}
	// Every outer class up the chain: a$Inner, a$Inner$Deeper ...
	for i := 0; i < 4; i++ {
		dollar := strings.LastIndexByte(candidates[len(candidates)-1], '$')
		if dollar <= 0 {
			break
		}
		candidates = append(candidates, candidates[len(candidates)-1][:dollar])
	}
	for _, cand := range candidates {
		if _, ok := components[cand]; ok {
			return true
		}
		// Relative manifest names ("com.sync.media.hub.Main" written as
		// ".Main") are expanded against the app package.
		if appPackage != "" && strings.HasPrefix(cand, appPackage+".") {
			if _, ok := components[strings.TrimPrefix(cand, appPackage+".")]; ok {
				return true
			}
		}
		if _, ok := components[classSimpleName(cand)]; ok {
			return true
		}
	}
	return false
}

// isAppPackageOrChild keeps the application's own namespace out of the
// library bucket even when its names are obfuscated.
func isAppPackageOrChild(pkg, appPackage string) bool {
	if appPackage == "" {
		return false
	}
	return pkg == appPackage || strings.HasPrefix(pkg, appPackage+".")
}

// smaliPackageOf derives the dotted package from a smali path
// ("smali/z/Foo.smali" → "z") when SmaliClass metadata is unavailable.
func smaliPackageOf(path string) string {
	p := strings.ReplaceAll(path, "\\", "/")
	for _, root := range []string{"smali/", "smali_classes"} {
		if strings.HasPrefix(p, root) {
			rest := strings.TrimPrefix(p, root)
			// smali_classes2/... — skip the digits up to the slash.
			if root == "smali_classes" {
				if slash := strings.IndexByte(rest, '/'); slash >= 0 {
					rest = rest[slash+1:]
				}
			}
			if slash := strings.LastIndexByte(rest, '/'); slash >= 0 {
				rest = rest[:slash]
				return strings.ReplaceAll(rest, "/", ".")
			}
		}
	}
	return ""
}

// classSimpleName returns the last segment of a dotted/inner class name.
func classSimpleName(name string) string {
	if i := strings.LastIndexAny(name, "./$"); i >= 0 && i+1 < len(name) {
		return name[i+1:]
	}
	return name
}

// looksObfuscatedClassName identifies the random identifier shapes produced
// by common Android obfuscators: single/double-letter ProGuard names ("a",
// "bb"), the "Ox…" digit-laden runs used by StringFog-family renamers
// ("Ox0K00KK0K0KK00KK09B9…" — the leading 'O' is part of the marker, not a
// pronounceable vowel), and vowel-free digit/letter mixes in general.
func looksObfuscatedClassName(name string) bool {
	if name == "" {
		return false
	}
	if i := strings.IndexByte(name, '$'); i >= 0 {
		name = name[:i]
	}
	if name == "" {
		return false
	}
	if len(name) <= 2 {
		return true
	}
	// Strip the obfuscator marker prefix before counting vowels: "Ox" is a
	// constant of the scheme, and its 'o' would otherwise read as a vowel
	// and make every renamed class look like a meaningful name.
	if len(name) > 2 && (name[0] == 'O' || name[0] == 'o') && (name[1] == 'x' || name[1] == 'X') {
		name = name[2:]
	}
	hasDigit, letters, vowels := false, 0, 0
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 'a' && r <= 'z':
			letters++
			switch r {
			case 'a', 'e', 'i', 'o', 'u':
				vowels++
			}
		}
	}
	return hasDigit && letters >= 4 && vowels == 0
}
