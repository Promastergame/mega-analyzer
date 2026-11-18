package pipeline

// Structural detectors distilled from the Mamont/RADAR conveyor case
// (November 2026): com.salacazi.dowarojani / com.zbdguujx.wqkoddpcub builds.
//
// Each check fires on a fact observed in live samples that no signature or
// permission rule catches:
//
//   - LEANBACK-only launcher: the manifest exposes the app exclusively to
//     Android TV (android.intent.category.LEANBACK_LAUNCHER) while no
//     activity carries the phone LAUNCHER category. The app is invisible
//     on the victim's phone launcher by design.
//   - Account authenticator: a service handling
//     android.accounts.AccountAuthenticator lets the app plant entries in
//     the system AccountManager. In the live sample the account name was
//     "service@google.com" under a package-owned type — brand impersonation
//     used as persistence.
//   - Conveyor service-process template: services pinned to processes named
//     ":vnc_Svc_54206b33" / ":net_Svc_54206b33". The package name is
//     randomized per build, but the service-process template is a builder
//     constant — package-name rules miss the family, this does not.
//
// The ABI install-tripwire check lives in evaluateAbiTripwire (pipeline
// stage): lib/x86_64 carrying only stub-sized .so files while ARM ABIs
// carry real code makes the APK refuse to install on x86 emulators.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

const (
	manifestMainAction   = "android.intent.action.MAIN"
	manifestLauncherCat  = "android.intent.category.LAUNCHER"
	manifestLeanbackCat  = "android.intent.category.LEANBACK_LAUNCHER"
	authenticatorAction  = "android.accounts.AccountAuthenticator"

	// ABI tripwire thresholds: a stub ABI never exceeds 8 KiB per .so, real
	// code ABIs carry at least one library well above it. The live sample
	// shipped a 67-byte x86_64 stub against a 917 KB arm64-v8a set.
	abiStubMaxBytes = 8 << 10
	abiRealMinBytes = 512 << 10
)

// conveyorSvcProcessRe matches the RADAR/Mamont builder service-process
// template: ":vnc_Svc_54206b33", ":net_Svc_54206b33". Only these module
// prefixes are anchored so ordinary multi-process apps never match.
var conveyorSvcProcessRe = regexp.MustCompile(`^:(?:vnc|net|ws|rtmp)_[A-Za-z]{2,12}_[0-9a-fA-F]{6,16}$`)

// ConveyorManifestDetector reports builder-template shapes in the manifest.
type ConveyorManifestDetector struct{}

func NewConveyorManifestDetector() *ConveyorManifestDetector { return &ConveyorManifestDetector{} }

func (d *ConveyorManifestDetector) Name() string { return "conveyor_manifest" }

func (d *ConveyorManifestDetector) SupportsFile(fileType types.FileType, path string) bool {
	return fileType == types.FileTypeXML && strings.HasSuffix(strings.ToLower(path), "androidmanifest.xml")
}

func (d *ConveyorManifestDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx.FileType != types.FileTypeXML {
		return
	}
	manifest, err := bridgeDecodeManifest(ctx.Content)
	if err != nil || manifest == nil || manifest.Package == "" {
		return
	}

	// ── LEANBACK-only launcher: invisible on phone launchers ──────────────
	hasPhoneLauncher, hasLeanback := false, false
	for _, a := range manifest.Activities {
		for _, f := range a.IntentFilts {
			var hasMain, hasLauncher, hasLB bool
			for _, act := range f.Actions {
				if act == manifestMainAction {
					hasMain = true
				}
			}
			for _, c := range f.Categories {
				if c == manifestLauncherCat {
					hasLauncher = true
				}
				if c == manifestLeanbackCat {
					hasLB = true
				}
			}
			if hasMain && hasLauncher {
				hasPhoneLauncher = true
			}
			if hasMain && hasLB {
				hasLeanback = true
			}
		}
	}
	if hasLeanback && !hasPhoneLauncher {
		m := newMatchWithScore(
			types.CategoryMalware, analysis.Path, 0,
			"App launches only on Android TV (LEANBACK_LAUNCHER) with no phone LAUNCHER category — invisible on the victim's phone launcher",
			"leanback_only_launcher",
			75, false,
		)
		m.Metadata = map[string]string{
			"detector":      d.Name(),
			"finding_kind":  "malware",
			"evidence_type": "manifest_structure",
		}
		analysis.Matches = append(analysis.Matches, m)
	}

	// ── Conveyor service-process template ─────────────────────────────────
	for _, svc := range manifest.Services {
		if !conveyorSvcProcessRe.MatchString(svc.Process) {
			continue
		}
		m := newMatchWithScore(
			types.CategoryMalware, analysis.Path, 0,
			"Builder-template service process name '"+svc.Process+"' — package-randomized conveyor fingerprint (RADAR/Mamont)",
			svc.Process,
			90, true,
		)
		m.Metadata = map[string]string{
			"detector":      d.Name(),
			"finding_kind":  "malware",
			"evidence_type": "manifest_structure",
		}
		analysis.Matches = append(analysis.Matches, m)
	}

	// ── AccountManager authenticator ──────────────────────────────────────
	for _, svc := range manifest.Services {
		found := false
		for _, f := range svc.IntentFilts {
			for _, act := range f.Actions {
				if act == authenticatorAction {
					found = true
				}
			}
		}
		if !found {
			continue
		}
		m := newMatchWithScore(
			types.CategoryMalware, analysis.Path, 0,
			"Service declares android.accounts.AccountAuthenticator — the app can plant entries in the system AccountManager (observed in the wild as a fake 'service@google.com' account for persistence)",
			authenticatorAction,
			60, false,
		)
		m.Metadata = map[string]string{
			"detector":      d.Name(),
			"finding_kind":  "malware",
			"evidence_type": "manifest_structure",
		}
		analysis.Matches = append(analysis.Matches, m)
	}
}

// evaluateAbiTripwire detects the install-time anti-emulator tripwire: the
// APK ships real native code for ARM ABIs while x86/x86_64 receive only
// stub-sized libraries. PackageManager then refuses the install on x86
// emulators (INSTALL_FAILED_NO_MATCHING_ABIS) before a single instruction
// of the app ever runs. Runs as a pipeline stage over the extracted tree.
func (p *Pipeline) evaluateAbiTripwire() {
	if p.result == nil {
		return
	}
	root := p.result.TargetDir
	if root == "" {
		return
	}
	abis, err := os.ReadDir(filepath.Join(root, "lib"))
	if err != nil {
		return
	}

	maxSize := make(map[string]int64, 4)
	for _, abi := range abis {
		if !abi.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(root, "lib", abi.Name()))
		if err != nil {
			continue
		}
		var mx int64
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			info, err := f.Info()
			if err != nil {
				continue
			}
			if info.Size() > mx {
				mx = info.Size()
			}
		}
		if mx > 0 {
			maxSize[abi.Name()] = mx
		}
	}

	stub := func(abi string) bool { m, ok := maxSize[abi]; return ok && m <= abiStubMaxBytes }
	real := func(abi string) bool { m, ok := maxSize[abi]; return ok && m >= abiRealMinBytes }

	x86Stub := stub("x86_64") || stub("x86")
	armReal := real("arm64-v8a") || real("armeabi-v7a")
	if !x86Stub || !armReal {
		return
	}

	abisList := make([]string, 0, len(maxSize))
	for abi, m := range maxSize {
		abisList = append(abisList, fmt.Sprintf("%s max %d B", abi, m))
	}
	sort.Strings(abisList)

	p.result.ArtifactFindings = append(p.result.ArtifactFindings, types.ArtifactFinding{
		Path:     "lib/",
		Severity: types.SeverityHigh,
		Reason: "Install-time emulator tripwire: x86/x86_64 native libraries are stub-sized while ARM ABIs carry real code (" +
			strings.Join(abisList, "; ") +
			"). The build fails with INSTALL_FAILED_NO_MATCHING_ABIS on x86 emulators before any code runs — installer-level anti-analysis.",
	})
	p.result.Stats.TotalMatches++
}
