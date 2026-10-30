package nsc

import (
	"bytes"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
)

// manifest.go — the two AndroidManifest.xml attributes that change NSC
// verdicts. The manifest wins over the NSC in both cases:
//
//   - android:debuggable="true" makes <debug-overrides> legitimate —
//     flagging it Medium in a dev build is a false positive (the old
//     looksLikeDebugBuild stub always returned false, so it fired always).
//   - android:usesCleartextTraffic="true" on <application> permits plain
//     HTTP app-wide regardless of what the NSC says — a hardened NSC next
//     to this flag is a false negative without the cross-check.
//
// Binary (AXML) manifests cannot be read here; they yield Found=false and
// the audit keeps its previous conservative behavior.

// ManifestSignals carries manifest attributes into the audit. Zero value
// means "manifest unknown" and preserves the old behavior exactly.
type ManifestSignals struct {
	Found              bool
	Debuggable         bool
	CleartextPermitted *bool // nil = attribute absent/unknown
}

// LocateManifest looks for a text AndroidManifest.xml under an extracted
// APK directory (apktool root, jadx resources/, Gradle source tree).
func LocateManifest(root string) string {
	candidates := []string{
		filepath.Join(root, "AndroidManifest.xml"),
		filepath.Join(root, "resources", "AndroidManifest.xml"),
		filepath.Join(root, "app", "src", "main", "AndroidManifest.xml"),
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// ReadManifestSignals extracts the NSC-relevant attributes from a manifest.
// Binary AXML and unreadable files yield Found=false, never an error: the
// caller falls back to manifest-unaware auditing.
func ReadManifestSignals(path string) ManifestSignals {
	data, err := readFileCappedManifest(path)
	if err != nil || len(data) == 0 {
		return ManifestSignals{}
	}
	if len(data) >= 4 && data[0] == 0x03 && data[1] == 0x00 && data[2] == 0x08 && data[3] == 0x00 {
		return ManifestSignals{} // AXML: not parseable here
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = false
	for {
		tok, err := d.Token()
		if err != nil {
			return ManifestSignals{}
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "application" {
			continue
		}
		var ms ManifestSignals
		ms.Found = true
		for _, a := range start.Attr {
			switch a.Name.Local {
			case "debuggable":
				ms.Debuggable = a.Value == "true"
			case "usesCleartextTraffic":
				v := a.Value == "true"
				ms.CleartextPermitted = &v
			}
		}
		return ms
	}
}

func readFileCappedManifest(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 8<<20))
}
