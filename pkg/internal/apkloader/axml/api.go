package axml

import (
	"fmt"
	"os"
	"strings"
)

// DecodeFile reads a binary AndroidManifest.xml from disk and returns
// the parsed structure together with the rendered XML text.
func DecodeFile(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Decode(data)
}

// IsBinaryXML returns true when the buffer starts with a RES_XML_TYPE
// chunk header. Cheap to call before DecodeFile so callers can skip
// already-textual manifests (some apps ship plain XML).
func IsBinaryXML(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	chunkType := uint16(data[0]) | uint16(data[1])<<8
	return chunkType == chunkXML
}

// Render returns just the plaintext XML form. Convenience wrapper for
// callers that don't care about the structured Manifest fields.
func Render(data []byte) (string, error) {
	m, err := Decode(data)
	if err != nil {
		return "", err
	}
	return string(m.XMLBytes), nil
}

// Summary produces a short human-readable digest of the parsed
// manifest, used for logs and CLI output. Stable, single line per
// fact, easy to grep.
func (m *Manifest) Summary() string {
	if m == nil {
		return "<nil manifest>"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "package=%s\n", m.Package)
	fmt.Fprintf(&b, "versionCode=%d versionName=%s\n", m.VersionCode, m.VersionName)
	fmt.Fprintf(&b, "minSdk=%d targetSdk=%d\n", m.MinSDK, m.TargetSDK)
	fmt.Fprintf(&b, "permissions=%d activities=%d services=%d receivers=%d providers=%d\n",
		len(m.Permissions), len(m.Activities), len(m.Services),
		len(m.Receivers), len(m.Providers))
	fmt.Fprintf(&b, "debuggable=%v allowBackup=%v cleartext=%v\n",
		m.Application.Debuggable, m.Application.AllowBackup, m.Application.UsesCleartext)
	return b.String()
}

// ExportedComponents returns components that are explicitly marked
// `android:exported="true"` or carry an intent-filter (which makes
// them implicitly exported). Useful for attack-surface enumeration.
func (m *Manifest) ExportedComponents() []Component {
	var out []Component
	groups := [...][]Component{m.Activities, m.Services, m.Receivers, m.Providers}
	for _, g := range groups {
		for _, c := range g {
			if c.Exported != nil && *c.Exported {
				out = append(out, c)
				continue
			}
			if len(c.IntentFilts) > 0 {
				out = append(out, c)
			}
		}
	}
	return out
}
