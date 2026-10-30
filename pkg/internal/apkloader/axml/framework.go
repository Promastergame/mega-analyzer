package axml

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
)

// maxFrameworkARSC bounds the resources.arsc read from a framework APK so a
// corrupted UncompressedSize64 cannot drive a multi-gigabyte allocation.
const maxFrameworkARSC = 256 << 20

// FrameworkResolver loads a framework APK/JAR (e.g. android.jar or
// framework-res.apk) and uses its resources.arsc to resolve @android:
// attribute / resource IDs at runtime. This replaces the hard-coded
// resourceID map for anything that ships inside the framework.
type FrameworkResolver struct {
	table *ResourceTable
}

// LoadFrameworkAPK opens a framework APK/JAR, extracts resources.arsc
// and builds a lookup table. Returns nil on any I/O or parse error
// (callers can fall back to the built-in resourceID map).
func LoadFrameworkAPK(path string) (*FrameworkResolver, error) {
	f, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open framework %s: %w", path, err)
	}
	defer f.Close()

	var arscData []byte
	for _, file := range f.File {
		if file.Name == "resources.arsc" {
			rc, err := file.Open()
			if err != nil {
				return nil, err
			}
			// io.ReadFull-style read with a cap: a single rc.Read used to
			// return fewer bytes than requested on large deflated entries,
			// and the truncated buffer was then parsed as an ARSC.
			arscData, err = io.ReadAll(io.LimitReader(rc, maxFrameworkARSC))
			rc.Close()
			if err != nil {
				return nil, err
			}
			break
		}
	}
	if arscData == nil {
		return nil, fmt.Errorf("framework %s has no resources.arsc", path)
	}

	table, err := ParseARSC(arscData)
	if err != nil {
		return nil, fmt.Errorf("parse framework arsc: %w", err)
	}

	return &FrameworkResolver{table: table}, nil
}

// ResolveName looks up a framework resource ID and returns its symbolic
// name (e.g. "@android:string/ok"). Falls back to the hex form when
// the ID is unknown in this framework table.
func (fr *FrameworkResolver) ResolveName(id uint32) string {
	if fr == nil || fr.table == nil {
		return ""
	}
	return fr.table.ResolveName(id)
}

// ResolveAttributeName tries to find the human-readable name for an
// android attribute ID. Returns "" when the framework does not define it.
func (fr *FrameworkResolver) ResolveAttributeName(id uint32) string {
	if fr == nil || fr.table == nil {
		return ""
	}
	pkgID := (id >> 24) & 0xff
	if pkgID != 0x01 { // android framework package is 0x01
		return ""
	}
	entry := fr.table.ResolveID(id)
	if entry == nil {
		return ""
	}
	return entry.Name
}

// AutoLoadFramework searches standard SDK paths for android.jar and
// returns a FrameworkResolver if one is found. Zero-allocation on failure.
func AutoLoadFramework() *FrameworkResolver {
	for _, env := range []string{"ANDROID_HOME", "ANDROID_SDK_ROOT"} {
		if sdk := os.Getenv(env); sdk != "" {
			// Try latest first, then scan platforms.
			candidates := []string{
				sdk + "/platforms/android-34/android.jar",
				sdk + "/platforms/android-33/android.jar",
				sdk + "/platforms/android-32/android.jar",
				sdk + "/platforms/android-31/android.jar",
				sdk + "/platforms/android-30/android.jar",
			}
			// dynamic scan as fallback
			if platforms, err := os.ReadDir(sdk + "/platforms"); err == nil {
				for _, p := range platforms {
					if p.IsDir() {
						candidates = append(candidates, sdk+"/platforms/"+p.Name()+"/android.jar")
					}
				}
			}
			for _, c := range candidates {
				if fr, err := LoadFrameworkAPK(c); err == nil {
					return fr
				}
			}
		}
	}
	return nil
}
