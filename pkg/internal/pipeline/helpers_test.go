package pipeline

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestClassifyFile_CacheArtifacts(t *testing.T) {
	tests := []struct {
		path string
		want types.FileType
	}{
		{path: "Payload/MyGame.app/Info.plist", want: types.FileTypeXML},
		{path: "cache/session.JSON", want: types.FileTypeJSON},
		{path: "assets/config.env", want: types.FileTypeText},
		{path: "scripts/bootstrap.js", want: types.FileTypeText},
		{path: "scripts/hotfix.lua", want: types.FileTypeText},
		{path: "ios/embedded.mobileprovision", want: types.FileTypeText},
		{path: "certs/public.PEM", want: types.FileTypeText},
	}

	for _, tt := range tests {
		if got := classifyFile(tt.path); got != tt.want {
			t.Errorf("classifyFile(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestDEXClassVirtualPath(t *testing.T) {
	tests := []struct {
		className string
		want      string
	}{
		{"Lsmellymoo/sand/MainActivity;", "smali/smellymoo/sand/MainActivity.smali"},
		{"Landroidx/core/app/ComponentActivity;", "smali/androidx/core/app/ComponentActivity.smali"},
		{"", "classes.dex::unknown-class"},
	}

	for _, tt := range tests {
		if got := dexClassVirtualPath("classes.dex", tt.className); got != tt.want {
			t.Errorf("dexClassVirtualPath(%q) = %q, want %q", tt.className, got, tt.want)
		}
	}
}

func TestDEXClassWorkUnits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "classes.dex")
	header := make([]byte, 0x64)
	copy(header, "dex\n035\x00")
	binary.LittleEndian.PutUint32(header[0x60:0x64], 1399)
	if err := os.WriteFile(path, header, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := dexClassWorkUnits(path); got != 1399 {
		t.Fatalf("dexClassWorkUnits() = %d, want 1399", got)
	}
	if got := dexClassWorkUnits(filepath.Join(t.TempDir(), "missing.dex")); got != 1 {
		t.Fatalf("missing DEX work units = %d, want fallback 1", got)
	}
}
