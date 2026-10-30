package axml

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func nativeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for path, data := range files {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestCompileNativeResources(t *testing.T) {
	dir := nativeProject(t, map[string]string{
		"AndroidManifest.xml":       `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.native" android:versionCode="1" android:versionName="1.0"><uses-sdk android:minSdkVersion="21" android:targetSdkVersion="35"/><application android:label="@string/app_name" android:theme="@android:style/Theme.Material.Light.NoActionBar"/></manifest>`,
		"res/values/strings.xml":    `<resources><string name="app_name">Native &amp; Go</string><string name="literal">\@not_a_reference</string><bool name="enabled">true</bool><integer name="limit">42</integer><color name="accent">#123456</color><dimen name="spacing">16dp</dimen><fraction name="half">50%</fraction></resources>`,
		"res/values-ru/strings.xml": `<resources><string name="app_name">Приложение</string></resources>`,
		"res/values/public.xml":     `<resources><public type="string" name="app_name" id="0x7f08002a"/></resources>`,
		"res/layout/main.xml":       `<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android" android:layout_width="match_parent" android:layout_height="match_parent" android:orientation="vertical" android:padding="16dp"><TextView android:id="@+id/title" android:layout_width="match_parent" android:layout_height="wrap_content" android:text="@string/app_name" android:textSize="18sp"/></LinearLayout>`,
		"res/raw/config.xml":        `<arbitrary>keep text</arbitrary>`,
	})
	result, err := CompileResourceDirectory(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	table, err := ParseARSC(result.Binary["resources.arsc"])
	if err != nil {
		t.Fatal(err)
	}
	if got := table.ResolveDefault(0x7f08002a); got != "Native & Go" {
		t.Fatalf("compiled string = %q", got)
	}
	entry := table.ResolveID(0x7f08002a)
	if entry == nil || len(entry.Values) != 2 {
		t.Fatalf("localized values = %+v", entry)
	}
	if !strings.Contains(result.Symbols, "int string app_name 0x7f08002a") || !strings.Contains(result.Symbols, "int id title ") {
		t.Fatalf("symbols: %s", result.Symbols)
	}
	manifest, err := ParseBinaryAXML(result.Binary["AndroidManifest.xml"])
	if err != nil {
		t.Fatal(err)
	}
	attr := func(e *DomElem, name string) DomAttr {
		for _, a := range e.Attrs {
			if a.Name == name {
				return a
			}
		}
		t.Fatalf("missing %s", name)
		return DomAttr{}
	}
	if a := attr(manifest.Root, "versionCode"); a.ResID != 0x0101021b || a.Type != typeIntDec || a.Data != 1 {
		t.Fatalf("versionCode wire format: %+v", a)
	}
	if a := attr(manifest.Root.Kids[0], "minSdkVersion"); a.ResID != 0x0101020c || a.Data != 21 {
		t.Fatalf("minSdkVersion wire format: %+v", a)
	}
	if a := attr(manifest.Root.Kids[1], "label"); a.ResID != 0x01010001 || a.Type != typeReference || a.Data != 0x7f08002a {
		t.Fatalf("label wire format: %+v", a)
	}
	layout, err := ParseBinaryAXML(result.Binary["res/layout/main.xml"])
	if err != nil {
		t.Fatal(err)
	}
	if a := attr(layout.Root, "padding"); a.Type != typeDimension || a.Data != 0x00001001 {
		t.Fatalf("16dp wire format: %+v", a)
	}
	if a := attr(layout.Root, "layout_width"); a.Type != typeIntHex || a.Data != 0xffffffff {
		t.Fatalf("match_parent wire format: %+v", a)
	}
	if a := attr(layout.Root, "orientation"); a.Data != 1 || a.Type != typeIntHex {
		t.Fatalf("orientation wire format: %+v", a)
	}
	if len(result.Copy) != 1 || result.Copy[0] != "res/raw/config.xml" {
		t.Fatalf("raw resources: %v", result.Copy)
	}
	if _, err := os.Stat(filepath.Join(dir, "resources.arsc")); !os.IsNotExist(err) {
		t.Fatal("compiler must not modify source resources")
	}
	second, err := CompileResourceDirectory(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range result.Binary {
		if !bytes.Equal(data, second.Binary[name]) {
			t.Fatalf("nondeterministic resource: %s", name)
		}
	}
}

func TestNativeResourceRejectsUnsupportedInput(t *testing.T) {
	for name, res := range map[string]string{"style": `<style name="AppTheme"/>`, "styled string": `<string name="s">Hello <b>world</b></string>`, "unresolved": `<string name="s">@string/missing</string>`, "duplicate": `<string name="s">one</string><string name="s">two</string>`, "malformed": `<string name="s">broken`} {
		t.Run(name, func(t *testing.T) {
			dir := nativeProject(t, map[string]string{"AndroidManifest.xml": `<manifest package="example.app"/>`, "res/values/test.xml": "<resources>" + res + "</resources>"})
			if _, err := CompileResourceDirectory(context.Background(), dir); err == nil {
				t.Fatal("unsupported resource silently accepted")
			}
		})
	}
	for _, text := range []string{`<manifest>`, `<manifest/><other/>`, `<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:unknownNativeAttr="test"/></manifest>`} {
		if _, err := CompileTextAXML([]byte(text), nil); err == nil {
			t.Fatalf("bad XML accepted: %s", text)
		}
	}
}

func TestNativeComplexAndroidEncoding(t *testing.T) {
	for _, tc := range []struct {
		text     string
		fraction bool
		want     uint32
	}{{"16dp", false, 0x1001}, {"-2px", false, 0xfffffe00}, {"0.5sp", false, 0x40000032}, {"50%", true, 0x40000030}, {"25%p", true, 0x20000031}} {
		got, err := nativeComplex(tc.text, tc.fraction)
		if err != nil || got != tc.want {
			t.Fatalf("%s: 0x%x %v, want 0x%x", tc.text, got, err, tc.want)
		}
	}
}

func TestNativeResourceQualifiers(t *testing.T) {
	cfg, err := nativeConfig("en-rUS-sw600dp-land-night-xhdpi-v26")
	if err != nil {
		t.Fatal(err)
	}
	if string(cfg[8:12]) != "enUS" || cfg[12] != 2 || cfg[29] != 0x20 || binary.LittleEndian.Uint16(cfg[14:]) != 320 || binary.LittleEndian.Uint16(cfg[24:]) != 26 || binary.LittleEndian.Uint16(cfg[30:]) != 600 {
		t.Fatalf("wrong qualifier bytes: %x", cfg)
	}
	for _, bad := range []string{"b+sr+Latn", "land-port", "vabc", "en-rUS-rGB"} {
		if _, err := nativeConfig(bad); err == nil {
			t.Fatalf("unsupported qualifier accepted: %s", bad)
		}
	}
}

func TestNativeLayoutDecodeOverlayPreservesPackedDimensions(t *testing.T) {
	original, err := CompileTextAXML([]byte(`<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android" android:layout_width="16dp" android:layout_height="wrap_content"/>`), nil)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(original)
	if err != nil {
		t.Fatal(err)
	}
	if !SameAXMLSemantics(original, decoded.XMLBytes) {
		t.Fatalf("unchanged decoded layout differs: %s", decoded.XMLBytes)
	}
	modified := bytes.ReplaceAll(decoded.XMLBytes, []byte(`android:layout_width="0x1001"`), []byte(`android:layout_width="24dp"`))
	bin, err := OverlayAXML(original, modified, nil)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ParseBinaryAXML(bin)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range doc.Root.Attrs {
		if a.Name == "layout_width" && (a.Type != typeDimension || a.Data != 0x1801) {
			t.Fatalf("24dp overlay wire format: %+v", a)
		}
	}
}
