package insights

import "testing"

func TestNamespaceURLsAreNotPrivacyEndpoints(t *testing.T) {
	urls := extractURLs([]byte(`<!-- Created with Tool (http://www.inkscape.org/) -->
<svg xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape"><image href="http://www.inkscape.org/image.png"/></svg>`))
	if len(urls) != 1 || urls[0] != "http://www.inkscape.org/image.png" {
		t.Fatalf("privacy endpoints = %#v", urls)
	}
}

func TestFirmwarePackageNamesDoNotMatchBrandMetadata(t *testing.T) {
	for _, path := range []string{"assets/logo.svg", "classes.dex"} {
		r := &FirmwareReport{}
		f := ScannedFile{Path: path, Data: []byte("board boa random metadata")}
		scanFirmwarePackages(r, f, path, f.Data)
		if len(r.Packages) != 0 {
			t.Fatalf("%s produced installed packages: %#v", path, r.Packages)
		}
	}
	r := &FirmwareReport{}
	f := ScannedFile{Path: "usr/sbin/boa", Data: []byte{0x7f, 'E', 'L', 'F'}}
	scanFirmwarePackages(r, f, f.Path, f.Data)
	if len(r.Packages) != 1 || r.Packages[0].Name != "boa" {
		t.Fatal("real firmware executable name was lost")
	}
}
