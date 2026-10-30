package main

import "testing"

func TestCleanArchivePath(t *testing.T) {
	if got, err := cleanArchivePath(`assets\\data.bin`); err != nil || got != "assets/data.bin" { t.Fatalf("got %q, %v", got, err) }
	for _, bad := range []string{"../x", "/absolute", "a/../../x", ""} {
		if _, err := cleanArchivePath(bad); err == nil { t.Fatalf("expected unsafe path rejection for %q", bad) }
	}
}

func TestSignatureDetection(t *testing.T) {
	for _, name := range []string{"META-INF/CERT.RSA", "META-INF/CERT.SF", "META-INF/MANIFEST.MF"} {
		if !isV1Signature(name) { t.Fatalf("expected signature: %s", name) }
	}
	if isV1Signature("assets/CERT.RSA") { t.Fatal("asset must not be treated as signature") }
}
