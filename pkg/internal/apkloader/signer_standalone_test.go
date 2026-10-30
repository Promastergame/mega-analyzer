package apkloader

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStandaloneSigningIgnoresInstalledDebugKeystore(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("MEGA_STANDALONE", "1")
	t.Setenv("PATH", dir)
	toolDir := filepath.Join(dir, "bin", "tools")
	if err := os.MkdirAll(toolDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"apksigner.jar", "debug.keystore"} {
		if err := os.WriteFile(filepath.Join(toolDir, name), []byte("must not be used"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	input := writeProjectZIP(t, map[string]string{"AndroidManifest.xml": "<manifest/>"})
	outcome, err := SignAPKWithConfig(input, SignConfig{})
	if err != nil {
		t.Fatalf("installed compatibility tools broke native signing: %v", err)
	}
	if !outcome.DebugKey || outcome.Method != SignMethodDebugPKCS7 {
		t.Fatalf("not native signing: %+v", outcome)
	}
	if _, err := VerifyV1SignatureOffline(input); err != nil {
		t.Fatal(err)
	}
	if result, err := VerifyV2V3Offline(input); err != nil || !result.V2 || !result.V3 {
		t.Fatalf("invalid signatures: %+v %v", result, err)
	}
	if _, err := SignAPKWithConfig(input, SignConfig{KeystorePath: filepath.Join(toolDir, "debug.keystore")}); err == nil {
		t.Fatal("explicit external keystore must remain prohibited")
	}
}
