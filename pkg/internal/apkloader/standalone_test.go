package apkloader

import (
	"os"
	"testing"
)

func TestStandaloneDisablesDiscovery(t *testing.T) {
	old, had := os.LookupEnv("MEGA_STANDALONE")
	defer func() {
		if had {
			os.Setenv("MEGA_STANDALONE", old)
		} else {
			os.Unsetenv("MEGA_STANDALONE")
		}
		SetStandalone(false)
	}()
	os.Unsetenv("MEGA_STANDALONE")
	SetStandalone(true)
	if !Standalone() {
		t.Fatal("Standalone() should be true after SetStandalone(true)")
	}
	if cfg := DefaultSmaliConfig(); cfg.SmaliJar != "" || cfg.BaksmaliJar != "" || cfg.JavaBinary != "" {
		t.Fatalf("standalone smali config must be empty, got %+v", cfg)
	}
	if cfg := DefaultAapt2Config(); cfg.Aapt2Path != "" {
		t.Fatalf("standalone aapt2 config must be empty, got %+v", cfg)
	}
	if err := tryOfficialZipAlign("a", "b"); err == nil {
		t.Fatal("standalone must not attempt official zipalign")
	}
}

func TestStandaloneEnv(t *testing.T) {
	old, had := os.LookupEnv("MEGA_STANDALONE")
	defer func() {
		if had {
			os.Setenv("MEGA_STANDALONE", old)
		} else {
			os.Unsetenv("MEGA_STANDALONE")
		}
		SetStandalone(false)
	}()
	SetStandalone(false)
	os.Setenv("MEGA_STANDALONE", "1")
	if !Standalone() {
		t.Fatal("MEGA_STANDALONE=1 should enable standalone")
	}
}
