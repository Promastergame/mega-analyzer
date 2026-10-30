package ml

import (
	"testing"
)

func TestDetectAdvancedThreats(t *testing.T) {
	mi := &MethodInfo{
		ClassName: "Lcom/malware/Stealthy;",
		Name:      "checkEnvironment",
		Calls: []CallInfo{
			{FullCall: "Landroid/os/Build;->hardware:Ljava/lang/String;"},
			{FullCall: "Landroid/os/Build;->model:Ljava/lang/String;"},
			{FullCall: "Landroid/os/Debug;->isDebuggerConnected()Z"},
			{FullCall: "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"},
			{FullCall: "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"},
			{FullCall: "Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V"},
		},
		StringConsts: []string{
			"generic", "google_sdk", "/system/xbin/su", "/sbin/su", "ptrace", "frida", "xposed",
		},
	}

	analysis := DetectAdvancedThreats(mi)

	if analysis.ThreatCount == 0 {
		t.Error("Expected threats to be detected, got 0")
	}

	// Check for anti-emulator
	hasEmu := false
	for _, tr := range analysis.Threats {
		if tr.Category == ThreatAntiEmulator {
			hasEmu = true
			break
		}
	}
	if !hasEmu {
		t.Error("Expected anti-emulator threat")
	}

	// Check for anti-root
	hasRoot := false
	for _, tr := range analysis.Threats {
		if tr.Category == ThreatAntiRoot {
			hasRoot = true
			break
		}
	}
	if !hasRoot {
		t.Error("Expected anti-root threat")
	}

	if analysis.HighestSeverity != "critical" {
		t.Errorf("Expected highest severity critical (due to dynamic loading), got %s", analysis.HighestSeverity)
	}
}

func TestAdvancedThreats_NetworkAndFile(t *testing.T) {
	mi := &MethodInfo{
		Calls: []CallInfo{
			{FullCall: "Ljava/net/Socket;-><init>(Ljava/lang/String;I)V"},
			{FullCall: "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;"},
			{FullCall: "Ljava/io/File;->exists()Z"},
		},
		StringConsts: []string{
			"1337", "/data/system/",
		},
	}

	analysis := DetectAdvancedThreats(mi)

	hasNet := false
	for _, tr := range analysis.Threats {
		if tr.Category == ThreatSuspiciousNet {
			hasNet = true
			break
		}
	}
	if !hasNet {
		t.Error("Expected suspicious network threat")
	}
}

func TestHasRandomPattern(t *testing.T) {
	tests := []struct {
		s        string
		expected bool
	}{
		{"normal", false},
		{"aeiou", false},
		{"bcdfghjklmnp", true},
		{"a1b2c3", false}, // 1 vowel / 3 letters = 0.33 > 0.2
		{"", false},
	}

	for _, tt := range tests {
		if hasRandomPattern(tt.s) != tt.expected {
			t.Errorf("hasRandomPattern(%q) = %v, want %v", tt.s, !tt.expected, tt.expected)
		}
	}
}
