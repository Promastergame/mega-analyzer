package sandbox

import (
	"strings"
	"testing"
)

// ─── parsePort ────────────────────────────────────────────────────────────────

func TestParsePort_Empty(t *testing.T) {
	if got := parsePort(""); got != "9339" {
		t.Errorf("empty addr: got %q, want 9339", got)
	}
}

func TestParsePort_ColonPort(t *testing.T) {
	if got := parsePort("localhost:8080"); got != "8080" {
		t.Errorf("host:port: got %q, want 8080", got)
	}
}

func TestParsePort_BarePort(t *testing.T) {
	if got := parsePort("1234"); got != "1234" {
		t.Errorf("bare port: got %q, want 1234", got)
	}
}

func TestParsePort_UnknownFormat(t *testing.T) {
	if got := parsePort("notaport"); got != "9339" {
		t.Errorf("unknown format: got %q, want 9339", got)
	}
}

func TestParsePort_IPv6(t *testing.T) {
	got := parsePort("[::1]:4321")
	if got != "4321" {
		t.Errorf("ipv6: got %q, want 4321", got)
	}
}

// ─── installFailureHint ───────────────────────────────────────────────────────

func TestInstallFailureHint_UserRestricted(t *testing.T) {
	h := installFailureHint("INSTALL_FAILED_USER_RESTRICTED")
	if !strings.Contains(h, "Developer Options") {
		t.Errorf("user_restricted: got %q", h)
	}
}

func TestInstallFailureHint_DeviceOffline(t *testing.T) {
	h := installFailureHint("error: device offline")
	if !strings.Contains(h, "OFFLINE") {
		t.Errorf("device offline: got %q", h)
	}
}

func TestInstallFailureHint_Unauthorized(t *testing.T) {
	h := installFailureHint("error: device unauthorized")
	if !strings.Contains(h, "Allow USB debugging") {
		t.Errorf("unauthorized: got %q", h)
	}
}

func TestInstallFailureHint_VersionDowngrade(t *testing.T) {
	h := installFailureHint("INSTALL_FAILED_VERSION_DOWNGRADE")
	if !strings.Contains(h, "newer version") {
		t.Errorf("downgrade: got %q", h)
	}
}

func TestInstallFailureHint_NoMatchingABIs(t *testing.T) {
	h := installFailureHint("INSTALL_FAILED_NO_MATCHING_ABIS")
	if !strings.Contains(h, "ABI") {
		t.Errorf("no_matching_abis: got %q", h)
	}
}

func TestInstallFailureHint_InsufficientStorage(t *testing.T) {
	h := installFailureHint("INSTALL_FAILED_INSUFFICIENT_STORAGE")
	if !strings.Contains(h, "storage") {
		t.Errorf("insufficient_storage: got %q", h)
	}
}

func TestInstallFailureHint_InvalidAPK(t *testing.T) {
	h := installFailureHint("Failed to parse APK")
	if !strings.Contains(h, "valid") {
		t.Errorf("invalid_apk: got %q", h)
	}
}

func TestInstallFailureHint_Unknown(t *testing.T) {
	h := installFailureHint("some unknown error")
	if h != "" {
		t.Errorf("unknown error should return empty, got %q", h)
	}
}

func TestInstallFailureHint_Offline2(t *testing.T) {
	h := installFailureHint("offline device detected")
	if !strings.Contains(h, "OFFLINE") {
		t.Errorf("offline2: got %q", h)
	}
}

func TestInstallFailureHint_UpdateIncompatible(t *testing.T) {
	h := installFailureHint("INSTALL_FAILED_UPDATE_INCOMPATIBLE")
	if !strings.Contains(h, "newer version") {
		t.Errorf("update_incompatible: got %q", h)
	}
}
