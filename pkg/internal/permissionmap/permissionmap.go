// Package permissionmap maps Android manifest-declared permissions to
// actual API usage in decompiled code (.smali, .java, .kt), flags
// unused (over-privileged) and undeclared-but-used permissions, and
// scores the result.
package permissionmap

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// UsageStatus is the tri-state usage classification of a declared
// permission. A permission we have no detection patterns for is
// "unknown", NOT "unused" — unknown never contributes to the score.
type UsageStatus string

const (
	StatusUsed    UsageStatus = "used"
	StatusUnused  UsageStatus = "unused"
	StatusUnknown UsageStatus = "unknown"
)

// Protection levels (subset of Android protection levels we track).
const (
	ProtNormal    = "normal"
	ProtDangerous = "dangerous"
	ProtSignature = "signature"
)

const (
	// maxScanFileSize skips pathological blobs (repacked resources,
	// embedded archives renamed to .smali, etc.).
	maxScanFileSize = 8 << 20 // 8 MiB
	// maxSitesPerPermission caps evidence collection per permission.
	maxSitesPerPermission = 5
)

// UsageSite is one structured piece of evidence.
type UsageSite struct {
	File    string `json:"file"`
	Pattern string `json:"pattern"`
}

// PermissionUsage maps a manifest-declared permission to its actual usage in code.
type PermissionUsage struct {
	Permission string      `json:"permission"`
	Used       bool        `json:"used"`
	Status     UsageStatus `json:"status"`
	UsageSites []string    `json:"usage_sites,omitempty"` // legacy "<file> matches <pattern>" strings
	Sites      []UsageSite `json:"sites,omitempty"`
	APILevel   string      `json:"api_level,omitempty"` // e.g. "deprecated since API 30"
	Protection string      `json:"protection,omitempty"`
}

// MissingPermission is an API usage detected in code without the
// corresponding permission declared in the manifest: either dead code,
// a crash waiting to happen, or hidden functionality.
type MissingPermission struct {
	Permission string      `json:"permission"`
	Protection string      `json:"protection,omitempty"`
	Sites      []UsageSite `json:"sites,omitempty"`
}

// Report holds the permission-to-code mapping result.
type Report struct {
	GeneratedAt      string   `json:"generated_at"`
	Target           string   `json:"target"`
	DeclaredCount    int      `json:"declared_count"`
	UsedCount        int      `json:"used_count"`
	UnusedCount      int      `json:"unused_count"`
	UnknownCount     int      `json:"unknown_count"`
	DeprecatedCount  int      `json:"deprecated_count,omitempty"`
	CodeFilesScanned int      `json:"code_files_scanned"`
	CodeFilesSkipped int      `json:"code_files_skipped"`
	UnsupportedCode  int      `json:"unsupported_code"`
	Limitations      []string `json:"limitations,omitempty"`

	Permissions        []PermissionUsage   `json:"permissions"`
	MissingPermissions []MissingPermission `json:"missing_permissions,omitempty"`

	Score   int    `json:"score"`
	Verdict string `json:"verdict"`
}

// permInfo is the knowledge-base entry for one permission.
type permInfo struct {
	protection    string
	deprecatedAPI int      // 0 = not deprecated
	patterns      []string // plain substrings; matched with strings.Contains
	// reverse enables the undeclared-but-used check. Only set for
	// permissions whose patterns are specific enough to avoid false
	// positives (e.g. sendTextMessage, not ContactsContract).
	reverse bool
}

// knowledge maps permission → detection patterns + metadata.
// Patterns cover both smali (Landroid/...;) and java/kotlin source forms.
var knowledge = map[string]permInfo{
	"android.permission.CAMERA": {
		protection: ProtDangerous, reverse: true,
		patterns: []string{`Landroid/hardware/Camera;`, `android.hardware.Camera`, `Landroid/hardware/camera2/`, `android.hardware.camera2`, `android.media.action.IMAGE_CAPTURE`},
	},
	"android.permission.RECORD_AUDIO": {
		protection: ProtDangerous, reverse: true,
		patterns: []string{`Landroid/media/MediaRecorder;`, `android.media.MediaRecorder`, `Landroid/media/AudioRecord;`, `android.media.AudioRecord`},
	},
	"android.permission.ACCESS_FINE_LOCATION": {
		protection: ProtDangerous,
		patterns:   []string{`Landroid/location/LocationManager;`, `android.location.LocationManager`, `getLastKnownLocation`, `requestLocationUpdates`, `FusedLocationProviderClient`},
	},
	"android.permission.ACCESS_COARSE_LOCATION": {
		protection: ProtDangerous,
		patterns:   []string{`Landroid/location/LocationManager;`, `android.location.LocationManager`, `getLastKnownLocation`, `requestLocationUpdates`, `FusedLocationProviderClient`},
	},
	// Background location has no distinct API surface; usage is only
	// distinguishable at runtime. No patterns → declared = unknown.
	"android.permission.ACCESS_BACKGROUND_LOCATION": {protection: ProtDangerous},
	"android.permission.READ_CONTACTS": {
		protection: ProtDangerous,
		patterns:   []string{`Landroid/provider/ContactsContract`, `android.provider.ContactsContract`, `content://contacts`},
	},
	"android.permission.WRITE_CONTACTS": {
		protection: ProtDangerous,
		patterns:   []string{`Landroid/provider/ContactsContract`, `android.provider.ContactsContract`},
	},
	"android.permission.READ_SMS": {
		protection: ProtDangerous, reverse: true,
		patterns: []string{`content://sms`, `Landroid/provider/Telephony$Sms`, `android.provider.Telephony.Sms`},
	},
	"android.permission.SEND_SMS": {
		protection: ProtDangerous, reverse: true,
		patterns: []string{`sendTextMessage`, `sendMultipartTextMessage`, `sendDataMessage`},
	},
	"android.permission.RECEIVE_SMS": {
		protection: ProtDangerous, reverse: true,
		patterns: []string{`android.provider.Telephony.SMS_RECEIVED`, `SMS_RECEIVED`},
	},
	"android.permission.READ_PHONE_STATE": {
		protection: ProtDangerous, reverse: true,
		patterns: []string{`getDeviceId`, `getSubscriberId`, `getImei`, `getSimSerialNumber`, `getLine1Number`},
	},
	"android.permission.READ_CALL_LOG": {
		protection: ProtDangerous, reverse: true,
		patterns: []string{`content://call_log`, `Landroid/provider/CallLog`, `android.provider.CallLog`},
	},
	"android.permission.WRITE_CALL_LOG": {
		protection: ProtDangerous,
		patterns:   []string{`Landroid/provider/CallLog`, `android.provider.CallLog`},
	},
	"android.permission.CALL_PHONE": {
		protection: ProtDangerous,
		patterns:   []string{`android.intent.action.CALL`},
	},
	"android.permission.GET_ACCOUNTS": {
		protection: ProtDangerous,
		patterns:   []string{`Landroid/accounts/AccountManager;`, `android.accounts.AccountManager`},
	},
	"android.permission.READ_CALENDAR": {
		protection: ProtDangerous,
		patterns:   []string{`Landroid/provider/CalendarContract`, `android.provider.CalendarContract`, `content://com.android.calendar`},
	},
	"android.permission.WRITE_CALENDAR": {
		protection: ProtDangerous,
		patterns:   []string{`Landroid/provider/CalendarContract`, `android.provider.CalendarContract`},
	},
	"android.permission.POST_NOTIFICATIONS": {
		protection: ProtDangerous,
		patterns:   []string{`Landroid/app/NotificationManager;`, `android.app.NotificationManager`, `NotificationCompat`},
	},
	"android.permission.READ_MEDIA_IMAGES": {
		protection: ProtDangerous,
		patterns:   []string{`MediaStore$Images`, `MediaStore.Images`},
	},
	"android.permission.READ_MEDIA_VIDEO": {
		protection: ProtDangerous,
		patterns:   []string{`MediaStore$Video`, `MediaStore.Video`},
	},
	"android.permission.READ_MEDIA_AUDIO": {
		protection: ProtDangerous,
		patterns:   []string{`MediaStore$Audio`, `MediaStore.Audio`},
	},
	"android.permission.BLUETOOTH_CONNECT": {
		protection: ProtDangerous,
		patterns:   []string{`Landroid/bluetooth/BluetoothAdapter;`, `android.bluetooth.BluetoothAdapter`, `Landroid/bluetooth/BluetoothSocket;`, `android.bluetooth.BluetoothSocket`},
	},
	"android.permission.BLUETOOTH_SCAN": {
		protection: ProtDangerous,
		patterns:   []string{`BluetoothLeScanner`, `startDiscovery`, `startLeScan`},
	},
	"android.permission.WRITE_EXTERNAL_STORAGE": {
		protection: ProtDangerous, deprecatedAPI: 30,
		patterns: []string{`getExternalStorageDirectory`, `getExternalFilesDir`, `Environment.getExternalStorage`},
	},
	"android.permission.READ_EXTERNAL_STORAGE": {
		protection: ProtDangerous, deprecatedAPI: 33,
		patterns: []string{`getExternalStorageDirectory`, `getExternalFilesDir`, `Landroid/provider/MediaStore`, `android.provider.MediaStore`},
	},

	"android.permission.INTERNET": {
		protection: ProtNormal,
		patterns:   []string{`Ljava/net/URL;`, `java.net.URL`, `Ljava/net/HttpURLConnection;`, `java.net.HttpURLConnection`, `Lokhttp3/`, `okhttp3.`, `Lretrofit2/`, `retrofit2.`, `Ljava/net/Socket;`, `java.net.Socket`},
	},
	"android.permission.ACCESS_NETWORK_STATE": {
		protection: ProtNormal,
		patterns:   []string{`Landroid/net/ConnectivityManager;`, `android.net.ConnectivityManager`, `getActiveNetworkInfo`, `getNetworkCapabilities`},
	},
	"android.permission.ACCESS_WIFI_STATE": {
		protection: ProtNormal,
		patterns:   []string{`Landroid/net/wifi/WifiManager;`, `android.net.wifi.WifiManager`},
	},
	"android.permission.NFC": {
		protection: ProtNormal,
		patterns:   []string{`Landroid/nfc/NfcAdapter;`, `android.nfc.NfcAdapter`, `Landroid/nfc/`},
	},
	"android.permission.BLUETOOTH": {
		protection: ProtNormal, deprecatedAPI: 31,
		patterns: []string{`Landroid/bluetooth/BluetoothAdapter;`, `android.bluetooth.BluetoothAdapter`, `Landroid/bluetooth/BluetoothSocket;`},
	},
	"android.permission.BLUETOOTH_ADMIN": {
		protection: ProtNormal, deprecatedAPI: 31,
		patterns: []string{`startDiscovery`, `enable()`, `disable()`},
	},
	"android.permission.VIBRATE": {
		protection: ProtNormal,
		patterns:   []string{`Landroid/os/Vibrator;`, `android.os.Vibrator`, `VibratorManager`},
	},
	"android.permission.WAKE_LOCK": {
		protection: ProtNormal,
		patterns:   []string{`newWakeLock`, `PowerManager$WakeLock`, `PowerManager.WakeLock`},
	},
	"android.permission.FOREGROUND_SERVICE": {
		protection: ProtNormal,
		patterns:   []string{`startForeground`},
	},
	"android.permission.RECEIVE_BOOT_COMPLETED": {
		protection: ProtNormal,
		patterns:   []string{`android.intent.action.BOOT_COMPLETED`, `BOOT_COMPLETED`},
	},
	"android.permission.QUERY_ALL_PACKAGES": {
		protection: ProtNormal,
		patterns:   []string{`getInstalledPackages`, `getInstalledApplications`, `queryIntentActivities`},
	},
	"android.permission.USE_BIOMETRIC": {
		protection: ProtNormal,
		patterns:   []string{`BiometricPrompt`},
	},
	"android.permission.USE_FINGERPRINT": {
		protection: ProtNormal, deprecatedAPI: 28,
		patterns: []string{`FingerprintManager`},
	},

	"android.permission.SYSTEM_ALERT_WINDOW": {
		protection: ProtSignature, reverse: true,
		patterns: []string{`TYPE_APPLICATION_OVERLAY`, `TYPE_SYSTEM_ALERT`, `canDrawOverlays`, `ACTION_MANAGE_OVERLAY_PERMISSION`},
	},
	"android.permission.REQUEST_INSTALL_PACKAGES": {
		protection: ProtSignature, reverse: true,
		patterns: []string{`android.intent.action.INSTALL_PACKAGE`, `PackageInstaller`, `ACTION_VIEW_INSTALL`},
	},
}

// scannedExtensions lists code file types we inspect.
var scannedExtensions = []string{".smali", ".java", ".kt"}

func isScannable(path string) bool {
	for _, ext := range scannedExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// Analyze walks the target directory, reads declared permissions from a list,
// and checks whether each permission is actually referenced in code.
//
// Declared permissions with no knowledge-base patterns are reported as
// StatusUnknown and never penalized. Dangerous APIs detected in code
// without a matching declared permission are reported in
// Report.MissingPermissions.
func Analyze(targetDir string, declared []string) (*Report, error) {
	rep := &Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Target:      targetDir,
	}

	// Dedupe declared permissions, preserving order.
	seenDecl := make(map[string]bool, len(declared))
	permIdx := make(map[string]int, len(declared))
	for _, p := range declared {
		p = strings.TrimSpace(p)
		if p == "" || seenDecl[p] {
			continue
		}
		seenDecl[p] = true
		pu := PermissionUsage{Permission: p, Status: StatusUnknown}
		if info, ok := knowledge[p]; ok {
			pu.Protection = info.protection
			if info.deprecatedAPI > 0 {
				pu.APILevel = fmt.Sprintf("deprecated since API %d", info.deprecatedAPI)
			}
			if len(info.patterns) > 0 {
				pu.Status = StatusUnused
			}
		}
		rep.Permissions = append(rep.Permissions, pu)
		permIdx[p] = len(rep.Permissions) - 1
	}
	rep.DeclaredCount = len(rep.Permissions)

	reverseHits := map[string][]UsageSite{}

	err := filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d == nil {
			rep.CodeFilesSkipped++
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !isScannable(path) {
			switch strings.ToLower(filepath.Ext(path)) {
			case ".dex", ".class", ".jar", ".so":
				rep.UnsupportedCode++
			}
			return nil
		}
		if info, ierr := d.Info(); ierr != nil || info.Size() > maxScanFileSize {
			rep.CodeFilesSkipped++
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			rep.CodeFilesSkipped++
			return nil
		}
		rep.CodeFilesScanned++
		text := string(data)
		rel, rerr2 := filepath.Rel(targetDir, path)
		if rerr2 != nil {
			rel = path
		}

		for perm, info := range knowledge {
			idx, isDeclared := permIdx[perm]
			if !isDeclared && !info.reverse {
				continue // reverse check only for low-FP patterns
			}
			for _, pat := range info.patterns {
				if !strings.Contains(text, pat) {
					continue
				}
				site := UsageSite{File: rel, Pattern: pat}
				if isDeclared {
					pu := &rep.Permissions[idx]
					pu.Used = true
					pu.Status = StatusUsed
					if len(pu.Sites) < maxSitesPerPermission {
						pu.Sites = append(pu.Sites, site)
						pu.UsageSites = append(pu.UsageSites, rel+" matches "+pat)
					}
				} else if len(reverseHits[perm]) < maxSitesPerPermission {
					reverseHits[perm] = append(reverseHits[perm], site)
				}
				break // one hit per permission per file is enough
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if rep.CodeFilesScanned == 0 || rep.CodeFilesSkipped > 0 || rep.UnsupportedCode > 0 {
		rep.Limitations = append(rep.Limitations, "Code mapping is incomplete; absence of an API match does not establish that a permission is unused.")
		for i := range rep.Permissions {
			if rep.Permissions[i].Status == StatusUnused {
				rep.Permissions[i].Status = StatusUnknown
			}
		}
	}

	// Counts and scoring.
	score := 0
	for i := range rep.Permissions {
		p := &rep.Permissions[i]
		switch p.Status {
		case StatusUsed:
			rep.UsedCount++
		case StatusUnused:
			rep.UnusedCount++
			if p.Protection == ProtDangerous {
				score += 15 // over-privilege with a dangerous permission
			} else {
				score += 5
			}
		case StatusUnknown:
			rep.UnknownCount++
		}
		if p.APILevel != "" {
			rep.DeprecatedCount++
			score += 3 // dead/legacy permission still declared
		}
	}

	missingPerms := make([]string, 0, len(reverseHits))
	for perm := range reverseHits {
		missingPerms = append(missingPerms, perm)
	}
	sort.Strings(missingPerms)
	for _, perm := range missingPerms {
		rep.MissingPermissions = append(rep.MissingPermissions, MissingPermission{
			Permission: perm,
			Protection: knowledge[perm].protection,
			Sites:      reverseHits[perm],
		})
		score += 8
	}

	if score > 100 {
		score = 100
	}
	rep.Score = score
	switch {
	case score == 0:
		rep.Verdict = "ok"
	case score <= 15:
		rep.Verdict = "low"
	case score <= 40:
		rep.Verdict = "medium"
	default:
		rep.Verdict = "high"
	}
	if score == 0 && rep.DeclaredCount > 0 && rep.CodeFilesScanned == 0 {
		rep.Verdict = "unknown"
	}
	return rep, nil
}
