package ncer

// actionPermissionMap maps an ObservedAction.Action string to the Android
// permission that action requires. It is intentionally broad: the dynamic
// sandbox emits a small set today (network_connect / dns_query / tls_connect —
// see pkg/cmd/analyzer/ncer_authority.go), but the authority binder's signal
// is only as good as this table's coverage, so every action the sandbox and
// androidruntime layers can plausibly surface is mapped here rather than left
// to silently fall through as "unclassifiable."
//
// An unmapped action is excluded from authority binding entirely (see
// rust/crates/omnisec-ncer-reconcile/src/authority_binder.rs's module doc):
// it counts as neither authorized nor unauthorized, because a missing mapping
// is not evidence of anything either way. That exclusion is a blind spot, so
// AuthorityMappingCoverage lets callers measure how much of a session's
// observed actions actually landed in this table.
//
// Sources for the action→permission correspondence are the Android platform
// permission reference and the public PScout/axplorer API-to-permission
// datasets; the mapping is kept coarse (one representative permission per
// action) because the binder only needs "was *a* required permission granted,"
// not the full permission set an API might touch.
var actionPermissionMap = map[string]string{
	// Network / internet.
	"network_connect": "android.permission.INTERNET",
	"dns_query":       "android.permission.INTERNET",
	"tls_connect":     "android.permission.INTERNET",
	"http_request":    "android.permission.INTERNET",
	"socket_open":     "android.permission.INTERNET",
	"network_state":   "android.permission.ACCESS_NETWORK_STATE",
	"wifi_state":      "android.permission.ACCESS_WIFI_STATE",

	// Location.
	"location_fine":   "android.permission.ACCESS_FINE_LOCATION",
	"location_coarse": "android.permission.ACCESS_COARSE_LOCATION",
	"location_access": "android.permission.ACCESS_FINE_LOCATION",

	// Telephony / SMS.
	"sms_send":         "android.permission.SEND_SMS",
	"sms_read":         "android.permission.READ_SMS",
	"sms_receive":      "android.permission.RECEIVE_SMS",
	"call_phone":       "android.permission.CALL_PHONE",
	"read_phone_state": "android.permission.READ_PHONE_STATE",
	"read_call_log":    "android.permission.READ_CALL_LOG",

	// Personal data.
	"contacts_read":  "android.permission.READ_CONTACTS",
	"contacts_write": "android.permission.WRITE_CONTACTS",
	"calendar_read":  "android.permission.READ_CALENDAR",

	// Sensors / capture.
	"camera_access": "android.permission.CAMERA",
	"record_audio":  "android.permission.RECORD_AUDIO",
	"microphone":    "android.permission.RECORD_AUDIO",

	// Storage / filesystem.
	"external_storage_read":  "android.permission.READ_EXTERNAL_STORAGE",
	"external_storage_write": "android.permission.WRITE_EXTERNAL_STORAGE",

	// Device / account.
	"get_accounts":     "android.permission.GET_ACCOUNTS",
	"bluetooth":        "android.permission.BLUETOOTH",
	"bluetooth_scan":   "android.permission.BLUETOOTH_SCAN",
	"nfc":              "android.permission.NFC",
	"install_packages": "android.permission.REQUEST_INSTALL_PACKAGES",
}

// ActionToPermission returns the Android permission required to perform
// action, and whether a mapping exists at all.
func ActionToPermission(action string) (string, bool) {
	perm, ok := actionPermissionMap[action]
	return perm, ok
}

// AuthorityMappingCoverage reports how well a set of observed actions is
// covered by actionPermissionMap: the number of actions with a mapping, the
// total number of actions considered, and the fraction mapped in [0, 1]. An
// empty input reports (0, 0, 1.0) — vacuously fully covered, since there is no
// blind spot when nothing was observed.
//
// This exists because an unmapped action is silently dropped from authority
// binding (see actionPermissionMap's doc), so a d_authority computed over a
// session where half the actions were unmapped is far less trustworthy than
// one where all were mapped. Surfacing the coverage lets a caller flag that
// low-confidence case instead of treating every d_authority as equally solid.
func AuthorityMappingCoverage(actions []string) (mapped, total int, fraction float64) {
	total = len(actions)
	if total == 0 {
		return 0, 0, 1.0
	}
	for _, a := range actions {
		if _, ok := actionPermissionMap[a]; ok {
			mapped++
		}
	}
	return mapped, total, float64(mapped) / float64(total)
}
