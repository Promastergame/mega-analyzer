package pipeline

// ClassifyAndroidPermission returns a stable risk label for an Android permission.
func ClassifyAndroidPermission(permission string) (risk string, suspicious bool) {
	if _, ok := highRiskPermissions[permission]; ok {
		return "high-risk", true
	}
	if _, ok := dangerousPermissions[permission]; ok {
		return "dangerous", true
	}
	return "normal", false
}
