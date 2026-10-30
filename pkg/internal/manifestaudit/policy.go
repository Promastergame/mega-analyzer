package manifestaudit

import (
	"strings"

	"mega-analyzer/pkg/internal/apkloader/axml"
)

// EffectiveBool records both the runtime value and why that value applies.
// Known=false means another policy file (for example NSC) must be evaluated
// before a vulnerability decision can be made.
type EffectiveBool struct {
	Value        bool   `json:"value"`
	Known        bool   `json:"known"`
	Declared     bool   `json:"declared"`
	Source       string `json:"source"`
	OverriddenBy string `json:"overridden_by,omitempty"`
}

type ApplicationPolicy struct {
	TargetSDK   uint32        `json:"effective_target_sdk"`
	DeviceAPI   uint32        `json:"device_api"`
	AllowBackup EffectiveBool `json:"allow_backup"`
	Cleartext   EffectiveBool `json:"cleartext_traffic"`
	BackupRules string        `json:"backup_rules,omitempty"`
}

func EffectiveTargetSDK(m *axml.Manifest) uint32 {
	if m == nil {
		return 1
	}
	if m.TargetSDK != 0 {
		return m.TargetSDK
	}
	if m.MinSDK != 0 {
		return m.MinSDK
	}
	// Android treats an omitted <uses-sdk> as API 1 compatibility.
	return 1
}

func EffectiveApplicationPolicy(m *axml.Manifest, deviceAPI uint32) ApplicationPolicy {
	if m == nil {
		return ApplicationPolicy{}
	}
	target := EffectiveTargetSDK(m)
	if deviceAPI == 0 {
		deviceAPI = target
	}
	app := m.Application

	allowBackup := EffectiveBool{Value: true, Known: true, Source: "platform_default"}
	if app.AllowBackupDeclared != nil {
		allowBackup.Value = *app.AllowBackupDeclared
		allowBackup.Declared = true
		allowBackup.Source = "manifest"
	} else if app.AllowBackup {
		// Compatibility for callers constructing ApplicationInfo directly.
		allowBackup.Value = true
		allowBackup.Declared = true
		allowBackup.Source = "legacy_model"
	}

	cleartext := EffectiveBool{
		Value:  target < 28,
		Known:  true,
		Source: "platform_default",
	}
	if app.CleartextDeclared != nil {
		cleartext.Value = *app.CleartextDeclared
		cleartext.Declared = true
		cleartext.Source = "manifest"
	} else if app.UsesCleartext {
		cleartext.Value = true
		cleartext.Declared = true
		cleartext.Source = "legacy_model"
	}
	if strings.TrimSpace(app.NetworkSecCfg) != "" && deviceAPI >= 24 {
		cleartext.Known = false
		cleartext.OverriddenBy = "network_security_config"
		cleartext.Source = "network_security_config"
	}

	backupRules := strings.TrimSpace(app.DataExtractionRules)
	if backupRules == "" {
		backupRules = strings.TrimSpace(app.FullBackupContent)
	}
	return ApplicationPolicy{
		TargetSDK:   target,
		DeviceAPI:   deviceAPI,
		AllowBackup: allowBackup,
		Cleartext:   cleartext,
		BackupRules: backupRules,
	}
}
