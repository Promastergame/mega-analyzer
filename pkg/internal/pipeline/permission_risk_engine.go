package pipeline

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PERMISSION RISK SCORING ENGINE
// Комбо-детекция и оценка риска вместо просто обнаружения разрешений
// ═══════════════════════════════════════════════════════════════════════════════

// PermissionRiskRule определяет риск для комбинации разрешений
type PermissionRiskRule struct {
	ID          string
	Name        string
	Permissions []string // требуемые разрешения (в UPPERCASE)
	BaseScore   int      // 1-100
	Severity    string   // critical, high, medium, low
	Description string
	Combos      []string // Что это может сделать
}

// PermissionRiskEngine оценивает риск по разрешениям
type PermissionRiskEngine struct {
	rules            []PermissionRiskRule
	foundPermissions map[string]bool
	mu               sync.RWMutex
	totalScore       int
}

func NewPermissionRiskEngine() *PermissionRiskEngine {
	return &PermissionRiskEngine{
		rules:            GetDefaultPermissionRules(),
		foundPermissions: make(map[string]bool),
	}
}

func (e *PermissionRiskEngine) Name() string {
	return "permission_risk_scorer"
}

func (e *PermissionRiskEngine) SupportsFile(fileType types.FileType, path string) bool {
	return fileType == types.FileTypeXML && strings.HasSuffix(strings.ToLower(path), "androidmanifest.xml")
}

// Detect проходит по манифесту и ищет permission tags
func (e *PermissionRiskEngine) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx.FileType != types.FileTypeXML {
		return
	}

	// Permission risk checks only apply to the AndroidManifest.xml file
	pathLower := strings.ToLower(analysis.Path)
	if !strings.HasSuffix(pathLower, "androidmanifest.xml") {
		return
	}

	content := ctx.ContentLower

	// Ищем все android:name="android.permission.*" в манифесте
	permPrefix := []byte("android.permission.")
	searchStart := 0

	for {
		idx := bytes.Index(content[searchStart:], permPrefix)
		if idx < 0 {
			break
		}

		// Абсолютная позиция в content
		absoluteIdx := searchStart + idx + len(permPrefix)

		// Извлекаем название разрешения (до кавычки, >, пробела или конца)
		endIdx := absoluteIdx
		for endIdx < len(content) && content[endIdx] != '"' && content[endIdx] != '>' && content[endIdx] != ' ' && content[endIdx] != '\n' {
			endIdx++
		}

		if endIdx > absoluteIdx {
			// ← ИСПРАВЛЕНИЕ: конвертируем в UPPERCASE для сравнения с правилами
			perm := strings.ToUpper(string(content[absoluteIdx:endIdx]))
			e.mu.Lock()
			e.foundPermissions[perm] = true
			e.mu.Unlock()
		}

		// Сдвигаем позицию поиска
		searchStart = endIdx
		if searchStart >= len(content) {
			break
		}
	}

	// Оцениваем риск
	e.scorePermissions(analysis)
}

// scorePermissions оценивает риск найденных разрешений
func (e *PermissionRiskEngine) scorePermissions(analysis *types.FileAnalysis) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	checkedRules := make(map[string]bool)

	for _, rule := range e.rules {
		if checkedRules[rule.ID] {
			continue
		}
		checkedRules[rule.ID] = true

		// Проверяем, есть ли все разрешения этого правила
		allPermsPresent := true
		for _, perm := range rule.Permissions {
			if !e.foundPermissions[perm] {
				allPermsPresent = false
				break
			}
		}

		if allPermsPresent {
			e.totalScore += rule.BaseScore

			// Добавляем матч
			severity := determineSeverity(rule.Severity)
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategorySecurity,
				analysis.Path,
				0,
				fmt.Sprintf("High-Risk Permission Combo: %s", rule.Name),
				fmt.Sprintf("%s | Score: %d | %v", rule.Description, rule.BaseScore, rule.Combos),
				severity == types.SeverityCritical || severity == types.SeverityHigh,
			))
		}
	}
}

// GetTotalRiskScore возвращает суммарный риск-скор
func (e *PermissionRiskEngine) GetTotalRiskScore() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.totalScore
}

// GetFoundPermissions возвращает найденные разрешения
func (e *PermissionRiskEngine) GetFoundPermissions() map[string]bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make(map[string]bool)
	for k, v := range e.foundPermissions {
		result[k] = v
	}
	return result
}

// Reset очищает состояние для нового APK
func (e *PermissionRiskEngine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.foundPermissions = make(map[string]bool)
	e.totalScore = 0
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEFAULT PERMISSION RISK RULES
// ═══════════════════════════════════════════════════════════════════════════════

func GetDefaultPermissionRules() []PermissionRiskRule {
	return []PermissionRiskRule{
		// 🔴 CRITICAL COMBOS
		{
			ID:        "sms_boot_internet",
			Name:      "SMS Stealer Pattern",
			BaseScore: 90,
			Severity:  "critical",
			Permissions: []string{
				"READ_SMS",
				"RECEIVE_BOOT_COMPLETED",
				"INTERNET",
			},
			Description: "Can steal SMS, start on boot, send to attacker",
			Combos:      []string{"2FA interception", "OTP hijacking", "Payment hijacking"},
		},
		{
			ID:        "accessibility_overlay_combo",
			Name:      "Bank Overlay Attack",
			BaseScore: 95,
			Severity:  "critical",
			Permissions: []string{
				"BIND_ACCESSIBILITY_SERVICE",
				"SYSTEM_ALERT_WINDOW",
				"INTERNET",
			},
			Description: "Can overlay fake screens and intercept input",
			Combos:      []string{"Overlay attack", "Credential stealing", "Bank trojan"},
		},
		{
			ID:        "device_admin_boot_internet",
			Name:      "Device Admin Malware",
			BaseScore: 85,
			Severity:  "critical",
			Permissions: []string{
				"DEVICE_ADMIN",
				"RECEIVE_BOOT_COMPLETED",
				"INTERNET",
			},
			Description: "Can become admin, persist on boot, and communicate with C&C",
			Combos:      []string{"Persistent malware", "Remote wipe", "Data exfiltration"},
		},

		// 🟠 HIGH SEVERITY
		{
			ID:        "sms_camera_location",
			Name:      "Spyware Indicators",
			BaseScore: 75,
			Severity:  "high",
			Permissions: []string{
				"READ_SMS",
				"CAMERA",
				"ACCESS_FINE_LOCATION",
			},
			Description: "Can spy on messages, camera, and location",
			Combos:      []string{"Surveillance", "Stalkerware", "Information gather"},
		},
		{
			ID:        "call_interception",
			Name:      "Call Interception Pattern",
			BaseScore: 70,
			Severity:  "high",
			Permissions: []string{
				"READ_CALL_LOG",
				"PROCESS_OUTGOING_CALLS",
				"INTERNET",
			},
			Description: "Can monitor, log, and redirect calls",
			Combos:      []string{"Call recording", "Call hijacking", "Number spoofing"},
		},
		{
			ID:        "accessibility_internet",
			Name:      "Accessibility Service with Internet",
			BaseScore: 65,
			Severity:  "high",
			Permissions: []string{
				"BIND_ACCESSIBILITY_SERVICE",
				"INTERNET",
			},
			Description: "Can steal data and communicate externally",
			Combos:      []string{"Click simulation", "Form auto-fill", "Data exfiltration"},
		},

		// 🟡 MEDIUM SEVERITY
		{
			ID:        "location_tracking",
			Name:      "Location Tracking",
			BaseScore: 40,
			Severity:  "medium",
			Permissions: []string{
				"ACCESS_FINE_LOCATION",
				"ACCESS_BACKGROUND_LOCATION",
				"INTERNET",
			},
			Description: "Can track location in background and send to server",
			Combos:      []string{"Stalking", "Harassment", "Location harvesting"},
		},
		{
			ID:        "contact_exfiltration",
			Name:      "Contact Data Theft",
			BaseScore: 50,
			Severity:  "high",
			Permissions: []string{
				"READ_CONTACTS",
				"INTERNET",
				"RECEIVE_BOOT_COMPLETED",
			},
			Description: "Can steal contacts and sync with attacker server",
			Combos:      []string{"Contact harvesting", "Spam targeting", "Social engineering"},
		},
	}
}

// determineSeverity конвертирует строку severity в константу types.Severity
func determineSeverity(s string) types.Severity {
	switch s {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}
