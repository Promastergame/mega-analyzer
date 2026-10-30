package ml

import (
	"regexp"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// APP TYPES — типы приложений для контекстного анализа
// ═══════════════════════════════════════════════════════════════════════════════

// AppType — тип приложения, влияющий на интерпретацию сигналов
type AppType string

const (
	// Финансовые — максимальная критичность угроз
	AppTypeBanking AppType = "banking" // банки, платежи, кошельки
	AppTypePayment AppType = "payment" // платёжные системы (отдельно от банков)
	AppTypeCrypto  AppType = "crypto"  // криптокошельки, биржи

	// Контентные — специфичные паттерны
	AppTypePiracy   AppType = "piracy"   // пиратские загрузчики, торренты
	AppTypeDonation AppType = "donation" // apps с донатами (twitch, patreon)
	AppTypeSocial   AppType = "social"   // соцсети, мессенджеры
	AppTypeGaming   AppType = "gaming"   // игры

	// Системные — легитимное использование опасных API
	AppTypeAccessibility AppType = "accessibility" // screen readers, a11y tools
	AppTypeSecurity      AppType = "security"      // антивирусы, VPN, firewalls
	AppTypeSystem        AppType = "system"        // системные утилиты
	AppTypeLauncher      AppType = "launcher"      // лаунчеры, кастомизация

	// Угрозы
	AppTypeMalware AppType = "malware" // определённый malware
	AppTypeGeneric AppType = "generic" // неопределённый тип
)

// AppTypeInfo — метаданные типа приложения
type AppTypeInfo struct {
	Type        AppType
	DisplayName string
	Description string
	RiskBias    int // базовое смещение риска: -10..+10
	Icon        string
}

// appTypeRegistry — информация о типах
var appTypeRegistry = map[AppType]AppTypeInfo{
	AppTypeBanking: {
		Type:        AppTypeBanking,
		DisplayName: "Banking",
		Description: "Banking, finance, money transfer apps",
		RiskBias:    +5, // угрозы критичнее
		Icon:        "bank",
	},
	AppTypePayment: {
		Type:        AppTypePayment,
		DisplayName: "Payment",
		Description: "Payment systems, wallets",
		RiskBias:    +4,
		Icon:        "payment",
	},
	AppTypeCrypto: {
		Type:        AppTypeCrypto,
		DisplayName: "Crypto",
		Description: "Cryptocurrency wallets and exchanges",
		RiskBias:    +5,
		Icon:        "crypto",
	},
	AppTypePiracy: {
		Type:        AppTypePiracy,
		DisplayName: "Piracy",
		Description: "Torrent clients, piracy tools",
		RiskBias:    +2, // ожидаемые "плохие" сигналы
		Icon:        "piracy",
	},
	AppTypeDonation: {
		Type:        AppTypeDonation,
		DisplayName: "Donation",
		Description: "Apps with donation/tipping features",
		RiskBias:    0,
		Icon:        "donation",
	},
	AppTypeSocial: {
		Type:        AppTypeSocial,
		DisplayName: "Social",
		Description: "Social networks, messengers",
		RiskBias:    0,
		Icon:        "social",
	},
	AppTypeGaming: {
		Type:        AppTypeGaming,
		DisplayName: "Gaming",
		Description: "Games and entertainment",
		RiskBias:    -1,
		Icon:        "game",
	},
	AppTypeAccessibility: {
		Type:        AppTypeAccessibility,
		DisplayName: "Accessibility",
		Description: "Screen readers, accessibility tools",
		RiskBias:    -3, // a11y API легитимен
		Icon:        "accessibility",
	},
	AppTypeSecurity: {
		Type:        AppTypeSecurity,
		DisplayName: "Security",
		Description: "Antivirus, VPN, security tools",
		RiskBias:    -2, // device admin легитимен
		Icon:        "security",
	},
	AppTypeSystem: {
		Type:        AppTypeSystem,
		DisplayName: "System",
		Description: "System utilities, tools",
		RiskBias:    -1,
		Icon:        "system",
	},
	AppTypeLauncher: {
		Type:        AppTypeLauncher,
		DisplayName: "Launcher",
		Description: "Home launchers, customization",
		RiskBias:    -1,
		Icon:        "launcher",
	},
	AppTypeMalware: {
		Type:        AppTypeMalware,
		DisplayName: "Malware",
		Description: "Detected malicious application",
		RiskBias:    +10,
		Icon:        "malware",
	},
	AppTypeGeneric: {
		Type:        AppTypeGeneric,
		DisplayName: "Generic",
		Description: "Unknown application type",
		RiskBias:    0,
		Icon:        "mobile",
	},
}

// GetAppTypeInfo возвращает информацию о типе
func GetAppTypeInfo(t AppType) AppTypeInfo {
	if info, ok := appTypeRegistry[t]; ok {
		return info
	}
	return appTypeRegistry[AppTypeGeneric]
}

// AllAppTypes возвращает все типы приложений
func AllAppTypes() []AppType {
	return []AppType{
		AppTypeBanking, AppTypePayment, AppTypeCrypto,
		AppTypePiracy, AppTypeDonation, AppTypeSocial, AppTypeGaming,
		AppTypeAccessibility, AppTypeSecurity, AppTypeSystem, AppTypeLauncher,
		AppTypeMalware, AppTypeGeneric,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PERMISSION FLAGS — битовые флаги для быстрой проверки permissions
// ═══════════════════════════════════════════════════════════════════════════════

// PermissionFlags — битовые флаги опасных/важных permissions
type PermissionFlags uint64

const (
	// Overlay & UI
	PermOverlay  PermissionFlags = 1 << iota // SYSTEM_ALERT_WINDOW
	PermDrawOver                             // другие overlay permissions

	// Accessibility & Admin
	PermAccessibility        // BIND_ACCESSIBILITY_SERVICE
	PermDeviceAdmin          // BIND_DEVICE_ADMIN
	PermNotificationListener // BIND_NOTIFICATION_LISTENER_SERVICE

	// Communication
	PermSendSMS
	PermReceiveSMS
	PermReadSMS
	PermCallPhone
	PermReadCallLog
	PermReadContacts

	// Media & Sensors
	PermCamera
	PermMicrophone
	PermBodySensors

	// Location
	PermFineLocation
	PermCoarseLocation
	PermBackgroundLocation

	// Storage
	PermReadStorage
	PermWriteStorage
	PermManageStorage // MANAGE_EXTERNAL_STORAGE (Android 11+)

	// Network
	PermInternet
	PermAccessNetworkState
	PermChangeNetworkState

	// System
	PermBootCompleted     // RECEIVE_BOOT_COMPLETED
	PermInstallPackages   // REQUEST_INSTALL_PACKAGES
	PermDeletePackages    // REQUEST_DELETE_PACKAGES
	PermSystemAlertWindow // same as Overlay but explicit
	PermWriteSettings     // WRITE_SETTINGS
	PermUsageStats        // PACKAGE_USAGE_STATS

	// Bluetooth
	PermBluetooth
	PermBluetoothAdmin

	// Biometric
	PermBiometric
	PermFingerprint
)

// permissionMapping — маппинг Android permissions на флаги
var permissionMapping = map[string]PermissionFlags{
	// Overlay
	"android.permission.SYSTEM_ALERT_WINDOW": PermOverlay | PermSystemAlertWindow,

	// Accessibility & Admin
	"android.permission.BIND_ACCESSIBILITY_SERVICE":         PermAccessibility,
	"android.permission.BIND_DEVICE_ADMIN":                  PermDeviceAdmin,
	"android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": PermNotificationListener,

	// SMS
	"android.permission.SEND_SMS":    PermSendSMS,
	"android.permission.RECEIVE_SMS": PermReceiveSMS,
	"android.permission.READ_SMS":    PermReadSMS,

	// Phone
	"android.permission.CALL_PHONE":    PermCallPhone,
	"android.permission.READ_CALL_LOG": PermReadCallLog,
	"android.permission.READ_CONTACTS": PermReadContacts,

	// Media
	"android.permission.CAMERA":       PermCamera,
	"android.permission.RECORD_AUDIO": PermMicrophone,
	"android.permission.BODY_SENSORS": PermBodySensors,

	// Location
	"android.permission.ACCESS_FINE_LOCATION":       PermFineLocation,
	"android.permission.ACCESS_COARSE_LOCATION":     PermCoarseLocation,
	"android.permission.ACCESS_BACKGROUND_LOCATION": PermBackgroundLocation,

	// Storage
	"android.permission.READ_EXTERNAL_STORAGE":   PermReadStorage,
	"android.permission.WRITE_EXTERNAL_STORAGE":  PermWriteStorage,
	"android.permission.MANAGE_EXTERNAL_STORAGE": PermManageStorage,

	// Network
	"android.permission.INTERNET":             PermInternet,
	"android.permission.ACCESS_NETWORK_STATE": PermAccessNetworkState,
	"android.permission.CHANGE_NETWORK_STATE": PermChangeNetworkState,

	// System
	"android.permission.RECEIVE_BOOT_COMPLETED":   PermBootCompleted,
	"android.permission.REQUEST_INSTALL_PACKAGES": PermInstallPackages,
	"android.permission.REQUEST_DELETE_PACKAGES":  PermDeletePackages,
	"android.permission.WRITE_SETTINGS":           PermWriteSettings,
	"android.permission.PACKAGE_USAGE_STATS":      PermUsageStats,

	// Bluetooth
	"android.permission.BLUETOOTH":       PermBluetooth,
	"android.permission.BLUETOOTH_ADMIN": PermBluetoothAdmin,

	// Biometric
	"android.permission.USE_BIOMETRIC":   PermBiometric,
	"android.permission.USE_FINGERPRINT": PermFingerprint,
}

// ParsePermissions конвертирует список permissions в флаги
func ParsePermissions(permissions []string) PermissionFlags {
	var flags PermissionFlags
	for _, perm := range permissions {
		if flag, ok := permissionMapping[perm]; ok {
			flags |= flag
		}
	}
	return flags
}

// Has проверяет наличие флага
func (pf PermissionFlags) Has(flag PermissionFlags) bool {
	return pf&flag == flag
}

// HasAny проверяет наличие любого из флагов
func (pf PermissionFlags) HasAny(flags PermissionFlags) bool {
	return pf&flags != 0
}

// HasAll проверяет наличие всех флагов
func (pf PermissionFlags) HasAll(flags PermissionFlags) bool {
	return pf&flags == flags
}

// Count возвращает количество установленных флагов
func (pf PermissionFlags) Count() int {
	count := 0
	for pf != 0 {
		count += int(pf & 1)
		pf >>= 1
	}
	return count
}

// DangerousCount возвращает количество опасных permissions
func (pf PermissionFlags) DangerousCount() int {
	dangerous := PermOverlay | PermAccessibility | PermDeviceAdmin |
		PermNotificationListener | PermSendSMS | PermReceiveSMS |
		PermInstallPackages | PermUsageStats
	return (pf & dangerous).Count()
}

// String возвращает читаемое представление флагов
func (pf PermissionFlags) String() string {
	var parts []string
	flagNames := map[PermissionFlags]string{
		PermOverlay:              "OVERLAY",
		PermAccessibility:        "A11Y",
		PermDeviceAdmin:          "ADMIN",
		PermNotificationListener: "NOTIF",
		PermSendSMS:              "SMS_SEND",
		PermReceiveSMS:           "SMS_RECV",
		PermCamera:               "CAMERA",
		PermMicrophone:           "MIC",
		PermFineLocation:         "LOC",
		PermInstallPackages:      "INSTALL",
	}

	for flag, name := range flagNames {
		if pf.Has(flag) {
			parts = append(parts, name)
		}
	}

	if len(parts) == 0 {
		return "NONE"
	}
	return strings.Join(parts, "|")
}

// ═══════════════════════════════════════════════════════════════════════════════
// APP CONTEXT — полный контекст приложения
// ═══════════════════════════════════════════════════════════════════════════════

// AppContext — контекст приложения для контекстно-зависимого скоринга
type AppContext struct {
	// Идентификация
	PackageName string `json:"package_name"`
	AppName     string `json:"app_name,omitempty"`

	// Определённый тип
	DetectedType   AppType  `json:"detected_type"`
	TypeConfidence float64  `json:"type_confidence"`        // 0.0 - 1.0
	TypeSignals    []string `json:"type_signals,omitempty"` // что повлияло на детекцию

	// Permissions
	Permissions    []string        `json:"permissions,omitempty"`
	PermFlags      PermissionFlags `json:"perm_flags"`
	DangerousPerms int             `json:"dangerous_perms"`

	// Обнаруженные сигналы (для скоринга)
	DetectedSignals []string `json:"detected_signals,omitempty"`

	// Опасные комбинации
	DangerousCombos []DetectedCombo `json:"dangerous_combos,omitempty"`

	// SDK версии
	TargetSDK int `json:"target_sdk,omitempty"`
	MinSDK    int `json:"min_sdk,omitempty"`

	// Дополнительные флаги
	IsSystemApp    bool `json:"is_system_app,omitempty"`
	IsDebugBuild   bool `json:"is_debug_build,omitempty"`
	HasNativeCode  bool `json:"has_native_code,omitempty"`
	HasDynamicCode bool `json:"has_dynamic_code,omitempty"`

	// Manifest signals
	ExportsMainActivity bool `json:"exports_main,omitempty"`
	HasHiddenActivities bool `json:"has_hidden_activities,omitempty"`
	UsesObfuscation     bool `json:"uses_obfuscation,omitempty"`
}

// DetectedCombo — обнаруженная опасная комбинация
type DetectedCombo struct {
	Name       string   `json:"name"`
	Signals    []string `json:"signals"`
	ThreatType string   `json:"threat_type,omitempty"`
	Severity   string   `json:"severity"` // critical, high, medium, low
}

// NewAppContext создаёт контекст с базовой детекцией типа
func NewAppContext(packageName string, permissions []string) *AppContext {
	ctx := &AppContext{
		PackageName:     packageName,
		Permissions:     permissions,
		PermFlags:       ParsePermissions(permissions),
		DetectedSignals: make([]string, 0),
		DangerousCombos: make([]DetectedCombo, 0),
	}

	ctx.DangerousPerms = ctx.PermFlags.DangerousCount()

	// Определяем тип приложения
	ctx.DetectedType, ctx.TypeConfidence, ctx.TypeSignals = detectAppType(packageName, permissions, ctx.PermFlags)

	// Определяем базовые сигналы из permissions
	ctx.detectPermissionSignals()

	return ctx
}

// detectPermissionSignals добавляет сигналы на основе permissions
func (ctx *AppContext) detectPermissionSignals() {
	if ctx.PermFlags.Has(PermOverlay) {
		ctx.DetectedSignals = append(ctx.DetectedSignals, "overlay_permission")
	}
	if ctx.PermFlags.Has(PermAccessibility) {
		ctx.DetectedSignals = append(ctx.DetectedSignals, "accessibility_service")
	}
	if ctx.PermFlags.Has(PermDeviceAdmin) {
		ctx.DetectedSignals = append(ctx.DetectedSignals, "device_admin")
	}
	if ctx.PermFlags.Has(PermNotificationListener) {
		ctx.DetectedSignals = append(ctx.DetectedSignals, "notification_listener")
	}
	if ctx.PermFlags.HasAny(PermSendSMS | PermReceiveSMS | PermReadSMS) {
		ctx.DetectedSignals = append(ctx.DetectedSignals, "sms_permission")
	}
	if ctx.PermFlags.Has(PermInstallPackages) {
		ctx.DetectedSignals = append(ctx.DetectedSignals, "install_packages")
	}
	if ctx.PermFlags.Has(PermUsageStats) {
		ctx.DetectedSignals = append(ctx.DetectedSignals, "usage_stats")
	}
	if ctx.PermFlags.Has(PermBootCompleted) {
		ctx.DetectedSignals = append(ctx.DetectedSignals, "boot_receiver")
	}
	if ctx.PermFlags.HasAll(PermCamera | PermMicrophone) {
		ctx.DetectedSignals = append(ctx.DetectedSignals, "av_recording")
	}
	if ctx.PermFlags.Has(PermBackgroundLocation) {
		ctx.DetectedSignals = append(ctx.DetectedSignals, "background_location")
	}
}

// AddSignal добавляет обнаруженный сигнал
func (ctx *AppContext) AddSignal(signal string) {
	for _, s := range ctx.DetectedSignals {
		if s == signal {
			return // already exists
		}
	}
	ctx.DetectedSignals = append(ctx.DetectedSignals, signal)
}

// HasSignal проверяет наличие сигнала
func (ctx *AppContext) HasSignal(signal string) bool {
	for _, s := range ctx.DetectedSignals {
		if s == signal {
			return true
		}
	}
	return false
}

// AddCombo добавляет обнаруженную комбинацию
func (ctx *AppContext) AddCombo(combo DetectedCombo) {
	ctx.DangerousCombos = append(ctx.DangerousCombos, combo)
}

// IsDangerousComboPresent проверяет наличие опасных комбо
func (ctx *AppContext) IsDangerousComboPresent() bool {
	return len(ctx.DangerousCombos) > 0
}

// GetRiskBias возвращает смещение риска для типа приложения
func (ctx *AppContext) GetRiskBias() int {
	return GetAppTypeInfo(ctx.DetectedType).RiskBias
}

// IsFinancial проверяет, является ли приложение финансовым
func (ctx *AppContext) IsFinancial() bool {
	return ctx.DetectedType == AppTypeBanking ||
		ctx.DetectedType == AppTypePayment ||
		ctx.DetectedType == AppTypeCrypto
}

// IsLegitimateAccessibilityUser проверяет легитимность использования A11Y
func (ctx *AppContext) IsLegitimateAccessibilityUser() bool {
	return ctx.DetectedType == AppTypeAccessibility ||
		ctx.DetectedType == AppTypeSecurity ||
		ctx.DetectedType == AppTypeLauncher
}

// IsLegitimateAdminUser проверяет легитимность использования Device Admin
func (ctx *AppContext) IsLegitimateAdminUser() bool {
	return ctx.DetectedType == AppTypeSecurity ||
		ctx.DetectedType == AppTypeSystem
}

// ═══════════════════════════════════════════════════════════════════════════════
// APP TYPE DETECTION — определение типа приложения
// ═══════════════════════════════════════════════════════════════════════════════

// typeDetectionRule — правило детекции типа
type typeDetectionRule struct {
	appType         AppType
	packagePatterns []*regexp.Regexp
	packageKeywords []string
	requiredPerms   PermissionFlags
	optionalPerms   PermissionFlags
	weight          float64
}

// compiledTypeRules — скомпилированные правила детекции
var compiledTypeRules []typeDetectionRule

func init() {
	compiledTypeRules = []typeDetectionRule{
		// Banking — самый высокий приоритет для финансов
		{
			appType: AppTypeBanking,
			packagePatterns: compilePatterns(
				`(?i)\.bank\.`, `(?i)banking`, `(?i)\.sber`, `(?i)\.tinkoff`,
				`(?i)\.alfa`, `(?i)\.vtb`, `(?i)\.raiffeisen`, `(?i)\.chase`,
				`(?i)\.citi`, `(?i)\.wells\.?fargo`, `(?i)\.bofa`,
			),
			packageKeywords: []string{"bank", "banking", "finance", "financial"},
			weight:          1.5,
		},

		// Payment
		{
			appType: AppTypePayment,
			packagePatterns: compilePatterns(
				`(?i)\.pay\.`, `(?i)payment`, `(?i)\.wallet`,
				`(?i)\.paypal`, `(?i)\.venmo`, `(?i)\.cashapp`,
				`(?i)\.gpay`, `(?i)\.applepay`, `(?i)\.samsungpay`,
			),
			packageKeywords: []string{"pay", "payment", "wallet", "money", "transfer"},
			weight:          1.3,
		},

		// Crypto
		{
			appType: AppTypeCrypto,
			packagePatterns: compilePatterns(
				`(?i)crypto`, `(?i)bitcoin`, `(?i)ethereum`, `(?i)blockchain`,
				`(?i)\.binance`, `(?i)\.coinbase`, `(?i)\.kraken`,
				`(?i)\.metamask`, `(?i)\.trustwallet`,
			),
			packageKeywords: []string{"crypto", "bitcoin", "btc", "eth", "blockchain", "defi", "nft"},
			weight:          1.4,
		},

		// Accessibility — требует специфичный permission
		{
			appType:       AppTypeAccessibility,
			requiredPerms: PermAccessibility,
			packagePatterns: compilePatterns(
				`(?i)accessibility`, `(?i)talkback`, `(?i)a11y`,
				`(?i)screen\.?reader`, `(?i)voice\.?assistant`,
			),
			packageKeywords: []string{"accessibility", "talkback", "screenreader", "a11y"},
			weight:          1.2,
		},

		// Security
		{
			appType: AppTypeSecurity,
			packagePatterns: compilePatterns(
				`(?i)antivirus`, `(?i)security`, `(?i)\.avg\.`,
				`(?i)\.avast`, `(?i)\.kaspersky`, `(?i)\.norton`,
				`(?i)\.mcafee`, `(?i)\.bitdefender`, `(?i)\.vpn`,
				`(?i)firewall`, `(?i)malware`,
			),
			packageKeywords: []string{"antivirus", "security", "vpn", "firewall", "protect"},
			optionalPerms:   PermDeviceAdmin | PermUsageStats,
			weight:          1.1,
		},

		// Piracy
		{
			appType: AppTypePiracy,
			packagePatterns: compilePatterns(
				`(?i)torrent`, `(?i)pirate`, `(?i)\.utorrent`,
				`(?i)\.bittorrent`, `(?i)\.flud`, `(?i)\.tixati`,
				`(?i)mod\.`, `(?i)\.hack`, `(?i)crack`,
			),
			packageKeywords: []string{"torrent", "pirate", "crack", "mod", "hack", "warez"},
			weight:          1.0,
		},

		// Gaming
		{
			appType: AppTypeGaming,
			packagePatterns: compilePatterns(
				`(?i)\.game\.`, `(?i)\.games\.`, `(?i)gaming`,
				`(?i)\.supercell`, `(?i)\.king\.`, `(?i)\.rovio`,
				`(?i)\.ea\.`, `(?i)\.gameloft`, `(?i)\.unity`,
			),
			packageKeywords: []string{"game", "games", "play", "arcade", "puzzle"},
			weight:          0.8,
		},

		// Social
		{
			appType: AppTypeSocial,
			packagePatterns: compilePatterns(
				`(?i)\.facebook`, `(?i)\.instagram`, `(?i)\.twitter`,
				`(?i)\.tiktok`, `(?i)\.snapchat`,
				`(?i)\.whatsapp`, `(?i)\.viber`, `(?i)\.messenger`,
				`(?i)\.discord`, `(?i)\.slack`, `(?i)\.reddit`,
			),
			packageKeywords: []string{"social", "chat", "messenger", "message"},
			weight:          0.9,
		},

		// Donation
		{
			appType: AppTypeDonation,
			packagePatterns: compilePatterns(
				`(?i)\.twitch`, `(?i)\.patreon`, `(?i)donate`,
				`(?i)\.ko-?fi`, `(?i)\.buymeacoffee`, `(?i)tip`,
			),
			packageKeywords: []string{"donate", "donation", "tip", "support", "patron"},
			weight:          0.7,
		},

		// System
		{
			appType: AppTypeSystem,
			packagePatterns: compilePatterns(
				`(?i)\.settings`, `(?i)\.system`, `(?i)\.util`,
				`(?i)\.tools`, `(?i)\.manager`, `(?i)\.cleaner`,
			),
			packageKeywords: []string{"system", "util", "tool", "manager", "settings"},
			weight:          0.6,
		},

		// Launcher
		{
			appType: AppTypeLauncher,
			packagePatterns: compilePatterns(
				`(?i)launcher`, `(?i)\.home`, `(?i)\.nova`,
				`(?i)\.apex`, `(?i)\.action\.?launcher`,
			),
			packageKeywords: []string{"launcher", "home", "desktop"},
			optionalPerms:   PermAccessibility, // launchers may use a11y
			weight:          0.9,
		},
	}
}

// compilePatterns компилирует regex паттерны
func compilePatterns(patterns ...string) []*regexp.Regexp {
	result := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			result = append(result, re)
		}
	}
	return result
}

// detectAppType определяет тип приложения
func detectAppType(packageName string, _ []string, permFlags PermissionFlags) (AppType, float64, []string) {
	packageLower := strings.ToLower(packageName)

	type candidate struct {
		appType AppType
		score   float64
		signals []string
	}

	candidates := make([]candidate, 0, len(compiledTypeRules))

	for _, rule := range compiledTypeRules {
		score := 0.0
		signals := make([]string, 0)

		// Проверка required permissions
		if rule.requiredPerms != 0 {
			if !permFlags.HasAll(rule.requiredPerms) {
				continue // required perms not found, skip
			}
			score += 0.3
			signals = append(signals, "required_perm_match")
		}

		// Проверка optional permissions (бонус, но не обязательно)
		if rule.optionalPerms != 0 && permFlags.HasAny(rule.optionalPerms) {
			score += 0.1
			signals = append(signals, "optional_perm_match")
		}

		// Проверка package patterns
		for _, re := range rule.packagePatterns {
			if re.MatchString(packageName) {
				score += 0.4
				signals = append(signals, "package_pattern:"+re.String()[:min(20, len(re.String()))])
				break
			}
		}

		// Проверка keywords в package name
		for _, kw := range rule.packageKeywords {
			if strings.Contains(packageLower, kw) {
				score += 0.2
				signals = append(signals, "keyword:"+kw)
				break
			}
		}

		// Применяем вес правила
		score *= rule.weight

		if score > 0 {
			candidates = append(candidates, candidate{
				appType: rule.appType,
				score:   score,
				signals: signals,
			})
		}
	}

	// Находим лучшего кандидата
	if len(candidates) == 0 {
		return AppTypeGeneric, 0.0, nil
	}

	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.score > best.score {
			best = c
		}
	}

	// Нормализуем confidence (max ~1.0)
	confidence := best.score
	if confidence > 1.0 {
		confidence = 1.0
	}

	return best.appType, confidence, best.signals
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
