package anomaly

import (
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ANOMALY DETECTOR — Smart Noise Filtering with Threat Bypass
// ═══════════════════════════════════════════════════════════════════════════════
//
// Это движок для «умной фильтрации» шума. Он делает две вещи:
//   1. Определяет, какие находки можно смело скрыть (настоящий шум)
//   2. Вытаскивает на свет АНОМАЛИИ — подозрительную активность
//      ДАЖЕ ВНУТРИ «доверенных» библиотек
//
// Принцип: «Если библиотека для рекламы лезет в контакты — это не шум,
//           это АЛЕРТ, несмотря на то что пакет называется com/google/ads»
// ═══════════════════════════════════════════════════════════════════════════════

// Result — результат анализа аномалий для одной находки
type Result struct {
	// Решение
	IsNoise      bool    `json:"is_noise"`              // true = можно скрыть
	IsAnomaly    bool    `json:"is_anomaly"`            // true = подозрительно, ПОКАЗАТЬ!
	NoiseScore   float64 `json:"noise_score"`           // 0-1 (1 = чистый шум)
	AnomalyScore float64 `json:"anomaly_score"`         // 0-1 (1 = точно аномалия)
	BypassType   string  `json:"bypass_type,omitempty"` // "sensitive_api", etc.

	// Причины
	NoiseReasons  []string `json:"noise_reasons,omitempty"`
	AnomalyAlerts []string `json:"anomaly_alerts,omitempty"`
	ForcedVisible bool     `json:"forced_visible"` // true = фильтр принудительно обойдён
}

// FindingInfo — входная информация о находке для анализа
type FindingInfo struct {
	Path        string   // путь к файлу
	RelPath     string   // относительный путь
	FileType    string   // тип файла
	Category    string   // категория находки (ads, analytics, threat, etc.)
	Pattern     string   // сработавший паттерн
	LibraryName string   // имя библиотеки
	MatchCount  int      // количество совпадений
	MethodCalls []string // вызванные методы (если есть)
	Permissions []string // запрошенные разрешения (если есть)
	RiskLevel   int      // 0-4 (none, low, medium, high, critical)
	IsLibrary   bool     // классификация из filter/classifier
	IsAppCode   bool
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETECTOR
// ═══════════════════════════════════════════════════════════════════════════════

// Detector — основной движок обнаружения аномалий
type Detector struct {
	// Таблица «ожидаемого поведения» для известных библиотек
	libraryProfiles map[string]*LibraryProfile

	// Критические API — всегда показываем
	sensitiveAPIs []string

	// Критические категории — всегда показываем
	criticalCategories map[string]bool

	// Порог шума
	noiseThreshold   float64
	anomalyThreshold float64
}

// LibraryProfile — профиль «нормального» поведения библиотеки
type LibraryProfile struct {
	Name            string   `json:"name"`
	Prefix          string   `json:"prefix"`
	ExpectedActions []string `json:"expected_actions"` // что эта либа ОБЫЧНО делает
	ForbiddenAPIs   []string `json:"forbidden_apis"`   // что она НИКОГДА не должна делать
	NoisyPatterns   []string `json:"noisy_patterns"`   // паттерны, типичные для шума
}

// NewDetector создаёт детектор с настройками по умолчанию
func NewDetector() *Detector {
	d := &Detector{
		libraryProfiles:  make(map[string]*LibraryProfile),
		noiseThreshold:   0.6,
		anomalyThreshold: 0.5,
		criticalCategories: map[string]bool{
			"threat":     true,
			"malware":    true,
			"c2":         true,
			"backdoor":   true,
			"spyware":    true,
			"ransomware": true,
			"exploit":    true,
		},
	}

	d.sensitiveAPIs = defaultSensitiveAPIs()
	d.loadDefaultProfiles()

	return d
}

// ═══════════════════════════════════════════════════════════════════════════════
// SENSITIVE APIS — всегда показываем, где бы они ни были
// ═══════════════════════════════════════════════════════════════════════════════

func defaultSensitiveAPIs() []string {
	return []string{
		// Телефония и SMS
		"sendtextmessage", "getdeviceid", "getsubscriberid",
		"getline1number", "senddatamessage", "telephonymanager",
		"smsmanager",

		// Контакты и личные данные
		"contactscontract", "content://contacts", "content://call_log",
		"content://sms", "content://calendar",

		// Камера и микрофон
		"mediarecorder", "audiocapture", "camera.open",
		"audiorecord",

		// Местоположение
		"getlastknownlocation", "requestlocationupdates",
		"fusedlocationproviderclient",

		// Файловая система (опасные операции)
		"runtime.exec", "processbuilder",
		"dalvik.system.dexclassloader",
		"java.lang.reflect",

		// Сеть (подозрительные паттерны)
		"urlconnection", "httpurlconnection",
		"socket", "serversocket",
		"datagramsocket",

		// Крипто (потенциальные утечки ключей)
		"secretkeyspec", "cipher.getinstance",
		"keystore.getinstance",

		// Accessibility (abuse detection)
		"accessibilityservice", "accessibilityevent",
		"performglobalaction",

		// Installer / Dynamic loading
		"packageinstaller", "dexclassloader",
		"pathclassloader", "inmemorydexclassloader",

		// Root / System
		"/system/bin/su", "/system/xbin/su", "superuser",
		"supersu", "magisk",
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEFAULT LIBRARY PROFILES
// ═══════════════════════════════════════════════════════════════════════════════

func (d *Detector) loadDefaultProfiles() {
	profiles := []*LibraryProfile{
		{
			Name:   "Google Ads SDK",
			Prefix: "com/google/android/gms/ads",
			ExpectedActions: []string{
				"loadadrequest", "adlistener", "interstitial",
				"rewarded", "banner", "native", "mediation",
			},
			ForbiddenAPIs: []string{
				"sendtextmessage", "contactscontract", "mediarecorder",
				"runtime.exec", "processbuilder", "dexclassloader",
				"packageinstaller",
			},
			NoisyPatterns: []string{
				"adview", "adrequest", "adlistener", "mediation",
				"interstitialad", "rewardedadcallback", "bannersize",
			},
		},
		{
			Name:   "Facebook SDK",
			Prefix: "com/facebook",
			ExpectedActions: []string{
				"loginmanager", "accesstoken", "graphrequest",
				"appeventlogger", "shareapi",
			},
			ForbiddenAPIs: []string{
				"sendtextmessage", "mediarecorder", "camera.open",
				"runtime.exec", "processbuilder",
			},
			NoisyPatterns: []string{
				"facebookactivity", "loginbutton", "sharebutton",
				"accesstokentracker",
			},
		},
		{
			Name:   "Firebase",
			Prefix: "com/google/firebase",
			ExpectedActions: []string{
				"analytics", "messaging", "remoteconfig",
				"crashlytics", "firestore", "auth",
			},
			ForbiddenAPIs: []string{
				"sendtextmessage", "contactscontract",
				"runtime.exec", "packageinstaller",
			},
			NoisyPatterns: []string{
				"firebaseapp", "firebasemessaging", "firebaseanalytics",
				"firebasecrashlytics", "firebaseauth",
			},
		},
		{
			Name:   "AndroidX",
			Prefix: "androidx/",
			ExpectedActions: []string{
				"recyclerview", "fragment", "lifecycle",
				"viewmodel", "livedata", "navigation",
			},
			ForbiddenAPIs: []string{
				"sendtextmessage", "runtime.exec", "dexclassloader",
				"packageinstaller", "socket", "serversocket",
			},
			NoisyPatterns: []string{
				"appcompat", "constraintlayout", "recyclerview",
				"lifecycle", "livedata", "viewmodel",
			},
		},
		{
			Name:   "OkHttp",
			Prefix: "okhttp3/",
			ExpectedActions: []string{
				"okhttpclient", "request", "response", "interceptor",
				"connectionpool", "cache",
			},
			ForbiddenAPIs: []string{
				"sendtextmessage", "contactscontract", "mediarecorder",
				"runtime.exec", "dexclassloader",
			},
			NoisyPatterns: []string{
				"okhttpclient", "requestbody", "responsebody",
				"httpurl", "protocol",
			},
		},
		{
			Name:   "Kotlin Stdlib",
			Prefix: "kotlin/",
			ExpectedActions: []string{
				"collections", "coroutines", "sequences",
				"text", "io", "math",
			},
			ForbiddenAPIs: []string{
				"sendtextmessage", "contactscontract",
				"packageinstaller",
			},
			NoisyPatterns: []string{
				"kotlin/unit", "kotlin/pair", "kotlin/triple",
				"kotlinx/coroutines",
			},
		},
		{
			Name:   "Unity Ads",
			Prefix: "com/unity3d/ads",
			ExpectedActions: []string{
				"unityads", "showad", "listener",
			},
			ForbiddenAPIs: []string{
				"sendtextmessage", "contactscontract",
				"runtime.exec", "packageinstaller",
			},
			NoisyPatterns: []string{
				"unityads", "unityadslistener",
			},
		},
	}

	for _, p := range profiles {
		d.libraryProfiles[p.Prefix] = p
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

// Analyze анализирует одну находку и решает: шум или аномалия
func (d *Detector) Analyze(finding FindingInfo) *Result {
	result := &Result{}

	// ── 1. Critical category bypass — ВСЕГДА показываем ──────
	if d.criticalCategories[strings.ToLower(finding.Category)] {
		result.IsAnomaly = true
		result.AnomalyScore = 1.0
		result.ForcedVisible = true
		result.AnomalyAlerts = append(result.AnomalyAlerts,
			"Critical category: "+finding.Category+" — always visible")
		return result
	}

	// ── 2. High risk — ВСЕГДА показываем ─────────────────────
	if finding.RiskLevel >= 3 { // HIGH or CRITICAL
		result.IsAnomaly = true
		result.AnomalyScore = 0.9
		result.ForcedVisible = true
		result.AnomalyAlerts = append(result.AnomalyAlerts,
			"High risk level — forced visible regardless of library status")
		return result
	}

	// ── 3. Sensitive API bypass — ВСЕГДА показываем ──────────
	if sensitiveHit := d.checkSensitiveAPIs(finding); sensitiveHit != "" {
		result.IsAnomaly = true
		result.AnomalyScore = 0.85
		result.ForcedVisible = true
		result.AnomalyAlerts = append(result.AnomalyAlerts,
			"Sensitive API detected: "+sensitiveHit+" — ignoring noise filters")
		return result
	}

	// ── 4. Library anomaly detection ─────────────────────────
	if finding.IsLibrary {
		profile := d.findProfile(finding.Path)

		if profile != nil {
			// Проверяем forbidden APIs
			for _, call := range finding.MethodCalls {
				callLower := strings.ToLower(call)
				for _, forbidden := range profile.ForbiddenAPIs {
					if strings.Contains(callLower, forbidden) {
						result.IsAnomaly = true
						result.AnomalyScore = 0.9
						result.ForcedVisible = true
						result.AnomalyAlerts = append(result.AnomalyAlerts,
							"LIBRARY ANOMALY: "+profile.Name+" calling forbidden API: "+forbidden)
					}
				}
			}

			// Если аномалий нет — это «чистый» шум
			if !result.IsAnomaly {
				noiseScore := d.calculateNoiseScore(finding, profile)
				result.NoiseScore = noiseScore
				result.IsNoise = noiseScore > d.noiseThreshold
				if result.IsNoise {
					result.NoiseReasons = append(result.NoiseReasons,
						"Standard library behavior: "+profile.Name)
				}
			}
		} else {
			// Неизвестная библиотека — минимальный шум, но проверяем
			result.NoiseScore = 0.3
			result.NoiseReasons = append(result.NoiseReasons,
				"Unknown library — partial noise suppression only")
		}
	}

	// ── 5. App code — минимальное подавление ─────────────────
	if finding.IsAppCode {
		result.NoiseScore = 0.1 // почти никогда не скрываем app code
		result.IsNoise = false
	}

	return result
}

// AnalyzeBatch анализирует пачку находок
func (d *Detector) AnalyzeBatch(findings []FindingInfo) []*Result {
	results := make([]*Result, len(findings))
	for i, f := range findings {
		results[i] = d.Analyze(f)
	}
	return results
}

// FilterResults фильтрует список находок, оставляя только значимые
// Возвращает: visible (важные), hidden (шум), anomalies (аномалии в либах)
func (d *Detector) FilterResults(findings []FindingInfo) (visible, hidden, anomalies []FindingInfo) {
	for _, f := range findings {
		result := d.Analyze(f)

		if result.IsAnomaly || result.ForcedVisible {
			anomalies = append(anomalies, f)
			visible = append(visible, f) // аномалии всегда видимы
		} else if result.IsNoise {
			hidden = append(hidden, f)
		} else {
			visible = append(visible, f)
		}
	}
	return
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTERNAL CHECKS
// ═══════════════════════════════════════════════════════════════════════════════

// checkSensitiveAPIs проверяет, содержит ли находка вызовы критических API
func (d *Detector) checkSensitiveAPIs(finding FindingInfo) string {
	patternLower := strings.ToLower(finding.Pattern)
	for _, api := range d.sensitiveAPIs {
		if strings.Contains(patternLower, api) {
			return api
		}
	}

	for _, call := range finding.MethodCalls {
		callLower := strings.ToLower(call)
		for _, api := range d.sensitiveAPIs {
			if strings.Contains(callLower, api) {
				return api
			}
		}
	}

	return ""
}

// findProfile находит профиль библиотеки по пути
func (d *Detector) findProfile(path string) *LibraryProfile {
	pathLower := strings.ToLower(path)
	// Убираем smali/ prefix
	pathLower = strings.TrimPrefix(pathLower, "smali/")

	for prefix, profile := range d.libraryProfiles {
		if strings.HasPrefix(pathLower, strings.ToLower(prefix)) {
			return profile
		}
	}
	return nil
}

// calculateNoiseScore вычисляет «шумность» находки в контексте библиотеки
func (d *Detector) calculateNoiseScore(finding FindingInfo, profile *LibraryProfile) float64 {
	score := 0.5 // базовый шум для библиотеки

	patternLower := strings.ToLower(finding.Pattern)

	// Если паттерн совпадает с «типичным шумом» для этой либы
	for _, noisy := range profile.NoisyPatterns {
		if strings.Contains(patternLower, noisy) {
			score += 0.2
			break
		}
	}

	// Если это ожидаемое действие для либы
	for _, expected := range profile.ExpectedActions {
		if strings.Contains(patternLower, expected) {
			score += 0.15
			break
		}
	}

	// Низкий risk = больше шума
	if finding.RiskLevel <= 1 {
		score += 0.1
	}

	// Ограничиваем 0-1
	if score > 1.0 {
		score = 1.0
	}

	return score
}
