package ml

import (
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ENTRY POINT DETECTOR COMPONENT
// ═══════════════════════════════════════════════════════════════════════════════

// EntryPointType represents different types of entry points
type EntryPointType int

const (
	EntryPointUnknown EntryPointType = iota
	EntryPointActivity
	EntryPointService
	EntryPointReceiver
	EntryPointProvider
	EntryPointApplication
	EntryPointExportedMethod
	EntryPointIntentHandler
	EntryPointURLHandler
	EntryPointBundleHandler
)

// EntryPointDetector identifies entry points for security-focused analysis
type EntryPointDetector interface {
	Detect(mi *MethodInfo) *EntryPointInfo
	IsInteresting(info *EntryPointInfo) bool
}

// EntryPointInfo contains entry point analysis
type EntryPointInfo struct {
	Type        EntryPointType `json:"type"`
	IsExported  bool           `json:"is_exported"`
	HasIntent   bool           `json:"has_intent"`
	HasBundle   bool           `json:"has_bundle"`
	HasURL      bool           `json:"has_url"`
	Priority    int            `json:"priority"`
	Description string         `json:"description"`
	Confidence  float64        `json:"confidence"`
}

// DefaultEntryPointDetector implements EntryPointDetector interface
type DefaultEntryPointDetector struct {
	// Configuration for detection sensitivity
	enableIntentDetection bool
	enableBundleDetection bool
	enableURLDetection    bool
}

func NewEntryPointDetector() EntryPointDetector {
	return &DefaultEntryPointDetector{
		enableIntentDetection: true,
		enableBundleDetection: true,
		enableURLDetection:    true,
	}
}

func (epd *DefaultEntryPointDetector) Detect(mi *MethodInfo) *EntryPointInfo {
	if mi == nil {
		return &EntryPointInfo{
			Type:        EntryPointUnknown,
			Priority:    0,
			Description: "Invalid method info",
			Confidence:  0.0,
		}
	}

	info := &EntryPointInfo{
		Type:        EntryPointUnknown,
		IsExported:  false,
		HasIntent:   false,
		HasBundle:   false,
		HasURL:      false,
		Priority:    0,
		Description: "",
		Confidence:  0.0,
	}

	// Detect Android component entry points
	epd.detectAndroidComponents(mi, info)

	// Detect exported methods
	epd.detectExportedMethods(mi, info)

	// Detect intent handling
	if epd.enableIntentDetection {
		epd.detectIntentHandling(mi, info)
	}

	// Detect bundle handling
	if epd.enableBundleDetection {
		epd.detectBundleHandling(mi, info)
	}

	// Detect URL handling
	if epd.enableURLDetection {
		epd.detectURLHandling(mi, info)
	}

	// Calculate priority and confidence
	epd.calculatePriorityAndConfidence(info)

	return info
}

func (epd *DefaultEntryPointDetector) IsInteresting(info *EntryPointInfo) bool {
	if info == nil {
		return false
	}

	// Entry points with high priority are interesting
	if info.Priority >= 7 {
		return true
	}

	// Exported components are interesting
	if info.IsExported {
		return true
	}

	// Methods that handle external input are interesting
	if info.HasIntent || info.HasBundle || info.HasURL {
		return true
	}

	// High confidence detections are interesting
	if info.Confidence >= 0.8 {
		return true
	}

	return false
}

// detectAndroidComponents identifies Android framework component entry points
func (epd *DefaultEntryPointDetector) detectAndroidComponents(mi *MethodInfo, info *EntryPointInfo) {
	className := strings.ToLower(mi.ClassName)
	methodName := strings.ToLower(mi.Name)

	// Activity lifecycle methods
	if epd.isActivityClass(className) {
		if epd.isActivityLifecycleMethod(methodName) {
			info.Type = EntryPointActivity
			info.IsExported = true
			info.Description = "Activity lifecycle method"
			info.Confidence = 0.9
			return
		}
	}

	// Service methods
	if epd.isServiceClass(className) {
		if epd.isServiceMethod(methodName) {
			info.Type = EntryPointService
			info.IsExported = true
			info.Description = "Service entry point"
			info.Confidence = 0.9
			return
		}
	}

	// BroadcastReceiver methods
	if epd.isReceiverClass(className) {
		if methodName == "onreceive" {
			info.Type = EntryPointReceiver
			info.IsExported = true
			info.Description = "Broadcast receiver"
			info.Confidence = 0.95
			return
		}
	}

	// ContentProvider methods
	if epd.isProviderClass(className) {
		if epd.isProviderMethod(methodName) {
			info.Type = EntryPointProvider
			info.IsExported = true
			info.Description = "Content provider method"
			info.Confidence = 0.9
			return
		}
	}

	// Application class methods
	if epd.isApplicationClass(className) {
		if epd.isApplicationMethod(methodName) {
			info.Type = EntryPointApplication
			info.IsExported = true
			info.Description = "Application lifecycle method"
			info.Confidence = 0.8
			return
		}
	}
}

// detectExportedMethods identifies methods that are likely exported
func (epd *DefaultEntryPointDetector) detectExportedMethods(mi *MethodInfo, info *EntryPointInfo) {
	if info.Type != EntryPointUnknown {
		return // Already detected as component
	}

	methodName := strings.ToLower(mi.Name)

	// Check for public API patterns
	if epd.isPublicAPIMethod(methodName) {
		info.Type = EntryPointExportedMethod
		info.IsExported = true
		info.Description = "Public API method"
		info.Confidence = 0.6
	}

	// Check for native method declarations
	if epd.isNativeMethod(mi) {
		info.Type = EntryPointExportedMethod
		info.IsExported = true
		info.Description = "Native method"
		info.Confidence = 0.8
	}
}

// detectIntentHandling identifies methods that handle Android Intents
func (epd *DefaultEntryPointDetector) detectIntentHandling(mi *MethodInfo, info *EntryPointInfo) {
	intentKeywords := []string{
		"intent", "getintent", "setintent", "putextra", "getextra",
		"getaction", "setaction", "getdata", "setdata",
	}

	if rawBodyContainsAnyFold(mi.RawBody, intentKeywords) {
		info.HasIntent = true
		if info.Type == EntryPointUnknown {
			info.Type = EntryPointIntentHandler
			info.Description = "Intent handler method"
			info.Confidence = 0.7
		}
	}
}

// detectBundleHandling identifies methods that handle Android Bundles
func (epd *DefaultEntryPointDetector) detectBundleHandling(mi *MethodInfo, info *EntryPointInfo) {
	bundleKeywords := []string{
		"bundle", "getbundle", "putbundle", "savedinstancestate",
		"getstring", "putstring", "getint", "putint",
	}

	if rawBodyContainsAnyFold(mi.RawBody, bundleKeywords) {
		info.HasBundle = true
		if info.Type == EntryPointUnknown {
			info.Type = EntryPointBundleHandler
			info.Description = "Bundle handler method"
			info.Confidence = 0.6
		}
	}
}

// detectURLHandling identifies methods that handle URLs
func (epd *DefaultEntryPointDetector) detectURLHandling(mi *MethodInfo, info *EntryPointInfo) {
	urlKeywords := []string{
		"url", "uri", "http", "https", "scheme", "host",
		"getscheme", "gethost", "getpath", "getquery",
	}

	if rawBodyContainsAnyFold(mi.RawBody, urlKeywords) {
		info.HasURL = true
		// URL handling takes priority over exported method detection
		if info.Type == EntryPointUnknown || info.Type == EntryPointExportedMethod {
			info.Type = EntryPointURLHandler
			info.Description = "URL handler method"
			info.Confidence = 0.7
		}
	}
}

// calculatePriorityAndConfidence assigns priority and adjusts confidence
func (epd *DefaultEntryPointDetector) calculatePriorityAndConfidence(info *EntryPointInfo) {
	// Base priority by type
	switch info.Type {
	case EntryPointActivity:
		info.Priority = 9
	case EntryPointService:
		info.Priority = 8
	case EntryPointReceiver:
		info.Priority = 8
	case EntryPointProvider:
		info.Priority = 7
	case EntryPointApplication:
		info.Priority = 6
	case EntryPointExportedMethod:
		info.Priority = 5
	case EntryPointIntentHandler:
		info.Priority = 6
	case EntryPointURLHandler:
		info.Priority = 7
	case EntryPointBundleHandler:
		info.Priority = 4
	default:
		info.Priority = 1
	}

	// Boost priority for methods with multiple indicators
	bonusPoints := 0
	if info.HasIntent {
		bonusPoints++
	}
	if info.HasBundle {
		bonusPoints++
	}
	if info.HasURL {
		bonusPoints++
	}
	if info.IsExported {
		bonusPoints++
	}

	info.Priority += bonusPoints

	// Cap priority at 10
	if info.Priority > 10 {
		info.Priority = 10
	}

	// Adjust confidence based on multiple indicators
	if bonusPoints > 1 {
		info.Confidence += float64(bonusPoints-1) * 0.1
		if info.Confidence > 1.0 {
			info.Confidence = 1.0
		}
	}
}

// Helper methods for component detection

func (epd *DefaultEntryPointDetector) isActivityClass(className string) bool {
	return strings.Contains(className, "activity") ||
		strings.Contains(className, "mainactivity") ||
		strings.Contains(className, "baseactivity")
}

func (epd *DefaultEntryPointDetector) isActivityLifecycleMethod(methodName string) bool {
	lifecycleMethods := []string{
		"oncreate", "onstart", "onresume", "onpause", "onstop", "ondestroy",
		"onrestart", "onsaveinstancestate", "onrestoreinstancestate",
		"onnewintent", "onactivityresult",
	}

	for _, method := range lifecycleMethods {
		if methodName == method {
			return true
		}
	}
	return false
}

func (epd *DefaultEntryPointDetector) isServiceClass(className string) bool {
	return strings.Contains(className, "service") ||
		strings.Contains(className, "intentservice")
}

func (epd *DefaultEntryPointDetector) isServiceMethod(methodName string) bool {
	serviceMethods := []string{
		"onbind", "onunbind", "onstartcommand", "oncreate", "ondestroy",
		"onhandleintent",
	}

	for _, method := range serviceMethods {
		if methodName == method {
			return true
		}
	}
	return false
}

func (epd *DefaultEntryPointDetector) isReceiverClass(className string) bool {
	return strings.Contains(className, "receiver") ||
		strings.Contains(className, "broadcastreceiver")
}

func (epd *DefaultEntryPointDetector) isProviderClass(className string) bool {
	return strings.Contains(className, "provider") ||
		strings.Contains(className, "contentprovider")
}

func (epd *DefaultEntryPointDetector) isProviderMethod(methodName string) bool {
	providerMethods := []string{
		"query", "insert", "update", "delete", "gettype", "oncreate",
	}

	for _, method := range providerMethods {
		if methodName == method {
			return true
		}
	}
	return false
}

func (epd *DefaultEntryPointDetector) isApplicationClass(className string) bool {
	return strings.Contains(className, "application") ||
		strings.Contains(className, "mainapplication")
}

func (epd *DefaultEntryPointDetector) isApplicationMethod(methodName string) bool {
	appMethods := []string{
		"oncreate", "onterminate", "onlowmemory", "ontrimemory",
		"onconfigurationchanged",
	}

	for _, method := range appMethods {
		if methodName == method {
			return true
		}
	}
	return false
}

func (epd *DefaultEntryPointDetector) isPublicAPIMethod(methodName string) bool {
	// Check for common public API patterns
	publicPatterns := []string{
		"init", "start", "stop", "execute", "process", "handle",
		"validate", "authenticate", "authorize", "login", "logout",
	}

	for _, pattern := range publicPatterns {
		if strings.Contains(methodName, pattern) {
			return true
		}
	}
	return false
}

func (epd *DefaultEntryPointDetector) isNativeMethod(mi *MethodInfo) bool {
	// Оптимизация: скан без Join — 1 строка за раз
	if rawBodyContainsFold(mi.RawBody, "native") {
		return true
	}
	return strings.Contains(strings.ToLower(mi.Name), "native") ||
		len(mi.RawBody) == 0 // Native methods often have empty bodies in smali
}
