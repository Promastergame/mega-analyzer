package apkloader

import "sync"

type HeuristicPattern struct {
	Name        string
	Description string
	Indicators  []string
	Confidence  float64
	Category    string
	Severity    int
	Detectable  bool
	Replaceable bool
}

type HeuristicLibraryExpander struct {
	mu            sync.RWMutex
	patterns      map[string]*HeuristicPattern
	categories    map[string][]string
	patternsAdded int
}

func NewHeuristicLibraryExpander() *HeuristicLibraryExpander {
	expander := &HeuristicLibraryExpander{
		patterns:   make(map[string]*HeuristicPattern),
		categories: make(map[string][]string),
	}
	expander.initializePatterns()
	return expander
}

func (hle *HeuristicLibraryExpander) initializePatterns() {
	hle.addPattern(&HeuristicPattern{
		Name: "StringEncryption", Description: "Strings encrypted", Indicators: []string{"decrypt", "cipher", "key"}, Confidence: 0.85, Category: "StringObfuscation", Severity: 7, Detectable: true, Replaceable: true,
	})
	hle.addPattern(&HeuristicPattern{
		Name: "OpaquePredicates", Description: "Opaque predicates", Indicators: []string{"x*x>=0", "x^x==0"}, Confidence: 0.9, Category: "ControlFlowObfuscation", Severity: 5, Detectable: true, Replaceable: true,
	})
	hle.addPattern(&HeuristicPattern{
		Name: "DeadCodeInsertion", Description: "Dead code", Indicators: []string{"unreachable", "dead"}, Confidence: 0.8, Category: "ControlFlowObfuscation", Severity: 4, Detectable: true, Replaceable: true,
	})
	hle.addPattern(&HeuristicPattern{
		Name: "NameObfuscation", Description: "Name obfuscation", Indicators: []string{"a", "b", "c"}, Confidence: 0.7, Category: "NamingObfuscation", Severity: 3, Detectable: true, Replaceable: true,
	})
	hle.addPattern(&HeuristicPattern{
		Name: "ReflectionObfuscation", Description: "Reflection", Indicators: []string{"forName", "getMethod"}, Confidence: 0.85, Category: "ReflectionObfuscation", Severity: 8, Detectable: true, Replaceable: false,
	})
	hle.addPattern(&HeuristicPattern{
		Name: "DynamicCodeLoading", Description: "Dynamic loading", Indicators: []string{"loadDex", "defineClass"}, Confidence: 0.9, Category: "DynamicCodeLoading", Severity: 9, Detectable: true, Replaceable: false,
	})
	hle.addPattern(&HeuristicPattern{
		Name: "Virtualization", Description: "Virtualization", Indicators: []string{"dispatcher", "interpreter"}, Confidence: 0.8, Category: "Virtualization", Severity: 10, Detectable: true, Replaceable: false,
	})
	hle.addPattern(&HeuristicPattern{
		Name: "AntiAnalysis", Description: "Anti-analysis", Indicators: []string{"debugger", "emulator"}, Confidence: 0.75, Category: "AntiAnalysis", Severity: 8, Detectable: true, Replaceable: false,
	})
	hle.addPattern(&HeuristicPattern{
		Name: "Packing", Description: "Packing", Indicators: []string{"unpack", "decompress"}, Confidence: 0.8, Category: "Packing", Severity: 9, Detectable: true, Replaceable: false,
	})
	hle.addPattern(&HeuristicPattern{
		Name: "Polymorphism", Description: "Polymorphism", Indicators: []string{"random", "seed"}, Confidence: 0.7, Category: "Polymorphism", Severity: 9, Detectable: true, Replaceable: false,
	})
	hle.addPattern(&HeuristicPattern{
		Name: "Metamorphism", Description: "Metamorphism", Indicators: []string{"self-modify", "metamorphic"}, Confidence: 0.65, Category: "Metamorphism", Severity: 10, Detectable: true, Replaceable: false,
	})
}

func (hle *HeuristicLibraryExpander) addPattern(pattern *HeuristicPattern) {
	hle.patterns[pattern.Name] = pattern
	if _, exists := hle.categories[pattern.Category]; !exists {
		hle.categories[pattern.Category] = make([]string, 0)
	}
	hle.categories[pattern.Category] = append(hle.categories[pattern.Category], pattern.Name)
	hle.patternsAdded++
}

func (hle *HeuristicLibraryExpander) AddPattern(pattern *HeuristicPattern) {
	hle.mu.Lock()
	defer hle.mu.Unlock()
	hle.addPattern(pattern)
}

func (hle *HeuristicLibraryExpander) GetPattern(name string) *HeuristicPattern {
	hle.mu.RLock()
	defer hle.mu.RUnlock()
	return hle.patterns[name]
}

func (hle *HeuristicLibraryExpander) GetPatternsByCategory(category string) []*HeuristicPattern {
	hle.mu.RLock()
	defer hle.mu.RUnlock()
	var patterns []*HeuristicPattern
	for _, name := range hle.categories[category] {
		patterns = append(patterns, hle.patterns[name])
	}
	return patterns
}

func (hle *HeuristicLibraryExpander) GetAllPatterns() []*HeuristicPattern {
	hle.mu.RLock()
	defer hle.mu.RUnlock()
	var patterns []*HeuristicPattern
	for _, pattern := range hle.patterns {
		patterns = append(patterns, pattern)
	}
	return patterns
}

func (hle *HeuristicLibraryExpander) GetCategories() []string {
	hle.mu.RLock()
	defer hle.mu.RUnlock()
	var categories []string
	for category := range hle.categories {
		categories = append(categories, category)
	}
	return categories
}

func (hle *HeuristicLibraryExpander) MatchPatterns(indicators []string) []*HeuristicPattern {
	hle.mu.RLock()
	defer hle.mu.RUnlock()
	var matched []*HeuristicPattern
	for _, pattern := range hle.patterns {
		if hle.matchesPattern(pattern, indicators) {
			matched = append(matched, pattern)
		}
	}
	return matched
}

func (hle *HeuristicLibraryExpander) matchesPattern(pattern *HeuristicPattern, indicators []string) bool {
	for _, indicator := range indicators {
		for _, patternIndicator := range pattern.Indicators {
			if indicator == patternIndicator {
				return true
			}
		}
	}
	return false
}

func (hle *HeuristicLibraryExpander) GetStatistics() HeuristicLibraryStatistics {
	hle.mu.RLock()
	defer hle.mu.RUnlock()
	return HeuristicLibraryStatistics{TotalPatterns: len(hle.patterns), TotalCategories: len(hle.categories), PatternsAdded: hle.patternsAdded}
}

type HeuristicLibraryStatistics struct {
	TotalPatterns   int
	TotalCategories int
	PatternsAdded   int
}

type BehavioralClassifier struct {
	mu              sync.RWMutex
	behaviors       map[string][]string
	classifications map[string]int
}

func NewBehavioralClassifier() *BehavioralClassifier {
	classifier := &BehavioralClassifier{behaviors: make(map[string][]string), classifications: make(map[string]int)}
	classifier.initializeBehaviors()
	return classifier
}

func (bc *BehavioralClassifier) initializeBehaviors() {
	bc.behaviors["Cryptography"] = []string{"cipher", "encrypt", "decrypt", "hash", "digest", "key", "aes", "rsa", "md5", "sha", "hmac", "signature", "keystore", "pbe", "iv", "salt", "secretkey"}
	bc.behaviors["LicenseChecking"] = []string{"license", "verify", "check", "validate", "expired", "activation", "serial", "key", "registration", "purchase", "billing", "subscription"}
	bc.behaviors["ClassLoading"] = []string{"loadClass", "forName", "defineClass", "ClassLoader", "DexClassLoader", "PathClassLoader", "loadDex", "getSystemClassLoader", "BaseDexClassLoader"}
	bc.behaviors["Reflection"] = []string{"getMethod", "invoke", "getDeclaredMethod", "setAccessible", "newInstance", "getField", "getDeclaredField", "getConstructor", "getModifiers", "getType"}
	bc.behaviors["NetworkAccess"] = []string{"http", "https", "socket", "connect", "send", "receive", "request", "response", "url", "host", "port", "okhttp", "retrofit", "volley", "webview"}
	bc.behaviors["FileIO"] = []string{"file", "read", "write", "open", "close", "path", "directory", "save", "load", "delete", "exists", "buffered", "stream", "reader", "writer", "zip"}
	bc.behaviors["Logging"] = []string{"log", "debug", "info", "warn", "error", "trace", "print", "logger", "message", "level", "tag", "verbose", "wtf"}
	bc.behaviors["AntiDebug"] = []string{"debugger", "debug", "trace", "breakpoint", "ptrace", "isDebuggerConnected", "isDebuggable", "Debug.isDebuggerConnected", "android.os.Debug"}
	bc.behaviors["AntiVM"] = []string{"emulator", "vm", "virtual", "qemu", "virtualbox", "vmware", "sandbox", "isEmulator", "goldfish", "nox", "genymotion", "bluestacks", "build.hardware"}
	bc.behaviors["DynamicExecution"] = []string{"exec", "runtime", "process", "command", "shell", "bash", "sh", "system", "su", "root", "busybox"}
	bc.behaviors["Persistence"] = []string{"SharedPreferences", "SQLite", "database", "sql", "preference", "settings", "json", "xml", "storage", "internal", "external"}
	bc.behaviors["UIInteractions"] = []string{"Activity", "Fragment", "View", "Button", "Toast", "Dialog", "Intent", "Notification", "Layout", "Resources", "Inflate"}
	bc.behaviors["Permissions"] = []string{"checkSelfPermission", "requestPermissions", "Permission", "manifest", "ACCESS_FINE_LOCATION", "READ_CONTACTS", "INTERNET", "CAMERA"}
	bc.behaviors["IPC"] = []string{"Binder", "Service", "Broadcast", "Receiver", "ContentProvider", "Parcel", "AIDL", "Intent", "Messenger"}
}

func (bc *BehavioralClassifier) ClassifyBehavior(indicators []string) []string {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	var classifications []string
	for behavior, patterns := range bc.behaviors {
		if bc.matchesBehavior(patterns, indicators) {
			classifications = append(classifications, behavior)
			bc.classifications[behavior]++
		}
	}
	return classifications
}

func (bc *BehavioralClassifier) matchesBehavior(patterns, indicators []string) bool {
	for _, indicator := range indicators {
		for _, pattern := range patterns {
			if indicator == pattern {
				return true
			}
		}
	}
	return false
}

func (bc *BehavioralClassifier) GetBehaviors() map[string][]string {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	behaviors := make(map[string][]string)
	for k, v := range bc.behaviors {
		behaviors[k] = v
	}
	return behaviors
}

func (bc *BehavioralClassifier) GetClassificationStats() map[string]int {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	stats := make(map[string]int)
	for k, v := range bc.classifications {
		stats[k] = v
	}
	return stats
}
