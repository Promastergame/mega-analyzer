package ml

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Feature Registry — versioned, hash-tracked feature catalog
// ─────────────────────────────────────────────────────────────────────────────
// Проблема: раньше фичи разбросаны по 10+ файлам (structural_signals.go,
// modern_smali_signals.go, vulnsignals_*.go …). Любое переименование фичи
// ломает историю и делает старые history.json несовместимыми — train/serve
// skew без предупреждения.
//
// Решение: единый реестр с версионированием, хешем схемы и дрейф-трекингом.
// Каждая фича регистрируется один раз с именем, версией и описанием.
// Хеш схемы = sha256(sorted names + versions) — инвалидирует кэш и
// предупреждает о необходимости переобучения.
//
// Использование:
//   registry := GlobalFeatureRegistry()
//   registry.MustRegister(FeatureDef{Name:"if_check_count", Version:1, Origin:"structural", ...})
//   schema := registry.Schema() // []string sorted
//   hash := registry.SchemaHash() // "a3f1…"
//   drift := registry.DriftFrom(storedHash)

// FeatureDef описывает одну фичу в реестре
type FeatureDef struct {
	Name        string  `json:"name"`
	Version     int     `json:"version"`
	Origin      string  `json:"origin"` // structural / behavioral / hdc / feedback / derived
	Description string  `json:"description"`
	Importance  float64 `json:"importance"` // prior importance (SHAP or heuristic), 0..1
	AddedAt     string  `json:"added_at"`
	Deprecated  bool    `json:"deprecated,omitempty"`
}

// FeatureRegistry — потокобезопасный реестр фич с версионированием
type FeatureRegistry struct {
	mu       sync.RWMutex
	defs     map[string]*FeatureDef
	version  int       // инкремент при каждом Register
	hash     string    // кеш хеша схемы
	hashDirty bool
	updatedAt time.Time
}

var (
	globalRegistry     *FeatureRegistry
	globalRegistryOnce sync.Once
)

// GlobalFeatureRegistry возвращает синглтон реестра (ленивая инициализация)
func GlobalFeatureRegistry() *FeatureRegistry {
	globalRegistryOnce.Do(func() {
		globalRegistry = NewFeatureRegistry()
		globalRegistry.registerBuiltin()
	})
	return globalRegistry
}

// NewFeatureRegistry — пустой реестр (для тестов)
func NewFeatureRegistry() *FeatureRegistry {
	return &FeatureRegistry{
		defs:      make(map[string]*FeatureDef),
		hashDirty: true,
		updatedAt: time.Now(),
	}
}

// Register добавляет или обновляет фичу. Версия должна монотонно расти.
func (r *FeatureRegistry) Register(def FeatureDef) error {
	if def.Name == "" {
		return fmt.Errorf("feature_registry: empty name")
	}
	if def.Version < 1 {
		def.Version = 1
	}
	if def.AddedAt == "" {
		def.AddedAt = time.Now().Format(time.RFC3339)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.defs[def.Name]; ok && def.Version < existing.Version {
		return fmt.Errorf("feature_registry: version downgrade for %q: %d < %d", def.Name, def.Version, existing.Version)
	}
	// копия
	cp := def
	r.defs[def.Name] = &cp
	r.version++
	r.hashDirty = true
	r.updatedAt = time.Now()
	return nil
}

// MustRegister паникует при ошибке — для init() регистрации builtin фич
func (r *FeatureRegistry) MustRegister(def FeatureDef) {
	if err := r.Register(def); err != nil {
		panic(err)
	}
}

// Get возвращает копию определения или nil
func (r *FeatureRegistry) Get(name string) *FeatureDef {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if d, ok := r.defs[name]; ok {
		cp := *d
		return &cp
	}
	return nil
}

// Len — число фич
func (r *FeatureRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.defs)
}

// Schema — отсортированный список имён активных (не deprecated) фич
func (r *FeatureRegistry) Schema() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.defs))
	for name, def := range r.defs {
		if !def.Deprecated {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// SchemaHash — sha256(sorted "name:version;") — стабилен между прогонами
func (r *FeatureRegistry) SchemaHash() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.hashDirty && r.hash != "" {
		return r.hash
	}
	names := make([]string, 0, len(r.defs))
	for name, def := range r.defs {
		if !def.Deprecated {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		def := r.defs[n]
		fmt.Fprintf(h, "%s:%d;", n, def.Version)
	}
	r.hash = hex.EncodeToString(h.Sum(nil))[:16]
	r.hashDirty = false
	return r.hash
}

// DriftFrom проверяет, отличается ли сохранённый хеш от текущего (нужно переобучение)
func (r *FeatureRegistry) DriftFrom(storedHash string) bool {
	return r.SchemaHash() != storedHash
}

// Version — монотонный счётчик изменений
func (r *FeatureRegistry) Version() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.version
}

// UpdatedAt — время последнего изменения
func (r *FeatureRegistry) UpdatedAt() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.updatedAt
}

// Snapshot — копия всех определений (для логов/отчётов)
func (r *FeatureRegistry) Snapshot() []FeatureDef {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]FeatureDef, 0, len(r.defs))
	for _, d := range r.defs {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// registerBuiltin — 30+ фич из текущего пайплайна, чтобы реестр сразу имел покрытие
func (r *FeatureRegistry) registerBuiltin() {
	builtin := []FeatureDef{
		// structural
		{Name: "instruction_count", Version: 1, Origin: "structural", Description: "Total Dalvik instructions in method", Importance: 0.85},
		{Name: "register_count", Version: 1, Origin: "structural", Description: "Number of virtual registers", Importance: 0.30},
		{Name: "return_count", Version: 1, Origin: "structural", Description: "Number of return instructions", Importance: 0.55},
		{Name: "if_check_count", Version: 1, Origin: "structural", Description: "Number of if-* conditional branches", Importance: 0.90},
		{Name: "has_dual_return", Version: 1, Origin: "structural", Description: "Has both return-true and return-false paths", Importance: 0.75},
		{Name: "has_if_with_return", Version: 1, Origin: "structural", Description: "if-* immediately followed by return", Importance: 0.70},
		{Name: "is_short_method", Version: 1, Origin: "structural", Description: "Method length 3..20 instructions", Importance: 0.40},
		{Name: "guard_count", Version: 1, Origin: "structural", Description: "CFG guards (DominatesExit)", Importance: 0.80},
		{Name: "hard_gate_count", Version: 1, Origin: "structural", Description: "Hard gates (ExitPostDominates)", Importance: 0.88},
		{Name: "funnel_detected", Version: 1, Origin: "structural", Description: "AND-funnel pattern in CFG", Importance: 0.65},
		// behavioral / API
		{Name: "has_security_api", Version: 1, Origin: "behavioral", Description: "Calls security-relevant API (billing/integrity)", Importance: 0.92},
		{Name: "security_call_count", Version: 1, Origin: "behavioral", Description: "Count of security API calls", Importance: 0.85},
		{Name: "has_security_strings", Version: 1, Origin: "behavioral", Description: "Contains security keywords in const-string", Importance: 0.60},
		{Name: "string_entropy", Version: 1, Origin: "behavioral", Description: "Average entropy of string constants", Importance: 0.45},
		{Name: "invoke_count", Version: 1, Origin: "behavioral", Description: "Total invoke-* count", Importance: 0.50},
		// derived / scoring
		{Name: "dfg_license_check_conf", Version: 1, Origin: "derived", Description: "DFG license check confidence (max)", Importance: 0.88},
		{Name: "dfg_bonus", Version: 1, Origin: "derived", Description: "DFG-derived bonus added to risk", Importance: 0.75},
		{Name: "structural_bonus", Version: 1, Origin: "derived", Description: "Structural signals bonus (guards+gates)", Importance: 0.78},
		{Name: "interesting_score", Version: 1, Origin: "derived", Description: "InterestingScorer total score", Importance: 0.60},
		{Name: "entry_point_priority", Version: 1, Origin: "derived", Description: "Entry point priority (0..10)", Importance: 0.65},
		{Name: "ensemble_score", Version: 1, Origin: "derived", Description: "Ensemble structural/entropy/taint blend", Importance: 0.70},
		{Name: "is_app_code", Version: 1, Origin: "derived", Description: "1 if app code, 0 if library", Importance: 0.80},
		{Name: "is_library", Version: 1, Origin: "derived", Description: "1 if known library prefix", Importance: 0.75},
		{Name: "is_accessor", Version: 1, Origin: "structural", Description: "Is synthetic accessor (access$000)", Importance: 0.35},
		{Name: "is_callback", Version: 1, Origin: "structural", Description: "Is callback (onClick, onResume...)", Importance: 0.30},
		{Name: "has_check_prefix", Version: 1, Origin: "structural", Description: "Name starts with is*/check*/verify*", Importance: 0.55},
		{Name: "has_security_name", Version: 1, Origin: "structural", Description: "Name contains security keyword", Importance: 0.60},
		// HDC / graph
		{Name: "hdc_anchor_max_sim", Version: 1, Origin: "hdc", Description: "Max HDC Jaccard similarity to anchors", Importance: 0.70},
		{Name: "hdc_anchor_mean_sim", Version: 1, Origin: "hdc", Description: "Mean HDC similarity", Importance: 0.45},
		{Name: "graph_node_count", Version: 1, Origin: "structural", Description: "CFG node count", Importance: 0.50},
		{Name: "graph_edge_count", Version: 1, Origin: "structural", Description: "CFG edge count", Importance: 0.40},
		{Name: "graph_cyclomatic", Version: 1, Origin: "structural", Description: "Cyclomatic complexity", Importance: 0.55},
	}
	for _, d := range builtin {
		_ = r.Register(d)
	}
}
