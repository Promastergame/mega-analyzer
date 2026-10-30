package ml

import (
	"sort"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

type EconomyInfo = shared.EconomyInfo
type EconomyEvidence = shared.EconomyEvidence
type EconomyRelation = shared.EconomyRelation

const (
	EconomyBalanceRead  = "balance_read"
	EconomyBalanceWrite = "balance_write"
	EconomySpend        = "spend"
	EconomyReward       = "reward"
	EconomyPrice        = "price"
	EconomyAfford       = "affordability"
	EconomyValidation   = "validation"
	EconomyDisplay      = "display"
)

// One vocabulary is shared by discovery, scoring, generation and exported
// search metadata. Aliases match whole identifier/key tokens, not substrings.
type ResourceDefinition struct {
	ID      string   `json:"id"`
	Label   string   `json:"label"`
	LabelRu string   `json:"label_ru"`
	Aliases []string `json:"aliases"`
}

var resourceDefinitions = []ResourceDefinition{
	{"coins", "Coins", "Монеты", []string{"coin", "coins", "монета", "монеты", "монет", "moneta", "monety", "monet"}},
	{"diamonds", "Diamonds", "Алмазы", []string{"diamond", "diamonds", "алмаз", "алмазы", "алмазов", "almaz", "almazy"}},
	{"gems", "Gems", "Самоцветы", []string{"gem", "gems", "самоцвет", "самоцветы"}},
	{"crystals", "Crystals", "Кристаллы", []string{"crystal", "crystals", "кристалл", "кристаллы", "kristall"}},
	{"gold", "Gold", "Золото", []string{"gold", "золото", "zoloto"}},
	{"silver", "Silver", "Серебро", []string{"silver", "серебро", "serebro"}},
	{"rubies", "Rubies", "Рубины", []string{"ruby", "rubies", "рубин", "рубины"}},
	{"jewels", "Jewels", "Драгоценности", []string{"jewel", "jewels", "emerald", "emeralds"}},
	{"money", "Money", "Деньги", []string{"money", "cash", "bucks", "деньги", "dengi", "dengy"}},
	{"currency", "Currency", "Валюта", []string{"currency", "balance", "wallet", "валюта", "баланс"}},
	{"credits", "Credits", "Кредиты", []string{"credit", "credits", "кредит", "кредиты"}},
	{"energy", "Energy", "Энергия", []string{"energy", "stamina", "энергия", "выносливость", "energiya"}},
	{"lives", "Lives", "Жизни", []string{"life", "lives", "heart", "hearts", "жизни", "жизнь", "zhizni"}},
	{"health", "Health", "Здоровье", []string{"health", "hp", "здоровье"}},
	{"mana", "Mana", "Мана", []string{"mana", "мана"}},
	{"fuel", "Fuel", "Топливо", []string{"fuel", "топливо"}},
	{"ammo", "Ammo", "Боеприпасы", []string{"ammo", "ammunition", "bullets", "патроны"}},
	{"tickets", "Tickets", "Билеты", []string{"ticket", "tickets", "билет", "билеты"}},
	{"tokens", "Tokens", "Жетоны", []string{"token", "tokens", "жетон", "жетоны"}},
	{"keys", "Keys", "Ключи", []string{"key", "keys", "ключ", "ключи", "klyuchi"}},
	{"spins", "Spins", "Вращения", []string{"spin", "spins", "rolls", "summons", "вращения"}},
	{"fragments", "Fragments", "Фрагменты", []string{"fragment", "fragments", "shard", "shards", "фрагменты", "осколки"}},
	{"boosters", "Boosters", "Усилители", []string{"booster", "boosters", "powerup", "powerups", "hints", "усилители", "подсказки"}},
	{"moves", "Moves", "Ходы", []string{"move", "moves", "turns", "actions", "ходы"}},
	{"points", "Points", "Очки", []string{"point", "points", "stars", "score", "очки", "звезды", "ochki"}},
	{"medals", "Medals", "Медали", []string{"medal", "medals", "медаль", "медали"}},
	{"trophies", "Trophies", "Трофеи", []string{"trophy", "trophies", "cup", "cups", "трофей", "трофеи", "кубок"}},
	{"crowns", "Crowns", "Короны", []string{"crown", "crowns", "корона", "короны"}},
	{"elixir", "Elixir", "Эликсир", []string{"elixir", "эликсир"}},
	{"runes", "Runes", "Руны", []string{"rune", "runes", "руна", "руны"}},
	{"items", "Items", "Предметы", []string{"item", "items", "resource", "resources", "material", "materials", "scrolls", "orbs", "essence", "stardust", "предметы", "ресурсы"}},
}

var resourceAliasIndex = func() map[string]string {
	m := make(map[string]string)
	for _, def := range resourceDefinitions {
		for _, alias := range def.Aliases { m[alias] = def.ID }
	}
	return m
}()

// ResourceDefinitions returns a copy so callers cannot mutate the vocabulary.
func ResourceDefinitions() []ResourceDefinition {
	out := append([]ResourceDefinition(nil), resourceDefinitions...)
	for i := range out { out[i].Aliases = append([]string(nil), out[i].Aliases...) }
	return out
}

var economyWords = func() []string {
	set := map[string]bool{}
	for alias := range resourceAliasIndex { set[alias] = true }
	for _, word := range strings.Fields("get set add earn grant award reward collect increase increment spend deduct consume remove decrease decrement save update put load read fetch current total amount count remaining owned available enough afford sufficient has can is check validate verify price prices cost costs required free paid premium hard soft chest gacha inventory max min id index frame animation icon color colour texture sprite image text label format code type kind ordinal time timestamp duration rate expiry expired regeneration cooldown name list size length offset") { set[word] = true }
	words := make([]string, 0, len(set))
	for word := range set { words = append(words, word) }
	sort.Slice(words, func(i, j int) bool { if len(words[i]) != len(words[j]) { return len(words[i]) > len(words[j]) }; return words[i] < words[j] })
	return words
}()

func economyTokens(name string) []string {
	tokens := splitIdentifierTokens(strings.ReplaceAll(name, "ё", "е"))
	var out []string
	for _, token := range tokens {
		// Already lowercased Java names and concatenated save keys are common.
		// Accept only a complete segmentation into known words.
		var parts []string
		rest := token
		for rest != "" {
			matched := false
			for _, word := range economyWords {
				if strings.HasPrefix(rest, word) { parts = append(parts, word); rest = rest[len(word):]; matched = true; break }
			}
			if !matched { parts = nil; break }
		}
		if len(parts) == 0 { parts = economyAffixSplit(token) }
		if len(parts) > 0 { out = append(out, parts...) } else { out = append(out, token) }
	}
	return out
}

// economyAffixSplit tolerates a short unknown PREFIX (my|re|un + coins) when
// the remainder segments cleanly into known words. Suffixes are deliberately
// NOT stripped beyond s/es plurals: stripping "ume" off "costume" would invent
// a price where there is a garment. The affix itself is kept as a token so it
// can still veto (non-amount words) but never invents a resource.
func economyAffixSplit(token string) []string {
	runes := []rune(token)
	segment := func(s string) []string {
		var parts []string
		rest := s
		for rest != "" {
			matched := false
			for _, word := range economyWords {
				if strings.HasPrefix(rest, word) { parts = append(parts, word); rest = rest[len(word):]; matched = true; break }
			}
			if !matched { return nil }
		}
		return parts
	}
	for _, n := range []int{1, 2, 3} {
		if n >= len(runes) { continue }
		if tail := segment(string(runes[n:])); len(tail) > 0 {
			return append([]string{string(runes[:n])}, tail...)
		}
	}
	for _, suffix := range []string{"es", "s"} {
		if strings.HasSuffix(token, suffix) && len(token) > len(suffix)+1 {
			if stem := segment(strings.TrimSuffix(token, suffix)); len(stem) > 0 {
				return append(stem, suffix)
			}
		}
	}
	return nil
}

func tokenIn(tokens []string, words ...string) bool {
	for _, token := range tokens { for _, word := range words { if token == word { return true } } }
	return false
}

func resourcesIn(name string) []string {
	var resources []string
	for _, token := range economyTokens(name) { if id := resourceAliasIndex[token]; id != "" { resources = appendUniqueString(resources, id) } }
	// A specific unit is more useful than an additional generic "balance" tag.
	if len(resources) > 1 {
		out := resources[:0]
		for _, resource := range resources { if resource != "currency" && resource != "items" { out = append(out, resource) } }
		if len(out) > 0 { resources = out }
	}
	sort.Strings(resources)
	return resources
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values { if existing == value { return values } }
	return append(values, value)
}

func economyNonAmountName(name string) bool {
	return tokenIn(economyTokens(name), "id", "ids", "uid", "index", "idx", "frame", "animation", "icon", "color", "colour", "texture", "sprite", "image", "text", "label", "format", "code", "type", "kind", "ordinal", "offset", "name", "list", "size", "length", "timestamp", "time", "duration", "expiry", "expired", "cooldown", "regeneration", "rate", "tier", "tiers", "level", "levels", "lvl", "version", "ver", "state", "status", "mode", "category", "categories", "compare", "compareto", "hash", "hashcode", "pos", "position", "slot", "slots", "кадр", "иконка", "текст", "цвет", "уровень", "тип", "версия", "режим", "состояние", "статус")
}

func economyOperation(name string, rt string) string {
	tokens := economyTokens(name)
	if economyNonAmountName(name) { return EconomyDisplay }
	if tokenIn(tokens, "price", "prices", "cost", "costs", "цена", "стоимость") { return EconomyPrice }
	if tokenIn(tokens, "spend", "deduct", "consume", "remove", "decrease", "decrement", "потратить", "списать") { return EconomySpend }
	if tokenIn(tokens, "add", "earn", "grant", "award", "reward", "collect", "increase", "increment", "начислить", "добавить") { return EconomyReward }
	if tokenIn(tokens, "set", "save", "update", "put", "сохранить") { return EconomyBalanceWrite }
	if rt == "Z" {
		if tokenIn(tokens, "validate", "verify", "valid", "integrity", "checksum") { return EconomyValidation }
		if tokenIn(tokens, "can", "has", "enough", "afford", "sufficient") { return EconomyAfford }
		return ""
	}
	if isEconomyNumber(rt) { return EconomyBalanceRead }
	return ""
}

func isEconomyNumber(rt string) bool { return len(rt) == 1 && strings.Contains("BSCIJFD", rt) }

func isEconomyCandidate(info *EconomyInfo) bool {
	if info == nil || len(info.Resources) == 0 { return false }
	switch info.Operation {
	case EconomyBalanceRead, EconomyPrice:
		return isEconomyNumber(info.ValueType)
	case EconomyBalanceWrite, EconomySpend, EconomyReward:
		return info.ValueLinked || isEconomyNumber(info.ValueType)
	case EconomyAfford, EconomyValidation:
		return info.ValueType == "Z"
	}
	return false
}

func economyForMethod(mi *MethodInfo) *EconomyInfo {
	if mi == nil { return nil }
	if mi.Economy != nil || mi.economyScanned { return mi.Economy }
	info, _ := analyzeEconomyMethod(mi, nil)
	return info
}

func isResourceValueMethod(mi *MethodInfo) bool {
	info := economyForMethod(mi)
	return isEconomyCandidate(info) && info.ValueLinked && (info.Operation == EconomyBalanceRead || info.Operation == EconomyPrice)
}

// isEconomyTransactionMethod reports a linked spend/reward/write: the value is
// tied to a named field or key, so tiny-body and no-branch heuristics must not
// dismiss it as a decoy or a non-gate. It still needs transaction review and
// never receives an automatic rewrite.
func isEconomyTransactionMethod(mi *MethodInfo) bool {
	info := economyForMethod(mi)
	if !isEconomyCandidate(info) || !info.ValueLinked {
		return false
	}
	switch info.Operation {
	case EconomySpend, EconomyReward, EconomyBalanceWrite:
		return true
	}
	return false
}
