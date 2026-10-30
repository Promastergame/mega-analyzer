package ml

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

const (
	FeedbackRelevant = "relevant"
	FeedbackNoise    = "noise"
	FeedbackNeutral  = "neutral"
)

// UserOverrideTarget returns the user-facing target of an override. Keyword is
// preferred because legacy CLI records stored keyword feedback in both Path and
// Keyword, and treating such values as paths made broad substring filters fire.
func UserOverrideTarget(override UserOverride) string {
	if keyword := strings.TrimSpace(override.Keyword); keyword != "" {
		return keyword
	}
	return strings.TrimSpace(override.Path)
}

// NormalizeFeedbackTarget creates the stable identity used to reconcile
// feedback written by different CLI versions and operating systems.
func NormalizeFeedbackTarget(target string) string {
	target = strings.TrimSpace(target)
	target = strings.ReplaceAll(target, "\\", "/")
	for strings.Contains(target, "//") {
		target = strings.ReplaceAll(target, "//", "/")
	}
	target = strings.TrimPrefix(target, "./")
	return strings.ToLower(target)
}

func normalizeFeedbackAction(action string) string {
	return strings.ToLower(strings.TrimSpace(action))
}

func validFeedbackAction(action string) bool {
	switch normalizeFeedbackAction(action) {
	case FeedbackRelevant, FeedbackNoise, FeedbackNeutral:
		return true
	default:
		return false
	}
}

func userOverrideKey(override UserOverride) string {
	target := NormalizeFeedbackTarget(UserOverrideTarget(override))
	if target == "" {
		return ""
	}
	kind := "path:"
	if strings.TrimSpace(override.Keyword) != "" {
		kind = "keyword:"
	}
	return kind + target
}

type resolvedOverride struct {
	override UserOverride
	when     time.Time
	order    int
}

func trainingUserOverrideKey(override UserOverride) string {
	baseKey := userOverrideKey(override)
	if baseKey == "" {
		return ""
	}
	key := baseKey + "|apk:" + NormalizeFeedbackTarget(override.APKName)
	if override.Features != nil {
		data, _ := json.Marshal(override.Features)
		sum := sha256.Sum256(data)
		key += "|features:" + hex.EncodeToString(sum[:])
	}
	return key
}

// ResolveUserOverrideDecisions reconciles the append-only feedback journal.
// There is exactly one decision per normalized target; the newest timestamp
// wins and stream order breaks ties. Neutral decisions are retained here as
// tombstones so callers that build labels can explicitly clear an old label.
func ResolveUserOverrideDecisions(records []*AnalysisFeedback) []UserOverride {
	latest := make(map[string]resolvedOverride)
	order := 0
	for _, record := range records {
		if record == nil {
			continue
		}
		for _, raw := range record.UserOverrides {
			order++
			action := normalizeFeedbackAction(raw.Action)
			key := userOverrideKey(raw)
			if key == "" || !validFeedbackAction(action) {
				continue
			}

			candidate := raw
			candidate.Action = action
			when := candidate.Timestamp
			if when.IsZero() {
				when = record.Timestamp
			}
			previous, exists := latest[key]
			// A missing timestamp means ordering information is unavailable, so
			// append order is the safest tie-breaker. When both timestamps exist,
			// preserve the genuinely newer event even if an old event was copied
			// into a later history record.
			if exists && !when.IsZero() && !previous.when.IsZero() && when.Before(previous.when) {
				continue
			}
			latest[key] = resolvedOverride{override: candidate, when: when, order: order}
		}
	}

	keys := make([]string, 0, len(latest))
	for key := range latest {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]UserOverride, 0, len(keys))
	for _, key := range keys {
		result = append(result, latest[key].override)
	}
	return result
}

// ResolveUserOverrides returns only active noise/relevant decisions. It is the
// canonical view for inference, reports, and suggestion filtering.
func ResolveUserOverrides(records []*AnalysisFeedback) []UserOverride {
	decisions := ResolveUserOverrideDecisions(records)
	active := decisions[:0]
	for _, decision := range decisions {
		if decision.Action == FeedbackRelevant || decision.Action == FeedbackNoise {
			active = append(active, decision)
		}
	}
	return active
}

// FindUserOverrideDecision returns the effective decision for target. The
// boolean is true for a neutral tombstone as well as for active decisions.
func FindUserOverrideDecision(records []*AnalysisFeedback, target string, keyword bool) (UserOverride, bool) {
	probe := UserOverride{Path: target}
	if keyword {
		probe.Keyword = target
	}
	key := userOverrideKey(probe)
	for _, decision := range ResolveUserOverrideDecisions(records) {
		if userOverrideKey(decision) == key {
			return decision, true
		}
	}
	return UserOverride{}, false
}

// IsDuplicateUserOverride reports whether candidate would add any information
// to the journal. Label-only repeats are idempotent; feature-bearing feedback
// is only a duplicate when target, APK, feature vector, and action all match.
func IsDuplicateUserOverride(records []*AnalysisFeedback, candidate UserOverride) bool {
	candidate.Action = normalizeFeedbackAction(candidate.Action)
	if userOverrideKey(candidate) == "" || !validFeedbackAction(candidate.Action) {
		return false
	}
	if candidate.Features == nil {
		for _, decision := range ResolveUserOverrideDecisions(records) {
			if userOverrideKey(decision) == userOverrideKey(candidate) {
				return decision.Action == candidate.Action
			}
		}
		return false
	}

	candidateKey := trainingUserOverrideKey(candidate)
	for _, existing := range ResolveTrainingUserOverrides(records) {
		if trainingUserOverrideKey(existing) == candidateKey && existing.Action == candidate.Action {
			return true
		}
	}
	return false
}

// ResolveTrainingUserOverrides produces one current label per target, APK and
// feature vector. This removes overrides copied into later history records and
// prevents corrected labels from entering train/calibration as contradictions,
// while still allowing the same target to provide distinct examples in other
// APKs or with another feature vector.
func ResolveTrainingUserOverrides(records []*AnalysisFeedback) []UserOverride {
	latest := make(map[string]resolvedOverride)
	order := 0
	for _, record := range records {
		if record == nil {
			continue
		}
		for _, raw := range record.UserOverrides {
			order++
			action := normalizeFeedbackAction(raw.Action)
			baseKey := userOverrideKey(raw)
			if baseKey == "" || !validFeedbackAction(action) {
				continue
			}

			candidate := raw
			candidate.Action = action
			key := trainingUserOverrideKey(candidate)

			when := candidate.Timestamp
			if when.IsZero() {
				when = record.Timestamp
			}
			previous, exists := latest[key]
			if exists && !when.IsZero() && !previous.when.IsZero() && when.Before(previous.when) {
				continue
			}
			latest[key] = resolvedOverride{override: candidate, when: when, order: order}
		}
	}

	resolved := make([]resolvedOverride, 0, len(latest))
	for _, decision := range latest {
		if decision.override.Action == FeedbackRelevant || decision.override.Action == FeedbackNoise {
			resolved = append(resolved, decision)
		}
	}
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].order < resolved[j].order })
	result := make([]UserOverride, len(resolved))
	for i := range resolved {
		result[i] = resolved[i].override
	}
	return result
}
