package pipeline

import (
	"strings"

	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/logger"
)

// Accessibility capability rule, final-form enforcement.
//
// Code-level accessibility references (API calls, AccessibilityService
// subclasses, gesture/click simulation) only describe a capability of the app
// when BOTH hold: a <service> bound with BIND_ACCESSIBILITY_SERVICE in the
// manifest and a class that actually extends AccessibilityService. Compat
// libraries alone must never produce the signal.
//
// The detector emits during per-file processing, while the manifest and the
// subclass class may be parsed later (workers run concurrently), so a final
// sweep after all files are processed drops code-level accessibility matches
// from runs where the capability never got confirmed.

// accessibilityServiceSuperclass is the framework class an accessibility
// service must extend (SmaliClass.SuperClass is stored dotted).
const accessibilityServiceSuperclass = "android.accessibilityservice.AccessibilityService"

// sweepUnconfirmedAccessibility drops unconfirmed code-level accessibility
// matches and keeps the aggregate match statistics consistent with what is
// left.
func (p *Pipeline) sweepUnconfirmedAccessibility() {
	if p.result == nil {
		return
	}
	if p.accessibilityCapabilityConfirmed() {
		return
	}

	dropped := 0
	droppedCritical := 0
	for _, fa := range p.result.Files {
		if fa == nil || len(fa.Matches) == 0 {
			continue
		}
		kept := fa.Matches[:0]
		for _, m := range fa.Matches {
			if unconfirmedAccessibilityMatch(&m) {
				dropped++
				if m.IsCritical {
					droppedCritical++
				}
				if p.result.MatchesByCategory != nil {
					p.result.MatchesByCategory[m.Category]--
				}
				p.result.Stats.TotalMatches--
				if m.IsCritical {
					p.result.Stats.CriticalMatches--
				}
				continue
			}
			kept = append(kept, m)
		}
		fa.Matches = kept
	}
	if dropped > 0 {
		logger.Warn("accessibility capability not confirmed: dropped code-level matches",
			"dropped", dropped, "critical", droppedCritical)
	}
}

// accessibilityCapabilityConfirmed recomputes the capability rule from final
// results, independent of per-file processing order: the manifest declares a
// BIND_ACCESSIBILITY_SERVICE binding and some class extends
// AccessibilityService. The binding is accepted from either the parsed
// <uses-permission> list or the detector's own manifest match — services
// declare the binding via the android:permission attribute, which the
// permission list does not include.
func (p *Pipeline) accessibilityCapabilityConfirmed() bool {
	hasBinding := false
	for _, fa := range p.result.Files {
		if fa == nil {
			continue
		}
		if fa.XMLData != nil {
			for _, perm := range fa.XMLData.Permissions {
				if strings.EqualFold(strings.TrimSpace(perm), "android.permission.BIND_ACCESSIBILITY_SERVICE") {
					hasBinding = true
					break
				}
			}
		}
		if !hasBinding {
			for i := range fa.Matches {
				m := &fa.Matches[i]
				if strings.HasPrefix(m.Context, "Accessibility Service binding declared") ||
					strings.HasPrefix(m.Metadata["title"], "Accessibility Service binding declared") {
					hasBinding = true
					break
				}
			}
		}
		if hasBinding {
			break
		}
	}
	if !hasBinding {
		return false
	}
	for _, fa := range p.result.Files {
		if fa == nil || fa.SmaliClass == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(fa.SmaliClass.SuperClass), accessibilityServiceSuperclass) {
			return true
		}
	}
	return false
}

// unconfirmedAccessibilityMatch matches the text shapes emitted by the
// accessibility detector's code-level sections (API calls, subclass notes,
// gesture/click simulation). Config C2/geo matches keep their own text and
// are never dropped here.
func unconfirmedAccessibilityMatch(m *types.Match) bool {
	// The detector stores the label in Context and Metadata["title"]; Text
	// carries the code snippet. Check all three surfaces.
	for _, t := range []string{m.Context, m.Metadata["title"], m.Text} {
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "AccessibilityService API: ") ||
			strings.HasPrefix(t, "Custom AccessibilityService implementation") ||
			strings.HasPrefix(t, "Gesture/click simulation: ") ||
			strings.Contains(t, "Multiple click simulations") {
			return true
		}
	}
	return false
}
