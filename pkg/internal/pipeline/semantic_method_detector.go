package pipeline

import (
	"bytes"
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

type SemanticMethodDetector struct {
	accessPatterns []semanticPattern
	fieldPatterns  []semanticPattern
}

type semanticPattern struct {
	pattern     string
	patternLow  []byte
	description string
	category    types.Category
	critical    bool
	weight      int
}

func NewSemanticMethodDetector() *SemanticMethodDetector {
	d := &SemanticMethodDetector{}

	d.accessPatterns = []semanticPattern{
		{"entitlement", nil, "Entitlement check", types.CategoryPremiumCheck, true, 10},
		{"hasaccess", nil, "Access check", types.CategoryPremiumCheck, true, 9},
		{"canaccess", nil, "Access permission", types.CategoryPremiumCheck, true, 9},
		{"accesslevel", nil, "Access level", types.CategoryPremiumCheck, true, 8},
		{"accesstier", nil, "Access tier", types.CategoryPremiumCheck, true, 8},
		{"usertier", nil, "User tier check", types.CategoryPremiumCheck, true, 9},
		{"membershiplevel", nil, "Membership level", types.CategoryPremiumCheck, true, 8},
		{"accountlevel", nil, "Account level", types.CategoryPremiumCheck, true, 8},
		{"featuregate", nil, "Feature gate", types.CategoryFeatureFlags, true, 9},
		{"paywall", nil, "Paywall logic", types.CategorySubscription, true, 10},
		{"showpaywall", nil, "Show paywall", types.CategorySubscription, true, 10},
		{"shouldshowpaywall", nil, "Paywall decision", types.CategorySubscription, true, 10},
		{"purchasemanager", nil, "Purchase manager", types.CategoryBillingClient, true, 9},
		{"iapmanager", nil, "IAP manager", types.CategoryBillingClient, true, 9},
		{"validatereceipt", nil, "Receipt validation", types.CategoryPurchaseVerify, true, 10},
		{"verifyreceipt", nil, "Receipt verification", types.CategoryPurchaseVerify, true, 10},
	}

	d.fieldPatterns = []semanticPattern{
		{"isentitled", nil, "Entitlement flag", types.CategoryPremiumCheck, true, 9},
		{"hasentitlement", nil, "Has entitlement", types.CategoryPremiumCheck, true, 9},
		{"accessgranted", nil, "Access granted flag", types.CategoryPremiumCheck, true, 8},
	}

	for i := range d.accessPatterns {
		d.accessPatterns[i].patternLow = []byte(strings.ToLower(d.accessPatterns[i].pattern))
	}
	for i := range d.fieldPatterns {
		d.fieldPatterns[i].patternLow = []byte(strings.ToLower(d.fieldPatterns[i].pattern))
	}

	return d
}

func (d *SemanticMethodDetector) Name() string { return "semantic_methods" }

func (d *SemanticMethodDetector) SupportsFile(fileType types.FileType, _ string) bool {
	return fileType == types.FileTypeSmali
}

func (d *SemanticMethodDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if !ctx.IsAppCode {
		return
	}
	if ctx.FileType != types.FileTypeSmali {
		return
	}

	// Access/tier vocabulary (hasAccess, accessLevel, ...) is ordinary game
	// code (level access, area access). Critical only when billing/licensing
	// machinery appears NEAR this specific occurrence (per-match window, not
	// a whole-file signal that misfires on classes touching IAP broadly).
	d.detectAccessMethods(ctx, analysis)
	d.detectFieldAccess(ctx, analysis)
	// detectBooleanChecks УДАЛЁН — генерировал 6000+ ложных срабатываний
}

func (d *SemanticMethodDetector) detectAccessMethods(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	for _, sp := range d.accessPatterns {
		if idx := bytes.Index(ctx.ContentLower, sp.patternLow); idx >= 0 {
			if sp.pattern == "hasaccess" || sp.pattern == "canaccess" {
				window := getSurrounding(ctx.ContentLower, idx, billingEvidenceWindow)
				if !hasBillingMachinery(window) && !bytes.Contains(window, []byte("premium")) && !bytes.Contains(window, []byte("entitlement")) {
					continue
				}
			}
			// Android accessibility APIs (hasAccessibility*, AccessibilityService,
			// Daltonizer, etc.) contain "hasaccess"/"access..." as substrings but
			// are OS accessibility probes — never premium/entitlement gates.
			// Seen in the wild: hasAccessibilityDisplayDaltonizer matched as
			// "Access check" → false client_side_auth_gate chain (subwaysurf).
			if isAccessibilityAPIContext(getSurrounding(ctx.ContentLower, idx, 64)) {
				continue
			}
			surrounding := getSurrounding(ctx.Content, idx, 50)
			if bytes.Contains(surrounding, []byte(".method")) ||
				bytes.Contains(surrounding, []byte("->")) {
				line := lineAt(ctx.LineOffsets, idx)
				analysis.Matches = append(analysis.Matches, types.Match{
					SourceLocation: types.SourceLocation{
						File: analysis.Path,
						Line: line,
					},
					Categorized: types.Categorized{Category: sp.category},
					Pattern:     sp.description,
					Text:        types.TruncateString(string(surrounding), 150),
					IsCritical:  sp.critical && hasBillingMachinery(getSurrounding(ctx.ContentLower, idx, billingEvidenceWindow)),
					Scored:      types.Scored{Score: float64(sp.weight)},
				})
			}
		}
	}
}

func (d *SemanticMethodDetector) detectFieldAccess(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	for _, sp := range d.fieldPatterns {
		if idx := bytes.Index(ctx.ContentLower, sp.patternLow); idx >= 0 {
			// Same accessibility exclusion as methods: getAccessibility* /
			// AccessibilityService field traffic is not an entitlement flag.
			if isAccessibilityAPIContext(getSurrounding(ctx.ContentLower, idx, 64)) {
				continue
			}
			surrounding := getSurrounding(ctx.Content, idx, 40)
			if bytes.Contains(surrounding, []byte("get")) ||
				bytes.Contains(surrounding, []byte("put")) ||
				bytes.Contains(surrounding, []byte(".field")) {
				line := lineAt(ctx.LineOffsets, idx)
				analysis.Matches = append(analysis.Matches, types.Match{
					SourceLocation: types.SourceLocation{
						File: analysis.Path,
						Line: line,
					},
					Categorized: types.Categorized{Category: sp.category},
					Pattern:     fmt.Sprintf("Field: %s", sp.description),
					Text:        types.TruncateString(string(surrounding), 150),
					IsCritical:  sp.critical && hasBillingMachinery(getSurrounding(ctx.ContentLower, idx, billingEvidenceWindow)),
				})
			}
		}
	}
}

// isAccessibilityAPIContext reports whether the lower-cased window around a
// candidate access-pattern hit belongs to an Android accessibility API
// (AccessibilityService, hasAccessibility*, getAccessibility*, daltonizer,
// captioning, touch exploration...). Those share the "access" substring with
// entitlement vocabulary but are OS probes, never license gates.
func isAccessibilityAPIContext(windowLower []byte) bool {
	return bytes.Contains(windowLower, []byte("accessibility")) ||
		bytes.Contains(windowLower, []byte("daltonizer")) ||
		bytes.Contains(windowLower, []byte("captioning")) ||
		bytes.Contains(windowLower, []byte("touchexploration")) ||
		bytes.Contains(windowLower, []byte("accessibilityservice"))
}
