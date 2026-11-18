package pipeline

import (
	"bytes"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/types"
)

func hasPaymentAPI(contentLower []byte) bool {
	for _, api := range []string{"lcom/android/billingclient/api/", "lcom/android/vending/billing/", "ibillingservice", "->launchbillingflow(", "->querypurchases", "->queryskudetails", "->queryproductdetails", "com/revenuecat/purchases/"} {
		if bytes.Contains(contentLower, []byte(api)) {
			return true
		}
	}
	return false
}

// VPN feeds, telephony SubscriptionManager and reactive-library subscriptions
// share this vocabulary with paid billing. Preserve the literal as inventory
// unless payment APIs corroborate this occurrence, rather than invent a paywall.
func normalizeSubscriptionVocabulary(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx == nil || analysis == nil {
		return
	}
	for i := range analysis.Matches {
		m := &analysis.Matches[i]
		switch m.Category {
		case types.CategorySubscription, types.CategorySubscriptionCheck, types.CategoryRecurringPay:
		default:
			continue
		}
		// m.Pattern is not always a literal: resource-name patterns arrive as a
		// path ("res/layout/purchase.xml"), which never occurs verbatim in the
		// smali text. In that case corroborate against the whole file instead of
		// downgrading a real billing integration to "vocabulary observation".
		window := ctx.ContentLower
		if idx := bytes.Index(ctx.ContentLower, bytes.ToLower([]byte(m.Pattern))); idx >= 0 {
			window = getSurrounding(ctx.ContentLower, idx, billingEvidenceWindow)
		}
		if hasPaymentAPI(window) {
			continue
		}
		m.Category, m.Severity, m.IsCritical = types.CategoryVocabularyObservation, types.SeverityInfo, false
		m.Score, m.Scored.Confidence = 0, 0.9
		m.Text = "Subscription vocabulary; paid billing not established"
		m.Context = "A subscription-related word or resource name was found without corroborating payment APIs near this occurrence. It may describe a VPN feed, telephony or a library observer."
		if m.Metadata == nil {
			m.Metadata = make(map[string]string)
		}
		m.Metadata["title"], m.Metadata["finding_kind"] = m.Text, "inventory"
		m.Explanation = &finding.Explanation{Status: "observation", Summary: m.Context,
			Limitations: []string{"Vocabulary alone does not show a paid subscription, purchase flow or charged account."},
			NextChecks:  []string{"Inspect the enclosing method and actual billing SDK/API usage before assigning a payment role."}}
	}
}
