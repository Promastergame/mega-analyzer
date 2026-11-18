package matcher

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestFossifyIdentifierBoundaries(t *testing.T) {
	compiled, err := Compile()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		text     string
		category types.Category
		want     bool
	}{
		{".method public isProperSDFolder()Z", types.CategoryPremiumCheck, false},
		{".method public isProjected()Z", types.CategoryPremiumCheck, false},
		{".field private isProvidingHint:Z", types.CategoryPremiumCheck, false},
		{"invoke-static {}, Lapp/A;->hasProperStoredDocumentUri()Z", types.CategoryPremiumCheck, false},
		{"invoke-virtual {}, Lapp/A;->showAddIncludedFolderDialog()V", types.CategoryAdShow, false},
		{"invoke-virtual {}, Landroid/view/View;->isActivated()Z", types.CategoryLicenseCheck, false},
		{".method public isPro()Z", types.CategoryPremiumCheck, true},
		{".method public isProUser()Z", types.CategoryPremiumCheck, true},
		{".method public hasProAccess()Z", types.CategoryPremiumCheck, true},
		{"invoke-virtual {}, Lapp/Ads;->showAd()V", types.CategoryAdShow, true},
		{"invoke-virtual {}, Lapp/License;->isLicenseActivated()Z", types.CategoryLicenseCheck, true},
	} {
		t.Run(tc.text, func(t *testing.T) {
			got := false
			for _, group := range compiled.Groups {
				if group.Category != tc.category {
					continue
				}
				for _, pattern := range group.Patterns {
					got = got || pattern.Regex.MatchString(tc.text)
				}
			}
			if got != tc.want {
				t.Fatalf("category %s: match=%v, want %v", tc.category, got, tc.want)
			}
		})
	}
}
