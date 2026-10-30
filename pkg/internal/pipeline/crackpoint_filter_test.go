package pipeline

import (
	"reflect"
	"testing"

	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/internal/crackpoint"
	"mega-analyzer/pkg/internal/types"
)

func TestIsAlwaysFilteredSDKKeepsAppsFlyerLVL(t *testing.T) {
	if isAlwaysFilteredSDK(
		`smali\com\appsflyer\lvl\AppsFlyerLVLImpl.smali`,
		"Lcom/appsflyer/lvl/AppsFlyerLVLImpl;",
	) {
		t.Fatal("AppsFlyer LVL wrapper should remain eligible for crack-point analysis")
	}

	if !isAlwaysFilteredSDK(
		`smali\com\appsflyer\internal\AFj1kSDK.smali`,
		"Lcom/appsflyer/internal/AFj1kSDK;",
	) {
		t.Fatal("AppsFlyer internals should remain filtered as SDK noise")
	}
}

func TestAnalyzeCrackPointsReusesCachedCFG(t *testing.T) {
	method := types.SmaliMethod{
		Name: "checkLicense", Params: "()", ReturnType: "Z",
		Body: []string{
			"    .registers 1",
			"    const/4 v0, 0x1",
			"    return v0",
		},
	}
	class := &types.SmaliClass{
		Name:    "Lcom/example/License;",
		Methods: []types.SmaliMethod{method},
	}
	graph := buildMethodCFG(cfg.NewCFGBuilder(), class.Name, &class.Methods[0])
	if graph == nil {
		t.Fatal("fixture CFG is nil")
	}
	fa := &types.FileAnalysis{
		Path: "smali/com/example/License.smali", SmaliClass: class,
		MethodCFGs: []*cfg.ControlFlowGraph{graph},
	}

	cached := analyzeCrackPoints(crackpoint.NewFinder(), fa, class.Name, nil, nil)
	fa.MethodCFGs = nil
	fresh := analyzeCrackPoints(crackpoint.NewFinder(), fa, class.Name, nil, nil)
	if !reflect.DeepEqual(cached, fresh) {
		t.Fatalf("cached CFG changed crack-point output:\ncached=%#v\nfresh=%#v", cached, fresh)
	}
}

func TestDedupeCrackPointsCollapsesDuplicatesAndCallbacks(t *testing.T) {
	licenseFile := `smali\com\android\vending\licensing\ILicensingService$Stub.smali`
	licenseClass := "Lcom/android/vending/licensing/ILicensingService$Stub;"
	billingFile := `smali\com\supercell\titan\PurchaseManagerGoogle.smali`
	billingClass := "Lcom/supercell/titan/PurchaseManagerGoogle;"

	points := []types.CrackPoint{
		{
			Location:   types.SourceLocation{File: licenseFile, Line: 20},
			ClassName:  licenseClass,
			Method:     "onTransact",
			Category:   "callback",
			Confidence: 0.80,
			Impact:     4,
		},
		{
			Location:   types.SourceLocation{File: licenseFile, Line: 56},
			ClassName:  licenseClass,
			Method:     "onTransact",
			Category:   "license",
			Confidence: 0.95,
			Impact:     9,
			Evidence:   []string{"license keyword"},
		},
		{
			Location:   types.SourceLocation{File: licenseFile, Line: 99},
			ClassName:  licenseClass,
			Method:     "onTransact",
			Category:   "license",
			Confidence: 0.90,
			Impact:     9,
		},
		{
			Location:   types.SourceLocation{File: billingFile, Line: 12},
			ClassName:  billingClass,
			Method:     "getPendingPurchases",
			Category:   "billing",
			Confidence: 0.80,
			Impact:     7,
		},
		{
			Location:   types.SourceLocation{File: billingFile, Line: 88},
			ClassName:  billingClass,
			Method:     "getPendingPurchases",
			Category:   "billing",
			Confidence: 0.85,
			Impact:     8,
			Evidence:   []string{"billing keyword"},
		},
	}

	got := dedupeCrackPoints(points)
	if len(got) != 2 {
		t.Fatalf("expected 2 deduped crack points, got %d: %#v", len(got), got)
	}
	for _, pt := range got {
		if pt.Category == "callback" {
			t.Fatalf("callback should be suppressed when a concrete point exists: %#v", pt)
		}
		if pt.Method == "getPendingPurchases" && pt.Confidence != 0.85 {
			t.Fatalf("expected strongest billing point to win, got %#v", pt)
		}
	}
}
