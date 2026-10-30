package crackpoint

import "testing"

func TestIsNoisyInvokeKeepsAppsFlyerLVL(t *testing.T) {
	if isNoisyInvoke("invoke-virtual {v0}, Lcom/appsflyer/lvl/AppsFlyerLVLImpl;->getLVLResult()V") {
		t.Fatal("AppsFlyer LVL invokes should remain eligible")
	}
	if !isNoisyInvoke("invoke-static {v0}, Lcom/appsflyer/internal/AFj1kSDK;->getRevenue(Ljava/lang/String;)Z") {
		t.Fatal("AppsFlyer internal invokes should remain filtered")
	}
}
