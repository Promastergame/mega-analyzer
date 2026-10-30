package web

import "testing"

func TestWebBundleBudgetValidation(t *testing.T) {
	for _, value := range []string{"compact", "large"} {
		if _, err := validateWorkspaceScanFlags([]string{"-bundle-budget", value}); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"unlimited", "-output", "../../file", "100000000"} {
		if _, err := validateWorkspaceScanFlags([]string{"-bundle-budget", value}); err == nil {
			t.Fatalf("accepted %s", value)
		}
	}
}
