package rules

import "testing"

func TestContainsTokenRejectsSubstringNoise(t *testing.T) {
	cases := []struct {
		item, value string
		want        bool
	}{
		{"Lcom/fsck/k9/helper/DefaultTrustedSocketFactory;", "Socket", false},
		{"Ljava/net/Socket;", "Socket", true},
		{"Ljava/net/Socket;->getInputStream()Ljava/io/InputStream;", "InputStream", true},
		{"getInputStream", "InputStream", true},
		{"Ljava/io/FileInputStream;", "InputStream", false},
		{"openConnection", "Connection", true},
		{"SecureX509TrustManager", "X509TrustManager", false},
		{"Ljavax/net/ssl/X509TrustManager;", "X509TrustManager", true},
		{"You cannot start a load ... which usually occurs", "su", false},
		{"su", "su", true},
		{"/system/xbin/su", "su", true},
		{"su -c id", "su", true},
		{"Runtime.exec", "exec", true},
		{"Ljava/util/concurrent/ExecutorService;->execute(Ljava/lang/Runnable;)V", "exec", false},
		{"secret_key", "secret", true},
		{"Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;", "accessibilitynodeinfo;->gettext(", false},
		{"landroid/view/accessibility/accessibilitynodeinfo;->gettext()", "accessibilitynodeinfo;->gettext(", true},
		{"Ljava/lang/Runtime;", "Runtime.getRuntime", false},
		{"Runtime.getRuntime", "Runtime.getRuntime", true},
		{"display", "pay", false},
		{"com.google.android.gms.ads.AdView", "com.google.android.gms", true},
	}
	for _, c := range cases {
		if got := containsToken([]string{c.item}, c.value); got != c.want {
			t.Errorf("containsToken(%q, %q) = %v, want %v", c.item, c.value, got, c.want)
		}
	}
}

func TestExplicitSubstringMode(t *testing.T) {
	if containsCondition([]string{"usually"}, "su", "") {
		t.Fatal("default token mode should reject substrings")
	}
	if !containsCondition([]string{"usually"}, "su", "substring") {
		t.Fatal("explicit substring mode should preserve broad matching")
	}
	r := Rule{ID: "invalid", Name: "invalid", Conditions: []Condition{{Type: "string", Value: "x", MatchMode: "typo"}}}
	if r.Validate() == nil {
		t.Fatal("invalid match mode should be rejected")
	}
}
