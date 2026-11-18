package networkrefs

import "testing"

func TestRecoveredHostnamesExcludePackageNames(t *testing.T) {
	for _, host := range []string{"controller.example.org", "telemetry.example.cfd", "backup.example.cyou", "vpn.example.club"} {
		if !IsRecoveredHostname(host) {
			t.Errorf("host %q rejected", host)
		}
	}
	for _, value := range []string{"java.lang.String", "com.buttonvpn.hjexqm", "not a hostname.org", "bad..example.com", "-bad.example.com"} {
		if IsRecoveredHostname(value) {
			t.Errorf("non-host %q accepted", value)
		}
	}
}
