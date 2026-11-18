package sandbox

import (
	"strings"
	"testing"
)

func TestAndroidSocketsRequireTargetProcessOwnership(t *testing.T) {
	// This includes the ADB listener and launcher traffic seen on Android 14.
	// Neither belongs to the target even though all sockets share the device.
	raw := `Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program Name
tcp6 0 0 [::]:5555 [::]:* LISTEN 20207/adbd
tcp6 25 0 ::ffff:172.17.0.2:33736 ::ffff:20.79.131.13:443 CLOSE_WAIT 13027/com.tcl.android.launcher
tcp 0 0 10.0.2.15:12345 93.184.216.34:443 ESTABLISHED 12139/com.example.target
udp 0 0 10.0.2.15:5353 224.0.0.251:5353 12139/com.example.target
tcp6 0 0 [::1]:4444 [::1]:5555 ESTABLISHED 12140/com.example.target:remote
tcp 0 0 10.0.2.15:7777 93.184.216.34:443 ESTABLISHED 121390/other
unix 2 [ ] STREAM CONNECTED 12 12139/com.example.target
`
	connections, incomplete := parseAndroidAppConnections(raw, []int{12139, 12140})
	if incomplete || len(connections) != 3 {
		t.Fatalf("target sockets = %+v, incomplete=%v", connections, incomplete)
	}
	if connections[0].PID != 12139 || connections[0].RemoteAddr != "93.184.216.34:443" || connections[0].State != "ESTABLISHED" {
		t.Fatalf("TCP attribution = %+v", connections[0])
	}
	if connections[1].Protocol != "udp" || connections[1].State != "" || connections[2].PID != 12140 {
		t.Fatalf("UDP/child-process attribution = %+v", connections)
	}
}

func TestAndroidUnownedSocketsCannotBecomeAppBehavior(t *testing.T) {
	for _, owner := range []string{"", "-", "not-a-pid/app", "0/app", "12139/"} {
		t.Run(owner, func(t *testing.T) {
			raw := "tcp 0 0 10.0.2.15:12345 93.184.216.34:443 ESTABLISHED " + owner + "\n"
			connections, incomplete := parseAndroidAppConnections(raw, []int{12139})
			if !incomplete || len(connections) != 0 {
				t.Fatalf("unowned device socket became target evidence: %+v, incomplete=%v", connections, incomplete)
			}
			behavior := buildBehaviorSummary(&Report{Connections: connections})
			if behavior.ConnectionCount != 0 || behavior.PublicConnectionCount != 0 {
				t.Fatalf("unowned traffic affected target behavior: %+v", behavior)
			}
		})
	}
}

func TestAndroidReportDoesNotClaimHostExecutionLimits(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		report := &Report{
			RedirectedEnv:      RedirectedEnv{UserProfile: "host-home"},
			SandboxPermissions: SandboxPermissions{MaxMemoryMB: 512, MaxProcessCount: 64, MonitoredRegistryKeys: []string{"HKCU"}, ExposedWritePaths: []string{"host-workspace"}},
			EffectiveConfig:    &EffectiveConfig{MaxMemoryMB: 512},
		}
		configureAndroidReport(Config{BlockNetwork: blocked}, report)
		permissions := report.SandboxPermissions
		if report.ExecutionEnvironment != "android" || report.RedirectedEnv != (RedirectedEnv{}) || permissions.MaxMemoryMB != 0 || permissions.MaxProcessCount != 0 || len(permissions.MonitoredRegistryKeys) != 0 || len(permissions.ExposedWritePaths) != 0 || report.EffectiveConfig.MaxMemoryMB != 0 {
			t.Fatalf("Android report claims host limits: %+v", report)
		}
		wantNetwork := "live"
		if blocked {
			wantNetwork = "not_applied"
		}
		if report.NetworkMode != wantNetwork || permissions.NetworkAccess != wantNetwork || report.NetworkGuardApplied {
			t.Fatalf("Android report claims a network guard: %+v", report)
		}
		markdown := renderMarkdownReport(report)
		if !strings.Contains(markdown, "Execution environment: `android`") || strings.Contains(markdown, "Memory limit: `512 MB`") || !strings.Contains(markdown, "Memory limit: not enforced") {
			t.Fatalf("misleading Android report limits:\n%s", markdown)
		}
	}
}
