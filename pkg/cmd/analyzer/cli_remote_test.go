package main

import "testing"

func TestRemoteSandboxCLI(t *testing.T) {
	base := []string{"-sandbox-remote-config", "host.json", "-t", `C:\Lab\fixture.exe`}
	p := NewCLIParser()
	o, err := p.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	if err = o.Validate(); err != nil {
		t.Fatal(err)
	}
	if !o.IsSandboxCommand() || o.SandboxAllowHostExecution || !o.Sandbox {
		t.Fatal("invalid remote dispatch")
	}
	for _, flags := range [][]string{{"-sandbox-allow-host-execution"}, {"-sandbox-stream"}, {"-sandbox-vss-revert"}, {"-sandbox-args", "--arg"}, {"-sandbox-allow-net"}, {"-sandbox-time-scale", "2"}, {"-sandbox-duration", "4"}, {"-sandbox-memory", "1024"}, {"-sandbox-device", "phone"}} {
		p = NewCLIParser()
		o, err = p.Parse(append(append([]string{}, base...), flags...))
		if err == nil {
			err = o.Validate()
		}
		if err == nil {
			t.Fatalf("unsupported remote flags accepted: %v", flags)
		}
	}
}
