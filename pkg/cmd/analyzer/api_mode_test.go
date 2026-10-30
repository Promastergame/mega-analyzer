package main

import "testing"

func TestCLIParsesUnifiedAPIMode(t *testing.T) {
	opts, err := NewCLIParser().Parse([]string{"--api", "--api-port", "6100"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.APIServer || opts.APIPort != 6100 {
		t.Fatalf("unexpected API options: enabled=%v port=%d", opts.APIServer, opts.APIPort)
	}
	if err := opts.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCLIRejectsInvalidAPIPort(t *testing.T) {
	opts := &CLIOptions{APIServer: true, APIPort: 70000}
	if err := opts.Validate(); err == nil {
		t.Fatal("expected invalid API port error")
	}
}
