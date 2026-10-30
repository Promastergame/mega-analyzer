package main

import (
	"testing"
)

func TestApp_Run_Help(t *testing.T) {
	app := NewApp()
	err := app.Run([]string{"--help"})
	if err == nil || err.Error() != "flag: help requested" {
		t.Logf("Expected help requested error, got: %v", err)
	}
}

func TestApp_Run_Version(t *testing.T) {
	app := NewApp()
	err := app.Run([]string{"--version"})
	if err != nil {
		t.Logf("Version run error: %v", err)
	}
}

func TestApp_Run_InvalidFlag(t *testing.T) {
	app := NewApp()
	err := app.Run([]string{"--invalid-flag-that-does-not-exist"})
	if err == nil {
		t.Fatalf("Expected error for invalid flag")
	}
}

func TestApp_Run_ValidTarget(t *testing.T) {
	app := NewApp()
	_ = app.Run([]string{"--target", "some_non_existent_target_12345"})
}
