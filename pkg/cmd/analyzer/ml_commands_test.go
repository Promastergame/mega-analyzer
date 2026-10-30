package main

import (
	"testing"
)

func TestMLRunner_Commands(t *testing.T) {
	app := NewApp()
	app.opts = &CLIOptions{}
	runner, err := NewMLRunner(app.opts)
	if err != nil {
		t.Logf("Expected or unexpected err: %v", err)
	}
	if runner != nil {
		app.opts.MLTrain = true
		_ = runner.Run()

		app.opts.MLTrain = false
		app.opts.MLStats = true
		_ = runner.Run()

		app.opts.MLStats = false
		app.opts.MLHistory = true
		_ = runner.Run()

		app.opts.MLHistory = false
		app.opts.MLExList = true
		_ = runner.Run()

		app.opts.MLExList = false
		app.opts.MLPatch = true
		_ = runner.Run()
	}
}
