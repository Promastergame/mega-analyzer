//go:build !js

package main

import (
	"context"
	"fmt"
	"mega-analyzer/pkg/buildinfo"
	"mega-analyzer/pkg/internal/vmware"
	"os"
)

// ═══════════════════════════════════════════════════════════════════════════════
// VERSION INFO — injectable через ldflags
// ═══════════════════════════════════════════════════════════════════════════════
//
// Сборка с версией:
//   go build -ldflags "-X main.Version=1.0.0-beta.1 -X main.BuildDate=$(date +%F) -X main.CommitHash=$(git rev-parse --short HEAD)"
//

var (
	AppName    = "Mega Analyzer"
	Version    = ""
	BuildDate  = ""
	CommitHash = ""
)

func init() {
	buildinfo.Configure(Version, BuildDate, CommitHash)
	Version, BuildDate, CommitHash = buildinfo.Version, buildinfo.BuildDate, buildinfo.CommitHash
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN — минимальная точка входа
// ═══════════════════════════════════════════════════════════════════════════════

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--vmware-guest-session" {
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "expected one VMware guest session directory")
			os.Exit(2)
		}
		if err := vmware.RunGuest(context.Background(), os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := configureConsoleUTF8(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: UTF-8 console setup unavailable: %v\n", err)
	}
	app := NewApp()

	if err := app.Run(os.Args[1:]); err != nil {
		app.Fatal(err)
	}
	if code := app.ExitCode(); code != 0 {
		os.Exit(code)
	}
}
