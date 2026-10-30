package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"mega-analyzer/pkg/cmd/smaliaudit"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(smaliaudit.Main(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
