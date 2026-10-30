// Command labkit runs one or more local lab test servers from a JSON config
// file or from quick single-server flags. Everything binds to loopback unless
// the config explicitly opts out.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	labkit "labs-labkit"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "labkit:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("labkit", flag.ContinueOnError)
	var (
		configPath  = fs.String("config", "", "path to a JSON lab config; overrides the quick flags")
		httpAddr    = fs.String("http", "", "quick mode: start an HTTP echo server on this loopback addr (e.g. 127.0.0.1:8080)")
		tcpAddr     = fs.String("tcp", "", "quick mode: start a TCP line-echo server on this loopback addr")
		udpAddr     = fs.String("udp", "", "quick mode: start a UDP echo server on this loopback addr")
		logLevel    = fs.String("log-level", "info", "log level: debug, info, warn, error")
		shutdownDur = fs.Duration("shutdown-timeout", 10*time.Second, "graceful shutdown deadline")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	log := labkit.NewLogger(os.Stderr, labkit.ParseLevel(*logLevel))

	cfg, err := buildConfig(*configPath, *httpAddr, *tcpAddr, *udpAddr, *logLevel)
	if err != nil {
		return err
	}

	mgr := labkit.NewManager(log)
	if err := mgr.BuildFromConfig(cfg); err != nil {
		return err
	}
	if err := mgr.Start(); err != nil {
		return err
	}
	for _, s := range mgr.Services() {
		log.Info("listening", labkit.Fields{"server": s.Name(), "addr": s.Addr()})
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	log.Info("shutdown signal received", nil)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), *shutdownDur)
	defer cancel()
	return mgr.Shutdown(shutdownCtx)
}

func buildConfig(path, httpAddr, tcpAddr, udpAddr, logLevel string) (*labkit.Config, error) {
	if path != "" {
		return labkit.LoadConfig(path)
	}
	cfg := &labkit.Config{LogLevel: logLevel}
	if httpAddr != "" {
		cfg.Servers = append(cfg.Servers, labkit.ServerConfig{
			Name: "http", Kind: "http", Addr: httpAddr, HTTP: &labkit.HTTPConfig{},
		})
	}
	if tcpAddr != "" {
		cfg.Servers = append(cfg.Servers, labkit.ServerConfig{
			Name: "tcp", Kind: "tcp", Addr: tcpAddr, TCP: &labkit.TCPConfig{Framing: "line"},
		})
	}
	if udpAddr != "" {
		cfg.Servers = append(cfg.Servers, labkit.ServerConfig{
			Name: "udp", Kind: "udp", Addr: udpAddr, UDP: &labkit.UDPConfig{},
		})
	}
	if len(cfg.Servers) == 0 {
		return nil, fmt.Errorf("nothing to run: pass -config or one of -http/-tcp/-udp")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}
