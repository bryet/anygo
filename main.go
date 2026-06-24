package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"sync"

	"anygo/config"
	"anygo/pkg/inbound"
	"anygo/pkg/logger"
	"anygo/pkg/outbound"
	"anygo/pkg/quic"
)

const version = "0.1.0"

func main() {
	configPath := flag.String("config", "config.yaml", "config file path")
	showVersion := flag.Bool("version", false, "show version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("anygo v%s\n", version)
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		// logger not yet initialized; use fmt directly
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Tune GC for proxy workloads: lower GOGC reduces peak memory at the cost
	// of slightly more CPU during high-throughput transfers (e.g., speedtest).
	// Default is 100; 50 means GC triggers at 150% of live heap vs 200%.
	// Override by setting GOGC in the environment.
	if os.Getenv("GOGC") == "" && os.Getenv("GOMEMLIMIT") == "" {
		debug.SetGCPercent(50)
	}

	// initialize logger with level from config
	logger.Init(cfg.LogLevel)

	// count inbound/outbound tunnels
	inboundCount, outboundCount := 0, 0
	for i := range cfg.Tunnels {
		switch cfg.Tunnels[i].Mode() {
		case "inbound":
			inboundCount++
		case "outbound":
			outboundCount++
		}
	}
	logger.Info("anygo v%s starting | inbound: %d  outbound: %d", version, inboundCount, outboundCount)

	var wg sync.WaitGroup
	errCh := make(chan error, len(cfg.Tunnels)*2)

	for i := range cfg.Tunnels {
		merged := cfg.MergeInto(&cfg.Tunnels[i])

		switch merged.Mode() {
		case "inbound":
			wg.Add(1)
			go func(m *config.MergedConfig) {
				defer wg.Done()
				if err := inbound.New(m).Run(); err != nil {
					errCh <- fmt.Errorf("inbound %s: %w", m.Listen, err)
				}
			}(merged)

			wg.Add(1)
			go func(m *config.MergedConfig) {
				defer wg.Done()
				if err := quic.NewInbound(m).Run(); err != nil {
					errCh <- fmt.Errorf("quic-inbound %s: %w", m.Listen, err)
				}
			}(merged)

		case "outbound":
			wg.Add(1)
			go func(m *config.MergedConfig) {
				defer wg.Done()
				if err := outbound.New(m).Run(); err != nil {
					errCh <- fmt.Errorf("outbound %s: %w", m.Listen, err)
				}
			}(merged)

			wg.Add(1)
			go func(m *config.MergedConfig) {
				defer wg.Done()
				if err := quic.NewOutbound(m).Run(); err != nil {
					errCh <- fmt.Errorf("quic-outbound %s: %w", m.Listen, err)
				}
			}(merged)
		}
	}

	// close errCh after wg completes to avoid drain goroutine leak
	go func() {
		wg.Wait()
		close(errCh)
	}()

	for err := range errCh {
		logger.Error("tunnel error: %v", err)
	}

	logger.Info("all tunnels stopped, exiting")
	os.Exit(1)
}