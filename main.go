package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"

	"anygo/config"
	"anygo/pkg/inbound"
	"anygo/pkg/logger"
	"anygo/pkg/outbound"
	"anygo/pkg/quic"
)

// detectMemoryLimit tries to determine a reasonable GOMEMLIMIT value.
// Priority: cgroup v2 → cgroup v1 → 512 MiB default.
// Returns 0 if a limit cannot be determined (caller should not override).
func detectMemoryLimit() int64 {
	// cgroup v2 (Docker / Kubernetes default)
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "max" {
			if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
				return n
			}
		}
	}
	// cgroup v1
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		s := strings.TrimSpace(string(data))
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
			// A value near MaxInt64 means "no limit" in cgroup v1.
			if n < (1 << 50) { // sanity cap at ~1 PB
				return n
			}
		}
	}
	// No cgroup — use a conservative default that prevents the Go runtime
	// from holding more than 512 MiB of OS memory. This is safe for most
	// VPS deployments (1-2 GB total RAM) while still allowing bursts.
	// Override by setting GOMEMLIMIT in the environment.
	return 512 << 20
}

// version is set via -ldflags at build time, e.g.:
//   go build -ldflags "-X main.version=v1.2.3" -o anygo .
// Falls back to "dev" when built without -ldflags.
var version = "dev"

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

	// ── GC tuning for long-running proxy workloads ─────────────────────────
	//
	// Without these settings, the Go runtime tends to retain OS memory after
	// traffic spikes (it prioritizes GC CPU cost over memory). Over days/weeks
	// this looks like a continuous memory leak even though the live heap is
	// stable. Two knobs work together:
	//
	//   GOGC=50        — GC triggers at 150% of live heap (vs default 200%).
	//                    More CPU but lower peak memory during speedtests.
	//   GOMEMLIMIT     — Soft memory cap. Go runs GC more aggressively as the
	//                    heap approaches this limit, preventing runaway growth.
	//                    Go 1.19+ reads this from the env var automatically.
	//
	// Both can be overridden via environment variables.
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(50)
	}
	// If GOMEMLIMIT is not set and we are not in a cgroup, use a reasonable
	// default. In containerized deployments the cgroup limit takes precedence.
	if os.Getenv("GOMEMLIMIT") == "" {
		limit := detectMemoryLimit()
		if limit > 0 {
			debug.SetMemoryLimit(limit)
		}
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