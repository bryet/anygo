package main

import (
	"flag"
	"log"
	"os"
	"sync"

	"anygo/config"
	"anygo/pkg/inbound"
	"anygo/pkg/outbound"
	"anygo/pkg/quic"
)

const version = "0.1.0"

func main() {
	configPath := flag.String("config", "config.yaml", "配置文件路径")
	showVersion := flag.Bool("version", false, "显示版本")
	flag.Parse()

	if *showVersion {
		log.Printf("anygo v%s", version)
		os.Exit(0)
	}

	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	log.Printf("=== anygo v%s | 模式: %s | 规则数: %d ===", version, cfg.Mode(), len(cfg.Tunnels))

	var wg sync.WaitGroup
	errCh := make(chan error, len(cfg.Tunnels)*2)

	for i := range cfg.Tunnels {
		merged := cfg.MergeInto(&cfg.Tunnels[i])

		switch cfg.Mode() {
		case "inbound":
			// TCP隧道
			wg.Add(1)
			go func(m *config.MergedConfig) {
				defer wg.Done()
				if err := inbound.New(m).Run(); err != nil {
					errCh <- err
				}
			}(merged)

			// UDP/QUIC隧道
			wg.Add(1)
			go func(m *config.MergedConfig) {
				defer wg.Done()
				if err := quic.NewInbound(m).Run(); err != nil {
					errCh <- err
				}
			}(merged)

		case "outbound":
			// TCP隧道
			wg.Add(1)
			go func(m *config.MergedConfig) {
				defer wg.Done()
				if err := outbound.New(m).Run(); err != nil {
					errCh <- err
				}
			}(merged)

			// UDP/QUIC隧道
			wg.Add(1)
			go func(m *config.MergedConfig) {
				defer wg.Done()
				if err := quic.NewOutbound(m).Run(); err != nil {
					errCh <- err
				}
			}(merged)
		}
	}

	go func() {
		for err := range errCh {
			log.Printf("tunnel error: %v", err)
		}
	}()

	wg.Wait()
}