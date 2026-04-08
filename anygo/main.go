package main

import (
	"flag"
	"fmt"
	"os"
	"sync"

	"anygo/config"
	"anygo/pkg/inbound"
	"anygo/pkg/logger"
	"anygo/pkg/outbound"
	"anygo/pkg/quic"
)

const version = "0.1.0"

func main() {
	configPath := flag.String("config", "config.yaml", "配置文件路径")
	showVersion := flag.Bool("version", false, "显示版本")
	flag.Parse()

	if *showVersion {
		fmt.Printf("anygo v%s\n", version)
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		// 此时 logger 还未初始化，直接用 fmt
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志（使用配置文件里的级别）
	logger.Init(cfg.LogLevel)

	// 统计 inbound/outbound 数量
	inboundCount, outboundCount := 0, 0
	for i := range cfg.Tunnels {
		switch cfg.Tunnels[i].Mode() {
		case "inbound":
			inboundCount++
		case "outbound":
			outboundCount++
		}
	}
	logger.Info("anygo v%s 启动 | inbound: %d  outbound: %d", version, inboundCount, outboundCount)

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

	// wg 结束后关闭 errCh，避免 drain goroutine 泄漏
	go func() {
		wg.Wait()
		close(errCh)
	}()

	for err := range errCh {
		logger.Error("tunnel error: %v", err)
	}

	logger.Info("所有 tunnel 已停止，程序退出")
	os.Exit(1)
}