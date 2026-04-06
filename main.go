package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
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
		fmt.Printf("anygo v%s\n", version)
		os.Exit(0)
	}

	// 初始化日志：写入程序所在目录下的 anygo.log，同时输出到标准输出
	if err := initLogger(); err != nil {
		log.Fatalf("初始化日志失败: %v", err)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	// 统计 inbound/outbound 数量，方便日志展示
	inboundCount, outboundCount := 0, 0
	for i := range cfg.Tunnels {
		switch cfg.Tunnels[i].Mode() {
		case "inbound":
			inboundCount++
		case "outbound":
			outboundCount++
		}
	}
	log.Printf("=== anygo v%s | inbound: %d outbound: %d ===", version, inboundCount, outboundCount)

	var wg sync.WaitGroup
	// 每条 tunnel 启动 TCP 和 QUIC 两个 goroutine
	errCh := make(chan error, len(cfg.Tunnels)*2)

	for i := range cfg.Tunnels {
		merged := cfg.MergeInto(&cfg.Tunnels[i])

		switch merged.Mode() {
		case "inbound":
			// TCP隧道
			wg.Add(1)
			go func(m *config.MergedConfig) {
				defer wg.Done()
				if err := inbound.New(m).Run(); err != nil {
					errCh <- fmt.Errorf("inbound %s: %w", m.Listen, err)
				}
			}(merged)

			// UDP/QUIC隧道
			wg.Add(1)
			go func(m *config.MergedConfig) {
				defer wg.Done()
				if err := quic.NewInbound(m).Run(); err != nil {
					errCh <- fmt.Errorf("quic-inbound %s: %w", m.Listen, err)
				}
			}(merged)

		case "outbound":
			// TCP隧道
			wg.Add(1)
			go func(m *config.MergedConfig) {
				defer wg.Done()
				if err := outbound.New(m).Run(); err != nil {
					errCh <- fmt.Errorf("outbound %s: %w", m.Listen, err)
				}
			}(merged)

			// UDP/QUIC隧道
			wg.Add(1)
			go func(m *config.MergedConfig) {
				defer wg.Done()
				if err := quic.NewOutbound(m).Run(); err != nil {
					errCh <- fmt.Errorf("quic-outbound %s: %w", m.Listen, err)
				}
			}(merged)
		}
	}

	// wg 结束后关闭 errCh，避免 goroutine 泄漏
	go func() {
		wg.Wait()
		close(errCh)
	}()

	// 任意 tunnel 出错则打印，所有 tunnel 停止后退出
	for err := range errCh {
		log.Printf("tunnel error: %v", err)
	}

	log.Println("所有 tunnel 已停止，程序退出")
	os.Exit(1)
}

// initLogger 初始化日志
// 日志文件固定为程序所在目录下的 anygo.log
// 同时写入标准输出和日志文件（tee 模式）
func initLogger() error {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// 获取程序所在目录
	execPath, err := os.Executable()
	if err != nil {
		// 获取失败则退化为只输出标准输出
		log.SetOutput(os.Stdout)
		log.Printf("警告: 获取程序路径失败，日志仅输出到标准输出: %v", err)
		return nil
	}

	logPath := filepath.Join(filepath.Dir(execPath), "anygo.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// 打开文件失败则退化为只输出标准输出，不影响程序运行
		log.SetOutput(os.Stdout)
		log.Printf("警告: 无法创建日志文件 %s，日志仅输出到标准输出: %v", logPath, err)
		return nil
	}

	log.SetOutput(io.MultiWriter(os.Stdout, f))
	log.Printf("日志文件: %s", logPath)
	return nil
}