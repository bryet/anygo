package main

import (
	"flag"
	"log"
	"os"

	"config"
	"pkg/inbound"
	"pkg/outbound"
)

func main() {
	configPath := flag.String("config", "config.yaml", "配置文件路径")
	flag.Parse()

	// 设置日志格式
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	switch cfg.Mode() {
	case "inbound":
		log.Println("=== AnyTLS Forward | 模式: inbound（境内入口）===")
		ib := inbound.New(cfg)
		if err := ib.Run(); err != nil {
			log.Fatal(err)
		}

	case "outbound":
		log.Println("=== AnyTLS Forward | 模式: outbound（境外出口）===")
		ob := outbound.New(cfg)
		if err := ob.Run(); err != nil {
			log.Fatal(err)
		}
	}
}
