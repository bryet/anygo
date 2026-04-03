package main

import (
	"flag"
	"log"
	"os"

	"anygo/config"
	"anygo/pkg/inbound"
	"anygo/pkg/outbound"
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

	switch cfg.Mode() {
	case "inbound":
		log.Printf("=== anygo v%s | inbound（境内入口）===", version)
		ib := inbound.New(cfg)
		if err := ib.Run(); err != nil {
			log.Fatal(err)
		}

	case "outbound":
		log.Printf("=== anygo v%s | outbound（境外出口）===", version)
		ob := outbound.New(cfg)
		if err := ob.Run(); err != nil {
			log.Fatal(err)
		}
	}
}
