package config

import (
	"errors"
	"os"

	"gopkg.in/yaml.v3"
)

type PaddingConfig struct {
	Templates []int `yaml:"templates"`
}

type Config struct {
	Listen   string        `yaml:"listen"`
	Remote   string        `yaml:"remote"`
	SNI      string        `yaml:"sni"`      // inbound专有：TLS伪装域名
	Cert     string        `yaml:"cert"`     // outbound专有：TLS证书
	Key      string        `yaml:"key"`      // outbound专有：TLS私钥
	Password string        `yaml:"password"` // 认证密钥
	Padding  PaddingConfig `yaml:"padding"`
}

// Mode 根据配置字段自动识别运行模式
func (c *Config) Mode() string {
	if c.SNI != "" {
		return "inbound"
	}
	if c.Cert != "" && c.Key != "" {
		return "outbound"
	}
	return "unknown"
}

func (c *Config) Validate() error {
	if c.Listen == "" {
		return errors.New("listen 不能为空")
	}
	if c.Password == "" {
		return errors.New("password 不能为空")
	}
	switch c.Mode() {
	case "inbound":
		if c.Remote == "" {
			return errors.New("inbound 模式需要配置 remote")
		}
	case "outbound":
		if c.Remote == "" {
			return errors.New("outbound 模式需要配置 remote")
		}
		if c.Cert == "" || c.Key == "" {
			return errors.New("outbound 模式需要配置 cert 和 key")
		}
	default:
		return errors.New("无法识别运行模式，请配置 sni（inbound）或 cert+key（outbound）")
	}
	if len(c.Padding.Templates) == 0 {
		c.Padding.Templates = []int{64, 128, 256, 512, 1024, 1440, 2048}
	}
	return nil
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
