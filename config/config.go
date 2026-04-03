package config

import (
	"errors"
	"os"

	"gopkg.in/yaml.v3"
)

// Config 统一配置结构，通过字段区分inbound/outbound模式
type Config struct {
	// 通用
	Listen   string `yaml:"listen"`
	Password string `yaml:"password"`
	SNI      string `yaml:"sni"`    // TLS伪装域名（inbound用于握手，outbound仅日志展示）
	Remote   string `yaml:"remote"` // inbound: outbound服务器地址；outbound: 最终转发目标地址

	// inbound专有
	Insecure bool `yaml:"insecure"` // 跳过TLS证书验证，自签证书时设为true

	// outbound专有
	Cert          string `yaml:"cert"`           // TLS证书路径
	Key           string `yaml:"key"`            // TLS私钥路径
	PaddingScheme string `yaml:"padding_scheme"` // 自定义PaddingScheme文本

	// Session管理（inbound）
	IdleSessionCheckInterval string `yaml:"idle_session_check_interval"` // 默认30s
	IdleSessionTimeout       string `yaml:"idle_session_timeout"`        // 默认60s
	MinIdleSession           int    `yaml:"min_idle_session"`            // 默认2
}

// Mode 根据配置字段自动识别运行模式：
// 有 cert+key 为 outbound，有 remote 为 inbound
func (c *Config) Mode() string {
	if c.Cert != "" && c.Key != "" {
		return "outbound"
	}
	if c.Remote != "" {
		return "inbound"
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
	if c.Remote == "" {
		return errors.New("remote 不能为空")
	}

	switch c.Mode() {
	case "inbound":
		if c.SNI == "" && !c.Insecure {
			return errors.New("inbound 模式需要配置 sni（TLS伪装域名），自签证书请同时设置 insecure: true")
		}
	case "outbound":
		if c.Cert == "" || c.Key == "" {
			return errors.New("outbound 模式需要配置 cert 和 key")
		}
	default:
		return errors.New("无法识别运行模式：请配置 remote（inbound）或 cert+key（outbound）")
	}

	// 默认值
	if c.MinIdleSession == 0 {
		c.MinIdleSession = 2
	}
	if c.IdleSessionCheckInterval == "" {
		c.IdleSessionCheckInterval = "30s"
	}
	if c.IdleSessionTimeout == "" {
		c.IdleSessionTimeout = "60s"
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
