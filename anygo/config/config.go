package config

import (
	"errors"
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// TunnelConfig 单条转发规则
type TunnelConfig struct {
	Listen   string `yaml:"listen"`
	Remote   string `yaml:"remote"`
	SNI      string `yaml:"sni"`
	Insecure bool   `yaml:"insecure"`
	Password string `yaml:"password"`
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	// MaxConns 最大并发连接数，0 表示不限制
	MaxConns int `yaml:"max_conns"`
}

func (t *TunnelConfig) Mode() string {
	if t.Cert != "" && t.Key != "" {
		return "outbound"
	}
	if t.Remote != "" {
		return "inbound"
	}
	return "unknown"
}

func (t *TunnelConfig) Validate(idx int) error {
	if t.Listen == "" {
		return fmt.Errorf("tunnels[%d]: listen 不能为空", idx)
	}
	if _, _, err := net.SplitHostPort(t.Listen); err != nil {
		return fmt.Errorf("tunnels[%d]: listen 格式错误，应为 host:port: %w", idx, err)
	}
	if t.Password == "" {
		return fmt.Errorf("tunnels[%d]: password 不能为空", idx)
	}
	if t.Remote == "" {
		return fmt.Errorf("tunnels[%d]: remote 不能为空", idx)
	}
	if _, _, err := net.SplitHostPort(t.Remote); err != nil {
		return fmt.Errorf("tunnels[%d]: remote 格式错误，应为 host:port: %w", idx, err)
	}
	switch t.Mode() {
	case "inbound":
		if t.SNI == "" && !t.Insecure {
			return fmt.Errorf("tunnels[%d]: inbound 需要配置 sni，或设置 insecure: true", idx)
		}
	case "outbound":
		// cert/key 已由 Mode() 确认
	default:
		return fmt.Errorf("tunnels[%d]: 无法识别模式", idx)
	}
	return nil
}

// Config 顶层配置
type Config struct {
	// 日志级别：debug / info / warn / error，默认 info
	LogLevel string `yaml:"log_level"`

	// 全局参数（inbound用）
	IdleSessionCheckInterval string `yaml:"idle_session_check_interval"`
	IdleSessionTimeout       string `yaml:"idle_session_timeout"`
	MinIdleSession           int    `yaml:"min_idle_session"`

	// 全局参数（outbound用）
	PaddingScheme string `yaml:"padding_scheme"`

	// 多条转发规则，每条独立判断 inbound/outbound，可混用
	Tunnels []TunnelConfig `yaml:"tunnels"`
}

func (c *Config) applyDefaults() {
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.IdleSessionCheckInterval == "" {
		c.IdleSessionCheckInterval = "30s"
	}
	if c.IdleSessionTimeout == "" {
		c.IdleSessionTimeout = "60s"
	}
	if c.MinIdleSession == 0 {
		c.MinIdleSession = 2
	}
}

func (c *Config) Validate() error {
	if len(c.Tunnels) == 0 {
		return errors.New("至少需要配置一条 tunnels 规则")
	}
	for i, t := range c.Tunnels {
		if err := t.Validate(i); err != nil {
			return err
		}
	}
	return nil
}

// MergedConfig 单条规则 + 全局参数
type MergedConfig struct {
	TunnelConfig
	IdleSessionCheckInterval string
	IdleSessionTimeout       string
	MinIdleSession           int
	PaddingScheme            string
}

func (c *Config) MergeInto(t *TunnelConfig) *MergedConfig {
	return &MergedConfig{
		TunnelConfig:             *t,
		IdleSessionCheckInterval: c.IdleSessionCheckInterval,
		IdleSessionTimeout:       c.IdleSessionTimeout,
		MinIdleSession:           c.MinIdleSession,
		PaddingScheme:            c.PaddingScheme,
	}
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
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}