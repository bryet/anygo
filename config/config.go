package config

import (
	"errors"
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// TunnelConfig represents a single forwarding rule
type TunnelConfig struct {
	Listen   string `yaml:"listen"`
	Remote   string `yaml:"remote"`
	SNI      string `yaml:"sni"`
	Insecure bool   `yaml:"insecure"`
	Password string `yaml:"password"`
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	// MaxConns: max concurrent connections, 0 means unlimited
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
		return fmt.Errorf("tunnels[%d]: listen must not be empty", idx)
	}
	if _, _, err := net.SplitHostPort(t.Listen); err != nil {
		return fmt.Errorf("tunnels[%d]: listen format error, expected host:port: %w", idx, err)
	}
	if t.Password == "" {
		return fmt.Errorf("tunnels[%d]: password must not be empty", idx)
	}
	if t.Remote == "" {
		return fmt.Errorf("tunnels[%d]: remote must not be empty", idx)
	}
	if _, _, err := net.SplitHostPort(t.Remote); err != nil {
		return fmt.Errorf("tunnels[%d]: remote format error, expected host:port: %w", idx, err)
	}
	switch t.Mode() {
	case "inbound":
		if t.SNI == "" && !t.Insecure {
			return fmt.Errorf("tunnels[%d]: inbound requires sni, or set insecure: true", idx)
		}
	case "outbound":
		// cert/key already validated by Mode()
	default:
		return fmt.Errorf("tunnels[%d]: cannot determine mode", idx)
	}
	return nil
}

// Config top-level configuration
type Config struct {
	// log level: debug/info/warn/error, default info
	LogLevel string `yaml:"log_level"`

	// global parameters (for inbound)
	IdleSessionCheckInterval string `yaml:"idle_session_check_interval"`
	IdleSessionTimeout       string `yaml:"idle_session_timeout"`
	MinIdleSession           int    `yaml:"min_idle_session"`
	MaxIdleSession           int    `yaml:"max_idle_session"` // hard cap on idle sessions, 0 = no limit

	// global parameters (for outbound)
	PaddingScheme string `yaml:"padding_scheme"`

	// multiple forwarding rules, each independently determines inbound/outbound, can be mixed
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
		return errors.New("at least one tunnels rule is required")
	}
	for i, t := range c.Tunnels {
		if err := t.Validate(i); err != nil {
			return err
		}
	}
	return nil
}

// MergedConfig combines single rule + global parameters
type MergedConfig struct {
	TunnelConfig
	IdleSessionCheckInterval string
	IdleSessionTimeout       string
	MinIdleSession           int
	MaxIdleSession           int // hard cap on idle sessions, 0 = no limit
	PaddingScheme            string
}

func (c *Config) MergeInto(t *TunnelConfig) *MergedConfig {
	return &MergedConfig{
		TunnelConfig:             *t,
		IdleSessionCheckInterval: c.IdleSessionCheckInterval,
		IdleSessionTimeout:       c.IdleSessionTimeout,
		MinIdleSession:           c.MinIdleSession,
		MaxIdleSession:           c.MaxIdleSession,
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