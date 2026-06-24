package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTunnelMode(t *testing.T) {
	tests := []struct {
		name   string
		tunnel TunnelConfig
		want   string
	}{
		{
			name:   "inbound with cert",
			tunnel: TunnelConfig{Remote: "example.com:443", Cert: "/path/cert", Key: "/path/key"},
			want:   "outbound",
		},
		{
			name:   "outbound without cert",
			tunnel: TunnelConfig{Remote: "example.com:443"},
			want:   "inbound",
		},
		{
			name:   "unknown - no cert and no remote",
			tunnel: TunnelConfig{},
			want:   "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tunnel.Mode(); got != tt.want {
				t.Errorf("Mode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTunnelValidate(t *testing.T) {
	tests := []struct {
		name    string
		tunnel  TunnelConfig
		wantErr bool
	}{
		{
			name:    "valid inbound",
			tunnel:  TunnelConfig{Listen: ":8080", Remote: "example.com:443", SNI: "bing.com", Password: "secret"},
			wantErr: false,
		},
		{
			name:    "inbound with insecure",
			tunnel:  TunnelConfig{Listen: ":8080", Remote: "example.com:443", Insecure: true, Password: "secret"},
			wantErr: false,
		},
		{
			name:    "inbound missing SNI",
			tunnel:  TunnelConfig{Listen: ":8080", Remote: "example.com:443", Password: "secret"},
			wantErr: true,
		},
		{
			name:    "valid outbound",
			tunnel:  TunnelConfig{Listen: ":44713", Remote: "127.0.0.1:25256", Cert: "/crt", Key: "/key", Password: "secret"},
			wantErr: false,
		},
		{
			name:    "missing listen",
			tunnel:  TunnelConfig{Remote: "example.com:443"},
			wantErr: true,
		},
		{
			name:    "bad listen format",
			tunnel:  TunnelConfig{Listen: "invalid", Remote: "example.com:443"},
			wantErr: true,
		},
		{
			name:    "missing password",
			tunnel:  TunnelConfig{Listen: ":8080", Remote: "example.com:443"},
			wantErr: true,
		},
		{
			name:    "missing remote",
			tunnel:  TunnelConfig{Listen: ":8080"},
			wantErr: true,
		},
		{
			name:    "bad remote format",
			tunnel:  TunnelConfig{Listen: ":8080", Remote: "bad-remote"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.tunnel.Validate(0)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	yamlContent := `
log_level: debug
idle_session_check_interval: 10s
idle_session_timeout: 30s
min_idle_session: 1
tunnels:
  - listen: ":8080"
    remote: "example.com:443"
    sni: "bing.com"
    password: "test123"
  - listen: ":44713"
    remote: "127.0.0.1:25256"
    cert: "/server.crt"
    key: "/server.key"
    password: "test123"
`
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
	if cfg.IdleSessionCheckInterval != "10s" {
		t.Errorf("IdleSessionCheckInterval = %q, want %q", cfg.IdleSessionCheckInterval, "10s")
	}
	if len(cfg.Tunnels) != 2 {
		t.Fatalf("len(Tunnels) = %d, want 2", len(cfg.Tunnels))
	}
	if mode := cfg.Tunnels[0].Mode(); mode != "inbound" {
		t.Errorf("Tunnels[0].Mode() = %q, want inbound", mode)
	}
	if mode := cfg.Tunnels[1].Mode(); mode != "outbound" {
		t.Errorf("Tunnels[1].Mode() = %q, want outbound", mode)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	yamlContent := `
tunnels:
  - listen: ":8080"
    remote: "example.com:443"
    sni: "bing.com"
    password: "test123"
`
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	// Verify defaults are applied
	if cfg.LogLevel != "info" {
		t.Errorf("default LogLevel = %q, want info", cfg.LogLevel)
	}
	if cfg.MinIdleSession != 2 {
		t.Errorf("default MinIdleSession = %d, want 2", cfg.MinIdleSession)
	}
}

func TestLoadConfigNoTunnels(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	if err := os.WriteFile(cfgPath, []byte("tunnels: []\n"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(cfgPath)
	if err == nil {
		t.Error("Load() with no tunnels should return an error")
	}
}

func TestMergeInto(t *testing.T) {
	cfg := &Config{
		LogLevel:                 "info",
		IdleSessionCheckInterval: "30s",
		IdleSessionTimeout:       "60s",
		MinIdleSession:           3,
		PaddingScheme:            "stop=8\n0=30-30",
	}

	tunnel := &TunnelConfig{
		Listen:   ":8080",
		Remote:   "example.com:443",
		SNI:      "bing.com",
		Password: "secret",
	}

	merged := cfg.MergeInto(tunnel)

	if merged.Listen != ":8080" {
		t.Errorf("Listen = %q, want :8080", merged.Listen)
	}
	if merged.MinIdleSession != 3 {
		t.Errorf("MinIdleSession = %d, want 3", merged.MinIdleSession)
	}
	if merged.PaddingScheme != "stop=8\n0=30-30" {
		t.Errorf("PaddingScheme not merged correctly")
	}
}
