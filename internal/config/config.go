// Package config manages daemon configuration stored in ~/.revelion/config.json.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds daemon settings persisted to disk.
type Config struct {
	APIToken string `json:"api_token"`
	BrainURL string `json:"brain_url"`
	// Container image for sandboxes
	SandboxImage string `json:"sandbox_image"`
}

func DefaultConfig() *Config {
	return &Config{
		BrainURL:     "wss://revelion-brain.fly.dev",
		SandboxImage: "ghcr.io/revelionai/revelion-sandbox:0.5.0",
	}
}

func configDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".revelion")
}

func configPath() string {
	return filepath.Join(configDir(), "config.json")
}

// Load reads the config file from ~/.revelion/config.json.
func Load() (*Config, error) {
	data, err := os.ReadFile(configPath())
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.APIToken == "" {
		return nil, fmt.Errorf("no API token configured")
	}
	return cfg, nil
}

// Save writes the config to disk.
func Save(cfg *Config) error {
	if err := os.MkdirAll(configDir(), 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(configPath(), data, 0600)
}
