// Package config manages daemon configuration stored in ~/.revelion/config.json.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const CurrentSandboxImage = "ghcr.io/revelionai/revelion-sandbox:0.7.0"

var legacyOfficialSandboxImages = map[string]struct{}{
	"ghcr.io/revelionai/revelion-sandbox:0.5.0": {},
	"ghcr.io/revelionai/revelion-sandbox:0.6.0": {},
}

// Config holds daemon settings persisted to disk.
type Config struct {
	APIToken string `json:"api_token"`
	BrainURL string `json:"brain_url"`
	// Container image for sandboxes
	SandboxImage string `json:"sandbox_image"`
	// Local Burp Bridge settings
	BurpProxyURL string `json:"burp_proxy_url"`
	BurpMCPURL   string `json:"burp_mcp_url"`
	BurpRESTURL  string `json:"burp_rest_url"`
	// BurpRESTAPIKey is stored daemon-local. Brain may forward it in transit to
	// the daemon, but Brain must not persist or log it.
	BurpRESTAPIKey string `json:"burp_rest_api_key,omitempty"`
	BurpCAPath     string `json:"burp_ca_path,omitempty"`
	// BURP_REST_FALLBACK / burp_rest_fallback keeps the Phase 3 outside-in REST
	// scanner lifecycle available for compatibility. Phase 4 extension scanner
	// control is the default.
	BurpRESTFallback bool `json:"burp_rest_fallback"`
	// BurpAutonomousMode controls whether Burp approval gates should be disabled
	// during setup. When false, supervised mode leaves Burp-side approvals active.
	BurpAutonomousMode bool `json:"burp_autonomous_mode"`
	// Local Revelion Burp Extension control-plane settings.
	BurpExtensionAddr               string    `json:"burp_extension_addr"`
	BurpExtensionPairToken          string    `json:"burp_extension_pair_token,omitempty"`
	BurpExtensionPairTokenExpiresAt time.Time `json:"burp_extension_pair_token_expires_at,omitempty"`
	BurpExtensionSessionToken       string    `json:"burp_extension_session_token,omitempty"`
}

func DefaultConfig() *Config {
	return &Config{
		BrainURL:           "wss://revelion-brain.fly.dev",
		SandboxImage:       CurrentSandboxImage,
		BurpProxyURL:       "http://127.0.0.1:8080",
		BurpMCPURL:         "http://127.0.0.1:9876",
		BurpRESTURL:        "http://127.0.0.1:1337",
		BurpAutonomousMode: true,
		BurpExtensionAddr:  "127.0.0.1:48761",
	}
}

func configDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".revelion")
}

// DefaultBurpCAPath is where the daemon stores the Burp CA it fetches for sandbox trust.
func DefaultBurpCAPath() string {
	return filepath.Join(configDir(), "burp-ca.pem")
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
	normalizeLoadedConfig(cfg)
	if cfg.APIToken == "" {
		return nil, fmt.Errorf("no API token configured")
	}
	return cfg, nil
}

func normalizeLoadedConfig(cfg *Config) {
	defaults := DefaultConfig()
	if cfg.SandboxImage == "" {
		cfg.SandboxImage = defaults.SandboxImage
	} else if _, ok := legacyOfficialSandboxImages[cfg.SandboxImage]; ok {
		cfg.SandboxImage = defaults.SandboxImage
	}
	if cfg.BurpExtensionAddr == "" {
		cfg.BurpExtensionAddr = defaults.BurpExtensionAddr
	}
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

// RandomHexToken returns a cryptographically random hex token with byteLength
// bytes of entropy.
func RandomHexToken(byteLength int) (string, error) {
	if byteLength <= 0 {
		return "", fmt.Errorf("byteLength must be positive")
	}
	buf := make([]byte, byteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
