package config

import "testing"

func TestNormalizeLoadedConfigUpgradesLegacyOfficialSandboxImage(t *testing.T) {
	cfg := &Config{SandboxImage: "ghcr.io/revelionai/revelion-sandbox:0.5.0"}

	normalizeLoadedConfig(cfg)

	if cfg.SandboxImage != CurrentSandboxImage {
		t.Fatalf("SandboxImage = %q, want %q", cfg.SandboxImage, CurrentSandboxImage)
	}
}

func TestNormalizeLoadedConfigKeepsCustomSandboxImage(t *testing.T) {
	cfg := &Config{SandboxImage: "ghcr.io/example/custom-sandbox:dev"}

	normalizeLoadedConfig(cfg)

	if cfg.SandboxImage != "ghcr.io/example/custom-sandbox:dev" {
		t.Fatalf("SandboxImage = %q, want custom image preserved", cfg.SandboxImage)
	}
}
