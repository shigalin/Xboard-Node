package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
)

// writeRootConfig re-serializes the whole file from a hand-maintained shadow
// struct, so every kernel setting it forgets is silently dropped when a binding
// is appended or removed. The local REALITY mapping must survive that round
// trip: losing it sends handshakes back to the panel's public destination.
func TestWriteRootConfigPreservesRealityTargetsFile(t *testing.T) {
	dir := t.TempDir()
	mapping := filepath.Join(dir, "reality-targets.yml")
	if err := os.WriteFile(mapping, []byte("site.example.com: 127.0.0.1:48080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PANEL_TOKEN_1", "test-token")

	panelOf := func(nodeID int) config.PanelConfig {
		return config.PanelConfig{URL: "https://panel.example.com", TokenEnv: "PANEL_TOKEN_1", NodeID: nodeID}
	}

	for _, tt := range []struct {
		name string
		root *config.RootConfig
	}{
		{
			name: "legacy single instance",
			root: &config.RootConfig{Config: config.Config{
				Panel:  panelOf(1),
				Kernel: config.KernelConfig{Type: "xray", RealityTargetsFile: mapping},
			}},
		},
		{
			name: "inherited from top level",
			root: &config.RootConfig{
				Config: config.Config{Kernel: config.KernelConfig{Type: "xray", RealityTargetsFile: mapping}},
				Instances: []config.Config{
					// LoadRoot already resolved inheritance, so the instance
					// carries the effective value here.
					{Panel: panelOf(1), Kernel: config.KernelConfig{Type: "xray", RealityTargetsFile: mapping}},
					{Panel: panelOf(2), Kernel: config.KernelConfig{Type: "xray", RealityTargetsFile: mapping}},
				},
			},
		},
		{
			name: "per-instance only",
			root: &config.RootConfig{
				Config: config.Config{Kernel: config.KernelConfig{Type: "xray"}},
				Instances: []config.Config{
					{Panel: panelOf(1), Kernel: config.KernelConfig{Type: "xray", RealityTargetsFile: mapping}},
					{Panel: panelOf(2), Kernel: config.KernelConfig{Type: "xray"}},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			if err := writeRootConfig(path, tt.root); err != nil {
				t.Fatal(err)
			}

			reloaded, err := config.LoadRoot(path)
			if err != nil {
				t.Fatalf("reload after write-back failed: %v", err)
			}
			instances, err := reloaded.NormalizeInstances()
			if err != nil {
				t.Fatal(err)
			}
			if len(instances) == 0 {
				t.Fatal("write-back produced no instances")
			}
			if instances[0].Kernel.RealityTargetsFile != mapping {
				t.Fatalf("mapping file was dropped: %q", instances[0].Kernel.RealityTargetsFile)
			}
			if instances[0].Kernel.RealityTargets["site.example.com"] != "127.0.0.1:48080" {
				t.Fatal("reloaded config lost the local REALITY destination")
			}
		})
	}
}
