package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRealityTargets(t *testing.T) {
	for _, tt := range []struct {
		name, text string
		valid      bool
	}{
		{"empty", "", false},
		{"comments only", "# local REALITY destinations\n", false},
		{"null", "null\n", false},
		{"empty mapping", "{}\n", false},
		{"ipv4", "site.example.com: 127.0.0.1:48080\n", true},
		{"ipv6", "site.example.com: '[::1]:48080'\n", true},
		{"normalized SNI", "' Site.example.com. ': 127.0.0.1:48080\n", true},
		{"public destination", "site.example.com: 192.0.2.1:443\n", false},
		{"domain destination", "site.example.com: localhost:443\n", false},
		{"missing port", "site.example.com: 127.0.0.1\n", false},
		{"invalid port", "site.example.com: 127.0.0.1:65536\n", false},
		{"invalid SNI", "'site.example.com:443': 127.0.0.1:48080\n", false},
		{"duplicate normalized SNI", "Site.example.com: 127.0.0.1:48080\nsite.example.com: 127.0.0.1:48081\n", false},
		{"port only", "site.example.com: 48080\n", false},
		{"null destination", "site.example.com:\n", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			targets, err := LoadRealityTargets(writeTemp(t, tt.text))
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v, error=%v", tt.valid, err)
			}
			if tt.valid && targets["site.example.com"] == "" {
				t.Fatal("SNI was not normalized for lookup")
			}
		})
	}
	if _, err := LoadRealityTargets(filepath.Join(t.TempDir(), "missing.yml")); err == nil {
		t.Fatal("explicitly configured missing file must fail")
	}
	if targets, err := LoadRealityTargets(""); err != nil || len(targets) != 0 {
		t.Fatal("unset path must preserve existing behavior")
	}
}

func TestRealityTargetsLoadForAllInstances(t *testing.T) {
	path := writeTemp(t, "Site.example.com: 127.0.0.1:48080\n")
	t.Setenv("REALITY_TARGETS_FILE", path)
	root, err := LoadRoot(writeTemp(t, `
instances:
  - panel: {url: "https://one.example.com", token: "test-token", node_id: 1}
  - panel: {url: "https://two.example.com", token: "test-token", node_id: 2}
    kernel: {type: xray}
`))
	if err != nil {
		t.Fatal(err)
	}
	instances, err := root.NormalizeInstances()
	if err != nil {
		t.Fatal(err)
	}
	for _, instance := range instances {
		if instance.Kernel.RealityTargets["site.example.com"] != "127.0.0.1:48080" {
			t.Fatal("instance did not receive the local destination map")
		}
	}
	legacy, err := Load(writeTemp(t, "panel: {url: 'https://one.example.com', token: 'test-token', node_id: 1}\n"))
	if err != nil || legacy.Kernel.RealityTargets["site.example.com"] != "127.0.0.1:48080" {
		t.Fatalf("legacy load failed: %v", err)
	}
	if err := os.WriteFile(path, []byte("site.example.com: 192.0.2.1:443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRoot(writeTemp(t, "panel: {url: 'https://one.example.com', token: 'test-token', node_id: 1}\n")); err == nil {
		t.Fatal("invalid destination must fail before node startup")
	}
}

func TestRealityTargetsFileFromConfigFile(t *testing.T) {
	path := writeTemp(t, "site.example.com: 127.0.0.1:48080\n")
	cfg, err := Load(writeTemp(t, fmt.Sprintf("panel: {url: 'https://one.example.com', token: 'test-token', node_id: 1}\nkernel:\n  reality_targets_file: %q\n", path)))
	if err != nil || cfg.Kernel.RealityTargets["site.example.com"] != "127.0.0.1:48080" {
		t.Fatalf("yaml-configured mapping was not loaded: %v", err)
	}

	// Follow the repository convention: the environment wins over YAML.
	override := writeTemp(t, "site.example.com: 127.0.0.1:48081\n")
	t.Setenv("REALITY_TARGETS_FILE", override)
	cfg, err = Load(writeTemp(t, fmt.Sprintf("panel: {url: 'https://one.example.com', token: 'test-token', node_id: 1}\nkernel:\n  reality_targets_file: %q\n", path)))
	if err != nil || cfg.Kernel.RealityTargets["site.example.com"] != "127.0.0.1:48081" {
		t.Fatalf("environment did not override the configured file: %v", err)
	}
}

func TestRealityTargetsFileInheritedByInstances(t *testing.T) {
	shared := writeTemp(t, "site.example.com: 127.0.0.1:48080\n")
	perInstance := writeTemp(t, "second.example.com: 127.0.0.1:48081\n")
	root, err := LoadRoot(writeTemp(t, fmt.Sprintf(`
kernel:
  reality_targets_file: %q
instances:
  - panel: {url: "https://one.example.com", token: "test-token", node_id: 1}
  - panel: {url: "https://two.example.com", token: "test-token", node_id: 2}
    kernel: {reality_targets_file: %q}
`, shared, perInstance)))
	if err != nil {
		t.Fatal(err)
	}
	instances, err := root.NormalizeInstances()
	if err != nil {
		t.Fatal(err)
	}
	if instances[0].Kernel.RealityTargets["site.example.com"] != "127.0.0.1:48080" {
		t.Fatal("instance did not inherit the top-level mapping file")
	}
	if instances[1].Kernel.RealityTargets["second.example.com"] != "127.0.0.1:48081" {
		t.Fatal("per-instance mapping file was not honoured")
	}
	if _, exists := instances[1].Kernel.RealityTargets["site.example.com"]; exists {
		t.Fatal("per-instance file must replace, not merge with, the inherited one")
	}
}
