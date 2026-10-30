package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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

// writeRootConfig rebuilds config.yml from hand-maintained shadow structs with
// hand-maintained "should I write this block" conditions, so any setting either
// list forgets is silently dropped when a binding is appended or removed. This
// round trip sets every persistable field, writes the file, loads it back and
// demands the settings survive — it fails as soon as a new config field is
// added without teaching writeRootConfig about it.
func TestWriteRootConfigRoundTripsEverySetting(t *testing.T) {
	dir := t.TempDir()
	mapping := filepath.Join(dir, "reality-targets.yml")
	if err := os.WriteFile(mapping, []byte("site.example.com: 127.0.0.1:48080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PANEL_TOKEN_1", "test-token")
	t.Setenv("MACHINE_TOKEN_2", "machine-token")

	kernelOf := func(dirName string) config.KernelConfig {
		return config.KernelConfig{
			Type:                "xray",
			ConfigDir:           filepath.Join(dir, dirName),
			LogLevel:            "debug",
			GeoDataDir:          filepath.Join(dir, "geo"),
			DeviceLimitCooldown: 240,
			CustomOutbound:      []map[string]any{{"tag": "warp", "protocol": "freedom"}},
			CustomRoute:         []map[string]any{{"outboundTag": "warp", "domain": []any{"example.com"}}},
			CustomConfig:        filepath.Join(dir, "custom.json"),
			RealityTargetsFile:  mapping,
		}
	}
	certOf := func(n int) config.CertConfig {
		return config.CertConfig{
			CertMode: "dns", Domain: fmt.Sprintf("node%d.example.com", n), Email: "ops@example.com",
			CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem"),
			CertDir: filepath.Join(dir, "certs"), DNSProvider: "cloudflare",
			DNSEnv: map[string]string{"CF_API_TOKEN": "token"}, HTTPPort: 8080 + n, AutoTLS: true,
		}
	}
	wsOf := func(n int) config.WSConfig {
		return config.WSConfig{StatusInterval: 20 + n, HandshakeTimeout: 25 + n, BackoffInitial: 2 + n, BackoffMax: 90 + n, DiscoveryInterval: 400 + n}
	}
	nodeOf := func(n int) config.NodeConfig {
		return config.NodeConfig{PushInterval: 70 + n, PullInterval: 80 + n, TrackInterval: 15 + n, DeviceReportInterval: 45 + n}
	}

	root := &config.RootConfig{
		Config: config.Config{
			Kernel:  kernelOf("top"),
			Log:     config.LogConfig{Level: "warn", Output: "stderr"},
			Node:    nodeOf(0),
			WS:      wsOf(0),
			Runtime: config.RuntimeConfig{GoMemLimit: "40MiB", GoGCPercent: 60},
			Cert:    certOf(0),
		},
		Instances: []config.Config{
			{
				Panel:      config.PanelConfig{URL: "https://panel.example.com", TokenEnv: "PANEL_TOKEN_1", NodeID: 1, NodeType: "vless"},
				Kernel:     kernelOf("one"),
				Log:        config.LogConfig{Level: "error", Output: "stdout"},
				Node:       nodeOf(1),
				WS:         wsOf(1),
				Runtime:    config.RuntimeConfig{GoMemLimit: "50MiB", GoGCPercent: 70},
				Cert:       certOf(1),
				HealthPort: 9101,
				Nodes: []config.NodeEntry{{NodeID: 11, NodeType: "trojan",
					Kernel: &config.KernelOverride{ConfigDir: filepath.Join(dir, "n11"), GeoDataDir: filepath.Join(dir, "geo"), LogLevel: "info", CustomConfig: filepath.Join(dir, "n11.json")}}},
			},
			{
				Panel:      config.PanelConfig{URL: "https://panel.example.com"},
				Machine:    &config.MachineConfig{MachineID: 2, TokenEnv: "MACHINE_TOKEN_2"},
				Kernel:     kernelOf("two"),
				Log:        config.LogConfig{Level: "info", Output: "stdout"},
				Node:       nodeOf(0),
				WS:         wsOf(2),
				Runtime:    config.RuntimeConfig{GoMemLimit: "60MiB", GoGCPercent: 80},
				Cert:       certOf(2),
				HealthPort: 9102,
				Standalone: &config.StandaloneConfig{
					Enabled: true,
					Node: config.StandaloneNodeConfig{Protocol: "vless", ServerPort: 2053, Network: "tcp",
						TLS: 2, Flow: "xtls-rprx-vision"},
					Users: []config.StandaloneUser{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}},
				},
			},
		},
	}

	path := filepath.Join(t.TempDir(), "config.yml")
	if err := writeRootConfig(path, root); err != nil {
		t.Fatal(err)
	}
	reloaded, err := config.LoadRoot(path)
	if err != nil {
		t.Fatalf("reload after write-back failed: %v", err)
	}

	// Top-level settings are the inheritance source and are neither inherited
	// nor defaulted, so they must come back exactly as written.
	assertKernelEqual(t, "top-level kernel", root.Config.Kernel, reloaded.Config.Kernel)
	if reloaded.Config.Log != root.Config.Log {
		t.Errorf("top-level log: got %+v, want %+v", reloaded.Config.Log, root.Config.Log)
	}
	if reloaded.Config.Node != root.Config.Node {
		t.Errorf("top-level node: got %+v, want %+v", reloaded.Config.Node, root.Config.Node)
	}
	if reloaded.Config.WS != root.Config.WS {
		t.Errorf("top-level ws: got %+v, want %+v", reloaded.Config.WS, root.Config.WS)
	}
	if reloaded.Config.Runtime != root.Config.Runtime {
		t.Errorf("top-level runtime: got %+v, want %+v", reloaded.Config.Runtime, root.Config.Runtime)
	}
	if !reflect.DeepEqual(reloaded.Config.Cert, root.Config.Cert) {
		t.Errorf("top-level cert: got %+v, want %+v", reloaded.Config.Cert, root.Config.Cert)
	}

	instances, err := reloaded.NormalizeInstances()
	if err != nil {
		t.Fatal(err)
	}
	if len(instances) != len(root.Instances) {
		t.Fatalf("instance count = %d, want %d", len(instances), len(root.Instances))
	}
	for i, want := range root.Instances {
		got := instances[i]
		assertKernelEqual(t, fmt.Sprintf("instance %d kernel", i), want.Kernel, got.Kernel)
		if got.Log != want.Log {
			t.Errorf("instance %d log: got %+v, want %+v", i, got.Log, want.Log)
		}
		if got.Node != want.Node {
			t.Errorf("instance %d node: got %+v, want %+v", i, got.Node, want.Node)
		}
		if got.WS != want.WS {
			t.Errorf("instance %d ws: got %+v, want %+v", i, got.WS, want.WS)
		}
		if got.Runtime != want.Runtime {
			t.Errorf("instance %d runtime: got %+v, want %+v", i, got.Runtime, want.Runtime)
		}
		if !reflect.DeepEqual(got.Cert, want.Cert) {
			t.Errorf("instance %d cert: got %+v, want %+v", i, got.Cert, want.Cert)
		}
		if got.HealthPort != want.HealthPort {
			t.Errorf("instance %d health_port = %d, want %d", i, got.HealthPort, want.HealthPort)
		}
		if !reflect.DeepEqual(got.Nodes, want.Nodes) {
			t.Errorf("instance %d nodes: got %+v, want %+v", i, got.Nodes, want.Nodes)
		}
		if !reflect.DeepEqual(got.Standalone, want.Standalone) {
			t.Errorf("instance %d standalone: got %+v, want %+v", i, got.Standalone, want.Standalone)
		}
		if got.Panel.URL != want.Panel.URL || got.Panel.NodeID != want.Panel.NodeID ||
			got.Panel.NodeType != want.Panel.NodeType || got.Panel.TokenEnv != want.Panel.TokenEnv {
			t.Errorf("instance %d panel: got %+v, want %+v", i, got.Panel, want.Panel)
		}
		if (got.Machine == nil) != (want.Machine == nil) {
			t.Errorf("instance %d machine presence changed", i)
		} else if want.Machine != nil && (got.Machine.MachineID != want.Machine.MachineID || got.Machine.TokenEnv != want.Machine.TokenEnv) {
			t.Errorf("instance %d machine: got %+v, want %+v", i, got.Machine, want.Machine)
		}
	}
}

// assertKernelEqual compares every stored kernel setting. RealityTargets is a
// load product rather than a stored field, and the test above already covers
// that it is reloaded, so it is cleared before comparing.
func assertKernelEqual(t *testing.T, label string, want, got config.KernelConfig) {
	t.Helper()
	want.RealityTargets, got.RealityTargets = nil, nil
	if !reflect.DeepEqual(want, got) {
		t.Errorf("%s: got %+v, want %+v", label, got, want)
	}
}

// A block configured only through one of its less common settings must still be
// written. The previous hand-picked conditions looked at a few fields each —
// cert at cert_mode/domain/cert_file/auto_tls, ws at the first three intervals,
// the top-level kernel at type/log_level — and dropped the whole block when
// none of those happened to be set.
func TestWriteRootConfigKeepsBlocksWithOnlyUncommonSettings(t *testing.T) {
	t.Setenv("PANEL_TOKEN_1", "test-token")
	root := &config.RootConfig{
		Config: config.Config{
			Kernel: config.KernelConfig{CustomConfig: "/etc/xboard-node/custom.json", DeviceLimitCooldown: 300},
			Cert:   config.CertConfig{CertContent: "cert-pem", KeyContent: "key-pem"},
			WS:     config.WSConfig{BackoffMax: 120, DiscoveryInterval: 600},
		},
		Instances: []config.Config{
			{Panel: config.PanelConfig{URL: "https://panel.example.com", TokenEnv: "PANEL_TOKEN_1", NodeID: 1}},
		},
	}

	path := filepath.Join(t.TempDir(), "config.yml")
	if err := writeRootConfig(path, root); err != nil {
		t.Fatal(err)
	}
	reloaded, err := config.LoadRoot(path)
	if err != nil {
		t.Fatalf("reload after write-back failed: %v", err)
	}
	if reloaded.Config.Cert.CertContent != "cert-pem" || reloaded.Config.Cert.KeyContent != "key-pem" {
		t.Errorf("inline certificate material was dropped: %+v", reloaded.Config.Cert)
	}
	if reloaded.Config.WS.BackoffMax != 120 || reloaded.Config.WS.DiscoveryInterval != 600 {
		t.Errorf("ws block was dropped: %+v", reloaded.Config.WS)
	}
	if reloaded.Config.Kernel.CustomConfig != "/etc/xboard-node/custom.json" || reloaded.Config.Kernel.DeviceLimitCooldown != 300 {
		t.Errorf("top-level kernel block was dropped: %+v", reloaded.Config.Kernel)
	}
}
