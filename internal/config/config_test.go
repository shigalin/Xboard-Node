package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_ValidConfig(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://panel.example.com"
  token: "secret-token"
  node_id: 5
  node_type: "v2ray"
kernel:
  type: singbox
  log_level: warn
log:
  level: debug
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Panel.URL != "https://panel.example.com" {
		t.Errorf("url: got %q", cfg.Panel.URL)
	}
	if cfg.Panel.Token != "secret-token" {
		t.Errorf("token: got %q", cfg.Panel.Token)
	}
	if cfg.Panel.NodeID != 5 {
		t.Errorf("node_id: got %d", cfg.Panel.NodeID)
	}
	if cfg.Panel.NodeType != "v2ray" {
		t.Errorf("node_type: got %q", cfg.Panel.NodeType)
	}
	if cfg.Kernel.Type != "singbox" {
		t.Errorf("kernel.type: got %q", cfg.Kernel.Type)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("log.level: got %q", cfg.Log.Level)
	}
}

func TestLoad_Defaults(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://panel.example.com"
  token: "tok"
  node_id: 1
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Kernel.Type != "singbox" {
		t.Errorf("default kernel.type: got %q, want singbox", cfg.Kernel.Type)
	}
	// config_dir should default to the directory containing the config file.
	expectedDir := filepath.Dir(path)
	if cfg.Kernel.ConfigDir != expectedDir {
		t.Errorf("default config_dir: got %q, want %q", cfg.Kernel.ConfigDir, expectedDir)
	}
	if cfg.Kernel.LogLevel != "warn" {
		t.Errorf("default kernel log_level: got %q, want warn", cfg.Kernel.LogLevel)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("default log.level: got %q, want info", cfg.Log.Level)
	}
	if cfg.Log.Output != "stdout" {
		t.Errorf("default log.output: got %q, want stdout", cfg.Log.Output)
	}
	if cfg.Cert.HTTPPort != 80 {
		t.Errorf("default http_port: got %d, want 80", cfg.Cert.HTTPPort)
	}
	expectedCertDir := filepath.Join(expectedDir, "certs")
	if cfg.Cert.CertDir != expectedCertDir {
		t.Errorf("default cert_dir: got %q, want %q", cfg.Cert.CertDir, expectedCertDir)
	}
}

func TestLoad_SingleStaticNodeKeepsDefaultCertDir(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: https://panel.example.com
  token: tok
nodes:
  - node_id: 1
    kernel:
      config_dir: /tmp/other-config
`)
	want := filepath.Join(filepath.Dir(path), "certs")
	if err := os.MkdirAll(want, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(want, "cert.pem"), []byte("persisted"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := ValidateStartupLayout([]*Config{cfg}); err != nil {
		t.Fatalf("ValidateStartupLayout: %v", err)
	}
	if got := cfg.ExpandNodes()[0].Cert.CertDir; got != want {
		t.Errorf("single static node cert_dir: got %q, want %q", got, want)
	}
}

func TestLoad_SingleStaticNodeKernelOverrideKeepsParentConfigDir(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: https://panel.example.com
  token: tok
nodes:
  - node_id: 1
    kernel:
      log_level: debug
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.ExpandNodes()[0].Kernel.ConfigDir, cfg.Kernel.ConfigDir; got != want {
		t.Fatalf("single static node config_dir: got %q, want %q", got, want)
	}
}

func TestLoad_MultiNodeLegacyPEMRequiresMigrationEvenWithLocalMode(t *testing.T) {
	for _, mode := range []string{"none", "file"} {
		t.Run(mode, func(t *testing.T) {
			path := writeTemp(t, "")
			certDir := filepath.Join(filepath.Dir(path), "certs")
			if err := os.MkdirAll(certDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(certDir, "cert.pem"), []byte("persisted"), 0o600); err != nil {
				t.Fatal(err)
			}
			content := fmt.Sprintf("panel:\n  url: https://panel.example.com\n  token: tok\ncert:\n  cert_mode: %s\nnodes:\n  - node_id: 1\n  - node_id: 2\n", mode)
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "migrate") {
				t.Fatalf("panel TLS can override local %s; migration required: %v", mode, err)
			}
		})
	}
}

func TestLoad_MultiNodeLegacyDefaultCertDirRequiresMigration(t *testing.T) {
	for _, file := range []string{"cert.pem", "key.pem"} {
		t.Run(file, func(t *testing.T) {
			path := writeTemp(t, `
panel:
  url: https://panel.example.com
  token: tok
cert:
  cert_mode: self
nodes:
  - node_id: 1
  - node_id: 2
`)
			certDir := filepath.Join(filepath.Dir(path), "certs")
			if err := os.MkdirAll(certDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(certDir, file), []byte("persisted"), 0o600); err != nil {
				t.Fatal(err)
			}
			for name, load := range map[string]func(string) error{
				"Load":     func(path string) error { _, err := Load(path); return err },
				"LoadRoot": func(path string) error { _, err := LoadRoot(path); return err },
			} {
				err := load(path)
				if err == nil || !strings.Contains(err.Error(), certDir) || !strings.Contains(err.Error(), "cert_dir") || !strings.Contains(err.Error(), "migrat") || !strings.Contains(err.Error(), "nodes") {
					t.Fatalf("%s: got %v, want actionable legacy certificate migration error", name, err)
				}
			}
		})
	}
}

func TestValidateStartupLayout_LegacyDefaultCertDirRequiresMigration(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: https://panel.example.com
  token: tok
cert:
  cert_mode: self
nodes:
  - node_id: 1
    cert:
      cert_dir: /tmp/explicit-certs
  - node_id: 2
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	certDir := filepath.Join(filepath.Dir(path), "certs")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "key.pem"), []byte("persisted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateStartupLayout([]*Config{cfg}); err == nil || !strings.Contains(err.Error(), "migrat") || !strings.Contains(err.Error(), certDir) {
		t.Fatalf("ValidateStartupLayout: got %v, want legacy certificate migration error", err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "migrat") {
		t.Fatalf("Load with one default cert_dir: got %v, want migration error", err)
	}
}

func TestLoad_MultiNodeLegacyPEMNeedsMigrationWhenPanelMayOverrideLocalNone(t *testing.T) {
	path := writeTemp(t, "panel:\n  url: https://panel.example.com\n  token: tok\ncert:\n  cert_mode: none\nnodes:\n  - node_id: 1\n    node_type: vless\n  - node_id: 2\n    node_type: vless\n")
	legacy := filepath.Join(filepath.Dir(path), "certs")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "cert.pem"), []byte("unused legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "migrate") {
		t.Fatalf("panel TLS may override local none: %v", err)
	}
}

func TestLoad_MultiNodeLegacyPEMWithPanelTLSRequiresMigration(t *testing.T) {
	path := writeTemp(t, "panel:\n  url: https://panel.example.com\n  token: tok\nnodes:\n  - node_id: 1\n    node_type: vless\n  - node_id: 2\n    node_type: vless\n")
	legacy := filepath.Join(filepath.Dir(path), "certs")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "cert.pem"), []byte("may be needed by panel content fallback"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "migrate") {
		t.Fatalf("implicit TLS mode must protect panel content fallback: %v", err)
	}
}

func TestLoad_MultiNodeLegacyPEMWithExplicitUniqueDirs(t *testing.T) {
	path := writeTemp(t, "")
	certDir := filepath.Join(filepath.Dir(path), "certs")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "cert.pem"), []byte("persisted"), 0o600); err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf(`
panel:
  url: https://panel.example.com
  token: tok
nodes:
  - node_id: 1
    cert:
      cert_dir: %s
  - node_id: 2
    cert:
      cert_dir: %s
`, certDir, filepath.Join(filepath.Dir(path), "other-certs"))
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load with explicit unique cert_dir options: %v", err)
	}
	if got := cfg.ExpandNodes()[0].Cert.CertDir; got != certDir {
		t.Errorf("explicit parent cert_dir: got %q, want %q", got, certDir)
	}
	if err := ValidateStartupLayout([]*Config{cfg}); err != nil {
		t.Fatalf("ValidateStartupLayout with explicit unique cert_dir options: %v", err)
	}
}

func TestLoad_MultiNodeDefaultCertDirs(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://panel.example.com"
  token: "tok"
nodes:
  - node_id: 1
  - node_id: 2
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, node := range cfg.ExpandNodes() {
		want := filepath.Join(cfg.Kernel.ConfigDir, fmt.Sprintf("node-%d", node.Panel.NodeID), "certs")
		if node.Cert.CertDir != want {
			t.Errorf("node %d cert_dir: got %q, want %q", node.Panel.NodeID, node.Cert.CertDir, want)
		}
	}
}

func TestLoad_MultiNodeCertOverrides(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://panel.example.com"
  token: "tok"
kernel:
  config_dir: /tmp/parent-config
nodes:
  - node_id: 1
    kernel:
      log_level: debug
    cert:
      cert_dir: /tmp/explicit-certs
  - node_id: 2
    kernel:
      config_dir: /tmp/other-config
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	nodes := cfg.ExpandNodes()
	if got := nodes[0].Kernel.ConfigDir; got != "/tmp/parent-config/node-1" {
		t.Errorf("node 1 config_dir: got %q", got)
	}
	if got := nodes[0].Cert.CertDir; got != "/tmp/explicit-certs" {
		t.Errorf("node 1 explicit cert_dir: got %q", got)
	}
	if got := nodes[1].Cert.CertDir; got != "/tmp/other-config/certs" {
		t.Errorf("node 2 default cert_dir: got %q", got)
	}
}

func TestLoad_MultiNodeExplicitParentCertDir(t *testing.T) {
	path := writeTemp(t, "")
	parentCertDir := filepath.Join(filepath.Dir(path), "certs")
	content := fmt.Sprintf(`
panel:
  url: https://panel.example.com
  token: tok
cert:
  cert_dir: %s
nodes:
  - node_id: 1
  - node_id: 2
    cert:
      cert_dir: /tmp/other-certs
`, parentCertDir)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	nodes := cfg.ExpandNodes()
	if got := nodes[0].Cert.CertDir; got != parentCertDir {
		t.Errorf("node 1 explicit parent cert_dir: got %q, want %q", got, parentCertDir)
	}
	if got := nodes[1].Cert.CertDir; got != "/tmp/other-certs" {
		t.Errorf("node 2 explicit cert_dir: got %q", got)
	}
}

func TestLoad_MultiNodeSharedCertDirRejected(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cert  string
		nodes string
	}{
		{"explicit parent", "cert:\n  cert_dir: /tmp/shared-certs\n", "  - node_id: 1\n  - node_id: 2\n"},
		{"per-node overrides", "", "  - node_id: 1\n    cert:\n      cert_dir: /tmp/shared-certs\n  - node_id: 2\n    cert:\n      cert_dir: /tmp/shared-certs/.\n"},
		{"default and explicit", "", "  - node_id: 1\n  - node_id: 2\n    cert:\n      cert_dir: %s\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, "")
			nodes := tc.nodes
			if tc.name == "default and explicit" {
				nodes = fmt.Sprintf(nodes, filepath.Join(filepath.Dir(path), "node-1", "certs"))
			}
			content := "panel:\n  url: https://panel.example.com\n  token: tok\n" + tc.cert + "nodes:\n" + nodes
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "cert_dir") {
				t.Fatalf("Load: got %v, want shared cert_dir error", err)
			}
		})
	}
}

func TestLoad_SharedCertDirViaSymlinkRejected(t *testing.T) {
	for _, kind := range []string{"directory", "parent"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			real := filepath.Join(base, "real")
			if err := os.MkdirAll(real, 0o755); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(base, "alias")
			if err := os.Symlink(real, alias); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			first, second := real, alias
			if kind == "parent" {
				first, second = filepath.Join(real, "new-certs"), filepath.Join(alias, "new-certs")
			}
			path := filepath.Join(base, "config.yml")
			content := fmt.Sprintf("panel:\n  url: https://panel.example.com\n  token: tok\nnodes:\n  - node_id: 1\n    cert:\n      cert_dir: %q\n  - node_id: 2\n    cert:\n      cert_dir: %q\n", first, second)
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "cert_dir") {
				t.Fatalf("Load: got %v, want symlink shared cert_dir error", err)
			}
		})
	}
}

func TestLoad_MachineSharedCertDirRejected(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: https://panel.example.com
machine:
  machine_id: 1
  token: tok
nodes:
  - node_id: 1
    cert:
      cert_dir: /tmp/shared-certs
  - node_id: 2
    cert:
      cert_dir: /tmp/shared-certs/.
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "cert_dir") || !strings.Contains(err.Error(), "nodes[1]") {
		t.Fatalf("Load: got %v, want nodes[1] shared cert_dir error", err)
	}
}

func TestValidateStartupLayout_MachineDefaultCertDirsAlias(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "machine")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(realDir, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	instances := []*Config{
		{InstanceID: "first", Machine: &MachineConfig{MachineID: 1}, Kernel: KernelConfig{ConfigDir: realDir}},
		{InstanceID: "second", Machine: &MachineConfig{MachineID: 2}, Kernel: KernelConfig{ConfigDir: alias}},
	}
	if err := ValidateStartupLayout(instances); err == nil || !strings.Contains(err.Error(), "config_dir") {
		t.Fatalf("aliased machine config dirs permit concurrent PEM writes: %v", err)
	}
}

func TestValidateStartupLayout_MachineOverrideSharesStaticCertDir(t *testing.T) {
	base := t.TempDir()
	shared := filepath.Join(base, "shared-certs")
	path := filepath.Join(base, "config.yml")
	content := fmt.Sprintf(`instances:
  - panel:
      url: https://panel.example.com
    machine:
      machine_id: 1
      token: tok
    kernel:
      config_dir: %q
    nodes:
      - node_id: 1
        cert:
          cert_dir: %q
  - panel:
      url: https://panel.example.com
      token: tok
      node_id: 2
    kernel:
      config_dir: %q
    cert:
      cert_dir: %q
`, filepath.Join(base, "machine"), shared, filepath.Join(base, "static"), shared)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := LoadRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	instances, err := root.NormalizeInstances()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateStartupLayout(instances); err == nil || !strings.Contains(err.Error(), "cert_dir") {
		t.Fatalf("ValidateStartupLayout: got %v, want shared machine/static cert_dir error", err)
	}
}

func TestValidateStartupLayout_DynamicMachineDefaultSharesStaticCertDir(t *testing.T) {
	base := t.TempDir()
	machineDir := filepath.Join(base, "machine")
	staticDir := filepath.Join(machineDir, "node-7", "certs")
	machine := fmt.Sprintf(`  - panel:
      url: https://panel.example.com
    machine:
      machine_id: 1
      token: tok
    kernel:
      config_dir: %q
`, machineDir)
	static := fmt.Sprintf(`  - panel:
      url: https://panel.example.com
      token: tok
      node_id: 9
    kernel:
      config_dir: %q
    cert:
      cert_dir: %q
`, filepath.Join(base, "static"), staticDir)
	for _, tc := range []struct{ name, instances string }{
		{"machine first", machine + static},
		{"static first", static + machine},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, "instances:\n"+tc.instances)
			root, err := LoadRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			instances, err := root.NormalizeInstances()
			if err != nil {
				t.Fatal(err)
			}
			for _, instance := range instances {
				if instance.IsMachineMode() {
					if got := instance.ExpandMachineNode(7, "").Cert.CertDir; got != staticDir {
						t.Fatalf("discovered node cert_dir: got %q, want %q", got, staticDir)
					}
				}
			}
			if err := ValidateStartupLayout(instances); err == nil || !strings.Contains(err.Error(), "cert_dir") || !strings.Contains(err.Error(), "node-7") {
				t.Fatalf("ValidateStartupLayout: got %v, want dynamic machine/static cert_dir conflict", err)
			}
		})
	}
}

func TestValidateStartupLayout_DynamicMachineDefaultSafeLayouts(t *testing.T) {
	for _, tc := range []struct {
		name        string
		staticRel   string
		machineNode string
	}{
		{"different directory", "node-7/other-certs", ""},
		{"different node directory", "node-07/certs", ""},
		{"overridden cert directory", "node-7/certs", "    nodes:\n      - node_id: 7\n        cert:\n          cert_dir: %q\n"},
		{"overridden config directory", "node-7/certs", "    nodes:\n      - node_id: 7\n        kernel:\n          config_dir: %q\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			machineDir := filepath.Join(base, "machine")
			machineNode := tc.machineNode
			if machineNode != "" {
				machineNode = fmt.Sprintf(machineNode, filepath.Join(base, "override"))
			}
			path := writeTemp(t, fmt.Sprintf(`instances:
  - panel:
      url: https://panel.example.com
    machine:
      machine_id: 1
      token: tok
    kernel:
      config_dir: %q
%s  - panel:
      url: https://panel.example.com
      token: tok
      node_id: 9
    kernel:
      config_dir: %q
    cert:
      cert_dir: %q
`, machineDir, machineNode, filepath.Join(base, "static"), filepath.Join(machineDir, filepath.FromSlash(tc.staticRel))))
			root, err := LoadRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			instances, err := root.NormalizeInstances()
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateStartupLayout(instances); err != nil {
				t.Fatalf("safe cert_dir layout rejected: %v", err)
			}
		})
	}
}

func TestValidateStartupLayout_InactiveMachineNodeLoopingCertSymlink(t *testing.T) {
	base := t.TempDir()
	machineBase := filepath.Join(base, "machine")
	dir := filepath.Join(machineBase, "node-7")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("certs", filepath.Join(dir, "certs")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	machine := &Config{InstanceID: "machine", Machine: &MachineConfig{MachineID: 1}, Kernel: KernelConfig{ConfigDir: machineBase}}
	if err := ValidateStartupLayout([]*Config{machine}); err != nil {
		t.Fatalf("inactive malformed node must not prevent other nodes starting: %v", err)
	}
}

func TestValidateStartupLayout_DanglingMachineCertSymlinkCanBecomeShared(t *testing.T) {
	base := t.TempDir()
	shared := filepath.Join(base, "shared")
	machineBase := filepath.Join(base, "machine")
	dir := filepath.Join(machineBase, "node-7")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(shared, filepath.Join(dir, "certs")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	machine := &Config{InstanceID: "machine", Machine: &MachineConfig{MachineID: 1}, Kernel: KernelConfig{ConfigDir: machineBase}}
	static := &Config{InstanceID: "static", Kernel: KernelConfig{ConfigDir: filepath.Join(base, "static")}, Cert: CertConfig{CertDir: shared}}
	if err := ValidateStartupLayout([]*Config{machine, static}); err == nil || !strings.Contains(err.Error(), "cert_dir") {
		t.Fatalf("dangling alias must reserve future shared cert directory: %v", err)
	}
}

func TestValidateStartupLayout_InactiveMachineNodeDanglingCertSymlink(t *testing.T) {
	base := t.TempDir()
	machineBase := filepath.Join(base, "machine")
	dir := filepath.Join(machineBase, "node-7")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "removed-certs"), filepath.Join(dir, "certs")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	machine := &Config{InstanceID: "machine", Machine: &MachineConfig{MachineID: 1}, Kernel: KernelConfig{ConfigDir: machineBase}}
	if err := ValidateStartupLayout([]*Config{machine}); err != nil {
		t.Fatalf("stale inactive node must not stop whole machine: %v", err)
	}
}

func TestValidateStartupLayout_DynamicMachineCertSymlinkToStaticCertSymlink(t *testing.T) {
	base := t.TempDir()
	shared := filepath.Join(base, "shared")
	if err := os.MkdirAll(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	machineBase := filepath.Join(base, "machine")
	staticBase := filepath.Join(base, "static")
	for _, dir := range []string{filepath.Join(machineBase, "node-7"), filepath.Join(staticBase, "node-9")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(shared, filepath.Join(dir, "certs")); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
	}
	machine := &Config{InstanceID: "machine", Machine: &MachineConfig{MachineID: 1}, Kernel: KernelConfig{ConfigDir: machineBase}}
	static := &Config{InstanceID: "static", Kernel: KernelConfig{ConfigDir: staticBase}, Nodes: []NodeEntry{{NodeID: 9}, {NodeID: 10}}}
	static.Cert.CertDir = filepath.Join(base, "static-default-certs")
	static.certDirDefaulted = true
	if err := ValidateStartupLayout([]*Config{machine, static}); err == nil || !strings.Contains(err.Error(), "cert_dir") {
		t.Fatalf("machine and static cert symlinks alias: %v", err)
	}
}

func TestValidateStartupLayout_DynamicMachineDefaultViaSymlink(t *testing.T) {
	for _, tc := range []string{"machine parent", "node directory"} {
		t.Run(tc, func(t *testing.T) {
			base := t.TempDir()
			real := filepath.Join(base, "real")
			if err := os.MkdirAll(real, 0o755); err != nil {
				t.Fatal(err)
			}
			machineDir := filepath.Join(real, "machine")
			staticDir := filepath.Join(machineDir, "node-7", "certs")
			switch tc {
			case "machine parent":
				alias := filepath.Join(base, "alias")
				if err := os.Symlink(real, alias); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				staticDir = filepath.Join(alias, "machine", "node-7", "certs")
			case "node directory":
				if err := os.MkdirAll(machineDir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(real, filepath.Join(machineDir, "node-7")); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			path := writeTemp(t, fmt.Sprintf(`instances:
  - panel:
      url: https://panel.example.com
    machine:
      machine_id: 1
      token: tok
    kernel:
      config_dir: %q
  - panel:
      url: https://panel.example.com
      token: tok
      node_id: 9
    kernel:
      config_dir: %q
    cert:
      cert_dir: %q
`, machineDir, filepath.Join(base, "static"), staticDir))
			root, err := LoadRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			instances, err := root.NormalizeInstances()
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateStartupLayout(instances); err == nil || !strings.Contains(err.Error(), "cert_dir") {
				t.Fatalf("ValidateStartupLayout: got %v, want symlink machine/static cert_dir conflict", err)
			}
		})
	}
}

func TestValidateStartupLayout_SharedCertDirViaParentSymlink(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	path := filepath.Join(base, "config.yml")
	content := fmt.Sprintf(`instances:
  - panel:
      url: https://panel.example.com
      token: tok
      node_id: 1
    cert:
      cert_dir: %q
  - panel:
      url: https://panel.example.com
      token: tok
      node_id: 2
    cert:
      cert_dir: %q
`, filepath.Join(real, "new-certs"), filepath.Join(alias, "new-certs"))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := LoadRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	instances, err := root.NormalizeInstances()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateStartupLayout(instances); err == nil || !strings.Contains(err.Error(), "cert_dir") {
		t.Fatalf("ValidateStartupLayout: got %v, want symlink shared cert_dir error", err)
	}
}

func TestValidateStartupLayout_SharedCertDir(t *testing.T) {
	path := writeTemp(t, `
instances:
  - panel:
      url: https://panel.example.com
      token: tok
      node_id: 1
    cert:
      cert_dir: /tmp/shared-certs
  - panel:
      url: https://panel.example.com
      token: tok
      node_id: 2
    cert:
      cert_dir: /tmp/shared-certs/.
`)
	root, err := LoadRoot(path)
	if err != nil {
		t.Fatalf("LoadRoot: %v", err)
	}
	instances, err := root.NormalizeInstances()
	if err != nil {
		t.Fatalf("NormalizeInstances: %v", err)
	}
	if err := ValidateStartupLayout(instances); err == nil || !strings.Contains(err.Error(), "cert_dir") {
		t.Fatalf("ValidateStartupLayout: got %v, want shared cert_dir error", err)
	}
}

func TestLoad_MissingURL(t *testing.T) {
	path := writeTemp(t, `
panel:
  token: "tok"
  node_id: 1
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing url")
	}
}

func TestLoad_MissingToken(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://example.com"
  node_id: 1
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestLoad_InvalidNodeID(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://example.com"
  token: "tok"
  node_id: 0
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for node_id=0")
	}
}

func TestLoad_NegativeNodeID(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://example.com"
  token: "tok"
  node_id: -1
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for negative node_id")
	}
}

func TestLoad_InvalidKernelType(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://example.com"
  token: "tok"
  node_id: 1
kernel:
  type: "invalid"
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid kernel type")
	}
}

func TestLoad_XrayKernel(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://example.com"
  token: "tok"
  node_id: 1
kernel:
  type: xray
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Kernel.Type != "xray" {
		t.Errorf("kernel.type: got %q, want xray", cfg.Kernel.Type)
	}
}

func TestLoad_AutoTLS_NoDomain(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://example.com"
  token: "tok"
  node_id: 1
cert:
  auto_tls: true
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for auto_tls without domain")
	}
}

func TestLoad_AutoTLS_WithDomain(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://example.com"
  token: "tok"
  node_id: 1
cert:
  auto_tls: true
  domain: "node.example.com"
  email: "admin@example.com"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Cert.AutoTLS {
		t.Error("auto_tls should be true")
	}
	if cfg.Cert.Domain != "node.example.com" {
		t.Errorf("domain: got %q", cfg.Cert.Domain)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTemp(t, "{{{{invalid yaml}}}")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoad_CustomCert(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://example.com"
  token: "tok"
  node_id: 1
cert:
  cert_file: "/custom/cert.pem"
  key_file: "/custom/key.pem"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Cert.CertFile != "/custom/cert.pem" {
		t.Errorf("cert_file: got %q", cfg.Cert.CertFile)
	}
	if cfg.Cert.KeyFile != "/custom/key.pem" {
		t.Errorf("key_file: got %q", cfg.Cert.KeyFile)
	}
}

func TestLoad_NegativeTickerAndBackoffIntervals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
	}{
		{"track", "node.track_interval"},
		{"discovery", "ws.discovery_interval"},
		{"status", "ws.status_interval"},
		{"backoff initial", "ws.backoff_initial"},
		{"backoff max", "ws.backoff_max"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parts := strings.Split(tc.field, ".")
			path := writeTemp(t, fmt.Sprintf(`
panel:
  url: https://panel.example.com
  token: tok
  node_id: 1
%s:
  %s: -1
`, parts[0], parts[1]))
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), tc.field) || !strings.Contains(err.Error(), "negative") {
				t.Fatalf("Load: got %v, want %s negative interval error", err, tc.field)
			}
		})
	}
}

func TestLoad_CustomIntervals(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://example.com"
  token: "tok"
  node_id: 1
node:
  push_interval: 30
  pull_interval: 60
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Node.PushInterval != 30 {
		t.Errorf("push_interval: got %d", cfg.Node.PushInterval)
	}
	if cfg.Node.PullInterval != 60 {
		t.Errorf("pull_interval: got %d", cfg.Node.PullInterval)
	}
}

func TestLoad_StandaloneConfig(t *testing.T) {
	path := writeTemp(t, `
standalone:
  enabled: true
  node:
    protocol: "vless"
    server_port: 8443
    network: "ws"
    tls: 1
    network_settings:
      path: "/ws"
  users:
    - id: 1
      uuid: "11111111-1111-1111-1111-111111111111"
kernel:
  type: xray
cert:
  cert_mode: none
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.IsStandalone() {
		t.Fatal("expected standalone mode to be enabled")
	}
	if cfg.Standalone.Node.Protocol != "vless" {
		t.Errorf("standalone.node.protocol: got %q", cfg.Standalone.Node.Protocol)
	}
	if cfg.Standalone.Node.ServerPort != 8443 {
		t.Errorf("standalone.node.server_port: got %d", cfg.Standalone.Node.ServerPort)
	}
	if len(cfg.Standalone.Users) != 1 {
		t.Fatalf("standalone.users: got %d", len(cfg.Standalone.Users))
	}
	if cfg.Standalone.Users[0].UUID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("standalone.users[0].uuid: got %q", cfg.Standalone.Users[0].UUID)
	}
}

func TestLoad_StandaloneRequiresUsers(t *testing.T) {
	path := writeTemp(t, `
standalone:
  enabled: true
  node:
    protocol: "trojan"
    server_port: 443
kernel:
  type: singbox
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for standalone mode without users")
	}
}

func TestLoadRoot_LegacyConfigNormalizesToSingleInstance(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://panel.example.com"
  token: "tok"
  node_id: 1
`)
	root, err := LoadRoot(path)
	if err != nil {
		t.Fatalf("LoadRoot: %v", err)
	}
	instances, err := root.NormalizeInstances()
	if err != nil {
		t.Fatalf("NormalizeInstances: %v", err)
	}
	if len(instances) != 1 {
		t.Fatalf("instances: got %d, want 1", len(instances))
	}
	if instances[0].Panel.URL != "https://panel.example.com" {
		t.Errorf("instance url: got %q", instances[0].Panel.URL)
	}
	if instances[0].InstanceID == "" {
		t.Fatal("expected auto instance id")
	}
}

func TestLoadRoot_InstancesConfig(t *testing.T) {
	path := writeTemp(t, `
instances:
  - panel:
      url: "https://panel-a.example.com"
      token_env: "PANEL_A_TOKEN"
      node_id: 1
    kernel:
      type: singbox
  - panel:
      url: "https://panel-b.example.com"
    machine:
      machine_id: 2
      token_env: "PANEL_B_MACHINE_TOKEN"
    kernel:
      type: singbox
`)
	t.Setenv("PANEL_A_TOKEN", "token-a")
	t.Setenv("PANEL_B_MACHINE_TOKEN", "token-b")
	root, err := LoadRoot(path)
	if err != nil {
		t.Fatalf("LoadRoot: %v", err)
	}
	instances, err := root.NormalizeInstances()
	if err != nil {
		t.Fatalf("NormalizeInstances: %v", err)
	}
	if len(instances) != 2 {
		t.Fatalf("instances: got %d, want 2", len(instances))
	}
	if instances[0].Panel.Token != "token-a" {
		t.Errorf("panel a token: got %q", instances[0].Panel.Token)
	}
	if instances[1].Machine == nil || instances[1].Machine.Token != "token-b" {
		t.Fatalf("machine token: got %+v", instances[1].Machine)
	}
	if instances[0].InstanceID == instances[1].InstanceID {
		t.Fatal("expected unique instance ids")
	}
}

func TestConfig_AutoInstanceIDStable(t *testing.T) {
	cfg := &Config{Panel: PanelConfig{URL: "https://Panel.Example.com/", NodeID: 1, Token: "tok"}}
	cfg.setDefaultsFrom("/etc/xboard-node")
	id1, err := cfg.AutoInstanceID()
	if err != nil {
		t.Fatalf("AutoInstanceID: %v", err)
	}
	id2, err := cfg.AutoInstanceID()
	if err != nil {
		t.Fatalf("AutoInstanceID second: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("ids differ: %q vs %q", id1, id2)
	}
}

func TestLoadRoot_InheritanceFromTopLevel(t *testing.T) {
	path := writeTemp(t, `
log:
  level: "debug"
  output: "stderr"
kernel:
  type: xray
  log_level: "error"
node:
  push_interval: 42
  pull_interval: 99
instances:
  - panel:
      url: "https://panel.example.com"
      token: "tok-a"
      node_id: 1
  - panel:
      url: "https://panel.example.com"
      token: "tok-b"
      node_id: 2
    log:
      level: "warn"
`)
	root, err := LoadRoot(path)
	if err != nil {
		t.Fatalf("LoadRoot: %v", err)
	}
	if len(root.Instances) != 2 {
		t.Fatalf("instances: got %d, want 2", len(root.Instances))
	}
	// Instance 0: inherits everything from top-level.
	inst0 := root.Instances[0]
	if inst0.Log.Level != "debug" {
		t.Errorf("inst0 log.level: got %q, want %q", inst0.Log.Level, "debug")
	}
	if inst0.Log.Output != "stderr" {
		t.Errorf("inst0 log.output: got %q, want %q", inst0.Log.Output, "stderr")
	}
	if inst0.Kernel.Type != "xray" {
		t.Errorf("inst0 kernel.type: got %q, want %q", inst0.Kernel.Type, "xray")
	}
	if inst0.Kernel.LogLevel != "error" {
		t.Errorf("inst0 kernel.log_level: got %q, want %q", inst0.Kernel.LogLevel, "error")
	}
	if inst0.Node.PushInterval != 42 {
		t.Errorf("inst0 push_interval: got %d, want 42", inst0.Node.PushInterval)
	}
	if inst0.Node.PullInterval != 99 {
		t.Errorf("inst0 pull_interval: got %d, want 99", inst0.Node.PullInterval)
	}
	// Instance 1: overrides log.level, inherits the rest.
	inst1 := root.Instances[1]
	if inst1.Log.Level != "warn" {
		t.Errorf("inst1 log.level: got %q, want %q", inst1.Log.Level, "warn")
	}
	if inst1.Log.Output != "stderr" {
		t.Errorf("inst1 log.output: got %q, want %q", inst1.Log.Output, "stderr")
	}
	if inst1.Kernel.Type != "xray" {
		t.Errorf("inst1 kernel.type: got %q, want %q", inst1.Kernel.Type, "xray")
	}
}

func TestLoadRoot_InstanceOrderDoesNotAffectConfigDir(t *testing.T) {
	yamlTmpl := func(first, second int) string {
		return fmt.Sprintf(`
instances:
  - panel:
      url: "https://panel.example.com"
      token: "tok-a"
      node_id: %d
  - panel:
      url: "https://panel.example.com"
      token: "tok-b"
      node_id: %d
`, first, second)
	}

	path1 := writeTemp(t, yamlTmpl(1, 2))
	path2 := writeTemp(t, yamlTmpl(2, 1))
	root1, err := LoadRoot(path1)
	if err != nil {
		t.Fatalf("LoadRoot order1: %v", err)
	}
	root2, err := LoadRoot(path2)
	if err != nil {
		t.Fatalf("LoadRoot order2: %v", err)
	}

	// Collect the config_dir suffix (relative to base) by InstanceID.
	suffix := func(instances []Config) map[string]string {
		m := map[string]string{}
		for _, inst := range instances {
			// The config_dir ends with .../{instanceID}, extract last component.
			m[inst.InstanceID] = filepath.Base(inst.Kernel.ConfigDir)
		}
		return m
	}
	dirs1 := suffix(root1.Instances)
	dirs2 := suffix(root2.Instances)

	for id, s1 := range dirs1 {
		s2, ok := dirs2[id]
		if !ok {
			t.Fatalf("instance %q missing in reversed order", id)
		}
		if s1 != s2 {
			t.Errorf("instance %q config_dir suffix differs: %q vs %q", id, s1, s2)
		}
	}
}

func TestInheritFrom_AutoTLSNotForcedWhenChildHasCertMode(t *testing.T) {
	parent := &Config{Cert: CertConfig{AutoTLS: true, Domain: "example.com"}}
	child := &Config{Cert: CertConfig{CertMode: "file", CertFile: "/etc/cert.pem"}}
	child.inheritFrom(parent)
	if child.Cert.AutoTLS {
		t.Error("auto_tls should NOT be inherited when child has explicit cert_mode")
	}
	if child.Cert.Domain != "example.com" {
		t.Errorf("domain: got %q, want %q", child.Cert.Domain, "example.com")
	}
}

func TestInheritFrom_AutoTLSInheritedWhenChildHasNoCertConfig(t *testing.T) {
	parent := &Config{Cert: CertConfig{AutoTLS: true, Domain: "example.com"}}
	child := &Config{}
	child.inheritFrom(parent)
	if !child.Cert.AutoTLS {
		t.Error("auto_tls should be inherited when child has no cert config")
	}
}
