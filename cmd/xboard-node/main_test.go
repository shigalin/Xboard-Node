package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
)

func TestPreflightReloadRejectsLayoutBeforeStoppingServices(t *testing.T) {
	base := t.TempDir()
	root := &config.RootConfig{Instances: []config.Config{
		{InstanceID: "one", Panel: config.PanelConfig{URL: "https://one.test", NodeID: 1}, Kernel: config.KernelConfig{ConfigDir: filepath.Join(base, "one")}, Cert: config.CertConfig{CertDir: filepath.Join(base, "shared")}},
		{InstanceID: "two", Panel: config.PanelConfig{URL: "https://two.test", NodeID: 2}, Kernel: config.KernelConfig{ConfigDir: filepath.Join(base, "two")}, Cert: config.CertConfig{CertDir: filepath.Join(base, "shared")}},
	}}
	if _, err := preflightReload(root); err == nil || !strings.Contains(err.Error(), "cert_dir") {
		t.Fatalf("unsafe reload accepted: %v", err)
	}
	root.Instances[1].Cert.CertDir = filepath.Join(base, "other")
	if _, err := preflightReload(root); err != nil {
		t.Fatalf("safe reload rejected: %v", err)
	}
}
