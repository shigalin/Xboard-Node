package model

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestNodeSpecFromPanelValidated_AllowsTargetsFromCustomConfigOutbounds(t *testing.T) {
	dir := t.TempDir()
	customConfigPath := filepath.Join(dir, "custom.json")
	if err := os.WriteFile(customConfigPath, []byte(`{"outbounds":[{"tag":"wg-exit","protocol":"wireguard"}]}`), 0o644); err != nil {
		t.Fatalf("write custom config: %v", err)
	}

	_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: 8388,
		CustomOutbounds: []panel.OutboundConfig{{
			Tag:      "proxy",
			Protocol: "socks",
			ProxyTag: "wg-exit",
			Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080},
		}},
		CustomRouteRules: []panel.CustomRouteRule{{
			Action: panel.RouteAction{Type: "route", Target: "wg-exit"},
			Match:  panel.RouteMatch{DomainSuffixes: []string{"example.com"}},
		}},
	}, config.KernelConfig{Type: "singbox", CustomConfig: customConfigPath})
	if err != nil {
		t.Fatalf("expected custom_config outbound tags to be available, got %v", err)
	}
}

func TestNodeSpecFromPanelValidated_RejectsDuplicateTagsAcrossSources(t *testing.T) {
	dir := t.TempDir()
	customConfigPath := filepath.Join(dir, "custom.yaml")
	if err := os.WriteFile(customConfigPath, []byte("outbounds:\n  - tag: warp\n    protocol: wireguard\n"), 0o644); err != nil {
		t.Fatalf("write custom config: %v", err)
	}

	_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: 8388,
		CustomOutbounds: []panel.OutboundConfig{{
			Tag:      "warp",
			Protocol: "socks",
			Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080},
		}},
	}, config.KernelConfig{
		Type:         "singbox",
		CustomConfig: customConfigPath,
		CustomOutbound: []map[string]any{{
			"tag":      "proxy",
			"protocol": "socks",
		}},
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), `custom_outbounds[0].tag duplicates "warp" from kernel.custom_config.outbounds[0]`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateOutboundTagCollisions_RejectsDuplicateRawSources(t *testing.T) {
	err := validateOutboundTagCollisions(nil, []outboundTagSource{
		{Tag: "warp", Source: "kernel.custom_outbound[0]"},
		{Tag: "warp", Source: "kernel.custom_config.outbounds[0]"},
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), `kernel.custom_config.outbounds[0].tag duplicates "warp" from kernel.custom_outbound[0]`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNodeSpecFromPanelValidated_RejectsCustomConfigForOtherKernel(t *testing.T) {
	dir := t.TempDir()
	singboxPath := filepath.Join(dir, "singbox.json")
	if err := os.WriteFile(singboxPath, []byte(`{"route":{"rules":[{"domain_suffix":["blocked.example"],"action":"reject"}]}}`), 0o644); err != nil {
		t.Fatalf("write custom config: %v", err)
	}
	xrayPath := filepath.Join(dir, "xray.json")
	if err := os.WriteFile(xrayPath, []byte(`{"routing":{"rules":[{"domain":["blocked.example"],"outboundTag":"block"}]}}`), 0o644); err != nil {
		t.Fatalf("write custom config: %v", err)
	}
	sharedPath := filepath.Join(dir, "shared.json")
	if err := os.WriteFile(sharedPath, []byte(`{"outbounds":[{"tag":"wg-exit","protocol":"wireguard"}]}`), 0o644); err != nil {
		t.Fatalf("write custom config: %v", err)
	}

	// Hysteria v2 moves an xray-configured node to sing-box; the sing-box rules then apply.
	if _, err := NodeSpecFromPanelValidated(&panel.NodeConfig{Protocol: "hysteria", Version: 2, ServerPort: 443},
		config.KernelConfig{Type: "xray", CustomConfig: singboxPath}); err != nil {
		t.Fatalf("sing-box custom config rejected for a node selected onto sing-box: %v", err)
	}
	// XHTTP moves a sing-box-configured node to Xray, which would ignore route.rules.
	_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{Protocol: "vless", Network: "xhttp", ServerPort: 443},
		config.KernelConfig{Type: "singbox", CustomConfig: singboxPath})
	if err == nil || !strings.Contains(err.Error(), `sing-box-only keys [route]`) {
		t.Fatalf("expected Xray to reject sing-box route rules, got %v", err)
	}
	// Hysteria moves an xray-configured node to sing-box, which would ignore routing.rules.
	_, err = NodeSpecFromPanelValidated(&panel.NodeConfig{Protocol: "hysteria", Version: 2, ServerPort: 443},
		config.KernelConfig{Type: "xray", CustomConfig: xrayPath})
	if err == nil || !strings.Contains(err.Error(), `xray-only keys [routing]`) {
		t.Fatalf("expected sing-box to reject xray routing rules, got %v", err)
	}
	// Xray's decoder matches keys case-insensitively, so the canonical
	// spelling and other case variants must be caught too.
	mixedCasePath := filepath.Join(dir, "mixed.json")
	if err := os.WriteFile(mixedCasePath, []byte(`{"fakeDns":{"ipPool":"198.18.0.0/15"},"Routing":{"rules":[]}}`), 0o644); err != nil {
		t.Fatalf("write custom config: %v", err)
	}
	_, err = NodeSpecFromPanelValidated(&panel.NodeConfig{Protocol: "hysteria", Version: 2, ServerPort: 443},
		config.KernelConfig{Type: "xray", CustomConfig: mixedCasePath})
	if err == nil || !strings.Contains(err.Error(), `xray-only keys [Routing fakeDns]`) {
		t.Fatalf("expected case-insensitive match on xray keys, got %v", err)
	}
	// Top-level keys shared by both formats are not dialect markers; the
	// kernel's own parser judges their contents.
	for _, kernelType := range []string{"singbox", "xray"} {
		if _, err := NodeSpecFromPanelValidated(&panel.NodeConfig{Protocol: "vless", Network: "tcp", ServerPort: 443},
			config.KernelConfig{Type: kernelType, CustomConfig: sharedPath}); err != nil {
			t.Fatalf("shared custom config rejected on %s: %v", kernelType, err)
		}
	}
}

func TestLoadCustomConfigForKernelRejectsForeignDNSOptions(t *testing.T) {
	for _, tc := range []struct {
		kernel, own, other, field string
	}{
		{"xray", `{"dns":{"disableCache":true}}`, `{"dns":{"disable_expire":true}}`, "dns.disable_expire"},
		{"singbox", `{"dns":{"disable_expire":true}}`, `{"dns":{"disableCache":true}}`, "dns.disableCache"},
	} {
		t.Run(tc.kernel, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "custom.json")
			if err := os.WriteFile(path, []byte(tc.own), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadCustomConfigForKernel(path, tc.kernel); err != nil {
				t.Fatalf("rejected native DNS option: %v", err)
			}
			if err := os.WriteFile(path, []byte(tc.other), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadCustomConfigForKernel(path, tc.kernel); err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("expected foreign option %s to be rejected, got %v", tc.field, err)
			}
		})
	}
}
