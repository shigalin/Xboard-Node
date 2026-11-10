package model

import (
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestNodeSpecFromPanelValidated(t *testing.T) {
	t.Run("valid custom outbounds and route targets", func(t *testing.T) {
		node, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panel.OutboundConfig{
				{Tag: "warp", Protocol: "wireguard", Settings: map[string]any{"server": "1.1.1.1", "server_port": 2408, "private_key": "pk"}},
				{Tag: "proxy", Protocol: "socks", ProxyTag: "warp", Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080}},
			},
			CustomRouteRules: []panel.CustomRouteRule{{
				Action: panel.RouteAction{Type: "route", Target: "proxy"},
				Match:  panel.RouteMatch{DomainSuffixes: []string{"example.com"}},
			}},
		}, config.KernelConfig{Type: "singbox"})
		if err != nil {
			t.Fatalf("NodeSpecFromPanelValidated: %v", err)
		}
		if node == nil || len(node.CustomOutbounds) != 2 {
			t.Fatalf("unexpected node spec: %#v", node)
		}
	})

	t.Run("invalid custom outbounds", func(t *testing.T) {
		_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panel.OutboundConfig{{
				Tag: "proxy", Protocol: "socks", ProxyTag: "missing", Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080},
			}},
		}, config.KernelConfig{Type: "singbox"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), `custom_outbounds[0].proxy_tag references unknown outbound "missing"`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("reject unsupported protocol for kernel", func(t *testing.T) {
		_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panel.OutboundConfig{{
				Tag: "hy2", Protocol: "hysteria2", Settings: map[string]any{"server": "2.2.2.2", "server_port": 8443},
			}},
		}, config.KernelConfig{Type: "xray"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), `protocol "hysteria2" is not supported by kernel "xray"`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("reject unknown route target", func(t *testing.T) {
		_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panel.OutboundConfig{{
				Tag: "warp", Protocol: "wireguard", Settings: map[string]any{"server": "1.1.1.1", "server_port": 2408, "private_key": "pk"},
			}},
			CustomRouteRules: []panel.CustomRouteRule{{
				Action: panel.RouteAction{Type: "route", Target: "missing"},
				Match:  panel.RouteMatch{DomainSuffixes: []string{"example.com"}},
			}},
		}, config.KernelConfig{Type: "singbox"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), `custom_route_rules[0].action.target references unknown outbound "missing"`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestNodeSpecFromPanelValidatedResolvesKernel(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured string
		node       panel.NodeConfig
		wantKernel string
	}{
		{"hysteria v2", "xray", panel.NodeConfig{Protocol: "hysteria", Version: 2}, "singbox"},
		{"hysteria2 alias", "xray", panel.NodeConfig{Protocol: "hysteria2"}, "singbox"},
		{"xhttp", "singbox", panel.NodeConfig{Protocol: "vless", Network: "xhttp"}, "xray"},
		{"splithttp", "singbox", panel.NodeConfig{Protocol: "vless", Network: "splithttp"}, "xray"},
		{"compatible xray", "xray", panel.NodeConfig{Protocol: "vless", Network: "tcp"}, "xray"},
		{"compatible singbox", "singbox", panel.NodeConfig{Protocol: "vless", Network: "ws"}, "singbox"},
		{"hysteria v1", "xray", panel.NodeConfig{Protocol: "hysteria", Version: 1}, "singbox"},
		{"hysteria v1 on singbox", "singbox", panel.NodeConfig{Protocol: "hysteria", Version: 1}, "singbox"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node, err := NodeSpecFromPanelValidated(&tc.node, config.KernelConfig{Type: tc.configured})
			if err != nil {
				t.Fatal(err)
			}
			if node.KernelType != tc.wantKernel {
				t.Fatalf("kernel = %q, want %q", node.KernelType, tc.wantKernel)
			}
			if tc.node.Protocol == "hysteria2" && (node.Protocol != "hysteria" || node.Version != 2) {
				t.Fatalf("hysteria2 was not normalized: protocol=%q version=%d", node.Protocol, node.Version)
			}
		})
	}
}

func TestNodeSpecFromPanelValidatedChecksSelectedKernelOutbounds(t *testing.T) {
	outbound := panel.OutboundConfig{Tag: "hy2", Protocol: "hysteria2", Settings: map[string]any{"server": "2.2.2.2", "server_port": 8443}}
	_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
		Protocol: "hysteria", Version: 2, CustomOutbounds: []panel.OutboundConfig{outbound},
	}, config.KernelConfig{Type: "xray"})
	if err != nil {
		t.Fatalf("sing-box outbound rejected after selecting sing-box: %v", err)
	}
	_, err = NodeSpecFromPanelValidated(&panel.NodeConfig{
		Protocol: "vless", Network: "xhttp", CustomOutbounds: []panel.OutboundConfig{outbound},
	}, config.KernelConfig{Type: "singbox"})
	if err == nil || !strings.Contains(err.Error(), `protocol "hysteria2" is not supported by kernel "xray"`) {
		t.Fatalf("expected selected Xray kernel to reject hysteria2 outbound, got %v", err)
	}
}

func TestNodeSpecFromPanelBandwidthIsServerSide(t *testing.T) {
	nc := &panel.NodeConfig{Protocol: "hysteria", Version: 2, ServerPort: 443, UpMbps: 20, DownMbps: 100}
	spec := NodeSpecFromPanel(nc)
	// Panel: client uploads 20, downloads 100. Server: uploads 100, downloads 20.
	if spec.UpMbps != 100 || spec.DownMbps != 20 {
		t.Fatalf("server-side bandwidth = up %d / down %d, want up 100 / down 20", spec.UpMbps, spec.DownMbps)
	}
	back := spec.ToPanel()
	if back.UpMbps != 20 || back.DownMbps != 100 {
		t.Fatalf("ToPanel did not restore the client's side: up %d / down %d", back.UpMbps, back.DownMbps)
	}
}
