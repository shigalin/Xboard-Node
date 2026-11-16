package model

import (
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestPanelVLESSMultiplexRejected(t *testing.T) {
	for _, kind := range []string{"xray", "singbox"} {
		for _, enabled := range []bool{false, true} {
			_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{Protocol: "vless", Multiplex: &panel.MultiplexConfig{Enabled: enabled, Padding: true}}, config.KernelConfig{Type: kind})
			if enabled {
				if err == nil || !strings.Contains(err.Error(), "multiplex") {
					t.Fatalf("%s: expected multiplex error, got %v", kind, err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestStandaloneKernelCompatibility(t *testing.T) {
	for _, kind := range []string{"xray", "singbox"} {
		for _, tc := range []struct {
			name      string
			node      config.StandaloneNodeConfig
			wantError string
		}{
			{"vless-mux", config.StandaloneNodeConfig{Protocol: "vless", Multiplex: &config.StandaloneMultiplexConfig{Enabled: true}}, "multiplex"},
			{"hysteria-v1", config.StandaloneNodeConfig{Protocol: "hysteria", Version: 1}, "version 2"},
			{"hysteria-v2", config.StandaloneNodeConfig{Protocol: "hysteria", Version: 2}, ""},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				_, err := NodeSpecFromStandaloneValidated(&config.Config{Kernel: config.KernelConfig{Type: kind}, Standalone: &config.StandaloneConfig{Enabled: true, Node: tc.node}})
				if kind == "xray" && tc.wantError != "" {
					if err == nil || !strings.Contains(err.Error(), tc.wantError) {
						t.Fatalf("expected %q error, got %v", tc.wantError, err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestHysteria2ObfuscationRequiresPassword(t *testing.T) {
	for _, kind := range []string{"xray", "singbox"} {
		for _, obfs := range []string{"salamander", "gecko"} {
			for _, password := range []string{"", "test-password"} {
				err := ValidateNodeSpec(&NodeSpec{Protocol: "hysteria", Version: 2, Obfs: obfs, ObfsPassword: password}, config.KernelConfig{Type: kind})
				if password == "" {
					if err == nil || !strings.Contains(err.Error(), "obfs password") {
						t.Fatalf("%s/%s: expected password error, got %v", kind, obfs, err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestHysteria2RejectsUnknownObfuscation(t *testing.T) {
	for _, kind := range []string{"xray", "singbox"} {
		err := ValidateNodeSpec(&NodeSpec{Protocol: "hysteria", Version: 2, Obfs: "unsupported", ObfsPassword: "test-password"}, config.KernelConfig{Type: kind})
		if err == nil || !strings.Contains(err.Error(), "obfuscation type") {
			t.Fatalf("%s: expected obfuscation type error, got %v", kind, err)
		}
	}
}
