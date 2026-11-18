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

func TestSnellSharedUserKeyValidation(t *testing.T) {
	for _, tc := range []struct {
		name, pskMode, key, mode, shadowServer, shadowPassword, wantError string
		version                                                           int
	}{
		{name: "unknown PSK mode", pskMode: "unknown", version: 6, wantError: "unknown Snell psk_mode"},
		{name: "v5 empty", pskMode: "shared_userkey", version: 5, wantError: "requires a PSK"},
		{name: "v5 short", pskMode: "shared_userkey", version: 5, key: "short"},
		{name: "v5 above v6 maximum", pskMode: "shared_userkey", version: 5, key: strings.Repeat("x", 256)},
		{name: "v6 below minimum", pskMode: "shared_userkey", version: 6, key: strings.Repeat("x", 11), wantError: "12 to 255 bytes"},
		{name: "v6 minimum with per-user ShadowTLS password", pskMode: "shared_userkey", version: 6, key: strings.Repeat("é", 6), shadowServer: "handshake.example"},
		{name: "v6 maximum with shared ShadowTLS password", pskMode: "shared_userkey", version: 6, key: strings.Repeat("x", 255), shadowServer: "handshake.example", shadowPassword: "test-shared-password"},
		{name: "v6 above maximum", pskMode: "shared_userkey", version: 6, key: strings.Repeat("x", 256), wantError: "12 to 255 bytes"},
		{name: "v6 raw", pskMode: "shared_userkey", version: 6, key: strings.Repeat("x", 12), mode: "unsafe-raw", wantError: "encrypted mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := &NodeSpec{Protocol: "snell", Version: tc.version, PSKMode: tc.pskMode, ServerKey: tc.key,
				Mode: tc.mode, ShadowTLSServer: tc.shadowServer, ShadowTLSPassword: tc.shadowPassword}
			err := ValidateNodeSpec(spec, config.KernelConfig{Type: "singbox"})
			if tc.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("want %q, got %v", tc.wantError, err)
			}
		})
	}
}

func TestSnellPSKModeConfigMapping(t *testing.T) {
	const psk = "snell-mapping-test-psk"
	const handshake = "handshake.example"
	const password = "snell-mapping-test-password"
	kcfg := config.KernelConfig{Type: "singbox"}
	for _, mode := range []string{"user", "shared_userkey"} {
		t.Run(mode, func(t *testing.T) {
			nc := &panel.NodeConfig{Protocol: "snell", Version: 6, ServerKey: psk, PSKMode: mode,
				ShadowTLSServer: handshake, ShadowTLSPassword: password}
			panelSpec, err := NodeSpecFromPanelValidated(nc, kcfg)
			if err != nil {
				t.Fatal(err)
			}
			standaloneSpec, err := NodeSpecFromStandaloneValidated(&config.Config{Kernel: kcfg, Standalone: &config.StandaloneConfig{
				Enabled: true, Node: config.StandaloneNodeConfig{Protocol: "snell", Version: 6, ServerKey: psk, PSKMode: mode,
					ShadowTLSServer: handshake, ShadowTLSPassword: password},
			}})
			if err != nil {
				t.Fatal(err)
			}
			for source, spec := range map[string]*NodeSpec{"panel": panelSpec, "standalone": standaloneSpec} {
				if spec.PSKMode != mode || spec.ServerKey != psk || spec.ShadowTLSServer != handshake || spec.ShadowTLSPassword != password {
					t.Errorf("%s config lost Snell authentication settings", source)
				}
			}
			if back := panelSpec.ToPanel(); back.PSKMode != mode || back.ShadowTLSPassword != password {
				t.Fatal("panel round trip lost Snell authentication settings")
			}
		})
	}
}
