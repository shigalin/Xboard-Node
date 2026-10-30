package xray

import (
	"reflect"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestBuildConfigLocalRealityTarget(t *testing.T) {
	for _, port := range []int{443, 2053} {
		nc := testNodeSpec(&panel.NodeConfig{Protocol: "vless", Network: "tcp", TLS: 2, ServerPort: port,
			TLSSettings: M{"server_name": "site.example.com", "server_port": 48081, "private_key": "test-key", "short_id": "abcd"}})
		cfg := buildConfig(config.KernelConfig{RealityTargets: map[string]string{"site.example.com": "127.0.0.1:48080"}}, nc, testUsers, kernel.TLSCert{})
		in := cfg["inbounds"].([]M)[0]
		reality := in["streamSettings"].(M)["realitySettings"].(M)
		if in["port"] != port || reality["dest"] != "127.0.0.1:48080" || !reflect.DeepEqual(reality["serverNames"], []string{"site.example.com"}) {
			t.Fatal("local target, SNI or listener port is incorrect")
		}
		if _, exists := nc.TLSSettings["dest"]; exists {
			t.Fatal("panel input was mutated")
		}
	}
}

func TestBuildRealitySettingsPreservesLegacyTargetPort(t *testing.T) {
	for _, value := range []any{48080, float64(48080), "48080"} {
		nc := testNodeSpec(&panel.NodeConfig{TLSSettings: M{"server_name": "site.example.com", "server_port": value}})
		if got := buildRealitySettings(nc)["dest"]; got != "site.example.com:443" {
			t.Fatalf("legacy fallback changed: %v", got)
		}
		nc.TLSSettings["dest"] = "panel.example.com:8443"
		if got := buildRealitySettings(nc)["dest"]; got != "panel.example.com:8443" {
			t.Fatalf("explicit panel destination changed: %v", got)
		}
	}
}
