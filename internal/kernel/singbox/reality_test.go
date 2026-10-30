package singbox

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestBuildConfigLocalRealityTarget(t *testing.T) {
	for _, protocol := range []string{"vless", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			for _, port := range []int{443, 2053} {
				for dest, host := range map[string]string{"127.0.0.1:48080": "127.0.0.1", "[::1]:48080": "::1"} {
					nc := testNodeSpec(&panel.NodeConfig{Protocol: protocol, Network: "tcp", TLS: 2, ServerPort: port,
						TLSSettings: M{"server_name": "site.example.com", "server_port": 48081, "private_key": "test-key", "short_id": "abcd"}})
					cfg := buildConfig(config.KernelConfig{RealityTargets: map[string]string{"site.example.com": dest}}, nc, testUsers, kernel.TLSCert{})
					in := cfg["inbounds"].([]M)[0]
					tls := in["tls"].(M)
					handshake := tls["reality"].(M)["handshake"].(M)
					if in["listen_port"] != port || tls["server_name"] != "site.example.com" || handshake["server"] != host || handshake["server_port"] != 48080 {
						t.Fatal("local target, SNI or listener port is incorrect")
					}
					if _, exists := nc.TLSSettings["dest"]; exists {
						t.Fatal("panel input was mutated")
					}
				}
			}
		})
	}
}

func TestBuildConfigUnmappedRealityTargetPreservesLegacyParsing(t *testing.T) {
	for _, protocol := range []string{"vless", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			for _, tt := range []struct {
				name    string
				targets map[string]string
			}{
				{name: "mapping disabled"},
				{name: "SNI unmatched", targets: map[string]string{"other.example.com": "[::1]:48080"}},
			} {
				t.Run(tt.name, func(t *testing.T) {
					nc := testNodeSpec(&panel.NodeConfig{Protocol: protocol, TLS: 2, ServerPort: 2053,
						TLSSettings: M{"server_name": "site.example.com", "dest": "[2001:db8::1]:8443"}})
					cfg := buildConfig(config.KernelConfig{RealityTargets: tt.targets}, nc, testUsers, kernel.TLSCert{})
					handshake := cfg["inbounds"].([]M)[0]["tls"].(M)["reality"].(M)["handshake"].(M)
					// Preserve even the legacy parser's IPv6 limitation outside
					// the explicitly enabled and matched local mapping path.
					if handshake["server"] != "[2001" || handshake["server_port"] != 443 {
						t.Fatalf("unmapped destination parsing changed: %#v", handshake)
					}
				})
			}
		})
	}
}
