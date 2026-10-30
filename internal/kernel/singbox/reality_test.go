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

func TestBuildConfigUnmappedRealityTargetUsesPanelDestination(t *testing.T) {
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
					if handshake["server"] != "2001:db8::1" || handshake["server_port"] != 8443 {
						t.Fatalf("panel destination was not parsed: %#v", handshake)
					}
				})
			}
		})
	}
}

// The panel destination parser must keep its documented fallbacks.
func TestBuildRealityConfigDestinationFallbacks(t *testing.T) {
	for _, tt := range []struct {
		name     string
		settings M
		server   string
		port     int
	}{
		{"host and port", M{"server_name": "site.example.com", "dest": "panel.example.com:8443"}, "panel.example.com", 8443},
		{"host only uses panel port", M{"server_name": "site.example.com", "dest": "panel.example.com", "server_port": 8443}, "panel.example.com", 8443},
		{"host only without panel port", M{"server_name": "site.example.com", "dest": "panel.example.com"}, "panel.example.com", 443},
		{"non-numeric port", M{"server_name": "site.example.com", "dest": "panel.example.com:https"}, "panel.example.com", 443},
		{"server name fallback", M{"server_name": "site.example.com"}, "site.example.com", 443},
		// An unbracketed IPv6 destination has no parsable port; keeping the
		// address whole is better than the old parser's truncated first group.
		{"bare ipv6", M{"server_name": "site.example.com", "dest": "2001:db8::1"}, "2001:db8::1", 443},
		{"bare ipv6 with panel port", M{"server_name": "site.example.com", "dest": "2001:db8::1", "server_port": 8443}, "2001:db8::1", 8443},
	} {
		t.Run(tt.name, func(t *testing.T) {
			nc := testNodeSpec(&panel.NodeConfig{Protocol: "vless", TLS: 2, TLSSettings: tt.settings})
			handshake := buildRealityConfig(nc)["reality"].(M)["handshake"].(M)
			if handshake["server"] != tt.server || handshake["server_port"] != tt.port {
				t.Fatalf("handshake = %#v", handshake)
			}
		})
	}
}
