package xray

import (
	"reflect"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestBuildConfigWebsiteFallbackFollowsPanel(t *testing.T) {
	const domain = "site.example.test"
	const httpsTarget = "127.0.0.1:48080"
	const httpTarget = "127.0.0.1:48081"
	cfg := config.KernelConfig{
		RealityTargets:    map[string]string{domain: httpsTarget},
		TLSWebsiteTargets: map[string]string{domain: httpTarget},
	}
	for _, tc := range []struct {
		name, network, host string
		tls, port           int
		wantRaw, wantXHTTP  bool
	}{
		{"TCP TLS", "tcp", domain, 1, 443, true, false},
		{"XHTTP TLS", "xhttp", domain, 1, 443, false, true},
		{"uppercase RAW TLS", "RAW", domain, 1, 443, true, false},
		{"uppercase XHTTP TLS", "XHTTP", domain, 1, 443, false, true},
		{"TCP REALITY", "tcp", domain, 2, 443, false, false},
		{"XHTTP REALITY", "xhttp", domain, 2, 443, false, false},
		{"missing mapping", "tcp", "other.example.test", 1, 443, false, false},
		{"unsupported transport", "ws", domain, 1, 443, false, false},
		{"self target", "xhttp", domain, 1, 48081, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nc := testNodeSpec(&panel.NodeConfig{Protocol: "vless", Network: tc.network, TLS: tc.tls,
				ServerPort: tc.port, TLSSettings: M{"server_name": tc.host}})
			in := buildConfig(cfg, nc, testUsers, kernel.TLSCert{})["inbounds"].([]M)[0]
			settings := in["settings"].(M)
			stream := in["streamSettings"].(M)
			if got, present := settings["fallbacks"]; present != tc.wantRaw || present && !reflect.DeepEqual(got, []M{{"name": domain, "dest": httpTarget}}) {
				t.Fatalf("unexpected raw fallback %v", got)
			}
			xhttp, _ := stream["xhttpSettings"].(M)
			if got, present := xhttp["httpFallback"]; present != tc.wantXHTTP || present && got != httpTarget {
				t.Fatalf("unexpected XHTTP fallback %v", got)
			}
			if tc.tls == 2 && stream["realitySettings"].(M)["dest"] != httpsTarget {
				t.Fatal("REALITY lost its HTTPS website destination")
			}
			if in["port"] != tc.port {
				t.Fatal("fallback changed the node port")
			}
		})
	}
}

func TestBuildConfigWebsiteFallbackRawKeepsALPNAndSkipsEncryption(t *testing.T) {
	const domain = "site.example.test"
	cfg := config.KernelConfig{TLSWebsiteTargets: map[string]string{domain: "127.0.0.1:48081"}}
	build := func(decryption string) M {
		nc := testNodeSpec(&panel.NodeConfig{Protocol: "vless", Network: "tcp", TLS: 1, ServerPort: 443,
			Decryption: decryption, TLSSettings: M{"server_name": domain}})
		return buildConfig(cfg, nc, testUsers, kernel.TLSCert{})["inbounds"].([]M)[0]
	}

	in := build("")
	if _, ok := in["settings"].(M)["fallbacks"]; !ok {
		t.Fatal("raw fallback missing")
	}
	// h2-only clients must still complete the TLS handshake.
	if _, ok := in["streamSettings"].(M)["tlsSettings"].(M)["alpn"]; ok {
		t.Fatal("raw fallback must keep the default ALPN")
	}

	// Xray rejects fallbacks together with VLESS Encryption.
	in = build("mlkem768x25519plus.native.0rtt.key")
	if _, ok := in["settings"].(M)["fallbacks"]; ok {
		t.Fatal("fallbacks must be skipped when VLESS decryption is enabled")
	}
}
