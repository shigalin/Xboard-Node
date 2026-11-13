package singbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/panel"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singJSON "github.com/sagernet/sing/common/json"
)

var testUsersPanel = []panel.User{
	{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444", SpeedLimit: 0, DeviceLimit: 0},
	{ID: 2, UUID: "bbbbbbbb-5555-6666-7777-888888888888", SpeedLimit: 3, DeviceLimit: 2},
}

// --- Shadowsocks ---

var testUsers = model.UserSpecsFromPanel(testUsersPanel)

func testNodeSpec(nc *panel.NodeConfig) *model.NodeSpec { return model.NodeSpecFromPanel(nc) }

func testRouteRules(r []panel.RouteRule) []model.RouteRule {
	if r == nil {
		return nil
	}
	return model.NodeSpecFromPanel(&panel.NodeConfig{Routes: r}).Routes
}

func TestBuildInbound_Shadowsocks(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: 111,
		Cipher:     "aes-128-gcm",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	assertMapValue(t, inbound, "type", "shadowsocks")
	assertMapValue(t, inbound, "method", "aes-128-gcm")
	assertMapValue(t, inbound, "listen_port", 111)

	users := inbound["users"].([]M)
	if len(users) != 2 {
		t.Fatalf("users: got %d, want 2", len(users))
	}
	assertMapValue(t, users[0], "name", "aaaaaaaa-1111-2222-3333-444444444444")
	assertMapValue(t, users[0], "password", "aaaaaaaa-1111-2222-3333-444444444444")
}

func TestBuildInbound_Shadowsocks2022(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: 222,
		Cipher:     "2022-blake3-aes-128-gcm",
		ServerKey:  "base64serverkey==",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	assertMapValue(t, inbound, "method", "2022-blake3-aes-128-gcm")
	assertMapValue(t, inbound, "password", "base64serverkey==")
}

// --- VMess ---

func TestBuildInbound_VMess(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 443,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	assertMapValue(t, inbound, "type", "vmess")
	assertMapValue(t, inbound, "tag", "vmess-in")

	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "uuid", "aaaaaaaa-1111-2222-3333-444444444444")
	assertMapValue(t, users[0], "alterId", 0)
}

func TestBuildInbound_VMess_WithTLS(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 443,
		TLS:        1,
		ServerName: "example.com",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	tls := inbound["tls"].(M)
	assertMapValue(t, tls, "enabled", true)
	assertMapValue(t, tls, "server_name", "example.com")
	assertMapValue(t, tls, "certificate", []string{"CERT"})
	assertMapValue(t, tls, "key", []string{"KEY"})
}

// Panel tls=1 with cert_mode none (no paths): inbound must be plain — TLS terminated at nginx/CDN.
func TestBuildInbound_VMess_TLS_PanelOn_NoCertFiles(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 8888,
		Network:    "ws",
		TLS:        1,
		ServerName: "example.com",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	if _, exists := inbound["tls"]; exists {
		t.Fatal("expected no tls block when cert/key paths are empty (nginx offload)")
	}
}

func TestBuildInbound_VMess_NoTLS(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 80,
		TLS:        0,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	if _, exists := inbound["tls"]; exists {
		t.Error("should not have TLS when tls=0")
	}
}

func TestBuildInbound_VMess_WithWebSocket(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 80,
		Network:    "ws",
		NetworkSettings: map[string]interface{}{
			"path": "/ws",
			"headers": map[string]interface{}{
				"Host": "example.com",
			},
		},
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	transport := inbound["transport"].(M)
	assertMapValue(t, transport, "type", "ws")
	assertMapValue(t, transport, "path", "/ws")
}

func TestBuildInbound_VMess_WithGRPC(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 443,
		Network:    "grpc",
		NetworkSettings: map[string]interface{}{
			"serviceName": "mygrpc",
		},
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	transport := inbound["transport"].(M)
	assertMapValue(t, transport, "type", "grpc")
	assertMapValue(t, transport, "service_name", "mygrpc")
}

func TestBuildInbound_VMess_WithGRPCSnakeCaseServiceName(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 443,
		Network:    "grpc",
		NetworkSettings: map[string]interface{}{
			"service_name": "mygrpc-snake",
		},
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	transport := inbound["transport"].(M)
	assertMapValue(t, transport, "type", "grpc")
	assertMapValue(t, transport, "service_name", "mygrpc-snake")
}

func TestBuildInbound_VMess_WithH2(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 443,
		Network:    "h2",
		NetworkSettings: map[string]interface{}{
			"path": "/h2path",
			"host": "example.com",
		},
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	transport := inbound["transport"].(M)
	assertMapValue(t, transport, "type", "http")
	assertMapValue(t, transport, "path", "/h2path")
}

func TestBuildInbound_VMess_WithHTTPUpgrade(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 443,
		Network:    "httpupgrade",
		NetworkSettings: map[string]interface{}{
			"path": "/upgrade",
			"host": "example.com",
		},
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	transport := inbound["transport"].(M)
	assertMapValue(t, transport, "type", "httpupgrade")
	assertMapValue(t, transport, "path", "/upgrade")
	assertMapValue(t, transport, "host", "example.com")
}

// --- VLESS ---

func TestBuildInbound_VLESS(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vless",
		ServerPort: 443,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	assertMapValue(t, inbound, "type", "vless")

	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "uuid", "aaaaaaaa-1111-2222-3333-444444444444")
}

func TestBuildInbound_VLESS_WithFlow(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vless",
		ServerPort: 443,
		Flow:       "xtls-rprx-vision",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "flow", "xtls-rprx-vision")
}

func TestBuildInbound_VLESS_Reality(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vless",
		ServerPort: 443,
		TLS:        2,
		TLSSettings: map[string]interface{}{
			"private_key": "test-private-key",
			"short_id":    "abc123",
			"dest":        "www.example.com:443",
			"server_name": "www.example.com",
		},
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	tls := inbound["tls"].(M)
	assertMapValue(t, tls, "enabled", true)

	reality := tls["reality"].(M)
	assertMapValue(t, reality, "enabled", true)
	assertMapValue(t, reality, "private_key", "test-private-key")

	handshake := reality["handshake"].(M)
	assertMapValue(t, handshake, "server", "www.example.com")
	assertMapValue(t, handshake, "server_port", 443)
}

func TestBuildInbound_VLESS_Reality_ShortIDArray(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "vless",
		ServerPort: 443,
		TLS:        2,
		TLSSettings: map[string]interface{}{
			"private_key": "pk",
			"short_id":    []interface{}{"id1", "id2"},
			"dest":        "example.com",
		},
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	reality := inbound["tls"].(M)["reality"].(M)
	ids := reality["short_id"].([]string)
	if len(ids) != 2 {
		t.Errorf("short_id: got %d entries, want 2", len(ids))
	}
}

// --- Trojan ---

func TestBuildInbound_Trojan_Reality(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "trojan",
		ServerPort: 443,
		TLS:        2,
		TLSSettings: map[string]interface{}{
			"private_key": "test-private-key",
			"dest":        "gateway.example.com:8443",
			"server_name": "cdn.example.com",
		},
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	tls := inbound["tls"].(M)
	assertMapValue(t, tls, "enabled", true)
	assertMapValue(t, tls, "server_name", "cdn.example.com")

	reality := tls["reality"].(M)
	assertMapValue(t, reality, "enabled", true)
	assertMapValue(t, reality, "private_key", "test-private-key")

	handshake := reality["handshake"].(M)
	assertMapValue(t, handshake, "server", "gateway.example.com")
	assertMapValue(t, handshake, "server_port", 8443)
}

func TestBuildInbound_Trojan_NoTLS(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "trojan",
		ServerPort: 80,
		TLS:        0,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	// Without certificate paths there is no TLS layer; sing-box trojan needs certs or Reality.
	if _, exists := inbound["tls"]; exists {
		t.Fatal("expected no tls when cert paths are empty and tls=0")
	}
}

func TestBuildInbound_Trojan_WithTLS(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "trojan",
		ServerPort: 443,
		TLS:        1,
		ServerName: "example.com",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	tls := inbound["tls"].(M)
	assertMapValue(t, tls, "enabled", true)
}

// --- Hysteria ---

func TestBuildInbound_Hysteria2(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "hysteria",
		ServerPort: 444,
		Version:    2,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	assertMapValue(t, inbound, "type", "hysteria2")

	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "password", "aaaaaaaa-1111-2222-3333-444444444444")

	tls := inbound["tls"].(M)
	assertMapValue(t, tls, "enabled", true)
	if alpn, ok := tls["alpn"].([]string); !ok || len(alpn) != 1 || alpn[0] != "h3" {
		t.Fatalf("hysteria2 alpn = %v, want [h3]", tls["alpn"])
	}
	if _, ok := inbound["up_mbps"]; ok {
		t.Fatal("up_mbps emitted without a panel value")
	}
}

func TestBuildInbound_Hysteria2_Bandwidth(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "hysteria",
		ServerPort: 444,
		Version:    2,
		UpMbps:     100,
		DownMbps:   200,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	assertMapValue(t, inbound, "type", "hysteria2")
	// Panel values are the client's up/down; the inbound's up is the server's send rate.
	assertMapValue(t, inbound, "up_mbps", 200)
	assertMapValue(t, inbound, "down_mbps", 100)
}

func TestBuildInbound_Hysteria2_WithObfs(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:     "hysteria",
		ServerPort:   444,
		Version:      2,
		Obfs:         "salamander",
		ObfsPassword: "secret",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	obfs := inbound["obfs"].(M)
	assertMapValue(t, obfs, "type", "salamander")
	assertMapValue(t, obfs, "password", "secret")
}

func TestBuildInbound_Hysteria2_GeckoObfs(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:     "hysteria",
		ServerPort:   444,
		Version:      2,
		Obfs:         "gecko",
		ObfsPassword: "secret",
	}
	tc := kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")}
	obfs := buildInbound(testNodeSpec(nc), testUsers, tc)["obfs"].(M)
	assertMapValue(t, obfs, "type", "gecko")
	assertMapValue(t, obfs, "password", "secret")
	// The bundled sing-box must accept the obfs type, not only receive it.
	data, err := json.Marshal(buildConfig(config.KernelConfig{}, testNodeSpec(nc), testUsers, tc))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := singJSON.UnmarshalExtendedContext[option.Options](include.Context(context.Background()), data); err != nil {
		t.Fatalf("sing-box rejected gecko obfs: %v", err)
	}
}

func TestBuildInbound_Snell(t *testing.T) {
	v5 := &panel.NodeConfig{Protocol: "snell", ServerPort: 6160, Version: 5, ServerKey: "0123456789abcdef", Obfs: "http", Mode: "unshaped"}
	inbound := buildInbound(testNodeSpec(v5), testUsers, kernel.TLSCert{})
	assertMapValue(t, inbound, "type", "snell")
	assertMapValue(t, inbound, "version", 5)
	assertMapValue(t, inbound, "psk", "0123456789abcdef")
	assertMapValue(t, inbound, "obfs_mode", "http")
	if _, ok := inbound["mode"]; ok {
		t.Error("v5 inbound must not carry the v6 mode")
	}
	users := inbound["users"].([]M)
	if len(users) != len(testUsers) {
		t.Fatalf("users = %d, want %d", len(users), len(testUsers))
	}
	assertMapValue(t, users[0], "name", "aaaaaaaa-1111-2222-3333-444444444444")
	assertMapValue(t, users[0], "userkey", "aaaaaaaa-1111-2222-3333-444444444444")

	v6 := &panel.NodeConfig{Protocol: "snell", ServerPort: 6160, Version: 6, ServerKey: "0123456789abcdef", Obfs: "http", Mode: "unshaped"}
	inbound = buildInbound(testNodeSpec(v6), testUsers, kernel.TLSCert{})
	assertMapValue(t, inbound, "version", 6)
	assertMapValue(t, inbound, "mode", "unshaped")
	if _, ok := inbound["obfs_mode"]; ok {
		t.Error("v6 inbound must not carry the v5 obfs mode")
	}

	for _, nc := range []*panel.NodeConfig{v5, v6} {
		// Builds the inbound itself, which checks the PSK and user keys.
		if err := New(config.KernelConfig{}).CheckConfig(testNodeSpec(nc), testUsers, kernel.TLSCert{}); err != nil {
			t.Fatalf("sing-box rejected snell v%d: %v", nc.Version, err)
		}
	}
}

// Without users sing-box would accept the shared PSK alone.
func TestBuildInbound_Snell_NoUsersStaysMultiUser(t *testing.T) {
	nc := &panel.NodeConfig{Protocol: "snell", ServerPort: 6160, Version: 5, ServerKey: "0123456789abcdef"}
	users := buildInbound(testNodeSpec(nc), nil, kernel.TLSCert{})["users"].([]M)
	if len(users) != 1 || users[0]["userkey"] == "" || users[0]["userkey"] == nc.ServerKey {
		t.Fatalf("placeholder user = %#v", users)
	}
}

// Behind ShadowTLS the users move to the ShadowTLS inbound; the Snell inbound
// keeps none and is not reachable from outside.
func TestBuildInbounds_SnellShadowTLS(t *testing.T) {
	for _, version := range []int{5, 6} {
		nc := &panel.NodeConfig{
			Protocol: "snell", ServerPort: 6160, Version: version, ServerKey: "0123456789abcdef",
			Obfs: "http", Mode: "unshaped", ShadowTLSServer: "www.example.com",
		}
		inbounds := buildInbounds(testNodeSpec(nc), testUsers, kernel.TLSCert{})
		if len(inbounds) != 2 {
			t.Fatalf("v%d: inbounds = %d, want 2", version, len(inbounds))
		}
		shadowTLS, snell := inbounds[0], inbounds[1]
		assertMapValue(t, shadowTLS, "type", "shadowtls")
		assertMapValue(t, shadowTLS, "listen", "::")
		assertMapValue(t, shadowTLS, "listen_port", 6160)
		assertMapValue(t, shadowTLS, "version", 3)
		assertMapValue(t, shadowTLS, "strict_mode", true)
		assertMapValue(t, shadowTLS, "detour", snell["tag"])
		handshake := shadowTLS["handshake"].(M)
		assertMapValue(t, handshake, "server", "www.example.com")
		assertMapValue(t, handshake, "server_port", 443)
		users := shadowTLS["users"].([]M)
		if len(users) != len(testUsers) {
			t.Fatalf("v%d: users = %d, want %d", version, len(users), len(testUsers))
		}
		assertMapValue(t, users[0], "name", "aaaaaaaa-1111-2222-3333-444444444444")
		assertMapValue(t, users[0], "password", "aaaaaaaa-1111-2222-3333-444444444444")

		assertMapValue(t, snell, "type", "snell")
		assertMapValue(t, snell, "listen", "127.0.0.1")
		assertMapValue(t, snell, "version", version)
		assertMapValue(t, snell, "psk", "0123456789abcdef")
		for _, key := range []string{"users", "listen_port", "obfs_mode"} {
			if _, ok := snell[key]; ok {
				t.Errorf("v%d: snell inbound must not carry %s", version, key)
			}
		}
		if _, ok := snell["mode"]; ok != (version == 6) {
			t.Errorf("v%d: snell inbound mode present = %v", version, ok)
		}
		if err := New(config.KernelConfig{}).CheckConfig(testNodeSpec(nc), testUsers, kernel.TLSCert{}); err != nil {
			t.Fatalf("sing-box rejected snell v%d behind shadowtls: %v", version, err)
		}
	}
}

func TestBuildInbounds_SnellShadowTLS_HandshakePort(t *testing.T) {
	nc := &panel.NodeConfig{Protocol: "snell", ServerPort: 6160, Version: 5, ServerKey: "0123456789abcdef", ShadowTLSServer: "www.example.com", ShadowTLSPort: 8443}
	shadowTLS := buildInbounds(testNodeSpec(nc), testUsers, kernel.TLSCert{})[0]
	assertMapValue(t, shadowTLS["handshake"].(M), "server_port", 8443)
}

// ShadowTLS v3 cannot start without users; the placeholder lets nobody in.
func TestBuildInbounds_SnellShadowTLS_NoUsers(t *testing.T) {
	nc := &panel.NodeConfig{Protocol: "snell", ServerPort: 6160, Version: 5, ServerKey: "0123456789abcdef", ShadowTLSServer: "www.example.com"}
	spec := testNodeSpec(nc)
	users := buildInbounds(spec, nil, kernel.TLSCert{})[0]["users"].([]M)
	if len(users) != 1 || users[0]["password"] == "" || users[0]["password"] == nc.ServerKey {
		t.Fatalf("placeholder user = %#v", users)
	}
	if _, named := users[0]["name"]; named {
		t.Fatalf("placeholder user must not carry an identity: %#v", users)
	}
	if !reflect.DeepEqual(buildInbounds(spec, nil, kernel.TLSCert{}), buildInbounds(spec, nil, kernel.TLSCert{})) {
		t.Fatal("rebuilding without users changed the inbounds")
	}
	if err := New(config.KernelConfig{}).CheckConfig(spec, nil, kernel.TLSCert{}); err != nil {
		t.Fatalf("sing-box rejected shadowtls without users: %v", err)
	}
}

func TestBuildInbound_Hysteria1(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "hysteria",
		ServerPort: 444,
		Version:    0,
		UpMbps:     100,
		DownMbps:   200,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	assertMapValue(t, inbound, "type", "hysteria")
	assertMapValue(t, inbound, "up_mbps", 200)
	assertMapValue(t, inbound, "down_mbps", 100)

	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "auth_str", "aaaaaaaa-1111-2222-3333-444444444444")

	tls := inbound["tls"].(M)
	if alpn, ok := tls["alpn"].([]string); !ok || len(alpn) != 1 || alpn[0] != "hysteria" {
		t.Fatalf("hysteria v1 alpn = %v, want [hysteria]", tls["alpn"])
	}
}

func TestBuildInbound_Hysteria1_PanelALPNWins(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:    "hysteria",
		ServerPort:  444,
		Version:     1,
		TLSSettings: map[string]interface{}{"alpn": []string{"custom"}},
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	tls := inbound["tls"].(M)
	if alpn, ok := tls["alpn"].([]string); !ok || len(alpn) != 1 || alpn[0] != "custom" {
		t.Fatalf("panel alpn overridden: %v", tls["alpn"])
	}
}

// --- TUIC ---

func TestBuildInbound_TUIC(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:          "tuic",
		ServerPort:        555,
		CongestionControl: "bbr",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	assertMapValue(t, inbound, "type", "tuic")
	assertMapValue(t, inbound, "congestion_control", "bbr")

	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "uuid", "aaaaaaaa-1111-2222-3333-444444444444")
	assertMapValue(t, users[0], "password", "aaaaaaaa-1111-2222-3333-444444444444")
}

// --- AnyTLS ---

func TestBuildInbound_AnyTLS(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:      "anytls",
		ServerPort:    443,
		PaddingScheme: "stop=8\n0=30-30",
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	assertMapValue(t, inbound, "type", "anytls")
	assertMapValue(t, inbound, "padding_scheme", "stop=8\n0=30-30")

	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "password", "aaaaaaaa-1111-2222-3333-444444444444")
}

func TestBuildInbound_AnyTLS_NoPaddingScheme(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "anytls",
		ServerPort: 443,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	if _, exists := inbound["padding_scheme"]; exists {
		t.Error("should not have padding_scheme when empty")
	}
}

// --- Naive ---

func TestBuildInbound_Naive(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "naive",
		ServerPort: 443,
		TLS:        1,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	assertMapValue(t, inbound, "type", "naive")

	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "username", "1")
	assertMapValue(t, users[0], "password", "aaaaaaaa-1111-2222-3333-444444444444")

	tls := inbound["tls"].(M)
	assertMapValue(t, tls, "enabled", true)
}

// --- Socks ---

func TestBuildInbound_Socks(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "socks",
		ServerPort: 1080,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	assertMapValue(t, inbound, "type", "socks")

	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "username", "aaaaaaaa-1111-2222-3333-444444444444")
	assertMapValue(t, users[0], "password", "aaaaaaaa-1111-2222-3333-444444444444")

	if _, exists := inbound["tls"]; exists {
		t.Error("socks should not have TLS")
	}
}

// --- HTTP ---

func TestBuildInbound_HTTP(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "http",
		ServerPort: 8080,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	assertMapValue(t, inbound, "type", "http")

	users := inbound["users"].([]M)
	assertMapValue(t, users[0], "username", "aaaaaaaa-1111-2222-3333-444444444444")
}

func TestBuildInbound_HTTP_WithTLS(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "http",
		ServerPort: 443,
		TLS:        1,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	tls := inbound["tls"].(M)
	assertMapValue(t, tls, "enabled", true)
}

// --- Unknown protocol ---

func TestBuildInbound_Unknown(t *testing.T) {
	nc := &panel.NodeConfig{
		Protocol:   "unknown-proto",
		ServerPort: 999,
	}
	inbound := buildInbound(testNodeSpec(nc), testUsers, kernel.TLSCert{})
	if inbound != nil {
		t.Errorf("unknown protocol should return nil, got %v", inbound)
	}
}

// --- buildConfig ---

func TestBuildConfig(t *testing.T) {
	kcfg := config.KernelConfig{LogLevel: "info"}
	nc := &panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: 111,
		Cipher:     "aes-128-gcm",
	}
	cfg := buildConfig(kcfg, testNodeSpec(nc), testUsers, kernel.TLSCert{})

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if len(data) == 0 {
		t.Error("empty JSON output")
	}

	logCfg := cfg["log"].(M)
	assertMapValue(t, logCfg, "level", "info")
	assertMapValue(t, logCfg, "timestamp", true)

	outbounds := cfg["outbounds"].([]M)
	if len(outbounds) != 2 {
		t.Errorf("outbounds: got %d, want 2", len(outbounds))
	}
	assertMapValue(t, outbounds[0], "type", "direct")
	assertMapValue(t, outbounds[1], "type", "block")

	inbounds := cfg["inbounds"].([]M)
	if len(inbounds) != 1 {
		t.Fatalf("inbounds: got %d, want 1", len(inbounds))
	}
	assertMapValue(t, inbounds[0], "type", "shadowsocks")
}

func TestBuildConfig_OutboundPriority(t *testing.T) {
	kcfg := config.KernelConfig{
		LogLevel: "info",
		CustomOutbound: []map[string]any{
			{"tag": "block", "type": "dns"}, // Local static override
		},
	}
	nc := &panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: 111,
		Cipher:     "aes-128-gcm",
		CustomOutbounds: []panel.OutboundConfig{
			{Tag: "direct", Protocol: "socks", Settings: map[string]any{"address": "1.2.3.4"}}, // Panel override
		},
	}

	cfg := buildConfig(kcfg, testNodeSpec(nc), testUsers, kernel.TLSCert{})
	outbounds := cfg["outbounds"].([]M)

	// We have 2 overrides in input, so we should have exactly 2 outbounds total
	// (no auto-generated defaults for these tags)
	if len(outbounds) != 2 {
		t.Errorf("outbounds: got %d, want 2", len(outbounds))
	}

	foundDirect := false
	foundBlock := false

	for _, o := range outbounds {
		tag := o["tag"].(string)
		if tag == "direct" {
			foundDirect = true
			if o["type"] != "socks" {
				t.Errorf("expected 'direct' outbound to be type 'socks' (panel priority), got %v", o["type"])
			}
		}
		if tag == "block" {
			foundBlock = true
			if o["type"] != "dns" {
				t.Errorf("expected 'block' outbound to be type 'dns' (static config priority), got %v", o["type"])
			}
		}
	}

	if !foundDirect || !foundBlock {
		t.Errorf("missing outbounds: direct=%v, block=%v", foundDirect, foundBlock)
	}
}

func TestBuildConfig_AllProtocols_ValidJSON(t *testing.T) {
	protocols := []struct {
		name string
		nc   *panel.NodeConfig
	}{
		{"shadowsocks", &panel.NodeConfig{Protocol: "shadowsocks", ServerPort: 111, Cipher: "aes-128-gcm"}},
		{"vmess", &panel.NodeConfig{Protocol: "vmess", ServerPort: 443}},
		{"vless", &panel.NodeConfig{Protocol: "vless", ServerPort: 443}},
		{"trojan", &panel.NodeConfig{Protocol: "trojan", ServerPort: 443}},
		{"hysteria2", &panel.NodeConfig{Protocol: "hysteria", ServerPort: 444, Version: 2}},
		{"hysteria1", &panel.NodeConfig{Protocol: "hysteria", ServerPort: 444, Version: 1}},
		{"tuic", &panel.NodeConfig{Protocol: "tuic", ServerPort: 555}},
		{"anytls", &panel.NodeConfig{Protocol: "anytls", ServerPort: 443}},
		{"naive", &panel.NodeConfig{Protocol: "naive", ServerPort: 443}},
		{"socks", &panel.NodeConfig{Protocol: "socks", ServerPort: 1080}},
		{"http", &panel.NodeConfig{Protocol: "http", ServerPort: 8080}},
	}

	for _, tc := range protocols {
		t.Run(tc.name, func(t *testing.T) {
			cfg := buildConfig(config.KernelConfig{LogLevel: "warn"}, testNodeSpec(tc.nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatalf("marshal %s: %v", tc.name, err)
			}
			var parsed map[string]interface{}
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("round-trip %s: %v", tc.name, err)
			}
		})
	}
}

// --- Routes ---

func TestBuildRoutes_Default(t *testing.T) {
	route := buildRoutes(nil, nil, nil)
	assertMapValue(t, route, "final", "direct")

	rules := route["rules"].([]M)
	if len(rules) < 2 {
		t.Fatalf("expected at least 2 default rules, got %d", len(rules))
	}
	assertMapValue(t, rules[0], "outbound", "block")
	assertMapValue(t, rules[1], "outbound", "block")
}

func TestBuildRoutes_WithCustomRules(t *testing.T) {
	rules := []panel.RouteRule{
		{ID: 1, Match: []string{"blocked.com"}, Action: "block"},
		{ID: 2, Match: []string{"10.0.0.0/8"}, Action: "block"},
		{ID: 3, Match: []string{"allowed.com"}, Action: "direct"},
	}
	route := buildRoutes(testRouteRules(rules), nil, nil)
	allRules := route["rules"].([]M)

	if len(allRules) != 5 {
		t.Fatalf("rules count: got %d, want 5", len(allRules))
	}

	assertMapValue(t, allRules[2], "outbound", "block")
	if _, ok := allRules[2]["domain_suffix"]; !ok {
		t.Error("domain rule should use domain_suffix")
	}

	assertMapValue(t, allRules[3], "outbound", "block")
	if _, ok := allRules[3]["ip_cidr"]; !ok {
		t.Error("IP rule should use ip_cidr")
	}
}

func TestBuildRoutes_MultiMatch(t *testing.T) {
	// A single route with mixed domain + CIDR matches should produce separate rules
	// Wildcard *.evil.com should become evil.com for domain_suffix
	rules := []panel.RouteRule{
		{ID: 1, Match: []string{"*.evil.com", "bad.org", "192.168.1.0/24"}, Action: "block"},
		{ID: 2, Match: []string{"*.bypass.com"}, Action: "direct"},
	}
	route := buildRoutes(testRouteRules(rules), nil, nil)
	allRules := route["rules"].([]M)

	// 2 default private-IP rules + 1 domain rule + 1 CIDR rule + 1 domain rule = 5
	if len(allRules) != 5 {
		t.Fatalf("rules count: got %d, want 5", len(allRules))
	}

	// Rule #2 (index 2): domains from first route (wildcards stripped)
	domains := allRules[2]["domain_suffix"].([]string)
	if len(domains) != 2 || domains[0] != "evil.com" || domains[1] != "bad.org" {
		t.Errorf("domain_suffix: got %v, want [evil.com bad.org]", domains)
	}
	assertMapValue(t, allRules[2], "outbound", "block")

	// Rule #3 (index 3): CIDRs from first route
	cidrs := allRules[3]["ip_cidr"].([]string)
	if len(cidrs) != 1 || cidrs[0] != "192.168.1.0/24" {
		t.Errorf("ip_cidr: got %v, want [192.168.1.0/24]", cidrs)
	}
	assertMapValue(t, allRules[3], "outbound", "block")

	// Rule #4 (index 4): direct rule (wildcard stripped)
	directDomains := allRules[4]["domain_suffix"].([]string)
	if len(directDomains) != 1 || directDomains[0] != "bypass.com" {
		t.Errorf("direct domain_suffix: got %v, want [bypass.com]", directDomains)
	}
	assertMapValue(t, allRules[4], "outbound", "direct")
}

func TestBuildRoutes_WithCustomRouteRules(t *testing.T) {
	customRules := []model.CustomRouteRule{
		{
			Name: "direct-mixed",
			Match: model.RouteMatch{
				Domains:        []string{"full.example.com"},
				DomainSuffixes: []string{"example.org"},
				IPCIDRs:        []string{"1.1.1.0/24"},
				Ports:          []string{"53", "1000-1002"},
				Networks:       []string{"tcp"},
				SourceCIDRs:    []string{"10.10.0.0/16"},
				SourcePorts:    []string{"2000-2001"},
			},
			Action: model.RouteAction{Type: "direct"},
		},
	}
	route := buildRoutes(nil, customRules, nil)
	allRules := route["rules"].([]M)
	if len(allRules) != 9 {
		t.Fatalf("rules count: got %d, want 9", len(allRules))
	}
	if allRules[0]["domain"].([]string)[0] != "full.example.com" {
		t.Fatalf("unexpected exact domain rule: %v", allRules[0])
	}
	if allRules[1]["domain_suffix"].([]string)[0] != "example.org" {
		t.Fatalf("unexpected domain suffix rule: %v", allRules[1])
	}
	if allRules[2]["ip_cidr"].([]string)[0] != "1.1.1.0/24" {
		t.Fatalf("unexpected ip cidr rule: %v", allRules[2])
	}
	if allRules[3]["port"].([]int)[0] != 53 {
		t.Fatalf("unexpected port rule: %v", allRules[3])
	}
	if allRules[4]["network"].([]string)[0] != "tcp" {
		t.Fatalf("unexpected network rule: %v", allRules[4])
	}
	if allRules[5]["source_ip_cidr"].([]string)[0] != "10.10.0.0/16" {
		t.Fatalf("unexpected source cidr rule: %v", allRules[5])
	}
	if allRules[6]["source_port_range"].([]string)[0] != "2000:2001" {
		t.Fatalf("unexpected source port rule: %v", allRules[6])
	}
}

func TestBuildRoutes_StructuredCustomRulesRemainFirst(t *testing.T) {
	raw := []map[string]any{{"domain": []string{"raw.example.com"}, "outbound": "raw-tag"}}
	custom := []model.CustomRouteRule{{
		Match:  model.RouteMatch{DomainSuffixes: []string{"structured.example"}},
		Action: model.RouteAction{Type: "direct"},
	}}
	route := buildRoutes(nil, custom, raw)
	allRules := route["rules"].([]M)
	if allRules[0]["outbound"] != "direct" {
		t.Fatalf("expected structured route first, got %v", allRules[0]["outbound"])
	}
	if allRules[1]["outbound"] != "raw-tag" {
		t.Fatalf("expected raw custom route second, got %v", allRules[1]["outbound"])
	}
}

// --- TLS Config ---

func TestBuildTLSConfig_WithCert(t *testing.T) {
	nc := &panel.NodeConfig{ServerName: "example.com"}
	tls := buildTLSConfig(testNodeSpec(nc), kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	assertMapValue(t, tls, "enabled", true)
	assertMapValue(t, tls, "server_name", "example.com")
	assertMapValue(t, tls, "certificate", []string{"CERT"})
	assertMapValue(t, tls, "key", []string{"KEY"})
}

func TestBuildTLSConfig_NoCert(t *testing.T) {
	nc := &panel.NodeConfig{ServerName: "example.com"}
	tls := buildTLSConfig(testNodeSpec(nc), kernel.TLSCert{})
	if tls != nil {
		t.Fatalf("expected nil tls config when cert paths are empty, got %+v", tls)
	}
}

func TestBuildTLSConfig_FallbackToHost(t *testing.T) {
	nc := &panel.NodeConfig{Host: "fallback.com"}
	tls := buildTLSConfig(testNodeSpec(nc), kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	assertMapValue(t, tls, "server_name", "fallback.com")
}

func TestBuildTLSConfig_TLSSettingsOverride(t *testing.T) {
	nc := &panel.NodeConfig{
		ServerName: "original.com",
		TLSSettings: map[string]interface{}{
			"server_name": "override.com",
		},
	}
	tls := buildTLSConfig(testNodeSpec(nc), kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})
	assertMapValue(t, tls, "server_name", "override.com")
}

// --- Transport ---

func TestApplyTransport_TCP(t *testing.T) {
	base := M{}
	nc := &panel.NodeConfig{Network: "tcp"}
	applyTransport(base, testNodeSpec(nc))
	if _, exists := base["transport"]; exists {
		t.Error("tcp should not add transport")
	}
}

func TestApplyTransport_Empty(t *testing.T) {
	base := M{}
	nc := &panel.NodeConfig{Network: ""}
	applyTransport(base, testNodeSpec(nc))
	if _, exists := base["transport"]; exists {
		t.Error("empty network should not add transport")
	}
}

func TestApplyTransport_WS_MaxEarlyData(t *testing.T) {
	base := M{}
	nc := &panel.NodeConfig{
		Network: "ws",
		NetworkSettings: map[string]interface{}{
			"path":                   "/ws",
			"max_early_data":         2048,
			"early_data_header_name": "Sec-WebSocket-Protocol",
		},
	}
	applyTransport(base, testNodeSpec(nc))
	transport := base["transport"].(M)
	assertMapValue(t, transport, "max_early_data", 2048)
	assertMapValue(t, transport, "early_data_header_name", "Sec-WebSocket-Protocol")
}

// --- helpers ---

func assertMapValue(t *testing.T, m M, key string, expected interface{}) {
	t.Helper()
	val, ok := m[key]
	if !ok {
		t.Errorf("key %q not found in map", key)
		return
	}
	switch e := expected.(type) {
	case int:
		switch v := val.(type) {
		case int:
			if v != e {
				t.Errorf("%s: got %d, want %d", key, v, e)
			}
		case float64:
			if int(v) != e {
				t.Errorf("%s: got %v, want %d", key, v, e)
			}
		default:
			t.Errorf("%s: got %v (type %T), want %d", key, val, val, e)
		}
	default:
		if !reflect.DeepEqual(val, expected) {
			t.Errorf("%s: got %v, want %v", key, val, expected)
		}
	}
}

func TestExtractECHInbound(t *testing.T) {
	tests := []struct {
		name      string
		tls       map[string]interface{}
		expectNil bool
		expectKey []string
	}{
		{"no ech", map[string]interface{}{}, true, nil},
		{"disabled", map[string]interface{}{"ech": map[string]interface{}{"enabled": false}}, true, nil},
		{"enabled with key", map[string]interface{}{"ech": map[string]interface{}{
			"enabled": true,
			"key":     "-----BEGIN ECH KEYS-----\nABCD\n-----END ECH KEYS-----\n",
		}}, false, []string{"-----BEGIN ECH KEYS-----\nABCD\n-----END ECH KEYS-----\n"}},
		{"enabled with key_path", map[string]interface{}{"ech": map[string]interface{}{
			"enabled":  true,
			"key_path": "/etc/ech/keys.pem",
		}}, false, nil},
		{"enabled no key", map[string]interface{}{"ech": map[string]interface{}{"enabled": true}}, false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractECHInbound(tt.tls)
			if tt.expectNil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result["enabled"] != true {
				t.Errorf("expected enabled=true, got %v", result["enabled"])
			}
			if tt.expectKey != nil {
				if !reflect.DeepEqual(result["key"], tt.expectKey) {
					t.Errorf("key: got %v, want %v", result["key"], tt.expectKey)
				}
			}
		})
	}
}

func TestBuildConfig_CustomNativeTopLevelLists(t *testing.T) {
	// Parse the fixture with the embedded sing-box version before testing the merge.
	customJSON := []byte(`{"services":[{"type":"oom-killer","tag":"memory-guard","memory_limit":"512MB"}],"certificate_providers":[{"type":"cloudflare-origin-ca","tag":"origin-cert","domain":"example.com","api_token":"not-a-real-token"}]}`)
	ctx := include.Context(context.Background())
	if _, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, customJSON); err != nil {
		t.Fatalf("native custom config unsupported by sing-box parser: %v", err)
	}

	var custom map[string]any
	if err := json.Unmarshal(customJSON, &custom); err != nil {
		t.Fatal(err)
	}
	cfg := buildConfig(config.KernelConfig{Type: "singbox", CustomConfigData: custom},
		testNodeSpec(&panel.NodeConfig{Protocol: "vless", ServerPort: 443}), testUsers, kernel.TLSCert{})
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, data)
	if err != nil {
		t.Fatalf("generated config rejected by sing-box parser: %v", err)
	}
	if len(parsed.Services) != 1 || parsed.Services[0].Type != "oom-killer" || parsed.Services[0].Tag != "memory-guard" {
		t.Errorf("generated config lost native services: %s", data)
	}
	if len(parsed.CertificateProviders) != 1 || parsed.CertificateProviders[0].Type != "cloudflare-origin-ca" || parsed.CertificateProviders[0].Tag != "origin-cert" {
		t.Errorf("generated config lost native certificate_providers: %s", data)
	}
}

func TestMergeCustomSingbox_UsesServiceSnapshotOverFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.json")
	if err := os.WriteFile(path, []byte(`{"route":{"rules":[{"domain_suffix":["from-file.example"],"action":"reject"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	kcfg := config.KernelConfig{Type: "singbox", CustomConfig: path, CustomConfigData: map[string]any{
		"route": map[string]any{"rules": []any{map[string]any{"domain_suffix": []any{"from-snapshot.example"}, "action": "reject"}}},
	}}
	cfg := buildConfig(kcfg, testNodeSpec(&panel.NodeConfig{Protocol: "vless", ServerPort: 443}), testUsers, kernel.TLSCert{})
	data, _ := json.Marshal(cfg)
	if !strings.Contains(string(data), "from-snapshot.example") || strings.Contains(string(data), "from-file.example") {
		t.Fatalf("expected the service snapshot to be merged instead of the file, got %s", data)
	}
}

func TestSnellUserPSKContract(t *testing.T) {
	const uuid = "11111111-1111-4111-8111-111111111111"
	const expected = uuid

	spec := &model.NodeSpec{Protocol: "snell", Version: 6, PSKMode: "user", ServerKey: "0123456789abcdef", ShadowTLSServer: "handshake.example"}
	in := buildInbounds(spec, []model.UserSpec{{UUID: uuid}}, kernel.TLSCert{})[1]
	if in["psk"] != nil || in["user_psk"] != true || in["auth_detour"] != shadowTLSInboundTag {
		t.Fatalf("invalid independent PSK config: %v", in)
	}
	if got := in["users"].([]M)[0]["psk"]; got != expected {
		t.Fatal("wrong user key")
	}
}
