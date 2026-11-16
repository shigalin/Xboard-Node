package xray

import (
	"context"
	"net"
	"testing"

	"github.com/cedar2025/xboard-node/internal/cert"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

func TestHysteriaConfigAcceptedByCore(t *testing.T) {
	manager := cert.NewManager(config.CertConfig{CertMode: "self", CertDir: t.TempDir()})
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer manager.Stop()
	for _, obfs := range []string{"", "salamander", "gecko"} {
		t.Run("obfs="+obfs, func(t *testing.T) {
			listener, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := listener.LocalAddr().(*net.UDPAddr).Port
			listener.Close()
			cfg := config.KernelConfig{Type: "xray", LogLevel: "error", ConfigDir: t.TempDir()}
			// Exercise the Xray adapter directly; panel policy selects sing-box.
			node := &model.NodeSpec{Protocol: "hysteria", Version: 2, ListenIP: "127.0.0.1", ServerPort: port, Obfs: obfs, ObfsPassword: "test-password", UpMbps: 10, DownMbps: 20}
			server := New(cfg)
			defer server.Stop()
			if err := server.CheckConfig(node, testUsers, manager.TLSCert()); err != nil {
				t.Fatal(err)
			}
			if err := server.Start(node, testUsers, manager.TLSCert()); err != nil {
				t.Fatal(err)
			}
			if !server.IsRunning() {
				t.Fatal("Hysteria2 listener did not start")
			}
		})
	}
}

func TestHysteriaObfuscationConfig(t *testing.T) {
	for _, obfs := range []string{"salamander", "gecko"} {
		t.Run(obfs, func(t *testing.T) {
			node := &model.NodeSpec{Protocol: "hysteria", Version: 2, Obfs: obfs, ObfsPassword: "test-password", UpMbps: 10, DownMbps: 20}
			inbound := buildInbound(node, testUsers, kernel.TLSCert{})
			mask, ok := inbound["streamSettings"].(M)["finalMask"].(M)
			if !ok {
				t.Fatal("missing finalMask")
			}
			udp, ok := mask["udp"].([]M)
			if !ok || len(udp) != 1 {
				t.Fatal("missing obfuscation")
			}
			settings := udp[0]["settings"].(M)
			if udp[0]["type"] != "salamander" || settings["password"] != "test-password" {
				t.Fatal("wrong obfuscation settings")
			}
			if obfs == "gecko" && settings["packetSize"] != "512-1200" {
				t.Fatal("missing gecko packet size")
			}
			params := mask["quicParams"].(M)
			if params["brutalUp"] != "10 mbps" || params["brutalDown"] != "20 mbps" {
				t.Fatal("obfuscation lost bandwidth settings")
			}
		})
	}
}
