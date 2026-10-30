//go:build with_utls

package kernel_test

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/kernel/singbox"
	"github.com/cedar2025/xboard-node/internal/kernel/xray"
	"github.com/cedar2025/xboard-node/internal/model"
	xnet "github.com/xtls/xray-core/common/net"
	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

func TestLocalRealityWebsiteAuthenticatedTraffic(t *testing.T) {
	website := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "camouflage website")
	}))
	website.EnableHTTP2 = true
	website.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	website.StartTLS()
	defer website.Close()
	websiteAddr := website.Listener.Addr().String()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "authenticated proxy response")
	}))
	defer upstream.Close()
	upstreamPort := upstream.Listener.Addr().(*net.TCPAddr).Port
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := base64.RawURLEncoding.EncodeToString(key.Bytes())
	publicKey := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	const sni = "website.example.invalid"
	const uuid = "11111111-1111-4111-8111-111111111111"

	for _, kind := range []string{"xray", "singbox"} {
		t.Run(kind, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()
			kcfg := config.KernelConfig{Type: kind, ConfigDir: t.TempDir(), LogLevel: "error",
				RealityTargets: map[string]string{sni: websiteAddr}}
			// Allow only the loopback test upstream before the normal private-IP block.
			var server kernel.Kernel
			if kind == "xray" {
				kcfg.CustomRoute = []map[string]any{{"type": "field", "ip": []string{"127.0.0.1/32"}, "outboundTag": "direct"}}
				// Xray's freedom outbound also blocks private IPs by default.
				// Permit only this local fixture, independently of the route rule.
				kcfg.CustomOutbound = []map[string]any{{"tag": "direct", "protocol": "freedom", "settings": map[string]any{
					"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}, "port": fmt.Sprint(upstreamPort)}}}}}
				server = xray.New(kcfg)
			} else {
				kcfg.CustomRoute = []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}}
				server = singbox.New(kcfg)
			}
			nc := &model.NodeSpec{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: port, Network: "tcp", TLS: 2,
				Flow: "xtls-rprx-vision", TLSSettings: map[string]any{"server_name": sni, "server_port": 443,
					"private_key": privateKey, "short_id": "abcd"}}
			if err := server.Start(nc, []model.UserSpec{{ID: 1, UUID: uuid}}, kernel.TLSCert{}); err != nil {
				t.Fatal(err)
			}
			defer server.Stop()
			clientJSON, err := json.Marshal(map[string]any{
				"log": map[string]any{"loglevel": "none"},
				"outbounds": []any{map[string]any{"protocol": "vless",
					"settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port,
						"users": []any{map[string]any{"id": uuid, "encryption": "none", "flow": "xtls-rprx-vision"}}}}},
					"streamSettings": map[string]any{"network": "tcp", "security": "reality",
						"realitySettings": map[string]any{"serverName": sni, "fingerprint": "chrome", "password": publicKey, "shortId": "abcd"}}}},
			})
			if err != nil {
				t.Fatal("could not construct test client configuration")
			}
			clientConfig, err := serial.LoadJSONConfig(strings.NewReader(string(clientJSON)))
			if err != nil {
				t.Fatal("could not parse test client configuration")
			}
			client, err := xcore.New(clientConfig)
			if err != nil {
				t.Fatal("could not create test client")
			}
			defer client.Close()
			if err := client.Start(); err != nil {
				t.Fatal("could not start test client")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := xcore.Dial(ctx, client, xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(upstreamPort)))
			if err != nil {
				t.Fatal("could not connect through REALITY")
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(15 * time.Second))
			if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"); err != nil {
				t.Fatal("could not send authenticated request")
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "GET"})
			if err != nil {
				t.Fatal("authenticated request failed", err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != "authenticated proxy response" {
				t.Fatal("request did not reach the authenticated upstream")
			}
		})
	}
}
