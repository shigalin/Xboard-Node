//go:build with_utls

package xray

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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	xnet "github.com/xtls/xray-core/common/net"
	xrayCore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

func TestRealitySNIRoutingAuthenticatedTrafficAndLifecycle(t *testing.T) {
	targets := make(map[string]string)
	for _, name := range []string{"one.example.com", "two.example.com"} {
		website := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, name)
		}))
		website.EnableHTTP2 = true
		website.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519},
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				if hello.ServerName != name {
					return nil, fmt.Errorf("wrong SNI reached this target")
				}
				return nil, nil
			}}
		website.StartTLS()
		t.Cleanup(website.Close)
		targets[name] = website.Listener.Addr().String()
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "authenticated proxy response")
	}))
	t.Cleanup(upstream.Close)
	upstreamPort := upstream.Listener.Addr().(*net.TCPAddr).Port
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := base64.RawURLEncoding.EncodeToString(key.Bytes())
	publicKey := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	listener := testTCPListener(t)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	const uuid = "11111111-1111-4111-8111-111111111111"
	users := []model.UserSpec{{ID: 1, UUID: uuid}}
	kcfg := config.KernelConfig{Type: "xray", LogLevel: "error", RealityTargets: targets,
		CustomRoute: []map[string]any{{"type": "field", "ip": []string{"127.0.0.1/32"}, "outboundTag": "direct"}},
		CustomOutbound: []map[string]any{{"tag": "direct", "protocol": "freedom", "settings": M{
			"finalRules": []M{{"action": "allow", "ip": []string{"127.0.0.1/32"}, "port": fmt.Sprint(upstreamPort)}}}}},
	}
	nc := &model.NodeSpec{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: port, Network: "tcp", TLS: 2,
		Flow: "xtls-rprx-vision", TLSSettings: M{"server_name": "one.example.com,two.example.com", "private_key": privateKey, "short_id": "abcd"}}
	server := New(kcfg)
	t.Cleanup(server.Stop)
	if err := server.Start(nc, users, kernel.TLSCert{}); err != nil {
		t.Fatal("could not start REALITY server", err)
	}
	first := server.instance
	firstRouter := first.GetFeature((*realitySNIRouterLease)(nil)).(*realitySNIRouterLease).realitySNIRouter
	if nc.TLSSettings["dest"] != nil || nc.TLSSettings["server_name"] != "one.example.com,two.example.com" {
		t.Fatal("panel input was mutated")
	}
	checkProxy := func(name, shortID string) {
		t.Helper()
		clientJSON, err := json.Marshal(M{"log": M{"loglevel": "none"}, "outbounds": []M{{"protocol": "vless",
			"settings": M{"vnext": []M{{"address": "127.0.0.1", "port": port,
				"users": []M{{"id": uuid, "encryption": "none", "flow": "xtls-rprx-vision"}}}}},
			"streamSettings": M{"network": "tcp", "security": "reality", "realitySettings": M{
				"serverName": name, "fingerprint": "chrome", "password": publicKey, "shortId": shortID}}}}})
		if err != nil {
			t.Fatal("could not construct test client")
		}
		pb, err := serial.LoadJSONConfig(strings.NewReader(string(clientJSON)))
		if err != nil {
			t.Fatal("could not parse test client")
		}
		xrayCreationMu.Lock()
		client, err := xrayCore.New(pb)
		xrayCreationMu.Unlock()
		if err != nil {
			t.Fatal("could not create test client")
		}
		defer client.Close()
		if err := client.Start(); err != nil {
			t.Fatal("could not start test client")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn, err := xrayCore.Dial(ctx, client, xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(upstreamPort)))
		if err != nil {
			t.Fatal("REALITY connection failed")
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
			t.Fatal("authenticated request reached the wrong endpoint")
		}
	}
	for _, name := range []string{"one.example.com", "two.example.com"} {
		checkProxy(name, "abcd")
	}
	// Ordinary probes must also reach the site matching their SNI.
	for _, name := range []string{"one.example.com", "two.example.com", "unknown.example.com"} {
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		}, TLSClientConfig: &tls.Config{ServerName: name, InsecureSkipVerify: true}}
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		response, err := client.Get("https://" + name)
		if name == "unknown.example.com" {
			if err == nil {
				response.Body.Close()
				t.Fatal("unknown SNI reached a website")
			}
		} else {
			if err != nil {
				t.Fatal("ordinary TLS probe failed", err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(body) != name {
				t.Fatal("ordinary TLS probe reached the wrong website")
			}
		}
		transport.CloseIdleConnections()
	}
	// A bad panel update leaves the old listener/router available.
	bad := *nc
	bad.TLSSettings = M{"server_name": "one.example.com,,two.example.com", "private_key": privateKey, "short_id": "abcd"}
	if err := server.Reload(&bad, users, kernel.TLSCert{}); err == nil || server.instance != first {
		t.Fatal("invalid update replaced the running instance")
	}
	checkProxy("two.example.com", "abcd")
	// Start a replacement with fresh credentials, then verify Stop owns the
	// current router and all routers retained by draining generations.
	replacement := *nc
	replacement.TLSSettings = M{"server_name": "one.example.com,two.example.com", "private_key": privateKey, "short_id": "beef"}
	if err := server.Reload(&replacement, users, kernel.TLSCert{}); err != nil {
		t.Fatal("reload failed", err)
	}
	secondRouter := server.instance.GetFeature((*realitySNIRouterLease)(nil)).(*realitySNIRouterLease).realitySNIRouter
	if secondRouter != firstRouter {
		t.Fatal("unchanged target mapping must reuse its router and probe-cache key")
	}
	checkProxy("one.example.com", "beef")
	checkProxy("two.example.com", "beef")
	server.Stop()
	for _, router := range []*realitySNIRouter{firstRouter, secondRouter} {
		deadline := time.Now().Add(3 * time.Second)
		for {
			if _, err := os.Stat(router.dir); os.IsNotExist(err) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("SNI router was not removed after shutdown/drain")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}
