package xray

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

func sniTestConfig(name string) M {
	return M{"inbounds": []M{{"streamSettings": M{"security": "reality", "realitySettings": M{
		"serverNames": []string{name}, "dest": "unchanged.example.com:443",
	}}}}}
}

func TestRealitySNIRouterRoutesTLSAndRejectsUnknownNames(t *testing.T) {
	for _, network := range []string{"tcp", "unix"} {
		t.Run(network, func(t *testing.T) {
			// Each target accepts only its own SNI, so a fixed/wrong destination
			// cannot accidentally satisfy the positive routing assertions.
			targets := make(map[string]string)
			for _, name := range []string{"one.example.com", "two.example.com"} {
				website := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					fmt.Fprint(w, name)
				}))
				website.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					if hello.ServerName != name {
						return nil, fmt.Errorf("unexpected SNI")
					}
					return nil, nil
				}}
				website.StartTLS()
				t.Cleanup(website.Close)
				targets[name] = website.Listener.Addr().String()
			}
			cfg := sniTestConfig("one.example.com,two.example.com")
			nc := &model.NodeSpec{TLS: 2, TLSSettings: M{"server_name": "one.example.com,two.example.com"}}
			router, err := prepareRealitySNIRouting(cfg, nc, targets, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { router.Close() })
			reality := cfg["inbounds"].([]M)[0]["streamSettings"].(M)["realitySettings"].(M)
			if !reflect.DeepEqual(reality["serverNames"], []string{"one.example.com", "two.example.com"}) {
				t.Fatal("REALITY did not receive all allowed SNI names")
			}
			// The real private entry is Unix. A TCP bridge models REALITY's
			// unchanged ClientHello forwarding without terminating TLS.
			addr := reality["dest"].(string)
			if network == "tcp" {
				bridge := testTCPListener(t)
				go func() {
					for {
						client, err := bridge.Accept()
						if err != nil {
							return
						}
						go func() {
							defer client.Close()
							upstream, err := net.Dial("unix", reality["dest"].(string))
							if err != nil {
								return
							}
							defer upstream.Close()
							done := make(chan struct{})
							go func() { io.Copy(upstream, client); upstream.(*net.UnixConn).CloseWrite(); close(done) }()
							io.Copy(client, upstream)
							client.Close()
							<-done
						}()
					}
				}()
				addr = bridge.Addr().String()
			}
			for _, name := range []string{"one.example.com", "two.example.com", "unlisted.example.com", ""} {
				transport := &http.Transport{
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, network, addr)
					},
					TLSClientConfig: &tls.Config{ServerName: name, InsecureSkipVerify: true}, // local fixture certificate
				}
				client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
				// An IP URL omits SNI when ServerName is empty.
				resp, err := client.Get("https://127.0.0.1/")
				transport.CloseIdleConnections()
				if targets[name] == "" {
					if err == nil {
						resp.Body.Close()
						t.Fatal("unlisted/absent SNI reached a target")
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || string(body) != name {
					t.Fatalf("SNI %s reached wrong target: %q, %v", name, body, err)
				}
			}
			// Closing a generation must also end established, anonymous TLS
			// forwards, which are intentionally absent from user/IP accounting.
			raw, err := net.Dial(network, addr)
			if err != nil {
				t.Fatal(err)
			}
			idle := tls.Client(raw, &tls.Config{ServerName: "one.example.com", InsecureSkipVerify: true})
			defer idle.Close()
			idle.SetDeadline(time.Now().Add(3 * time.Second))
			if err := idle.Handshake(); err != nil {
				t.Fatal(err)
			}
			partial, err := net.Dial(network, addr)
			if err != nil {
				t.Fatal(err)
			}
			defer partial.Close()
			partial.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := partial.Write([]byte{22, 3}); err != nil {
				t.Fatal(err)
			}
			if err := router.Close(); err != nil {
				t.Fatal(err)
			}
			for _, conn := range []net.Conn{idle, partial} {
				if _, err := conn.Read(make([]byte, 1)); err == nil {
					t.Fatal("closed router still forwards traffic")
				} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					t.Fatal("closed router retained a connection")
				}
			}
			if _, err := os.Stat(router.dir); !os.IsNotExist(err) {
				t.Fatal("router socket directory remains after close")
			}
		})
	}
}

func TestPanelRealitySNITargets(t *testing.T) {
	for _, port := range []any{nil, "", 443, float64(443), "443"} {
		names, targets, err := panelRealitySNITargets(" One.example.com. , two.example.com,one.example.com", port, nil)
		if err != nil || !reflect.DeepEqual(names, []string{"one.example.com", "two.example.com"}) ||
			!reflect.DeepEqual(targets, map[string]string{"one.example.com": "one.example.com:443", "two.example.com": "two.example.com:443"}) {
			t.Fatalf("unexpected panel mapping: %v, %v, %v", names, targets, err)
		}
	}
	_, targets, err := panelRealitySNITargets("one.example.com,two.example.com", 8443, map[string]string{"one.example.com": "127.0.0.1:48080"})
	if err != nil || targets["one.example.com"] != "127.0.0.1:48080" || targets["two.example.com"] != "two.example.com:8443" {
		t.Fatal("shared port or local override was lost")
	}
	for _, raw := range []string{"", "one.example.com,", ",one.example.com", "one.example.com,,two.example.com", "*.example.com,two.example.com", "127.0.0.1,two.example.com", "one.example.com:443,two.example.com"} {
		if _, _, err := panelRealitySNITargets(raw, 443, nil); err == nil {
			t.Fatalf("invalid SNI list accepted: %q", raw)
		}
	}
	for _, port := range []any{0, -1, 65536, "443,8443", 443.5} {
		if _, _, err := panelRealitySNITargets("one.example.com,two.example.com", port, nil); err == nil {
			t.Fatal("invalid shared port accepted")
		}
	}
}

func TestRealitySNIRoutingPreservesSingleNameNodes(t *testing.T) {
	cfg := sniTestConfig("one.example.com")
	before, _ := marshalConfig(cfg)
	nc := &model.NodeSpec{TLS: 2, TLSSettings: M{"server_name": "one.example.com"}}
	router, err := prepareRealitySNIRouting(cfg, nc, nil, nil)
	after, _ := marshalConfig(cfg)
	if err != nil || router != nil || string(before) != string(after) {
		t.Fatal("single-name node configuration changed")
	}
	nc.TLS = 1
	nc.TLSSettings["server_name"] = "one.example.com,two.example.com"
	if router, err := prepareRealitySNIRouting(cfg, nc, nil, nil); err != nil || router != nil {
		t.Fatal("non-REALITY node changed")
	}
}

func TestRealitySNIRouterLeasesReuseAndReleaseGenerations(t *testing.T) {
	nc := &model.NodeSpec{TLS: 2, TLSSettings: M{"server_name": "one.example.com,two.example.com", "server_port": 443}}
	first, err := prepareRealitySNIRouting(sniTestConfig("unused"), nc, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { first.Close() })
	second, err := prepareRealitySNIRouting(sniTestConfig("unused"), nc, nil, first.realitySNIRouter)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { second.Close() })
	if first == second || first.realitySNIRouter != second.realitySNIRouter {
		t.Fatal("generations need separate leases on the same unchanged router")
	}
	first.Close()
	first.Close() // repeated core Close must not release the newer generation
	if _, err := os.Stat(second.dir); err != nil {
		t.Fatal("old generation closed a router still used by the new one")
	}
	nc.TLSSettings["server_port"] = 8443
	changed, err := prepareRealitySNIRouting(sniTestConfig("unused"), nc, nil, second.realitySNIRouter)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { changed.Close() })
	if changed.realitySNIRouter == second.realitySNIRouter || second.targets["one.example.com"] != "one.example.com:443" {
		t.Fatal("new mapping mutated the previous generation")
	}
	second.Close()
	if _, err := os.Stat(second.dir); !os.IsNotExist(err) {
		t.Fatal("last lease did not remove its router")
	}
	if _, err := os.Stat(changed.dir); err != nil {
		t.Fatal("closing an old mapping affected the changed mapping")
	}
}

func TestRealitySNIRouterCleanedUpOnMainConfigFailure(t *testing.T) {
	// Keep the Unix path short on macOS, and isolate it so leaked sockets can
	// be detected without depending on other tests/processes' temporary files.
	dir, err := os.MkdirTemp("/tmp", "xb-fail-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("TMPDIR", dir)
	server := New(config.KernelConfig{})
	nc := &model.NodeSpec{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: 443, Network: "tcp", TLS: 2,
		TLSSettings: M{"server_name": "one.example.com,two.example.com", "private_key": "invalid-test-key", "short_id": "abcd"}}
	if err := server.Start(nc, nil, kernel.TLSCert{}); err == nil {
		server.Stop()
		t.Fatal("invalid main REALITY config unexpectedly started")
	}
	paths, err := filepath.Glob(filepath.Join(dir, "xb-sni-*"))
	if err != nil || len(paths) != 0 {
		t.Fatal("failed main startup leaked the SNI router")
	}
}
