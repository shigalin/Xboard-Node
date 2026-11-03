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
			cfg := sniTestConfig("one.example.com")
			router, err := prepareRealitySNIRouting(cfg, targets)
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

func TestRealitySNIRoutingRequiresDefaultAndPreservesUnconfiguredNodes(t *testing.T) {
	cfg := sniTestConfig("default.example.com")
	if _, err := prepareRealitySNIRouting(cfg, map[string]string{"other.example.com": "127.0.0.1:443"}); err == nil {
		t.Fatal("must not break the subscription's default SNI")
	}
	for _, cfg := range []M{sniTestConfig("default.example.com"), {"inbounds": []M{{"streamSettings": M{"security": "tls"}}}}} {
		before, _ := marshalConfig(cfg)
		router, err := prepareRealitySNIRouting(cfg, nil)
		after, _ := marshalConfig(cfg)
		if err != nil || router != nil || string(before) != string(after) {
			t.Fatal("unset SNI routing changed the generated config")
		}
	}
	cfg = M{"inbounds": []M{{"streamSettings": M{"security": "tls"}}}}
	if router, err := prepareRealitySNIRouting(cfg, map[string]string{"one.example.com": "127.0.0.1:443"}); err != nil || router != nil {
		t.Fatal("SNI routing must apply only to REALITY")
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
	server := New(config.KernelConfig{RealitySNITargets: map[string]string{"one.example.com": "127.0.0.1:443"}})
	nc := &model.NodeSpec{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: 443, Network: "tcp", TLS: 2,
		TLSSettings: M{"server_name": "one.example.com", "private_key": "invalid-test-key", "short_id": "abcd"}}
	if err := server.Start(nc, nil, kernel.TLSCert{}); err == nil {
		server.Stop()
		t.Fatal("invalid main REALITY config unexpectedly started")
	}
	paths, err := filepath.Glob(filepath.Join(dir, "xb-sni-*"))
	if err != nil || len(paths) != 0 {
		t.Fatal("failed main startup leaked the SNI router")
	}
}
