package service

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/panel"
	"golang.org/x/net/proxy"
)

type kernelTestControlPlane struct {
	controlplane.ControlPlane
	kcfg   config.KernelConfig
	node   panel.NodeConfig
	users  []model.UserSpec
	polled *model.NodeSpec
}

func TestWSInvalidCertificatePreservesKernelAndCertificate(t *testing.T) {
	for _, mode := range []string{"content", "file"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			cfg := &config.Config{Kernel: config.KernelConfig{Type: "xray"}, Cert: config.CertConfig{CertMode: "self", CertDir: t.TempDir()}}
			s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
			if err := s.cert.Start(ctx); err != nil {
				t.Fatal(err)
			}
			defer func() { s.cert.Stop(); s.kernel.Stop() }()
			old := &fakeKernel{running: true}
			s.kernel = old
			original := &model.NodeSpec{Protocol: "vless", Network: "tcp"}
			s.lastConfig, s.lastConfigHash = original, computeConfigHash(original)
			previousCert := s.cert
			missing := t.TempDir()
			update := &model.NodeSpec{Protocol: "hysteria", Version: 2, CertConfig: &config.CertConfig{
				CertMode: mode, CertContent: "invalid", KeyContent: "invalid",
				CertFile: filepath.Join(missing, "missing.pem"), KeyFile: filepath.Join(missing, "missing.key"),
			}}
			s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncConfig, Config: update})
			if s.kernel != old || !old.IsRunning() || s.lastConfig != original || s.cert != previousCert {
				t.Fatal("invalid certificate update changed the active kernel, config, or certificate")
			}
			// A later panel rollback to the active config must cancel the pending
			// update; it must not reappear on the next unchanged poll.
			s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncConfig, Config: original})
			if s.pendingConfig != nil {
				t.Fatal("panel rollback did not supersede the pending update")
			}
			s.applyPullResult(ctx, pullResult{})
			if s.kernel != old || !old.IsRunning() {
				t.Fatal("unchanged poll reapplied a cancelled update")
			}
		})
	}
}

func TestNonTLSConfigCanStartWithInvalidCertificateOverride(t *testing.T) {
	ctx := context.Background()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	cfg := &config.Config{
		Kernel: config.KernelConfig{Type: "singbox"},
		Cert:   config.CertConfig{CertMode: "self", CertDir: t.TempDir()},
	}
	cp := &kernelTestControlPlane{
		kcfg: cfg.Kernel,
		node: panel.NodeConfig{
			Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: port,
			CertConfig: &panel.CertConfig{CertMode: "content", CertContent: "invalid", KeyContent: "invalid"},
		},
		users: []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}},
	}
	s := NewWithControlPlane(cfg, cp)
	if err := s.cert.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { s.kernel.Stop(); s.cert.Stop() }()
	active := s.cert
	if err := s.initialSetup(ctx); err != nil || !s.kernel.IsRunning() || s.cert != active {
		t.Fatalf("invalid optional certificate blocked startup or replaced local certificate: %v", err)
	}
	next := *s.lastConfig
	next.CertConfig = &config.CertConfig{CertMode: "none"}
	s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncConfig, Config: &next})
	if s.lastConfig != &next || !s.kernel.IsRunning() || s.cert != active || !active.HasCert() {
		t.Fatal("empty certificate override removed local material or blocked the config update")
	}
}

func TestKernelSwitchPreflightKeepsRunningKernelOnNativeConfigError(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{Kernel: config.KernelConfig{
		Type: "singbox", CustomOutbound: []map[string]any{{"type": "direct", "tag": "singbox-only"}},
	}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	old := &fakeKernel{running: true}
	s.kernel = old
	previous := &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	s.lastConfig = previous
	s.appliedState.Config = previous
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}})
	next := &model.NodeSpec{Protocol: "vless", Network: "xhttp", ServerPort: previous.ServerPort}
	if err := s.applyNodeConfig(ctx, next); err == nil || !strings.Contains(err.Error(), "check xray configuration") {
		t.Fatalf("expected preflight to reject incompatible outbound: %v", err)
	}
	if !old.IsRunning() || old.startCalls != 0 || s.kernel != old || s.lastConfig != previous {
		t.Fatal("preflight failure interrupted the previous kernel")
	}
}

func TestKernelSwitchRestoresPreviousListenerAfterSamePortStartFailure(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	old := &fakeKernel{running: true}
	s.kernel = old
	previous := &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	s.lastConfig = previous
	s.appliedState.Config = previous
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}})
	next := &model.NodeSpec{Protocol: "vless", Network: "xhttp", ServerPort: previous.ServerPort}
	startErr := errors.New("bind failed after successful preflight")
	candidate := &fakeKernel{startErr: startErr}
	if err := s.switchKernel(ctx, candidate, "xray", next, kernel.TLSCert{}); !errors.Is(err, startErr) {
		t.Fatalf("unexpected switch result: %v", err)
	}
	if s.kernel != old || !old.IsRunning() || old.startCalls != 1 || s.lastConfig != previous {
		t.Fatal("old listener was not restored after failed handoff")
	}
	_ = s.switchKernel(ctx, candidate, "xray", next, kernel.TLSCert{})
	if candidate.startCalls != 1 || old.startCalls != 1 {
		t.Fatal("an unchanged failure immediately interrupted the restored listener again")
	}
}

func (p *kernelTestControlPlane) Initial(context.Context, func() map[string]interface{}, chan<- controlplane.Event, chan<- controlplane.StatusChange) (controlplane.Bootstrap, error) {
	node, err := model.NodeSpecFromPanelValidated(&p.node, p.kcfg)
	return controlplane.Bootstrap{Config: node, Users: p.users, DeviceUsers: map[int][]string{1: {"192.0.2.1"}}}, err
}

func (p *kernelTestControlPlane) Poll(context.Context) (controlplane.Snapshot, error) {
	return controlplane.Snapshot{Config: p.polled}, nil
}

func (p *kernelTestControlPlane) SupportsPolling() bool          { return p.polled != nil }
func (*kernelTestControlPlane) SupportsDiscovery() bool          { return false }
func (*kernelTestControlPlane) SupportsReporting() bool          { return false }
func (*kernelTestControlPlane) SupportsDeviceReports() bool      { return false }
func (*kernelTestControlPlane) Metrics() controlplane.APIMetrics { return controlplane.APIMetrics{} }

func TestInitialSetupSelectsKernelWithoutUsers(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured string
		node       panel.NodeConfig
		wantKernel string
	}{
		{"hysteria2", "xray", panel.NodeConfig{Protocol: "hysteria", Version: 2, CertConfig: &panel.CertConfig{CertMode: "self"}}, "sing-box"},
		{"xhttp", "singbox", panel.NodeConfig{Protocol: "vless", Network: "xhttp"}, "xray"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Kernel: config.KernelConfig{Type: tc.configured, ConfigDir: t.TempDir()}}
			s := NewWithControlPlane(cfg, &kernelTestControlPlane{kcfg: cfg.Kernel, node: tc.node})
			defer func() { s.kernel.Stop() }()
			if err := s.initialSetup(context.Background()); err != nil {
				t.Fatal(err)
			}
			if s.kernel.Name() != tc.wantKernel {
				t.Fatalf("kernel = %q, want %q", s.kernel.Name(), tc.wantKernel)
			}
			if cfg.Kernel.Type != tc.configured {
				t.Fatal("runtime kernel selection changed the configured preference")
			}
			if s.kernel.IsRunning() {
				t.Fatal("kernel started without users")
			}
		})
	}
}

func TestConfigUpdatesSelectKernelAndRejectInvalidConfig(t *testing.T) {
	for _, transport := range []string{"ws", "rest"} {
		t.Run(transport, func(t *testing.T) {
			cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir()}, Cert: config.CertConfig{CertDir: t.TempDir()}}
			s := NewWithControlPlane(cfg, &kernelTestControlPlane{kcfg: cfg.Kernel, node: panel.NodeConfig{Protocol: "vless", Network: "tcp"}})
			defer func() { s.kernel.Stop() }()
			if err := s.initialSetup(context.Background()); err != nil {
				t.Fatal(err)
			}
			apply := func(node *model.NodeSpec) {
				if transport == "ws" {
					s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: node})
				} else {
					s.applyPullResult(context.Background(), pullResult{config: node, configHash: computeConfigHash(node)})
				}
			}
			invalid := &model.NodeSpec{Protocol: "vless", Network: "xhttp", TLS: 2}
			original := s.lastConfig
			apply(invalid)
			if s.kernel.Name() != "sing-box" || s.lastConfig != original {
				t.Fatal("invalid config replaced the active kernel or config")
			}
			xhttp := &model.NodeSpec{Protocol: "vless", Network: "xhttp"}
			apply(xhttp)
			if s.kernel.Name() != "xray" || s.lastConfig != xhttp {
				t.Fatal("xhttp update did not select Xray")
			}
			hy2 := &model.NodeSpec{Protocol: "hysteria", Version: 2, CertConfig: &config.CertConfig{CertMode: "self", CertDir: t.TempDir()}}
			apply(hy2)
			if s.kernel.Name() != "sing-box" || s.lastConfig != hy2 {
				t.Fatal("hysteria2 update did not select sing-box")
			}
		})
	}
}

func TestConfigRetriedAfterKernelStartFailure(t *testing.T) {
	for _, transport := range []string{"ws", "rest"} {
		t.Run(transport, func(t *testing.T) {
			cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error"}}
			cp := &kernelTestControlPlane{kcfg: cfg.Kernel, node: panel.NodeConfig{Protocol: "vless", Network: "tcp"}}
			s := NewWithControlPlane(cfg, cp)
			defer func() { s.kernel.Stop() }()
			if err := s.initialSetup(context.Background()); err != nil {
				t.Fatal(err)
			}
			old := s.kernel
			s.updateUserState([]model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}})
			apply := func(node *model.NodeSpec) {
				if transport == "ws" {
					s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: node})
					return
				}
				cp.polled = node
				s.pullViaAPIAsync(context.Background())
				s.applyPullResult(context.Background(), <-s.pullResults)
			}

			busy, err := net.Listen("tcp", ":0")
			if err != nil {
				t.Fatal(err)
			}
			port := busy.Addr().(*net.TCPAddr).Port
			apply(&model.NodeSpec{Protocol: "vless", Network: "xhttp", ServerPort: port})
			if s.kernel != old || s.pendingConfig == nil {
				busy.Close()
				t.Fatal("failed Xray start replaced the current kernel or discarded the candidate")
			}
			busy.Close()
			apply(&model.NodeSpec{Protocol: "vless", Network: "xhttp", ServerPort: port})
			if !s.kernel.IsRunning() {
				t.Fatal("same config was not retried after the start failure")
			}
		})
	}
}

func TestKernelSwitchRetriesAfterREST304(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := busy.Addr().(*net.TCPAddr).Port
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/config") {
			if r.Header.Get("If-None-Match") == `"config-v1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"config-v1"`)
			json.NewEncoder(w).Encode(map[string]any{"protocol": "vless", "network": "xhttp", "server_port": port, "listen_ip": "127.0.0.1"})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/user") {
			json.NewEncoder(w).Encode(map[string]any{"users": []map[string]any{{"id": 1, "uuid": "11111111-1111-4111-8111-111111111111"}}})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	cfg := &config.Config{Panel: config.PanelConfig{URL: server.URL, NodeID: 1}, Kernel: config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error"}}
	cp := controlplane.NewPanelControlPlane(cfg.Panel, cfg.WS, cfg.Kernel)
	s := NewWithControlPlane(cfg, cp)
	old := s.kernel
	defer func() { s.kernel.Stop() }()
	pull := func() pullResult {
		s.pullViaAPIAsync(context.Background())
		select {
		case result := <-s.pullResults:
			s.applyPullResult(context.Background(), result)
			return result
		case <-time.After(10 * time.Second):
			t.Fatal("poll timed out")
			return pullResult{}
		}
	}
	first := pull()
	if first.config == nil || s.kernel != old || s.pendingConfig == nil {
		t.Fatal("first poll did not fail Xray startup as intended")
	}
	if s.lastConfigHash != "" {
		t.Fatal("failed start did not clear service config hash")
	}
	busy.Close()
	second := pull()
	if second.config != nil {
		t.Fatal("expected real REST client to suppress unchanged config on HTTP 304")
	}
	if !s.kernel.IsRunning() {
		t.Fatal("kernel remains stopped after port recovered: HTTP 304 prevents retry despite cleared lastConfigHash")
	}
	if s.lastConfigHash != computeConfigHash(s.lastConfig) {
		t.Fatal("successful retry did not clear pending config")
	}
	third := pull()
	if third.config != nil || !s.kernel.IsRunning() {
		t.Fatal("unchanged poll disrupted the recovered kernel")
	}
}

type stopSignalKernel struct {
	kernel.Kernel
	stopStarted chan struct{}
}

func (k *stopSignalKernel) Stop() { close(k.stopStarted); k.Kernel.Stop() }
func TestKernelSwitchCollectsDrainingTraffic(t *testing.T) {
	t.Run("current instance", func(t *testing.T) { testKernelSwitchCollectsDrainingTraffic(t, false) })
	t.Run("previously restarted instance", func(t *testing.T) { testKernelSwitchCollectsDrainingTraffic(t, true) })
}

func testKernelSwitchCollectsDrainingTraffic(t *testing.T, restart bool) {
	ctx := context.Background()
	const uuid = "11111111-1111-4111-8111-111111111111"
	const initialBytes = 17
	const drainBytes = 4096
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	stopStarted := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		c, e := target.Accept()
		if e != nil {
			serverDone <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, e = c.Write(make([]byte, initialBytes)); e != nil {
			serverDone <- e
			return
		}
		select {
		case <-stopStarted:
		case <-time.After(10 * time.Second):
			serverDone <- fmt.Errorf("switch not started")
			return
		}
		_, e = c.Write(make([]byte, drainBytes))
		serverDone <- e
	}()
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error", CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}}}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	users := []model.UserSpec{{ID: 1, UUID: uuid}}
	s.updateUserState(users)
	if !s.startKernel(&model.NodeSpec{Protocol: "socks", ServerPort: port}, users) {
		t.Fatal("start")
	}
	old := s.kernel
	defer old.Stop()
	s.kernel = &stopSignalKernel{Kernel: old, stopStarted: stopStarted}
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: uuid, Password: uuid}, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.Dial("tcp", target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = io.ReadFull(conn, make([]byte, initialBytes)); err != nil {
		t.Fatal(err)
	}
	if restart {
		reserve, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		nextPort := reserve.Addr().(*net.TCPAddr).Port
		reserve.Close()
		if err := old.Start(&model.NodeSpec{Protocol: "socks", ServerPort: nextPort}, users, kernel.TLSCert{}); err != nil {
			t.Fatal(err)
		}
	}
	clientDone := make(chan error, 1)
	go func() { _, e := io.ReadFull(conn, make([]byte, drainBytes)); conn.Close(); clientDone <- e }()
	// The old sing-box instance has its own native route. The candidate uses
	// the generated Xray configuration.
	s.cfg.Kernel.CustomRoute = nil
	if err = s.applyNodeConfig(ctx, &model.NodeSpec{Protocol: "vless", Network: "xhttp", ServerPort: port}); err != nil {
		t.Fatal(err)
	}
	defer s.kernel.Stop()
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
	if err = <-clientDone; err != nil {
		t.Fatal(err)
	}
	actual, _, _, err := old.GetUserTraffic(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reported := s.tracker.FlushTraffic()
	t.Logf("old kernel actual=%v report buffer=%v", actual[1], reported[1])
	if actual[1][1] != initialBytes+drainBytes {
		t.Fatalf("fixture did not transfer all bytes: %v", actual)
	}
	if reported[1] != actual[1] {
		t.Fatalf("lost drain traffic: reported=%v actual=%v", reported[1], actual[1])
	}
}

func TestFailedSamePortKernelSwitchBacksOff(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	old := &fakeKernel{running: true}
	s.kernel = old
	previous := &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	s.lastConfig = previous
	s.appliedState.Config = previous
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}})
	next := &model.NodeSpec{Protocol: "vless", Network: "xhttp", ServerPort: previous.ServerPort}
	candidate := &fakeKernel{startErr: errors.New("start failed")}

	for i, want := range kernelSwitchRetryDelays {
		s.kernelRetryAt = time.Time{}
		before := time.Now()
		if err := s.switchKernel(ctx, candidate, "xray", next, kernel.TLSCert{}); err == nil {
			t.Fatal("switch unexpectedly succeeded")
		}
		if got := s.kernelRetryAt.Sub(before); got < want || got > want+time.Second {
			t.Fatalf("failure %d: retry delay = %v, want %v", i+1, got, want)
		}
		if !old.IsRunning() {
			t.Fatal("previous kernel was not restored")
		}
	}
	s.kernelRetryAt = time.Time{}
	_ = s.switchKernel(ctx, candidate, "xray", next, kernel.TLSCert{})
	if got := time.Until(s.kernelRetryAt); got < 59*time.Minute {
		t.Fatalf("retry delay was not capped at one hour: %v", got)
	}
	if err := s.switchKernel(ctx, candidate, "xray", next, kernel.TLSCert{}); !errors.Is(err, errKernelSwitchDeferred) {
		t.Fatalf("retry was not deferred: %v", err)
	}

	other := &model.NodeSpec{Protocol: "vless", Network: "xhttp", ServerPort: previous.ServerPort, Host: "other"}
	before := time.Now()
	_ = s.switchKernel(ctx, candidate, "xray", other, kernel.TLSCert{})
	if got := s.kernelRetryAt.Sub(before); got > time.Minute+time.Second {
		t.Fatalf("a new config inherited the previous backoff: %v", got)
	}
}

func TestPolledUsersStartActiveConfigWhilePendingConfigIsBlocked(t *testing.T) {
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	k := &fakeKernel{}
	s.kernel = k
	active := &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	s.lastConfig = active
	s.lastConfigHash = computeConfigHash(active)
	blocked := &model.NodeSpec{Protocol: "trojan", ServerPort: 12345}
	users := []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}}

	s.applyPullResult(context.Background(), pullResult{
		config: blocked, configHash: computeConfigHash(blocked),
		users: users, userHash: computeUserHash(users),
	})
	if !k.IsRunning() || s.lastConfig != active || s.appliedState.Config != active {
		t.Fatal("new users did not start the kernel with the active config")
	}
	if s.pendingConfig != blocked {
		t.Fatal("the blocked config was not kept for retry")
	}
}

// panelConfigServer serves a switchable config with content ETags, like the
// panel, and can fail the user endpoint to simulate a partially failed poll.
type panelConfigServer struct {
	mu        sync.Mutex
	config    map[string]any
	usersDown bool
}

func (p *panelConfigServer) set(config map[string]any, usersDown bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config, p.usersDown = config, usersDown
}

func (p *panelConfigServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	config, usersDown := p.config, p.usersDown
	p.mu.Unlock()
	switch {
	case strings.HasSuffix(r.URL.Path, "/handshake"):
		json.NewEncoder(w).Encode(map[string]any{"websocket": map[string]any{"enabled": false}})
	case strings.HasSuffix(r.URL.Path, "/config"):
		body, _ := json.Marshal(config)
		etag := fmt.Sprintf(`"%x"`, sha256.Sum256(body))
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Write(body)
	case strings.HasSuffix(r.URL.Path, "/user"):
		if usersDown {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"users": []map[string]any{{"id": 1, "uuid": "11111111-1111-4111-8111-111111111111"}}})
	case strings.HasSuffix(r.URL.Path, "/devices"):
		json.NewEncoder(w).Encode(map[string]any{"users": map[string]any{}})
	default:
		http.NotFound(w, r)
	}
}

func TestREST304ResolvesPendingConfigAgainstPanelConfig(t *testing.T) {
	configA := map[string]any{"protocol": "vless", "network": "tcp", "server_port": 20001}
	// The fake kernel cannot serve trojan, so B stays pending.
	configB := map[string]any{"protocol": "trojan", "network": "tcp", "server_port": 20002}
	configC := map[string]any{"protocol": "vless", "network": "tcp", "server_port": 20003}

	setup := func(t *testing.T) (*Service, *panelConfigServer, func() bool) {
		panelServer := &panelConfigServer{config: configA}
		server := httptest.NewServer(panelServer)
		t.Cleanup(server.Close)
		cfg := &config.Config{Panel: config.PanelConfig{URL: server.URL, NodeID: 1}, Kernel: config.KernelConfig{Type: "singbox"}}
		s := NewWithControlPlane(cfg, controlplane.NewPanelControlPlane(cfg.Panel, cfg.WS, cfg.Kernel))
		s.kernel = &fakeKernel{}
		if err := s.initialSetup(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !s.kernel.IsRunning() {
			t.Fatal("initial REST config A did not start")
		}
		poll := func() bool {
			s.pullBackoff.onSuccess() // poll immediately after a simulated failure
			s.pullViaAPIAsync(context.Background())
			deadline := time.After(10 * time.Second)
			for {
				select {
				case result := <-s.pullResults:
					s.applyPullResult(context.Background(), result)
					return true
				case <-deadline:
					t.Fatal("poll timed out")
				case <-time.After(5 * time.Millisecond):
					// A successful poll blocks on pullResults before clearing
					// pullActive, so an idle poller without a result failed.
					if !s.pullActive.Load() {
						select {
						case result := <-s.pullResults:
							s.applyPullResult(context.Background(), result)
							return true
						default:
							return false
						}
					}
				}
			}
		}
		return s, panelServer, poll
	}
	pushB := func(t *testing.T, s *Service) *model.NodeSpec {
		raw, _ := json.Marshal(configB)
		var node panel.NodeConfig
		if err := json.Unmarshal(raw, &node); err != nil {
			t.Fatal(err)
		}
		// Translate exactly as the WS client does.
		spec, err := model.NodeSpecFromPanelValidated(&node, s.cfg.Kernel)
		if err != nil {
			t.Fatal(err)
		}
		s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: spec})
		if s.pendingConfig == nil {
			t.Fatal("WS config B did not stay pending")
		}
		return spec
	}

	t.Run("rollback after REST bootstrap", func(t *testing.T) {
		s, _, poll := setup(t)
		active := computeConfigHash(s.lastConfig)
		pushB(t, s)
		// The panel serves A again and the rollback event was lost.
		if !poll() {
			t.Fatal("poll failed")
		}
		if s.pendingConfig != nil || s.lastConfigHash != active {
			t.Fatal("HTTP 304 for the bootstrap config kept retrying the withdrawn config")
		}
	})

	t.Run("304 after a poll whose user request failed", func(t *testing.T) {
		s, panelServer, poll := setup(t)
		pending := pushB(t, s)
		panelServer.set(configB, true)
		if poll() {
			t.Fatal("poll with a failing user endpoint produced a result")
		}
		panelServer.set(configB, false)
		if !poll() {
			t.Fatal("poll failed")
		}
		if s.pendingConfig == nil || computeConfigHash(s.pendingConfig) != computeConfigHash(pending) {
			t.Fatal("HTTP 304 for the config the panel still serves discarded it")
		}
	})

	t.Run("config from a failed poll is applied after 304", func(t *testing.T) {
		s, panelServer, poll := setup(t)
		panelServer.set(configC, true)
		if poll() {
			t.Fatal("poll with a failing user endpoint produced a result")
		}
		panelServer.set(configC, false)
		if !poll() {
			t.Fatal("poll failed")
		}
		if s.lastConfig == nil || s.lastConfig.ServerPort != 20003 || s.pendingConfig != nil {
			t.Fatal("the config behind the cached ETag was never applied")
		}
	})

	t.Run("poll older than a WS config", func(t *testing.T) {
		s, _, _ := setup(t)
		active := s.lastConfig
		s.wsConfigRevision++
		stale := &model.NodeSpec{Protocol: "vless", ServerPort: 20003}
		s.applyPullResult(context.Background(), pullResult{config: stale, configHash: computeConfigHash(stale)})
		if s.pendingConfig != nil || s.lastConfig != active {
			t.Fatal("a poll older than the latest WS config was applied")
		}
	})
}
