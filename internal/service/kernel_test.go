package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/cert"
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
			s.appliedState.Config, s.appliedState.TLS = original, s.cert.TLSCert()
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

func TestApplyNodeConfigRechecksCustomConfigAgainstSelectedKernel(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "custom.json")
	if err := os.WriteFile(path, []byte(`{"route":{"rules":[{"domain_suffix":["blocked.example"],"action":"reject"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox", CustomConfig: path}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	old := &fakeKernel{running: true}
	s.kernel = old
	previous := &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	s.lastConfig = previous
	s.appliedState.Config = previous
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}})
	// Translated while the file was sing-box native...
	next, err := model.NodeSpecFromPanelValidated(&panel.NodeConfig{Protocol: "vless", Network: "tcp", ServerPort: 12346}, cfg.Kernel)
	if err != nil {
		t.Fatal(err)
	}
	// ...then rewritten in Xray's format before the config is applied.
	if err := os.WriteFile(path, []byte(`{"routing":{"rules":[{"domain":["blocked.example"],"outboundTag":"block"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.applyNodeConfig(ctx, next); err == nil || !strings.Contains(err.Error(), "xray-only keys [routing]") {
		t.Fatalf("expected apply to re-check custom_config against the selected kernel: %v", err)
	}
	if !old.IsRunning() || old.startCalls != 0 || s.lastConfig != previous {
		t.Fatal("rejected custom_config interrupted the running kernel")
	}
}

func TestUserUpdateDoesNotStartKernelWithForeignCustomConfig(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "custom.json")
	if err := os.WriteFile(path, []byte(`{"route":{"rules":[]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox", CustomConfig: path}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	stopped := &fakeKernel{}
	s.kernel = stopped
	// The node idles without users on a config translated while the file was native.
	spec, err := model.NodeSpecFromPanelValidated(&panel.NodeConfig{Protocol: "vless", Network: "tcp", ServerPort: 12345}, cfg.Kernel)
	if err != nil {
		t.Fatal(err)
	}
	s.lastConfig = spec
	if err := os.WriteFile(path, []byte(`{"routing":{"rules":[]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	users := []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}}
	s.applyUserUpdate(ctx, users, computeUserHash(users))
	if stopped.startCalls != 0 || stopped.IsRunning() {
		t.Fatal("a user update started the kernel with a custom_config written for the other kernel")
	}
}

func TestKernelSwitchRollbackKeepsOldKernelCustomConfigSnapshot(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "custom.json")
	singboxRules := []byte(`{"route":{"rules":[{"domain_suffix":["blocked.example"],"action":"reject"}]}}`)
	if err := os.WriteFile(path, singboxRules, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox", CustomConfig: path}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	// Occupy the port so the new Xray kernel fails after the old one was stopped.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	old := &fakeKernel{running: true, customConfig: map[string]any{"route": "old snapshot"}}
	s.kernel = old
	previous := &model.NodeSpec{Protocol: "vless", ServerPort: port}
	s.lastConfig = previous
	s.appliedState.Config = previous
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}})

	// The operator rewrote custom_config for Xray before the panel moved the node to XHTTP.
	if err := os.WriteFile(path, []byte(`{"routing":{"rules":[{"domain":["blocked.example"],"outboundTag":"block"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	next := &model.NodeSpec{Protocol: "vless", Network: "xhttp", ServerPort: port, ListenIP: "127.0.0.1"}
	if err := s.applyNodeConfig(ctx, next); err == nil {
		t.Fatal("expected the Xray start on an occupied port to fail")
	}
	if s.kernel != old || !old.IsRunning() || old.startCalls != 1 {
		t.Fatal("old kernel was not restored after the failed handoff")
	}
	if old.customConfigSets != 0 || old.customConfig["route"] != "old snapshot" {
		t.Fatalf("rollback replaced the old kernel's custom_config snapshot: %v", old.customConfig)
	}
}

func TestUserUpdateRefusedByCustomConfigRefetchesUsers(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "custom.json")
	if err := os.WriteFile(path, []byte(`{"route":{"rules":[]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox", CustomConfig: path}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	stopped := &fakeKernel{}
	s.kernel = stopped
	spec, err := model.NodeSpecFromPanelValidated(&panel.NodeConfig{Protocol: "vless", Network: "tcp", ServerPort: 12345}, cfg.Kernel)
	if err != nil {
		t.Fatal(err)
	}
	s.lastConfig = spec
	s.appliedState.Config = spec
	s.lastConfigHash = computeConfigHash(spec)
	if err := os.WriteFile(path, []byte(`{"routing":{"rules":[]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	users := []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}}
	s.applyUserUpdate(ctx, users, computeUserHash(users))
	if stopped.startCalls != 0 {
		t.Fatal("kernel started with a foreign custom_config")
	}
	if len(s.lastUsers) != 0 || !s.userRefetch {
		t.Fatalf("refused start must keep the kernel's state and re-read users: last=%d refetch=%v", len(s.lastUsers), s.userRefetch)
	}
	// The file is fixed and the re-read list arrives.
	if err := os.WriteFile(path, []byte(`{"route":{"rules":[]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	s.applyPullResult(ctx, pullResult{users: users, userHash: computeUserHash(users), wsConfigRevision: s.wsConfigRevision, wsUserRevision: s.wsUserRevision})
	if stopped.startCalls != 1 || !stopped.IsRunning() || len(s.lastUsers) != 1 {
		t.Fatal("re-read users were not applied")
	}
	if stopped.customConfig == nil {
		t.Fatal("kernel started without the validated custom_config snapshot")
	}
}

// restUserNode starts a REST-polled node on a fake kernel with two users.
func restUserNode(t *testing.T) (*Service, *fakeKernel, *panelConfigServer, func()) {
	t.Helper()
	panelServer := &panelConfigServer{
		config: map[string]any{"protocol": "vless", "network": "tcp", "server_port": 20001},
		users: []map[string]any{
			{"id": 1, "uuid": "11111111-1111-4111-8111-111111111111"},
			{"id": 2, "uuid": "22222222-2222-4222-8222-222222222222"},
		},
	}
	server := httptest.NewServer(panelServer)
	t.Cleanup(server.Close)
	cfg := &config.Config{Panel: config.PanelConfig{URL: server.URL, NodeID: 1}, Kernel: config.KernelConfig{Type: "singbox"}}
	s := NewWithControlPlane(cfg, controlplane.NewPanelControlPlane(cfg.Panel, cfg.WS, cfg.Kernel))
	k := &fakeKernel{}
	s.kernel = k
	if err := s.initialSetup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !k.IsRunning() || len(s.lastUsers) != 2 {
		t.Fatal("initial REST setup did not start with two users")
	}
	poll := func() {
		t.Helper()
		s.pullBackoff.onSuccess()
		s.pullViaAPIAsync(context.Background())
		select {
		case result := <-s.pullResults:
			s.applyPullResult(context.Background(), result)
		case <-time.After(10 * time.Second):
			t.Fatal("poll timed out")
		}
	}
	return s, k, panelServer, poll
}

func hasUser(users []model.UserSpec, id int) bool {
	for _, u := range users {
		if u.ID == id {
			return true
		}
	}
	return false
}

func TestFailedRevocationIsReReadFromPanelAfterETag(t *testing.T) {
	s, k, panelServer, poll := restUserNode(t)
	// The panel revokes user 2; the kernel cannot apply it right now.
	panelServer.setUsers([]map[string]any{{"id": 1, "uuid": "11111111-1111-4111-8111-111111111111"}})
	k.updateErr = errors.New("hot update failed")
	k.startErr = errors.New("rebuild failed")
	poll()
	if !hasUser(s.lastUsers, 2) || !s.userRefetch {
		t.Fatalf("failed revocation must keep the running state and re-read users: users=%v refetch=%v", s.lastUsers, s.userRefetch)
	}
	// The kernel recovers. The panel's list is unchanged, so without a forced
	// re-read the user endpoint would answer 304 forever.
	k.updateErr, k.startErr = nil, nil
	k.running = true
	poll()
	if hasUser(s.lastUsers, 2) || len(s.lastUsers) != 1 || s.userRefetch {
		t.Fatalf("revocation was not re-read and applied: users=%v refetch=%v", s.lastUsers, s.userRefetch)
	}
}

func TestReReadAfterFailureDoesNotUndoNewerWSRevocation(t *testing.T) {
	s, k, panelServer, poll := restUserNode(t)
	revoked := []map[string]any{{"id": 1, "uuid": "11111111-1111-4111-8111-111111111111"}}
	panelServer.setUsers(revoked)
	k.updateErr = errors.New("hot update failed")
	k.startErr = errors.New("rebuild failed")
	poll()
	// The kernel recovers and the revocation arrives over WebSocket.
	k.updateErr, k.startErr = nil, nil
	k.running = true
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove",
		DeltaUsers: []model.UserSpec{{ID: 2, UUID: "22222222-2222-4222-8222-222222222222"}}})
	if hasUser(s.lastUsers, 2) {
		t.Fatal("WS revocation was not applied")
	}
	poll()
	if hasUser(s.lastUsers, 2) {
		t.Fatal("re-read after the failed update brought a revoked user back")
	}
}

func TestRevokingAllUsersStopsKernelWhenHotUpdateFails(t *testing.T) {
	s, k, panelServer, poll := restUserNode(t)
	panelServer.setUsers([]map[string]any{})
	k.updateErr = errors.New("hot update failed")
	poll()
	if k.IsRunning() {
		t.Fatal("kernel kept serving after every user was revoked")
	}
	if len(s.lastUsers) != 0 || s.userRefetch {
		t.Fatalf("empty user list was not recorded: users=%v refetch=%v", s.lastUsers, s.userRefetch)
	}
	// A later 304 must not bring anyone back.
	poll()
	if k.IsRunning() || len(s.lastUsers) != 0 {
		t.Fatal("revoked users came back after a 304")
	}
}

func TestRejectedSameKernelUpdateRestoresCustomConfigSnapshot(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "custom.json")
	if err := os.WriteFile(path, []byte(`{"route":{"rules":[{"domain_suffix":["a.example"],"action":"reject"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox", CustomConfig: path}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	runningSnapshot := map[string]any{"route": "running snapshot"}
	previous := &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	running := &fakeKernel{running: true, reloadErr: errors.New("reload rejected"), customConfig: runningSnapshot,
		startHook: func(spec *model.NodeSpec, _ []model.UserSpec) error {
			if spec != previous {
				return errors.New("start rejected")
			}
			return nil
		}}
	s.kernel = running
	s.appliedState.CustomConfig = runningSnapshot
	s.lastConfig = previous
	s.appliedState.Config = previous
	s.lastConfigHash = computeConfigHash(previous)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}})

	next := &model.NodeSpec{Protocol: "vless", ServerPort: 12346}
	if err := s.applyNodeConfig(ctx, next); err == nil {
		t.Fatal("expected the rejected update to fail")
	}
	// The fake kernel can start next to itself, so a rejected start must not
	// interrupt it at all: no stop, no restore.
	if !running.IsRunning() || running.startCalls != 1 || s.lastConfig != previous {
		t.Fatalf("rejected update disturbed the running kernel: running=%v starts=%d", running.IsRunning(), running.startCalls)
	}
	if running.customConfig["route"] != "running snapshot" {
		t.Fatalf("rejected update left its custom_config snapshot on the running kernel: %v", running.customConfig)
	}
}

func TestCustomConfigChangeRebuildsInsteadOfHotReload(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "custom.json")
	if err := os.WriteFile(path, []byte(`{"route":{"rules":[{"domain_suffix":["b.example"],"action":"reject"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox", CustomConfig: path}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	running := &fakeKernel{running: true}
	s.kernel = running
	spec := &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	s.appliedState.CustomConfig = map[string]any{"route": "older snapshot"}
	s.lastConfig = spec
	s.appliedState.Config = spec
	s.lastConfigHash = computeConfigHash(spec)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}})

	// Same node spec, users and certificate; only custom_config changed.
	if err := s.applyNodeConfig(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if running.reloadCalls != 0 || running.startCalls != 1 {
		t.Fatalf("custom_config change must rebuild, not hot reload: reload=%d start=%d", running.reloadCalls, running.startCalls)
	}
	if _, ok := s.appliedState.CustomConfig["route"].(map[string]any); !ok {
		t.Fatalf("new custom_config snapshot was not recorded as applied: %v", s.appliedState.CustomConfig)
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
	noETag    bool // answer every config request with 200, like panels without ETag support
	users     []map[string]any
}

func (p *panelConfigServer) setUsers(users []map[string]any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.users = users
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
		if p.noETag {
			w.Write(body)
			return
		}
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
		p.mu.Lock()
		users := p.users
		p.mu.Unlock()
		if users == nil {
			users = []map[string]any{{"id": 1, "uuid": "11111111-1111-4111-8111-111111111111"}}
		}
		body, _ := json.Marshal(map[string]any{"users": users})
		etag := fmt.Sprintf(`"%x"`, sha256.Sum256(body))
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Write(body)
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

	singbox := config.KernelConfig{Type: "singbox"}
	setup := func(t *testing.T, kcfg config.KernelConfig) (*Service, *panelConfigServer, func() bool) {
		panelServer := &panelConfigServer{config: configA}
		server := httptest.NewServer(panelServer)
		t.Cleanup(server.Close)
		cfg := &config.Config{Panel: config.PanelConfig{URL: server.URL, NodeID: 1}, Kernel: kcfg}
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
		s, _, poll := setup(t, singbox)
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
		s, panelServer, poll := setup(t, singbox)
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
		s, panelServer, poll := setup(t, singbox)
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

	t.Run("304 for a config that fails validation drops the stale candidate", func(t *testing.T) {
		s, panelServer, poll := setup(t, singbox)
		active := computeConfigHash(s.lastConfig)
		pushB(t, s)
		// The panel replaces B with C, which references an unknown outbound.
		invalidC := map[string]any{"protocol": "vless", "network": "tcp", "server_port": 20004,
			"custom_outbounds": []map[string]any{{"tag": "proxy", "protocol": "socks", "proxy_tag": "missing",
				"settings": map[string]any{"server": "2.2.2.2", "server_port": 1080}}}}
		panelServer.set(invalidC, false)
		if !poll() {
			t.Fatal("poll with an invalid config body failed")
		}
		if s.pendingConfig != nil {
			t.Fatalf("HTTP 200 for a replaced config kept the withdrawn candidate on port %d", s.pendingConfig.ServerPort)
		}
		// The ETag is now cached; a candidate pushed afterwards must be dropped by the 304 too.
		pushB(t, s)
		if !poll() {
			t.Fatal("poll failed")
		}
		if s.pendingConfig != nil {
			t.Fatalf("HTTP 304 for a replaced config kept retrying the withdrawn candidate on port %d", s.pendingConfig.ServerPort)
		}
		if s.lastConfigHash != active || !s.kernel.IsRunning() {
			t.Fatal("active config was disturbed by an invalid panel config")
		}
	})

	t.Run("200 without ETag for a config that fails validation drops the stale candidate", func(t *testing.T) {
		s, panelServer, poll := setup(t, singbox)
		active := computeConfigHash(s.lastConfig)
		pushB(t, s)
		invalidC := map[string]any{"protocol": "vless", "network": "tcp", "server_port": 20004,
			"custom_outbounds": []map[string]any{{"tag": "proxy", "protocol": "socks", "proxy_tag": "missing",
				"settings": map[string]any{"server": "2.2.2.2", "server_port": 1080}}}}
		panelServer.mu.Lock()
		panelServer.noETag = true
		panelServer.mu.Unlock()
		panelServer.set(invalidC, false)
		if !poll() {
			t.Fatal("poll with an invalid config body failed instead of delivering users")
		}
		if s.pendingConfig != nil {
			t.Fatalf("200 with a replaced config kept retrying the withdrawn candidate on port %d", s.pendingConfig.ServerPort)
		}
		if s.lastConfigHash != active || !s.kernel.IsRunning() {
			t.Fatal("active config was disturbed by an invalid panel config")
		}
	})

	t.Run("WS config that fails validation drops the stale candidate", func(t *testing.T) {
		s, _, _ := setup(t, singbox)
		active := computeConfigHash(s.lastConfig)
		pushB(t, s)
		revision := s.wsConfigRevision
		s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, ConfigErr: errors.New("translate node config: boom")})
		if s.pendingConfig != nil {
			t.Fatal("WS event for an invalid config kept the withdrawn candidate")
		}
		if s.wsConfigRevision != revision+1 {
			t.Fatal("invalid WS config did not supersede in-flight polls")
		}
		if s.lastConfigHash != active || !s.kernel.IsRunning() {
			t.Fatal("active config was disturbed by an invalid WS config")
		}
	})

	t.Run("304 for a candidate that stopped validating drops it", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "custom.json")
		if err := os.WriteFile(path, []byte(`{"route":{"rules":[]}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		s, panelServer, poll := setup(t, config.KernelConfig{Type: "singbox", CustomConfig: path})
		active := computeConfigHash(s.lastConfig)
		candidate := pushB(t, s)
		// The panel now serves B itself, and the local custom_config turns
		// into Xray's format, so B no longer validates for sing-box.
		panelServer.set(configB, false)
		if err := os.WriteFile(path, []byte(`{"routing":{"rules":[]}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if !poll() {
			t.Fatal("poll failed")
		}
		if s.pendingConfig != nil {
			t.Fatal("HTTP 200 for a candidate that stopped validating kept it")
		}
		// A copy translated earlier is pushed again; its hash equals the cached body.
		s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: candidate})
		if s.pendingConfig == nil {
			t.Fatal("WS config B did not stay pending")
		}
		if !poll() {
			t.Fatal("poll failed")
		}
		if s.pendingConfig != nil {
			t.Fatal("HTTP 304 matching the pending hash kept a candidate that no longer validates")
		}
		if s.lastConfigHash != active || !s.kernel.IsRunning() {
			t.Fatal("active config was disturbed")
		}
	})

	t.Run("pending certificate reload survives an invalid 304", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "custom.json")
		if err := os.WriteFile(path, []byte(`{"route":{"rules":[]}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		s, _, poll := setup(t, config.KernelConfig{Type: "singbox", CustomConfig: path})
		active := computeConfigHash(s.lastConfig)
		// The certificate renews while custom_config is temporarily in Xray's format.
		if err := os.WriteFile(path, []byte(`{"routing":{"rules":[]}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		s.cert = cert.NewManager(config.CertConfig{CertMode: "self"})
		if err := s.cert.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer s.cert.Stop()
		s.applyPullResult(context.Background(), pullResult{wsConfigRevision: s.wsConfigRevision})
		if s.pendingConfig == nil || computeConfigHash(s.pendingConfig) != active {
			t.Fatal("failed certificate reload did not queue the active config for retry")
		}
		// The panel resends the active config over WebSocket.
		resent := *s.lastConfig
		s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: &resent})
		if s.pendingConfig == nil {
			t.Fatal("WS resend of the active config discarded the pending certificate reload")
		}
		// The panel still serves the active config, which does not validate right now.
		if !poll() {
			t.Fatal("poll failed")
		}
		if s.pendingConfig == nil {
			t.Fatal("invalid 304 discarded the pending certificate reload")
		}
		// Once the file is native again the reload goes through.
		if err := os.WriteFile(path, []byte(`{"route":{"rules":[]}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if !poll() {
			t.Fatal("poll failed")
		}
		if s.pendingConfig != nil || s.lastConfigHash != active || !s.kernel.IsRunning() {
			t.Fatal("certificate reload was not applied after custom_config was fixed")
		}
	})

	t.Run("poll older than a WS config", func(t *testing.T) {
		s, _, _ := setup(t, singbox)
		active := s.lastConfig
		s.wsConfigRevision++
		stale := &model.NodeSpec{Protocol: "vless", ServerPort: 20003}
		s.applyPullResult(context.Background(), pullResult{config: stale, configHash: computeConfigHash(stale)})
		if s.pendingConfig != nil || s.lastConfig != active {
			t.Fatal("a poll older than the latest WS config was applied")
		}
	})
}

func TestRenewedCertificateAppliesWithoutPanelPoll(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	s.kernel = &fakeKernel{}
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}})
	s.cert = cert.NewManager(config.CertConfig{CertMode: "self"})
	defer s.cert.Stop()
	if err := s.cert.Start(ctx); err != nil {
		t.Fatal(err)
	}
	spec := &model.NodeSpec{Protocol: "vless", ServerPort: 20001, TLS: 1}
	if err := s.applyNodeConfig(ctx, spec); err != nil {
		t.Fatal(err)
	}
	before := s.appliedState.TLS.CertPEM
	// Simulate the ACME worker replacing the manager's PEM in memory.
	if err := s.cert.Start(ctx); err != nil {
		t.Fatal(err)
	}
	renewed := s.cert.TLSCert().CertPEM
	if bytes.Equal(before, renewed) {
		t.Fatal("test certificate did not change")
	}
	s.handlePullTick(ctx)
	if !bytes.Equal(s.appliedState.TLS.CertPEM, renewed) {
		t.Fatal("the kernel kept the old certificate without a successful panel poll")
	}
}

// echoTarget accepts TCP connections and echoes what it reads.
func echoTarget(t *testing.T) string {
	t.Helper()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { target.Close() })
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				io.Copy(conn, conn)
			}()
		}
	}()
	return target.Addr().String()
}

// socksReaches reports whether a SOCKS5 proxy on port relays to target.
func socksReaches(port int, uuid, target string) bool {
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: uuid, Password: uuid}, &net.Dialer{Timeout: time.Second})
	if err != nil {
		return false
	}
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		return false
	}
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	return err == nil && string(buf) == "ping"
}

func TestSingBoxSamePortCustomConfigRebuild(t *testing.T) {
	ctx := context.Background()
	const uuid = "11111111-1111-4111-8111-111111111111"
	target := echoTarget(t)
	path := filepath.Join(t.TempDir(), "custom.json")
	if err := os.WriteFile(path, []byte(`{"route":{"rules":[]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()

	// Generated routes block loopback targets; allow the echo target explicitly.
	// custom_config rules are prepended, so they still take precedence.
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error", CustomConfig: path,
		CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}}}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	defer s.kernel.Stop()
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: uuid}})
	spec := &model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: port}
	if err := s.applyNodeConfig(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if !socksReaches(port, uuid, target) {
		t.Fatal("initial node does not relay")
	}

	// A custom_config the kernel rejects must not interrupt the running listener.
	if err := os.WriteFile(path, []byte(`{"route":{"rules":[{"ip_cidr":["127.0.0.1/32"],"action":"no-such-action"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.applyNodeConfig(ctx, spec); err == nil {
		t.Fatal("expected the invalid custom_config to be rejected")
	}
	if !s.kernel.IsRunning() || !socksReaches(port, uuid, target) {
		t.Fatal("rejected custom_config interrupted the running listener")
	}

	// A valid change on the same port is applied completely.
	if err := os.WriteFile(path, []byte(`{"route":{"rules":[{"ip_cidr":["127.0.0.1/32"],"action":"reject"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rebuild := *spec
	rebuild.ListenIP = "::"
	if err := s.applyNodeConfig(ctx, &rebuild); err != nil {
		t.Fatalf("same-port rebuild failed: %v", err)
	}
	if !s.kernel.IsRunning() {
		t.Fatal("kernel not running after rebuild")
	}
	if socksReaches(port, uuid, target) {
		t.Fatal("new custom route was not applied by the rebuild")
	}
}

// pollAndApply runs one REST poll; between launching it and applying its
// result, between runs on the service goroutine (a WebSocket event racing the
// in-flight poll). It reports whether the poll produced a result.
func pollAndApply(t *testing.T, s *Service, between func()) bool {
	t.Helper()
	s.pullBackoff.onSuccess()
	s.pullViaAPIAsync(context.Background())
	if between != nil {
		between()
	}
	deadline := time.After(10 * time.Second)
	for {
		select {
		case result := <-s.pullResults:
			s.applyPullResult(context.Background(), result)
			return true
		case <-deadline:
			t.Fatal("poll timed out")
		case <-time.After(5 * time.Millisecond):
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

func TestDiscardedReReadIsRetriedInsteadOfTrusting304(t *testing.T) {
	s, k, panelServer, poll := restUserNode(t)
	panelServer.setUsers([]map[string]any{{"id": 1, "uuid": "11111111-1111-4111-8111-111111111111"}})
	k.updateErr, k.startErr = errors.New("hot update failed"), errors.New("rebuild failed")
	poll()
	k.updateErr, k.startErr = nil, nil
	k.running = true
	// The re-read is fetched, but a WebSocket delta lands while it is in flight,
	// so the service discards it. The client has cached its ETag regardless.
	pollAndApply(t, s, func() {
		s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove",
			DeltaUsers: []model.UserSpec{{ID: 9, UUID: "99999999-9999-4999-8999-999999999999"}}})
	})
	if !hasUser(s.lastUsers, 2) || !s.userRefetch {
		t.Fatalf("a discarded re-read must keep the re-read pending: users=%v refetch=%v", s.lastUsers, s.userRefetch)
	}
	poll()
	if hasUser(s.lastUsers, 2) || s.userRefetch {
		t.Fatalf("revocation was lost behind HTTP 304: users=%v refetch=%v", s.lastUsers, s.userRefetch)
	}
}

func TestFailedReReadKeepsRefetchPending(t *testing.T) {
	s, k, panelServer, poll := restUserNode(t)
	panelServer.setUsers([]map[string]any{{"id": 1, "uuid": "11111111-1111-4111-8111-111111111111"}})
	k.updateErr, k.startErr = errors.New("hot update failed"), errors.New("rebuild failed")
	poll()
	k.updateErr, k.startErr = nil, nil
	k.running = true
	panelServer.mu.Lock()
	panelServer.usersDown = true
	panelServer.mu.Unlock()
	if pollAndApply(t, s, nil) {
		t.Fatal("a poll with a failing user endpoint produced a result")
	}
	if !s.userRefetch {
		t.Fatal("a failed re-read cleared the pending re-read")
	}
	panelServer.mu.Lock()
	panelServer.usersDown = false
	panelServer.mu.Unlock()
	poll()
	if hasUser(s.lastUsers, 2) {
		t.Fatalf("revocation was not re-read after the user endpoint recovered: %v", s.lastUsers)
	}
}

func TestWSRollbackResendSupersedesInFlightPoll(t *testing.T) {
	s, _, panelServer, _ := restUserNode(t)
	// The panel briefly drops user 2; a poll fetches that list...
	panelServer.setUsers([]map[string]any{{"id": 1, "uuid": "11111111-1111-4111-8111-111111111111"}})
	pollAndApply(t, s, func() {
		// ...then rolls back and pushes the full current list, identical to
		// what the node already runs.
		s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers, Users: []model.UserSpec{
			{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"},
			{ID: 2, UUID: "22222222-2222-4222-8222-222222222222"},
		}})
	})
	if !hasUser(s.lastUsers, 2) {
		t.Fatal("an in-flight poll overwrote the panel's rollback")
	}
}

func TestXrayFailedCandidateKeepsOldListener(t *testing.T) {
	ctx := context.Background()
	const uuid = "11111111-1111-4111-8111-111111111111"
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	// Hold the candidate port on the exact address Xray binds, so the bind
	// really fails (a wildcard holder still lets BSD bind a specific address).
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	cfg := &config.Config{Kernel: config.KernelConfig{Type: "xray", ConfigDir: t.TempDir(), LogLevel: "error",
		CustomConfig: filepath.Join(t.TempDir(), "none.json")}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	defer s.kernel.Stop()
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: uuid}})
	spec := &model.NodeSpec{Protocol: "vless", Network: "tcp", ListenIP: "127.0.0.1", ServerPort: port}
	if err := s.applyNodeConfig(ctx, spec); err != nil {
		t.Fatal(err)
	}

	var refused atomic.Int32
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err != nil {
				refused.Add(1)
			} else {
				c.Close()
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	moved := *spec
	moved.ServerPort = busy.Addr().(*net.TCPAddr).Port
	s.applyConfigUpdate(ctx, &moved)
	time.Sleep(50 * time.Millisecond)
	close(stop)
	<-done
	if refused.Load() > 0 || !s.kernel.IsRunning() || s.lastConfig != spec {
		t.Fatalf("a candidate that cannot bind interrupted the working listener: refused=%d running=%v", refused.Load(), s.kernel.IsRunning())
	}
}
