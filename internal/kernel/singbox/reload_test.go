package singbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/sagernet/sing-box/adapter"
	singLog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func runningInbound(t *testing.T, s *SingBox, tag string) adapter.Inbound {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	inbound, ok := service.FromContext[adapter.InboundManager](s.ctx).Get(tag)
	if !ok {
		t.Fatalf("inbound %s not running", tag)
	}
	return inbound
}

func TestReloadRefusesChangesOutsideInbounds(t *testing.T) {
	users := []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}}
	s := New(config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error", CustomConfigData: map[string]any{}})
	defer s.Stop()
	spec := &model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: freePort(t)}
	if err := s.Start(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	before := runningInbound(t, s, "socks-in")
	sharedBefore := s.sharedKey

	// A new outbound and a route that uses it cannot be hot-swapped.
	s.cfg.CustomConfigData = map[string]any{
		"outbounds": []any{map[string]any{"type": "direct", "tag": "exit-b"}},
		"route":     map[string]any{"rules": []any{map[string]any{"ip_cidr": []any{"10.0.0.0/8"}, "outbound": "exit-b"}}},
	}
	if err := s.Reload(spec, users, kernel.TLSCert{}); !errors.Is(err, errRestartRequired) {
		t.Fatalf("expected errRestartRequired, got %v", err)
	}
	if runningInbound(t, s, "socks-in") != before || s.sharedKey != sharedBefore {
		t.Fatal("refused reload changed the running box")
	}
}

func TestReloadValidatesBeforeTouchingRunningBox(t *testing.T) {
	users := []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}}
	s := New(config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error", CustomConfigData: map[string]any{}})
	defer s.Stop()
	port := freePort(t)
	spec := &model.NodeSpec{Protocol: "shadowsocks", ListenIP: "127.0.0.1", ServerPort: port, Cipher: "aes-128-gcm"}
	if err := s.Start(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	before := runningInbound(t, s, "shadowsocks-in")

	bad := *spec
	bad.Cipher = "no-such-cipher"
	err := s.Reload(&bad, users, kernel.TLSCert{})
	if err == nil || errors.Is(err, errRestartRequired) {
		t.Fatalf("expected the invalid inbound to be rejected by validation, got %v", err)
	}
	if runningInbound(t, s, "shadowsocks-in") != before {
		t.Fatal("rejected reload replaced the running inbound")
	}
}

// Reload to a port that is already taken passes validation (box.New does not
// bind), so the bind failure happens after the running inbound was removed.
// The previous inbound must be restored and keep serving.
func TestReloadPortConflictKeepsRunningListener(t *testing.T) {
	users := []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}}
	s := New(config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error", CustomConfigData: map[string]any{}})
	defer s.Stop()
	portA := freePort(t)
	spec := &model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: portA}
	if err := s.Start(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	busy, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	portB := busy.Addr().(*net.TCPAddr).Port

	moved := *spec
	moved.ServerPort = portB
	err = s.Reload(&moved, users, kernel.TLSCert{})
	t.Logf("reload err: %v", err)
	if err == nil {
		t.Fatal("expected reload to fail on busy port")
	}
	s.mu.Lock()
	_, ok := service.FromContext[adapter.InboundManager](s.ctx).Get("socks-in")
	s.mu.Unlock()
	conn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", portA), time.Second)
	if conn != nil {
		conn.Close()
	}
	if !ok || dialErr != nil {
		t.Fatalf("failed reload left kernel running (IsRunning=%v) without its listener: inbound present=%v dial=%v", s.IsRunning(), ok, dialErr)
	}
}

func TestReloadUDPConflictReleasesCandidateTCPListener(t *testing.T) {
	users := []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}}
	s := New(config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error"})
	defer s.Stop()
	spec := &model.NodeSpec{Protocol: "shadowsocks", ServerPort: freePort(t), Cipher: "aes-128-gcm"}
	if err := s.Start(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	busy, err := net.ListenPacket("udp", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	moved := *spec
	moved.ServerPort = busy.LocalAddr().(*net.UDPAddr).Port
	if err := s.Reload(&moved, users, kernel.TLSCert{}); err == nil {
		t.Fatal("reload succeeded despite the occupied UDP port")
	}
	s.Stop()
	addr := fmt.Sprintf("127.0.0.1:%d", moved.ServerPort)
	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		conn.Close()
		t.Fatal("failed reload leaked its TCP listener")
	}
}

type failingInboundManager struct{ adapter.InboundManager }

func (failingInboundManager) Create(context.Context, adapter.Router, singLog.ContextLogger, string, string, any) error {
	return errors.New("inbound port taken during reload")
}

func TestFailedReloadAndRollbackCanRestartAppliedConfig(t *testing.T) {
	users := []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}}
	s := New(config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error"})
	defer s.Stop()
	spec := &model.NodeSpec{Protocol: "socks", ServerPort: freePort(t)}
	if err := s.Start(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	// Simulate both the candidate port and the released old port being taken.
	manager := service.FromContext[adapter.InboundManager](s.ctx)
	s.ctx = service.ExtendContext(s.ctx)
	service.MustRegister[adapter.InboundManager](s.ctx, failingInboundManager{manager})
	moved := *spec
	moved.ServerPort = freePort(t)
	if err := s.Reload(&moved, users, kernel.TLSCert{}); err == nil {
		t.Fatal("expected reload and restoration to fail")
	}
	if s.IsRunning() {
		t.Fatal("kernel reports running after losing its listener")
	}
	if err := s.Start(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatalf("could not restart the applied config: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", spec.ServerPort)
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("applied config did not resume listening: %v", err)
	}
	conn.Close()
}

func TestReloadAppliesRouteOnlyChangeWithoutRestart(t *testing.T) {
	users := []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}}
	s := New(config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error", CustomConfigData: map[string]any{}})
	defer s.Stop()
	spec := &model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: freePort(t)}
	if err := s.Start(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	runningBox, routeBefore := s.box, s.routeKey
	s.mu.Unlock()

	s.cfg.CustomConfigData = map[string]any{
		"route": map[string]any{"rules": []any{map[string]any{"ip_cidr": []any{"10.0.0.0/8"}, "action": "reject"}}},
	}
	if err := s.Reload(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatalf("route-only change was not hot-applied: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.box != runningBox {
		t.Fatal("route-only change replaced the running box")
	}
	if s.routeKey == routeBefore {
		t.Fatal("route rules were not updated")
	}
}

// Route rules that need process information cannot be served by a box that
// never set a process searcher up: sing-box refuses them, and Reload must
// turn that into a restart instead of a failed hot reload.
func TestReloadRequiresRestartForRulesTheBoxCannotServe(t *testing.T) {
	users := []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}}
	s := New(config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error", CustomConfigData: map[string]any{}})
	defer s.Stop()
	spec := &model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: freePort(t)}
	if err := s.Start(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	runningBox, routeBefore := s.box, s.routeKey
	s.mu.Unlock()

	s.cfg.CustomConfigData = map[string]any{
		"route": map[string]any{"rules": []any{map[string]any{"process_name": []any{"curl"}, "action": "reject"}}},
	}
	if err := s.Reload(spec, users, kernel.TLSCert{}); !errors.Is(err, errRestartRequired) {
		t.Fatalf("expected errRestartRequired, got %v", err)
	}
	s.mu.Lock()
	sameBox, sameRoute := s.box == runningBox, s.routeKey == routeBefore
	s.mu.Unlock()
	if !sameBox || !sameRoute {
		t.Fatal("a refused route change must leave the running box as it was")
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", spec.ServerPort), time.Second)
	if err != nil {
		t.Fatalf("the running box stopped listening: %v", err)
	}
	conn.Close()
}

func TestReleasedBoxRefusesInPlaceChanges(t *testing.T) {
	users := []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}}
	s := New(config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error", CustomConfigData: map[string]any{}})
	defer s.Stop()
	spec := &model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: freePort(t)}
	if err := s.Start(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	if !s.ReleaseListeners() {
		t.Fatal("a box without exclusive resources must release its listeners")
	}
	// The released inbound manager must never be touched again: sing-box
	// panics on Remove/Create once it has been closed.
	more := append(users, model.UserSpec{ID: 2, UUID: "22222222-2222-4222-8222-222222222222"})
	if _, err := s.AddUsers(more[1:]); err == nil {
		t.Fatal("AddUsers on a released box must fail")
	}
	if _, _, err := s.UpdateUsers(more); err == nil {
		t.Fatal("UpdateUsers on a released box must fail")
	}
	if err := s.Reload(spec, more, kernel.TLSCert{}); !errors.Is(err, errRestartRequired) {
		t.Fatalf("Reload on a released box must require a restart, got %v", err)
	}
	// Start replaces the released box normally.
	if err := s.Start(spec, more, kernel.TLSCert{}); err != nil {
		t.Fatalf("Start after release failed: %v", err)
	}
}

// A failed in-place change that could not be rolled back releases the
// listeners even when the box owns exclusive resources. Start must still be
// able to replace that box instead of waiting for the cache_file lock it holds.
func TestStartReplacesReleasedBoxWithExclusiveResources(t *testing.T) {
	users := []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}}
	s := New(config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error",
		CustomConfigData: map[string]any{"experimental": map[string]any{"cache_file": map[string]any{
			"enabled": true, "path": filepath.Join(t.TempDir(), "cache.db")}}}})
	defer s.Stop()
	spec := &model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: freePort(t)}
	if err := s.Start(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.releaseListenersLocked()
	s.mu.Unlock()
	if s.IsRunning() {
		t.Fatal("a box without listeners reports running")
	}
	if err := s.Start(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatalf("Start could not replace the released box: %v", err)
	}
	if !s.IsRunning() {
		t.Fatal("kernel is not running after replacing the released box")
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", spec.ServerPort), time.Second)
	if err != nil {
		t.Fatalf("replacement is not listening: %v", err)
	}
	conn.Close()
}

func TestReleaseRefusedForExclusiveResources(t *testing.T) {
	users := []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}}
	s := New(config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error",
		CustomConfigData: map[string]any{"experimental": map[string]any{"cache_file": map[string]any{
			"enabled": true, "path": filepath.Join(t.TempDir(), "cache.db")}}}})
	defer s.Stop()
	spec := &model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: freePort(t)}
	if err := s.Start(spec, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	if s.ReleaseListeners() {
		t.Fatal("a box holding the cache_file lock must not report its listeners released")
	}
	if s.CanReplaceInPlace(&model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: freePort(t)}) {
		t.Fatal("a box with exclusive resources cannot be replaced in place")
	}
}
