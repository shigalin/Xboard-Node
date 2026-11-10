package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/cert"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/model"
)

func TestStoppedNodeDoesNotReviveRevokedCredential(t *testing.T) {
	ctx := context.Background()
	const validUUID = "11111111-1111-4111-8111-111111111111"
	const revokedUUID = "22222222-2222-4222-8222-222222222222"
	target := echoTarget(t)
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	customPath := filepath.Join(t.TempDir(), "native.json")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(customPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"route":{"rules":[]}}`)
	cfg := &config.Config{Kernel: config.KernelConfig{
		Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error", CustomConfig: customPath,
		CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}},
	}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{}) // No successful REST poll.
	defer s.kernel.Stop()
	revoked := model.UserSpec{ID: 2, UUID: revokedUUID}
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: validUUID}, revoked})
	if err := s.applyNodeConfig(ctx, &model.NodeSpec{Protocol: "socks", ServerPort: port}); err != nil {
		t.Fatal(err)
	}
	if !socksReaches(port, revokedUUID, target) {
		t.Fatal("fixture did not authenticate the second user")
	}
	s.kernel.Stop()
	write(`{"routing":{"rules":[]}}`)
	s.handleWSEvent(ctx, controlplane.Event{
		Type: controlplane.EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{revoked},
	})
	if s.kernel.IsRunning() {
		t.Fatal("invalid native config did not prevent the first restart")
	}
	write(`{"route":{"rules":[]}}`)
	s.handlePullTick(ctx)
	if !socksReaches(port, validUUID, target) {
		t.Fatal("recovery did not start a listener for the valid user")
	}
	if socksReaches(port, revokedUUID, target) {
		t.Fatal("the stopped node restarted and allowed the explicitly revoked user to relay traffic")
	}
}

func TestPendingCandidateDoesNotBlockActivePEMRenewal(t *testing.T) {
	ctx := context.Background()
	reserve, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	busy, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error"}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	defer s.kernel.Stop()
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}})
	s.cert = cert.NewManager(config.CertConfig{CertMode: "self"})
	defer s.cert.Stop()
	if err := s.cert.Start(ctx); err != nil {
		t.Fatal(err)
	}
	active := &model.NodeSpec{Protocol: "http", TLS: 1, ServerPort: port}
	if err := s.applyNodeConfig(ctx, active); err != nil {
		t.Fatal(err)
	}
	readCertificate := func() []byte {
		t.Helper()
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) // Local self-signed fixture.
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].Raw
	}
	before := readCertificate()
	candidate := *active
	candidate.ServerPort = busy.Addr().(*net.TCPAddr).Port
	s.applyConfigUpdate(ctx, &candidate)
	if s.pendingConfig != &candidate {
		t.Fatal("test candidate was not left pending")
	}
	candidateRetry := s.rebuildRetry
	if err := s.cert.Start(ctx); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(s.cert.TLSCert().CertPEM)
	if block == nil || bytes.Equal(before, block.Bytes) {
		t.Fatal("fixture did not produce a new PEM")
	}
	s.handlePullTick(ctx)
	s.applyPullResult(ctx, pullResult{currentConfig: &candidate})
	if s.pendingConfig != &candidate || s.lastConfig != active {
		t.Fatal("certificate renewal disturbed the pending or active node config")
	}
	if s.rebuildRetry != candidateRetry {
		t.Fatal("certificate renewal disturbed the candidate's rebuild backoff")
	}
	if !bytes.Equal(block.Bytes, readCertificate()) {
		t.Fatal("active TLS listener still presented its old certificate after a pull tick and a successful 304")
	}
}

func TestInvalidDependenciesAreRejectedBeforeListenerRelease(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "native.json")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"route":{"rules":[]}}`)
	reserve, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), CustomConfig: path, LogLevel: "error"}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	defer s.kernel.Stop()
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}})
	spec := &model.NodeSpec{Protocol: "socks", ServerPort: port}
	if err := s.applyNodeConfig(ctx, spec); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ config, failure string }{
		{`{"outbounds":[{"type":"socks","tag":"exit","server":"127.0.0.1","server_port":1080,"detour":"missing"}]}`, "missing outbound"},
		{`{"outbounds":[{"type":"socks","tag":"exit","server":"127.0.0.1","server_port":1080,"detour":"exit"}]}`, "circular outbound"},
		{`{"dns":{"final":"missing"}}`, "default DNS server"},
		{`{"dns":{"servers":[{"type":"udp","tag":"resolver","server":"127.0.0.1","detour":"missing"}]}}`, "outbound detour not found"},
		{`{"dns":{"servers":[{"type":"udp","tag":"resolver","server":"127.0.0.1","detour":"direct"}]}}`, "empty direct outbound"},
	} {
		write(tc.config)
		if err := s.applyNodeConfig(ctx, spec); err == nil || !strings.Contains(err.Error(), tc.failure) {
			t.Fatalf("expected preflight error %q, got %v", tc.failure, err)
		}
		if !s.kernel.IsRunning() || s.rebuildRetry.failures != 0 {
			t.Fatal("invalid dependency reached listener startup instead of failing preflight")
		}
	}
}

func TestMalformedConfigDoesNotBlockRevocations(t *testing.T) {
	s, _, server, poll := restUserNode(t)
	if !hasUser(s.lastUsers, 2) {
		t.Fatal("fixture started without the second user")
	}
	candidate := &model.NodeSpec{Protocol: "trojan", ServerPort: 20002}
	s.pendingConfig = candidate
	server.set(map[string]any{"server_port": 20001}, false)
	server.setUsers([]map[string]any{{"id": 1, "uuid": "11111111-1111-4111-8111-111111111111"}})
	poll()
	if hasUser(s.lastUsers, 2) || s.pendingConfig != nil {
		t.Fatal("invalid HTTP 200 blocked the revocation or kept a stale candidate")
	}
	s.pendingConfig = candidate
	server.setUsers([]map[string]any{})
	poll()
	if len(s.lastUsers) != 0 || s.pendingConfig != nil {
		t.Fatal("304 for an invalid config blocked the revocation or kept a stale candidate")
	}
}

func TestMachineMailboxStartsWithCoalescedUsers(t *testing.T) {
	ctx := context.Background()
	s := NewWithControlPlane(&config.Config{Kernel: config.KernelConfig{Type: "singbox"}}, &kernelTestControlPlane{})
	s.kernel = &fakeKernel{startHook: func(_ *model.NodeSpec, users []model.UserSpec) error {
		if hasUser(users, 2) {
			t.Fatal("machine config started a stopped node with a revoked credential")
		}
		return nil
	}}
	s.updateUserState([]model.UserSpec{
		{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"},
		{ID: 2, UUID: "22222222-2222-4222-8222-222222222222"},
	})
	s.machineMailbox = controlplane.NewNodeMailbox()
	s.machineMailbox.MarkReady()
	s.machineMailbox.Apply(controlplane.Event{Type: controlplane.EventSyncConfig,
		Config: &model.NodeSpec{Protocol: "vless", ServerPort: 20001}})
	s.machineMailbox.Apply(controlplane.Event{Type: controlplane.EventSyncUserDelta,
		DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 2}}})
	s.drainMachineMailbox(ctx)
	if !s.kernel.IsRunning() || len(s.lastUsers) != 1 || s.wsUserRevision != 1 {
		t.Fatal("machine config did not start with the coalesced users and advance the WS revision")
	}
}
