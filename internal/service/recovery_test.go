package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

type queuedMailboxBootstrap struct {
	controlplane.ControlPlane
	bootstrap controlplane.Bootstrap
}

func (p *queuedMailboxBootstrap) Initial(context.Context, func() map[string]interface{}, chan<- controlplane.Event, chan<- controlplane.StatusChange) (controlplane.Bootstrap, error) {
	return p.bootstrap, nil
}

func (p *queuedMailboxBootstrap) Poll(context.Context) (controlplane.Snapshot, error) {
	return controlplane.Snapshot{}, errors.New("panel unavailable")
}

func (p *queuedMailboxBootstrap) SupportsPolling() bool { return true }

type shutdownTrafficKernel struct{ *fakeKernel }

func (k *shutdownTrafficKernel) GetUserTraffic(context.Context) (map[int][2]int64, map[int]map[string]bool, int, error) {
	if k.IsRunning() {
		return map[int][2]int64{1: {10, 0}}, nil, 1, nil
	}
	return map[int][2]int64{1: {20, 0}}, nil, 0, nil
}

type shutdownReportSink struct {
	controlplane.ControlPlane
	traffic map[int][2]int64
}

func (s *shutdownReportSink) SupportsReporting() bool { return true }
func (s *shutdownReportSink) Report(payload controlplane.ReportPayload) error {
	s.traffic = payload.Traffic
	return nil
}
func (s *shutdownReportSink) ReportAlive(map[int][]string, int64, bool) error { return nil }

func (p *queuedMailboxBootstrap) Metrics() controlplane.APIMetrics { return controlplane.APIMetrics{} }

func TestShutdownReportsTrafficAfterConnectionsDrain(t *testing.T) {
	cp := &queuedMailboxBootstrap{}
	s := NewWithControlPlane(&config.Config{Kernel: config.KernelConfig{Type: "singbox"}}, cp)
	k := &shutdownTrafficKernel{fakeKernel: &fakeKernel{running: true}}
	s.kernel = k
	sink := &shutdownReportSink{}
	s.sink = sink
	s.trackAndEnforce(context.Background())
	s.pushReportSync()
	if got := sink.traffic[1][0]; got != 20 {
		t.Fatalf("shutdown report = %d bytes; want all 20 bytes after drain", got)
	}
}

type shutdownConcurrentSink struct {
	controlplane.ControlPlane
	calls        atomic.Int32
	firstStarted chan struct{}
	firstRelease chan struct{}
	traffic      map[int][2]int64
}

func (s *shutdownConcurrentSink) SupportsReporting() bool { return true }
func (s *shutdownConcurrentSink) Report(payload controlplane.ReportPayload) error {
	if s.calls.Add(1) == 1 {
		close(s.firstStarted)
		<-s.firstRelease
		return errors.New("first report failed")
	}
	s.traffic = payload.Traffic
	return nil
}
func (s *shutdownConcurrentSink) ReportAlive(map[int][]string, int64, bool) error { return nil }

func TestShutdownWaitsForFailedAsyncReportBeforeFinalFlush(t *testing.T) {
	cp := &queuedMailboxBootstrap{}
	s := NewWithControlPlane(&config.Config{Kernel: config.KernelConfig{Type: "singbox"}}, cp)
	s.kernel = &fakeKernel{}
	sink := &shutdownConcurrentSink{firstStarted: make(chan struct{}), firstRelease: make(chan struct{})}
	s.sink = sink
	s.tracker.Process(map[int][2]int64{1: {10, 0}}, nil, 0)
	s.pushReportAsync()
	select {
	case <-sink.firstStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("async report did not start")
	}
	s.tracker.Process(map[int][2]int64{1: {20, 0}}, nil, 0)
	done := make(chan struct{})
	go func() { s.pushReportSync(); close(done) }()
	// With the broken ordering, the final report races ahead of the blocked
	// failure and flushes before its traffic can be restored.
	time.Sleep(40 * time.Millisecond)
	close(sink.firstRelease)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("final report did not finish")
	}
	if got := sink.traffic[1][0]; got != 20 {
		t.Fatalf("final report = %d bytes; want the restored async 10 plus subsequent 10", got)
	}
}

type deviceReportSeedSink struct {
	controlplane.ControlPlane
	full chan bool
}

func (*deviceReportSeedSink) SupportsReporting() bool     { return true }
func (*deviceReportSeedSink) SupportsDeviceReports() bool { return false }
func (s *deviceReportSeedSink) ReportAlive(_ map[int][]string, _ int64, full bool) error {
	s.full <- full
	return nil
}

func TestBusyRESTDeviceReportDoesNotLoseFullSeed(t *testing.T) {
	s := NewWithControlPlane(&config.Config{Kernel: config.KernelConfig{Type: "singbox"}}, &queuedMailboxBootstrap{})
	sink := &deviceReportSeedSink{full: make(chan bool, 1)}
	s.sink = sink
	s.devicePushActive.Store(true) // An earlier REST report is still in flight.
	s.reportDevices(context.Background())
	if s.restDevicesSeeded.Load() {
		t.Fatal("full REST snapshot was marked sent while another report held the gate")
	}
	s.devicePushActive.Store(false)
	s.reportDevices(context.Background())
	select {
	case full := <-sink.full:
		if !full {
			t.Fatal("retry did not send a full device snapshot")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("full device snapshot was not retried")
	}
}

func TestMachineBootstrapDoesNotAcceptUnconfirmedQueuedAdd(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprint("full=", full), func(t *testing.T) {
			user := model.UserSpec{ID: 2, UUID: "22222222-2222-4222-8222-222222222222"}
			mb := controlplane.NewNodeMailbox()
			if full {
				mb.Apply(controlplane.Event{Type: controlplane.EventSyncUsers, Users: []model.UserSpec{user}})
			} else {
				mb.Apply(controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{user}})
			}
			cp := &queuedMailboxBootstrap{bootstrap: controlplane.Bootstrap{
				Config: &model.NodeSpec{Protocol: "vless", ServerPort: 20001}, Users: []model.UserSpec{}, Mailbox: mb,
			}}
			s := NewWithControlPlane(&config.Config{Kernel: config.KernelConfig{Type: "singbox"}}, cp)
			k := &fakeKernel{startHook: func(_ *model.NodeSpec, users []model.UserSpec) error {
				if hasUser(users, 2) {
					t.Error("queued user was accepted without a fresh REST confirmation")
				}
				return nil
			}}
			s.kernel = k
			if err := s.initialSetup(context.Background()); err != nil {
				t.Fatal(err)
			}
			if k.IsRunning() || hasUser(s.lastUsers, 2) || !s.wsResyncPending.Load() {
				t.Fatal("unconfirmed queued add was not withheld for REST reconciliation")
			}
		})
	}
}

func TestMachineBootstrapDoesNotResurrectStaleFullSnapshot(t *testing.T) {
	valid := model.UserSpec{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}
	revoked := model.UserSpec{ID: 2, UUID: "22222222-2222-4222-8222-222222222222"}
	mb := controlplane.NewNodeMailbox()
	mb.Apply(controlplane.Event{Type: controlplane.EventSyncUsers, Users: []model.UserSpec{valid, revoked}})
	cp := &queuedMailboxBootstrap{bootstrap: controlplane.Bootstrap{
		Config: &model.NodeSpec{Protocol: "vless", ServerPort: 20001}, Users: []model.UserSpec{valid}, Mailbox: mb,
	}}
	s := NewWithControlPlane(&config.Config{Kernel: config.KernelConfig{Type: "singbox"}}, cp)
	k := &fakeKernel{startHook: func(_ *model.NodeSpec, users []model.UserSpec) error {
		if hasUser(users, 2) {
			t.Error("older queued snapshot reauthorized a user absent from REST bootstrap")
		}
		return nil
	}}
	s.kernel = k
	if err := s.initialSetup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !k.IsRunning() || hasUser(s.lastUsers, 2) || !s.wsResyncPending.Load() {
		t.Fatal("stale queued snapshot was not reconciled conservatively")
	}
}

func TestMachineBootstrapFiltersWSAddDuringKernelStart(t *testing.T) {
	mb := controlplane.NewNodeMailbox()
	cp := &queuedMailboxBootstrap{bootstrap: controlplane.Bootstrap{
		Config: &model.NodeSpec{Protocol: "vless", ServerPort: 20001}, Users: []model.UserSpec{}, Mailbox: mb,
	}}
	s := NewWithControlPlane(&config.Config{Kernel: config.KernelConfig{Type: "singbox"}}, cp)
	starting, release := make(chan struct{}), make(chan struct{})
	k := &fakeKernel{startHook: func(_ *model.NodeSpec, users []model.UserSpec) error {
		if hasUser(users, 2) {
			t.Error("WS addition unconfirmed by REST started a listener")
		}
		close(starting)
		<-release
		return nil
	}}
	// Start with a known REST user so the initial kernel start blocks. The
	// queued WS user arrives after the first drain but before startup ends.
	cp.bootstrap.Users = []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}}
	s.kernel = k
	done := make(chan error, 1)
	go func() { done <- s.initialSetup(context.Background()) }()
	select {
	case <-starting:
	case <-time.After(5 * time.Second):
		t.Fatal("kernel did not start")
	}
	mb.Apply(controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "add",
		DeltaUsers: []model.UserSpec{{ID: 2, UUID: "22222222-2222-4222-8222-222222222222"}}})
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bootstrap did not finish")
	}
	if hasUser(s.lastUsers, 2) || !s.wsResyncPending.Load() {
		t.Fatal("WS user arriving during kernel startup bypassed REST confirmation")
	}
}

func TestMachineBootstrapUsesRestrictiveLimitsUntilReconciled(t *testing.T) {
	for _, tc := range []struct{ rest, ws model.UserSpec }{
		{model.UserSpec{ID: 1, UUID: "same", SpeedLimit: 8, DeviceLimit: 1}, model.UserSpec{ID: 1, UUID: "same"}},
		{model.UserSpec{ID: 1, UUID: "same"}, model.UserSpec{ID: 1, UUID: "same", SpeedLimit: 8, DeviceLimit: 1}},
	} {
		mb := controlplane.NewNodeMailbox()
		mb.Apply(controlplane.Event{Type: controlplane.EventSyncUsers, Users: []model.UserSpec{tc.ws}})
		cp := &queuedMailboxBootstrap{bootstrap: controlplane.Bootstrap{
			Config: &model.NodeSpec{Protocol: "vless", ServerPort: 20001}, Users: []model.UserSpec{tc.rest}, Mailbox: mb,
		}}
		s := NewWithControlPlane(&config.Config{Kernel: config.KernelConfig{Type: "singbox"}}, cp)
		s.kernel = &fakeKernel{startHook: func(_ *model.NodeSpec, users []model.UserSpec) error {
			if len(users) != 1 || users[0].SpeedLimit != 8 || users[0].DeviceLimit != 1 {
				t.Errorf("bootstrap accepted looser queued limit: %+v", users)
			}
			return nil
		}}
		if err := s.initialSetup(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !s.wsResyncPending.Load() {
			t.Fatal("conflicting limits did not request reconciliation")
		}
	}
}

func TestMachineBootstrapStagesQueuedRevocationBeforeStart(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprint("full=", full), func(t *testing.T) {
			ctx := context.Background()
			users := []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}, {ID: 2, UUID: "22222222-2222-4222-8222-222222222222"}}
			mb := controlplane.NewNodeMailbox()
			if full {
				mb.Apply(controlplane.Event{Type: controlplane.EventSyncUsers, Users: users[:1]})
			} else {
				mb.Apply(controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: users[1:]})
			}
			cp := &queuedMailboxBootstrap{bootstrap: controlplane.Bootstrap{
				Config: &model.NodeSpec{Protocol: "vless", ServerPort: 20001}, Users: users, Mailbox: mb,
			}}
			s := NewWithControlPlane(&config.Config{Kernel: config.KernelConfig{Type: "singbox"}}, cp)
			startedWithRevoked := false
			k := &fakeKernel{startHook: func(_ *model.NodeSpec, active []model.UserSpec) error {
				if hasUser(active, 2) {
					startedWithRevoked = true
				}
				return nil
			}}
			s.kernel = k
			if err := s.initialSetup(ctx); err != nil {
				t.Fatal(err)
			}
			if startedWithRevoked || !k.IsRunning() || hasUser(s.lastUsers, 2) {
				t.Fatal("bootstrap briefly started the listener with a queued revoked credential")
			}
		})
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
