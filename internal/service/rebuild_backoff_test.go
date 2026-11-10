package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
)

// A pending same-kernel config whose start always fails. Between retries the
// user list changes (normal panel churn). The backoff must not restart from zero
// on every retry and interrupt the listener each time.
func TestRebuildBackoffSurvivesUserChurn(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	previous := &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	stops := 0
	k := &fakeKernel{running: true, reloadErr: errors.New("restart required"),
		startHook: func(spec *model.NodeSpec, _ []model.UserSpec) error {
			if spec != previous {
				return errors.New("start rejected")
			}
			return nil
		}}
	s.kernel = k
	s.lastConfig, s.appliedState.Config, s.lastConfigHash = previous, previous, computeConfigHash(previous)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}})

	broken := &model.NodeSpec{Protocol: "vless", ServerPort: 12345, Host: "broken"}
	for i := 0; i < 5; i++ {
		before := k.startCalls
		s.applyConfigUpdate(ctx, broken)
		if k.startCalls-before >= 3 { // in-place, stop+start, restore
			stops++
		}
		// One user added by the panel before the next poll.
		users := append(append([]model.UserSpec(nil), s.lastUsers...), model.UserSpec{ID: 10 + i, UUID: fmt.Sprintf("11111111-1111-4111-8111-1111111111%02d", i)})
		s.applyUserUpdate(ctx, users, computeUserHash(users))
	}
	t.Logf("listener interruptions over 5 polls within the 1m backoff: %d, failures counter=%d", stops, s.rebuildRetryFailures)
	if stops > 1 {
		t.Fatalf("backoff bypassed: %d stop/start cycles of the serving kernel in 5 polls", stops)
	}
}

type connectedPush struct{}

func (connectedPush) Run(context.Context)                           {}
func (connectedPush) IsConnected() bool                             { return true }
func (connectedPush) SendDeviceReport(map[int][]string, int64) bool { return true }

func TestPullTickRecoversStoppedKernelWhileWebSocketIsConnected(t *testing.T) {
	ctx := context.Background()
	s := NewWithControlPlane(&config.Config{Kernel: config.KernelConfig{Type: "singbox"}}, &kernelTestControlPlane{})
	k := &fakeKernel{}
	s.kernel = k
	s.wsClient = connectedPush{}
	spec := &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	s.lastConfig, s.appliedState.Config, s.lastConfigHash = spec, spec, computeConfigHash(spec)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}})

	// A failed rebuild whose restore also failed left the kernel stopped.
	s.handlePullTick(ctx)
	if !k.IsRunning() || k.startCalls != 1 {
		t.Fatal("pull tick with a connected WebSocket did not restart the stopped kernel")
	}
	// A healthy kernel is left alone.
	s.handlePullTick(ctx)
	if k.startCalls != 1 {
		t.Fatal("pull tick restarted a running kernel")
	}
}

func TestPullTickRecoversStoppedKernelWithoutPanelPoll(t *testing.T) {
	s := NewWithControlPlane(&config.Config{Kernel: config.KernelConfig{Type: "singbox"}}, &kernelTestControlPlane{})
	k := &fakeKernel{}
	s.kernel = k
	spec := &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	s.lastConfig, s.appliedState.Config, s.lastConfigHash = spec, spec, computeConfigHash(spec)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}})
	s.handlePullTick(context.Background())
	if !k.IsRunning() || k.lastStart != spec {
		t.Fatal("stopped kernel did not restart the applied config without a panel poll")
	}
}

// A failed user update left the kernel stopped and a re-read of the users
// pending. Restarting with the state the node has must not wait for that
// re-read: the panel may be unreachable (here: no poll is possible).
func TestPullTickRecoversStoppedKernelWhileUserRefetchIsPending(t *testing.T) {
	s := NewWithControlPlane(&config.Config{Kernel: config.KernelConfig{Type: "singbox"}}, &kernelTestControlPlane{})
	k := &fakeKernel{}
	s.kernel = k
	spec := &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	s.lastConfig, s.appliedState.Config, s.lastConfigHash = spec, spec, computeConfigHash(spec)
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}})
	s.userRefetch = true
	s.handlePullTick(context.Background())
	if !k.IsRunning() || k.lastStart != spec {
		t.Fatal("stopped kernel was not restarted while a user re-read was pending")
	}
	if !s.userRefetch {
		t.Fatal("restarting the kernel cleared the pending user re-read")
	}
}

func TestNoOpReapplyKeepsRebuildBackoff(t *testing.T) {
	ctx := context.Background()
	s := NewWithControlPlane(&config.Config{Kernel: config.KernelConfig{Type: "singbox"}}, &kernelTestControlPlane{})
	k := &fakeKernel{running: true}
	s.kernel = k
	spec := &model.NodeSpec{Protocol: "vless", ServerPort: 12345}
	s.lastConfig, s.appliedState.Config, s.lastConfigHash = spec, spec, computeConfigHash(spec)
	s.appliedState.CustomConfig = map[string]any{}
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}})
	s.rebuildRetryKey, s.rebuildRetryFailures, s.rebuildRetryAt = "failing", 2, time.Now().Add(time.Hour)

	// Re-applying the active config changes nothing and proves nothing.
	if err := s.applyNodeConfig(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if s.rebuildRetryKey != "failing" || s.rebuildRetryFailures != 2 {
		t.Fatal("a no-op re-apply cleared the rebuild backoff")
	}
}
