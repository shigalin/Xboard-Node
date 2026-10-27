package xray

import (
	"context"
	"errors"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/cedar2025/xboard-node/internal/model"
)

func TestXrayConfiguresSharedAdmissionBeforeStart(t *testing.T) {
	x := New(config.KernelConfig{Type: "xray", DeviceLimitCooldown: 120})
	users := []model.UserSpec{{ID: 1, UUID: "uuid-1", DeviceLimit: 3}}
	lookupCalled := false
	x.SetDeviceLimitFunc(func(uuid string) (int, bool) {
		if uuid != "uuid-1" {
			t.Fatalf("lookup used %q instead of user UUID", uuid)
		}
		lookupCalled = true
		return 1, true
	})
	global := map[int][]string{1: {"9.9.9.9"}}
	x.UpdateGlobalDevices(global)
	global[1][0] = "8.8.8.8" // The cached bootstrap must own a copy.
	ld := newTestDispatcher()
	x.attachDispatcher(ld)
	x.configureDispatcher(ld, users)
	link, raw := testLink()
	ld.innerDisp = &testInnerDispatcher{link: link}
	if _, err := ld.Dispatch(userContext(1, "9.9.9.9"), target(true)); err != nil {
		t.Fatalf("bootstrap IP was not restored: %v", err)
	}
	if !lookupCalled {
		t.Fatal("shared service lookup was not consulted")
	}
	if _, err := ld.Dispatch(userContext(1, "1.1.1.1"), target(true)); !errors.Is(err, limiter.ErrDeviceLimit) {
		t.Fatal("dynamic limit ignored in favor of user-spec fallback")
	}
	waitWriter(t, raw)
}

func TestXrayGlobalStateAndForceCloseAdapters(t *testing.T) {
	x := New(config.KernelConfig{Type: "xray"})
	ld := newTestDispatcher()
	x.attachDispatcher(ld)
	x.limitDispatcher = ld
	x.users = []model.UserSpec{{ID: 1, UUID: "uuid-1", DeviceLimit: 1}, {ID: 2, UUID: "uuid-2"}}
	x.updateDispatcherLimits(x.users)
	x.UpdateGlobalDevices(map[int][]string{1: {"8.8.8.8", "9.9.9.9"}})
	x.ClearGlobalDevices()
	first, writer1 := testLink()
	ld.innerDisp = &testInnerDispatcher{link: first}
	if _, err := ld.Dispatch(userContext(1, "1.1.1.1"), target(false)); err != nil {
		t.Fatal(err)
	}
	second, writer2 := testLink()
	ld.innerDisp = &testInnerDispatcher{link: second}
	if _, err := ld.Dispatch(userContext(2, "2.2.2.2"), target(true)); err != nil {
		t.Fatal(err)
	}
	if err := x.CloseUserConnections(context.Background(), "uuid-1"); err != nil {
		t.Fatal(err)
	}
	waitWriter(t, writer1)
	select {
	case <-writer2.closed:
		t.Fatal("closing one user affected another")
	default:
	}
	leaseID := second.Writer.(*closeTrackingWriter).lease.ID()
	if err := x.CloseConnection(context.Background(), leaseID); err != nil {
		t.Fatal(err)
	}
	waitWriter(t, writer2)
	if ld.devices.ActiveCount() != 0 {
		t.Fatal("force-close adapters left live IP slots")
	}
}

func TestXrayRestartKeepsDrainingSessionsAndLateSnapshots(t *testing.T) {
	x := New(config.KernelConfig{Type: "xray"})
	users := []model.UserSpec{{ID: 1, UUID: "uuid-1", DeviceLimit: 1}}
	old := newTestDispatcher()
	x.attachDispatcher(old)
	x.configureDispatcher(old, users)
	link, _ := testLink()
	old.innerDisp = &testInnerDispatcher{link: link}
	if _, err := old.Dispatch(userContext(1, "1.1.1.1"), target(false)); err != nil {
		t.Fatal(err)
	}

	// The replacement is configured before it is swapped in; the old instance
	// keeps draining its session meanwhile.
	next := newTestDispatcher()
	x.attachDispatcher(next)
	x.configureDispatcher(next, users)
	if _, err := next.Dispatch(userContext(1, "2.2.2.2"), target(false)); !errors.Is(err, limiter.ErrDeviceLimit) {
		t.Fatalf("draining session's IP was not counted after restart: %v", err)
	}
	if old.devices.ActiveCount() != 0 || next.devices.ActiveCount() != 0 {
		t.Fatal("breach on the new instance did not kick the draining session")
	}

	// A snapshot arriving before the swap must reach the replacement.
	x.devices.CloseUser(1)
	other := New(config.KernelConfig{Type: "xray"})
	fresh := newTestDispatcher()
	other.attachDispatcher(fresh)
	other.configureDispatcher(fresh, users)
	other.UpdateGlobalDevices(map[int][]string{1: {"9.9.9.9"}})
	if _, err := fresh.Dispatch(userContext(1, "3.3.3.3"), target(false)); !errors.Is(err, limiter.ErrDeviceLimit) {
		t.Fatalf("snapshot received before swap was lost: %v", err)
	}
}
