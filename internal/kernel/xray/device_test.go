package xray

import (
	"context"
	"errors"
	"testing"
	"time"

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

func TestXrayReloadKeepsGlobalSnapshotAge(t *testing.T) {
	x := New(config.KernelConfig{Type: "xray"})
	users := []model.UserSpec{{ID: 1, UUID: "uuid-1", DeviceLimit: 1}}
	x.SetDeviceLimitFunc(func(string) (int, bool) { return 1, true })
	x.UpdateGlobalDevices(map[int][]string{1: {"9.9.9.9"}})
	x.mu.Lock()
	x.globalDevicesAt = time.Now().Add(-301 * time.Second) // older than the panel TTL
	x.mu.Unlock()
	ld := newTestDispatcher()
	x.configureDispatcher(ld, users)
	link, _ := testLink()
	ld.innerDisp = &testInnerDispatcher{link: link}
	if _, err := ld.Dispatch(userContext(1, "1.1.1.1"), target(false)); err != nil {
		t.Fatalf("reload revived an expired global snapshot: %v", err)
	}
}
