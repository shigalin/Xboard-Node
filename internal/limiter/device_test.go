package limiter

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testDeviceManager() (*DeviceManager, *time.Time) {
	now := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	m := NewDeviceManager(0)
	m.now = func() time.Time { return now }
	return m, &now
}

func mustAcquire(t *testing.T, m *DeviceManager, uid int, ip string, limit int) *DeviceLease {
	t.Helper()
	l, err := m.Acquire(uid, ip, limit)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func waitClosed(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection was not closed")
	}
}

func TestDevicesStrictLimitKicksAndPunishesAllIPs(t *testing.T) {
	m, now := testDeviceManager()
	first := mustAcquire(t, m, 1, "9.9.9.9", 1)
	closed := make(chan struct{})
	first.Bind(func() { close(closed); first.Release() })
	second := mustAcquire(t, m, 1, "9.9.9.9", 1)
	if _, err := m.Acquire(1, "1.1.1.1", 1); !errors.Is(err, ErrDeviceLimit) {
		t.Fatalf("new IP admitted: %v", err)
	}
	waitClosed(t, closed)
	if _, count := m.Snapshot(); count != 0 {
		t.Fatalf("kicked connections still counted: %d", count)
	}
	if _, err := m.Acquire(1, "9.9.9.9", 1); !errors.Is(err, ErrDeviceLimit) {
		t.Fatal("old IP bypassed cooldown")
	}
	// Releasing an old lease after a reconnect must not decrement the new slot.
	*now = now.Add(DefaultDeviceLimitCooldown)
	third := mustAcquire(t, m, 1, "9.9.9.9", 1)
	first.Release()
	second.Release()
	if _, count := m.Snapshot(); count != 1 {
		t.Fatalf("stale release changed count: %d", count)
	}
	third.Release()
	third.Release()
	if _, count := m.Snapshot(); count != 0 {
		t.Fatal("duplicate release corrupted count")
	}
}

func TestDevicesGlobalUnionAndFreshness(t *testing.T) {
	for _, mode := range []string{"fresh", "expired", "cleared"} {
		t.Run(mode, func(t *testing.T) {
			m, now := testDeviceManager()
			m.UpdateGlobalDevices(map[int][]string{1: {"1.1.1.1", "9.9.9.9", "9.9.9.9"}})
			mustAcquire(t, m, 1, "1.1.1.1", 2)
			mustAcquire(t, m, 1, "9.9.9.9", 2).Release()
			if mode == "expired" {
				*now = now.Add(globalDeviceTTL + time.Nanosecond)
			}
			if mode == "cleared" {
				m.ClearGlobalDevices()
			}
			_, err := m.Acquire(1, "2.2.2.2", 2)
			if mode == "fresh" && !errors.Is(err, ErrDeviceLimit) {
				t.Fatal("global IP was not included")
			}
			if mode != "fresh" && err != nil {
				t.Fatalf("stale/cleared snapshot blocked local admission: %v", err)
			}
		})
	}
}

func TestDevicesConcurrentLastSlotAndLateBind(t *testing.T) {
	m := NewDeviceManager(time.Hour)
	var admitted atomic.Int64
	var wg sync.WaitGroup
	for i := 1; i <= 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := m.Acquire(1, fmt.Sprintf("10.0.0.%d", i), 1); err == nil {
				admitted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if admitted.Load() != 1 {
		t.Fatalf("last slot won by %d IPs", admitted.Load())
	}

	m = NewDeviceManager(0)
	lease := mustAcquire(t, m, 1, "1.1.1.1", 1)
	m.CloseUser(1) // Kicked after admission, before the transport was registered.
	closed := false
	if lease.Bind(func() { closed = true }) || !closed {
		t.Fatal("late transport escaped the sweep")
	}
	fresh := mustAcquire(t, m, 1, "2.2.2.2", 1)
	lease.Release()
	if m.ActiveCount() != 1 {
		t.Fatal("old sweep affected new admission")
	}
	fresh.Release()
}

func TestDevicesRebindAndInstanceIsolation(t *testing.T) {
	m := NewDeviceManager(0)
	l := mustAcquire(t, m, 1, "1.1.1.1", 1)
	if err := l.Rebind("::ffff:2.2.2.2", 1); err != nil {
		t.Fatal(err)
	}
	alive, count := m.Snapshot()
	if count != 1 || !alive[1]["2.2.2.2"] || alive[1]["1.1.1.1"] {
		t.Fatalf("incorrect rebind: %v", alive)
	}
	mustAcquire(t, m, 1, "2.2.2.2", 1)
	if err := l.Rebind("3.3.3.3", 1); !errors.Is(err, ErrDeviceLimit) {
		t.Fatal("rebind bypassed another live IP")
	}
	if err := l.Rebind("2.2.2.2", 1); !errors.Is(err, ErrConnectionClosed) {
		t.Fatal("revoked session was reusable")
	}
	other := NewDeviceManager(0)
	mustAcquire(t, other, 1, "3.3.3.3", 1)
}

func TestDevicesCloseByIDAndLimitReduction(t *testing.T) {
	m := NewDeviceManager(0)
	l := mustAcquire(t, m, 1, "1.1.1.1", 2)
	closed := false
	l.Bind(func() { closed = true })
	if !m.CloseByID(l.ID()) || !closed || m.CloseByID(l.ID()) {
		t.Fatal("CloseByID did not close exactly one live lease")
	}
	mustAcquire(t, m, 1, "1.1.1.1", 2)
	mustAcquire(t, m, 1, "2.2.2.2", 2)
	if _, err := m.Acquire(1, "1.1.1.1", 1); !errors.Is(err, ErrDeviceLimit) {
		t.Fatal("existing IP bypassed reduced limit")
	}
}

func TestDevicesGlobalSnapshotKeepsReceiveTime(t *testing.T) {
	for _, tc := range []struct {
		name  string
		age   time.Duration
		fresh bool
	}{{"within TTL", globalDeviceTTL - time.Second, true}, {"expired", globalDeviceTTL + time.Nanosecond, false}} {
		t.Run(tc.name, func(t *testing.T) {
			m, now := testDeviceManager()
			m.UpdateGlobalDevicesAt(map[int][]string{1: {"9.9.9.9"}}, now.Add(-tc.age))
			_, err := m.Acquire(1, "1.1.1.1", 1)
			if tc.fresh != errors.Is(err, ErrDeviceLimit) {
				t.Fatalf("snapshot aged %v: err=%v", tc.age, err)
			}
		})
	}
}

func TestDeviceScopesShareAdmissionButNotLifetimes(t *testing.T) {
	m := NewDeviceManager(0)
	old, next := m.NewScope(), m.NewScope()
	mustAcquire(t, old, 1, "1.1.1.1", 2)
	mustAcquire(t, next, 2, "2.2.2.2", 0)
	if _, err := next.Acquire(1, "3.3.3.3", 1); !errors.Is(err, ErrDeviceLimit) {
		t.Fatal("IP held through another scope was not counted")
	}
	if old.ActiveCount() != 0 || next.ActiveCount() != 1 {
		t.Fatalf("active counts = %d/%d, want 0/1", old.ActiveCount(), next.ActiveCount())
	}
	mustAcquire(t, old, 3, "4.4.4.4", 0)
	old.CloseAll()
	if old.ActiveCount() != 0 || next.ActiveCount() != 1 {
		t.Fatal("CloseAll reached leases of another scope")
	}
	if _, count := m.Snapshot(); count != 1 {
		t.Fatalf("shared snapshot count = %d, want 1", count)
	}
}
