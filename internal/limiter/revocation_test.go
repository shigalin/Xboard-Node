package limiter

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
)

func TestIdentityRevocationFencesAcquireRebindAndLateBind(t *testing.T) {
	m := NewDeviceManager(0)
	old := []model.UserSpec{{ID: 1, UUID: "old"}}
	m.UpdateUsers(old)
	scope := m.NewScope()
	lease, err := scope.Acquire(1, "old", "1.1.1.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	m.UpdateUsers([]model.UserSpec{{ID: 1, UUID: "new"}})
	var closes atomic.Int32
	if lease.Bind(func() { closes.Add(1) }) || closes.Load() != 1 {
		t.Fatal("transport bound after revocation escaped close")
	}
	if _, err := scope.Acquire(1, "old", "1.1.1.1", 0); !errors.Is(err, ErrUserRevoked) {
		t.Fatalf("old scope re-admitted revoked identity: %v", err)
	}
	if err := lease.Rebind("old", "2.2.2.2", 0); !errors.Is(err, ErrConnectionClosed) {
		t.Fatalf("revoked cached lease rebound: %v", err)
	}
	fresh, err := scope.Acquire(1, "new", "1.1.1.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Release()
	if err := fresh.Rebind("old", "2.2.2.2", 0); !errors.Is(err, ErrUserRevoked) {
		t.Fatalf("different credential reused the fresh lease: %v", err)
	}
	if err := fresh.Rebind("new", "2.2.2.2", 0); err != nil {
		t.Fatal(err)
	}
	m.UpdateUsers(nil)
	if _, err := scope.Acquire(1, "new", "1.1.1.1", 0); !errors.Is(err, ErrUserRevoked) {
		t.Fatal("empty user set was treated as uninitialized")
	}
}

func TestRevocationIsAtomicWithConcurrentAdmission(t *testing.T) {
	m := NewDeviceManager(0)
	m.UpdateUsers([]model.UserSpec{{ID: 1, UUID: "old"}})
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := m.NewScope().Acquire(1, "old", "1.1.1.1", 0)
			if err != nil && !errors.Is(err, ErrUserRevoked) {
				t.Errorf("Acquire: %v", err)
			}
		}()
	}
	close(start)
	m.UpdateUsers(nil)
	wg.Wait()
	if _, count := m.Snapshot(); count != 0 {
		t.Fatalf("%d old leases survived revocation", count)
	}
}
