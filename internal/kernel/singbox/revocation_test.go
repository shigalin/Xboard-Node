package singbox

import (
	"context"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/cedar2025/xboard-node/internal/model"
)

func TestRevokedMuxIdentityCannotCreateAnotherConnection(t *testing.T) {
	devices := limiter.NewDeviceManager(0)
	old := []model.UserSpec{{ID: 1, UUID: "old"}}
	current := []model.UserSpec{{ID: 2, UUID: "kept"}}
	tracker := NewConnTracker(devices.NewScope())
	tracker.SetUserMap(buildUserMap(old))
	stale := NewConnTracker(devices.NewScope())
	stale.SetUserMap(buildUserMap(old))
	tracker.SetUserMap(buildUserMap(current))
	devices.UpdateUsers(current)
	// A Mux child carries the identity authenticated by its outer connection.
	for _, tr := range []*ConnTracker{tracker, stale} {
		conn := &devicePacketConn{closed: make(chan struct{})}
		tr.RoutedPacketConnection(context.Background(), conn, testInboundContext("old", "1.1.1.1"), nil, nil)
		select {
		case <-conn.closed:
		default:
			t.Fatal("revoked Mux identity created a new packet session")
		}
	}
}

func TestUUIDRotationPreservesAlreadyAcceptedNewIdentity(t *testing.T) {
	devices := limiter.NewDeviceManager(0)
	tracker := NewConnTracker(devices.NewScope())
	old := []model.UserSpec{{ID: 1, UUID: "old"}}
	current := []model.UserSpec{{ID: 1, UUID: "new"}}
	tracker.SetUserMap(buildUserMap(old))
	oldConn := &devicePacketConn{closed: make(chan struct{})}
	tracker.RoutedPacketConnection(context.Background(), oldConn, testInboundContext("old", "1.1.1.1"), nil, nil)
	tracker.SetUserMap(buildUserMap(current))
	newConn := &devicePacketConn{closed: make(chan struct{})}
	wrapped := tracker.RoutedPacketConnection(context.Background(), newConn, testInboundContext("new", "1.1.1.1"), nil, nil)
	defer wrapped.Close()
	devices.UpdateUsers(current)
	select {
	case <-oldConn.closed:
	case <-time.After(time.Second):
		t.Fatal("old credential connection survived rotation")
	}
	if devices.ActiveCount() != 0 { // leases belong to the tracker scope
		t.Fatal("root unexpectedly owns leases")
	}
	if tracker.ActiveCount() != 1 {
		t.Fatal("new credential connection was revoked with the old identity")
	}
	select {
	case <-newConn.closed:
		t.Fatal("new credential transport was closed")
	default:
	}
}
