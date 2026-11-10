package xray

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common/protocol"
	xrayCore "github.com/xtls/xray-core/core"
	featurebandwidth "github.com/xtls/xray-core/features/bandwidth"
	xrayProxy "github.com/xtls/xray-core/proxy"
)

type addFailureUserManager struct {
	xrayProxy.UserManager
	users     map[string]*protocol.MemoryUser
	failEmail string
	failure   error
}

func (m *addFailureUserManager) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	return m.users[email]
}
func (m *addFailureUserManager) RemoveUser(_ context.Context, email string) error {
	delete(m.users, email)
	return nil
}
func (m *addFailureUserManager) AddUser(_ context.Context, user *protocol.MemoryUser) error {
	if user.Email == m.failEmail {
		return m.failure
	}
	m.users[user.Email] = user
	return nil
}

func TestAddUsersFailureRollsBackAndKeepsAdmission(t *testing.T) {
	for _, failure := range []string{"account build", "core add"} {
		t.Run(failure, func(t *testing.T) {
			old := model.UserSpec{ID: 1, UUID: "11111111-1111-4111-8111-111111111111", DeviceLimit: 1, SpeedLimit: 8}
			good := model.UserSpec{ID: 2, UUID: "22222222-2222-4222-8222-222222222222", DeviceLimit: 2, SpeedLimit: 16}
			last := model.UserSpec{ID: 3, UUID: "33333333-3333-4333-8333-333333333333", DeviceLimit: 3, SpeedLimit: 24}
			updated := old
			updated.DeviceLimit, updated.SpeedLimit = 4, 32
			users := []model.UserSpec{updated, good, last}
			um := &addFailureUserManager{users: make(map[string]*protocol.MemoryUser)}
			account, err := toMemoryUser("vless", &model.NodeSpec{Protocol: "vless"}, old)
			if err != nil {
				t.Fatal(err)
			}
			um.users[account.Email] = account
			if failure == "account build" {
				users[2].UUID = strings.Repeat("z", 36)
			} else {
				um.failEmail = userEmail(last.ID)
				um.failure = errors.New("injected add failure")
			}

			inst := new(xrayCore.Instance)
			bm := featurebandwidth.New()
			if err := inst.AddFeature(bm); err != nil {
				t.Fatal(err)
			}
			x := New(config.KernelConfig{Type: "xray"})
			x.instance, x.users = inst, []model.UserSpec{old}
			x.nodeConfig = &model.NodeSpec{Protocol: "vless"}
			x.protocol = "vless"
			x.limitDispatcher = newTestDispatcher()
			x.userManagerFunc = func() (xrayProxy.UserManager, error) { return um, nil }
			x.updateDispatcherLimits(x.users)
			x.updateBandwidthLimits(x.users)
			x.devices.UpdateUsers(x.users)
			oldLimiter := bm.GetUserLimiter(account.Email)
			if oldLimiter == nil {
				t.Fatal("old bandwidth limiter missing")
			}
			lease, err := x.devices.Acquire(old.ID, old.UUID, "1.1.1.1", old.DeviceLimit)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()

			added, err := x.AddUsers(users)
			if added != 0 || err == nil {
				t.Fatalf("AddUsers = %d, %v; want 0 and error", added, err)
			}
			if failure == "core add" && !errors.Is(err, um.failure) {
				t.Fatalf("AddUsers error = %v, want core failure", err)
			}
			if !reflect.DeepEqual(x.users, []model.UserSpec{old}) || len(um.users) != 1 || um.GetUser(context.Background(), account.Email) != account {
				t.Fatalf("failed add changed bookkeeping/authenticator: users=%v accounts=%v", x.users, um.users)
			}
			if got := x.limitDispatcher.deviceLimits[account.Email]; got != old.DeviceLimit {
				t.Fatalf("old device limit = %d, want %d", got, old.DeviceLimit)
			}
			for _, u := range users[1:] {
				if um.GetUser(context.Background(), userEmail(u.ID)) != nil || x.limitDispatcher.deviceLimits[userEmail(u.ID)] != 0 || bm.GetUserLimiter(userEmail(u.ID)) != nil {
					t.Fatalf("user %d was partially admitted", u.ID)
				}
				if l, err := x.devices.Acquire(u.ID, u.UUID, "2.2.2.2", 0); !errors.Is(err, limiter.ErrUserRevoked) {
					if l != nil {
						l.Release()
					}
					t.Fatalf("uncommitted user %d admission error = %v, want revoked", u.ID, err)
				}
			}
			if bm.GetUserLimiter(account.Email) != oldLimiter {
				t.Fatal("failed add changed existing bandwidth limiter")
			}
			if _, count := x.devices.Snapshot(); count != 1 {
				t.Fatalf("failed add closed old lease: %d", count)
			}
			// A service fallback can still diff against the original user set.
			if _, _, err := x.UpdateUsers(users); err == nil {
				t.Fatal("fallback UpdateUsers did not report the same failure")
			}
			if !reflect.DeepEqual(x.users, []model.UserSpec{old}) || len(um.users) != 1 || um.users[account.Email] != account {
				t.Fatal("failed fallback committed partial addition")
			}

			// Once the input/core failure is repaired, the full-update fallback
			// must be able to install the entire set from unchanged state.
			users[2].UUID = last.UUID
			um.failEmail = ""
			added, removed, err := x.UpdateUsers(users)
			if err != nil || added != 2 || removed != 0 {
				t.Fatalf("reconciled UpdateUsers = %d, %d, %v; want 2, 0, nil", added, removed, err)
			}
			if len(x.users) != 3 || len(um.users) != 3 || x.users[0] != updated {
				t.Fatalf("reconciliation incomplete: users=%v accounts=%v", x.users, um.users)
			}
			for _, u := range users[1:] {
				if um.GetUser(context.Background(), userEmail(u.ID)) == nil || x.limitDispatcher.deviceLimits[userEmail(u.ID)] != u.DeviceLimit || bm.GetUserLimiter(userEmail(u.ID)) == nil {
					t.Fatalf("reconciliation did not admit user %d", u.ID)
				}
			}
		})
	}
}
