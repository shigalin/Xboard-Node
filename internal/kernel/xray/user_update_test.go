package xray

import (
	"context"
	"errors"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common/protocol"
	xrayCore "github.com/xtls/xray-core/core"
	featurebandwidth "github.com/xtls/xray-core/features/bandwidth"
	xrayProxy "github.com/xtls/xray-core/proxy"
	hysteria "github.com/xtls/xray-core/proxy/hysteria/account"
)

type failingUserManager struct {
	xrayProxy.UserManager
	users map[string]*protocol.MemoryUser
	fail  *protocol.MemoryUser
}

func (m *failingUserManager) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	return m.users[email]
}
func (m *failingUserManager) RemoveUser(_ context.Context, email string) error {
	delete(m.users, email)
	return nil
}
func (m *failingUserManager) AddUser(_ context.Context, user *protocol.MemoryUser) error {
	if user.Account.Equals(m.fail.Account) {
		return errors.New("injected authenticator failure")
	}
	m.users[user.Email] = user
	return nil
}

func TestFailedAccountInstallRestoresRemovedUsers(t *testing.T) {
	nc := &model.NodeSpec{Protocol: "vless"}
	old := model.UserSpec{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}
	added := model.UserSpec{ID: 2, UUID: "22222222-2222-4222-8222-222222222222"}
	replacement := model.UserSpec{ID: 1, UUID: "33333333-3333-4333-8333-333333333333"}
	oldAccount, err := toMemoryUser("vless", nc, old)
	if err != nil {
		t.Fatal(err)
	}
	failedAccount, err := toMemoryUser("vless", nc, replacement)
	if err != nil {
		t.Fatal(err)
	}
	um := &failingUserManager{users: map[string]*protocol.MemoryUser{oldAccount.Email: oldAccount}, fail: failedAccount}
	if err := applyUserChanges(um, "vless", nc, []model.UserSpec{added, replacement}, []model.UserSpec{old}); err == nil {
		t.Fatal("failed installation reported success")
	}
	if len(um.users) != 1 || um.users[oldAccount.Email] != oldAccount {
		t.Fatal("rollback did not remove partial additions and restore the old account")
	}
}

type revocationUserManager struct {
	xrayProxy.UserManager
	users     map[string]*protocol.MemoryUser
	failEmail string
	failure   error
}

func (m *revocationUserManager) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	return m.users[email]
}
func (m *revocationUserManager) RemoveUser(_ context.Context, email string) error {
	if email == m.failEmail {
		return m.failure
	}
	if m.users[email] == nil {
		return errors.New("account not found")
	}
	delete(m.users, email)
	return nil
}
func (m *revocationUserManager) AddUser(_ context.Context, user *protocol.MemoryUser) error {
	m.users[user.Email] = user
	return nil
}

func TestRemoveUsersFailureKeepsAuthenticatorAndLimits(t *testing.T) {
	for _, failID := range []int{1, 2} {
		t.Run(userEmail(failID), func(t *testing.T) {
			users := []model.UserSpec{
				{ID: 1, UUID: "11111111-1111-4111-8111-111111111111", DeviceLimit: 1, SpeedLimit: 8},
				{ID: 2, UUID: "22222222-2222-4222-8222-222222222222", DeviceLimit: 2, SpeedLimit: 16},
				{ID: 3, UUID: "33333333-3333-4333-8333-333333333333"},
			}
			um := &revocationUserManager{users: make(map[string]*protocol.MemoryUser), failEmail: userEmail(failID), failure: errors.New("injected removal failure")}
			for _, user := range users {
				account, err := toMemoryUser("vless", &model.NodeSpec{Protocol: "vless"}, user)
				if err != nil {
					t.Fatal(err)
				}
				um.users[account.Email] = account
			}
			inst := new(xrayCore.Instance)
			bm := featurebandwidth.New()
			if err := inst.AddFeature(bm); err != nil {
				t.Fatal(err)
			}
			x := New(config.KernelConfig{Type: "xray"})
			x.instance, x.users = inst, users
			x.protocol = "vless"
			x.limitDispatcher = newTestDispatcher()
			x.userManagerFunc = func() (xrayProxy.UserManager, error) { return um, nil }
			x.updateDispatcherLimits(users)
			x.updateBandwidthLimits(users)
			x.devices.UpdateUsers(users)
			lease, err := x.devices.Acquire(failID, users[failID-1].UUID, "1.1.1.1", 0)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			removed, err := x.RemoveUsers([]model.UserSpec{users[0], users[1], {ID: 99}})
			if !errors.Is(err, um.failure) || removed != 0 {
				t.Fatalf("RemoveUsers = %d, %v; want 0 and removal failure", removed, err)
			}
			if len(x.users) != len(users) || len(um.users) != len(users) {
				t.Fatalf("failed removal changed bookkeeping/authenticator: users=%v accounts=%v", x.users, um.users)
			}
			for _, user := range users {
				if x.users[user.ID-1] != user || um.GetUser(context.Background(), userEmail(user.ID)) == nil {
					t.Fatalf("user %d lost on failed removal", user.ID)
				}
			}
			for _, user := range users[:2] {
				if got := x.limitDispatcher.deviceLimits[userEmail(user.ID)]; got != user.DeviceLimit {
					t.Fatalf("user %d device limit = %d, want %d", user.ID, got, user.DeviceLimit)
				}
				if bm.GetUserLimiter(userEmail(user.ID)) == nil {
					t.Fatalf("user %d bandwidth limit disappeared", user.ID)
				}
			}
			if _, count := x.devices.Snapshot(); count != 1 {
				t.Fatalf("failed removal closed active lease: %d", count)
			}
			// The service falls back to UpdateUsers after a failed delta. That path
			// must still see the old users and surface the same core failure.
			if _, _, err := x.UpdateUsers(users[2:]); !errors.Is(err, um.failure) {
				t.Fatalf("fallback UpdateUsers error = %v, want removal failure", err)
			}
			if len(x.users) != len(users) || len(um.users) != len(users) {
				t.Fatal("failed fallback committed partial revocation")
			}

			um.failEmail = ""
			removed, err = x.RemoveUsers([]model.UserSpec{users[0], users[1], {ID: 99}, users[0]})
			if err != nil || removed != 2 {
				t.Fatalf("retry RemoveUsers = %d, %v; want 2, nil", removed, err)
			}
			if len(x.users) != 1 || x.users[0] != users[2] || len(um.users) != 1 {
				t.Fatal("successful retry did not remove exactly the requested accounts")
			}
			for _, user := range users[:2] {
				if x.limitDispatcher.deviceLimits[userEmail(user.ID)] != 0 || bm.GetUserLimiter(userEmail(user.ID)) != nil {
					t.Fatalf("user %d limits survived successful removal", user.ID)
				}
			}
			if _, count := x.devices.Snapshot(); count != 0 {
				t.Fatalf("revoked user's lease survived removal: %d", count)
			}
		})
	}
}

type hysteriaUserManager struct {
	xrayProxy.UserManager
	validator *hysteria.Validator
}

func (m *hysteriaUserManager) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	return m.validator.GetByEmail(email)
}
func (m *hysteriaUserManager) RemoveUser(_ context.Context, email string) error {
	return m.validator.DelByEmail(email)
}
func (m *hysteriaUserManager) AddUser(_ context.Context, user *protocol.MemoryUser) error {
	return m.validator.Add(user)
}

func TestHysteriaRekeyUpdatesCoreValidator(t *testing.T) {
	nc := &model.NodeSpec{Protocol: "hysteria"}
	old := model.UserSpec{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}
	next := model.UserSpec{ID: 1, UUID: "22222222-2222-4222-8222-222222222222"}
	um := &hysteriaUserManager{validator: hysteria.NewValidator()}
	if err := applyUserChanges(um, "hysteria", nc, []model.UserSpec{old}, nil); err != nil {
		t.Fatal(err)
	}
	if err := applyUserChanges(um, "hysteria", nc, []model.UserSpec{next}, []model.UserSpec{old}); err != nil {
		t.Fatal(err)
	}
	if um.validator.Get(old.UUID) != nil || um.validator.Get(next.UUID) == nil {
		t.Fatal("Hysteria authenticator did not switch credentials")
	}
	if um.validator.Get("22222222-2222-1234-8222-222222222222") == nil {
		t.Fatal("new credential lost VR authentication")
	}
}
