package xray

import (
	"context"
	"errors"
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common/protocol"
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
