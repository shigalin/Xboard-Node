package service

import (
	"context"
	"github.com/cedar2025/xboard-node/internal/model"
	"testing"
)

func TestAddDeltaRekeysLastUserWithoutRemovingItFirst(t *testing.T) {
	k := &fakeKernel{running: true}
	s := newTestService(k)
	s.lastConfig = &model.NodeSpec{Protocol: "vless"}
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: "old"}})
	k.onRemoveUsers = func([]model.UserSpec) { k.running = false }
	k.onUpdateUsers = func(users []model.UserSpec) {
		if !k.running || len(users) != 1 || users[0].UUID != "new" {
			t.Fatal("rekey lost the running kernel or replacement credential")
		}
	}
	s.applyUserDelta(context.Background(), "add", []model.UserSpec{{ID: 1, UUID: "new"}})
	if k.removeCalls != 0 || k.addCalls != 0 || k.updateCalls != 1 {
		t.Fatalf("rekey calls: remove=%d add=%d update=%d", k.removeCalls, k.addCalls, k.updateCalls)
	}
	if len(s.lastUsers) != 1 || s.lastUsers[0].UUID != "new" {
		t.Fatal("replacement state was not published")
	}
}
