package xray

import (
	"context"
	"errors"
	"fmt"

	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common/protocol"
	xrayProxy "github.com/xtls/xray-core/proxy"
)

// Build replacements before touching the authenticator. If a core operation
// fails, restore its previous accounts and leave node/admission state unchanged.
func applyUserChanges(um xrayProxy.UserManager, proto string, nc *model.NodeSpec, toAdd, toRemove []model.UserSpec) error {
	accounts := make([]*protocol.MemoryUser, 0, len(toAdd))
	for _, u := range toAdd {
		account, err := toMemoryUser(proto, nc, u)
		if err != nil {
			return fmt.Errorf("build replacement user %d: %w", u.ID, err)
		}
		accounts = append(accounts, account)
	}
	ctx := context.Background()
	var removed, added []*protocol.MemoryUser
	rollback := func(cause error) error {
		errs := []error{cause}
		for _, u := range added {
			if err := um.RemoveUser(ctx, u.Email); err != nil {
				errs = append(errs, fmt.Errorf("rollback added account: %w", err))
			}
		}
		for _, u := range removed {
			if err := um.AddUser(ctx, u); err != nil {
				errs = append(errs, fmt.Errorf("restore removed account: %w", err))
			}
		}
		return errors.Join(errs...)
	}
	for _, u := range toRemove {
		account := um.GetUser(ctx, userEmail(u.ID))
		if account == nil {
			continue
		}
		if err := um.RemoveUser(ctx, account.Email); err != nil {
			return rollback(fmt.Errorf("remove user %d: %w", u.ID, err))
		}
		removed = append(removed, account)
	}
	for _, account := range accounts {
		if err := um.AddUser(ctx, account); err != nil {
			return rollback(fmt.Errorf("install replacement account: %w", err))
		}
		added = append(added, account)
	}
	return nil
}
