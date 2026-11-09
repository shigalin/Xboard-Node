package service

import (
	"context"
	"time"

	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// syncDeviceBans reports local violations immediately and periodically
// reconciles bans even when WebSocket delivery is unavailable.
func (s *Service) syncDeviceBans(ctx context.Context, syncer controlplane.DeviceBanSync) {
	const interval = time.Minute
	const reportRetryInterval = 10 * time.Second
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-s.devices.DeviceBanNotifications():
		}
		reports := s.devices.PendingDeviceBans()
		bans, err := syncer.SyncDeviceBans(ctx, reports)
		delay := interval
		switch {
		case err != nil:
			if len(reports) != 0 {
				delay = reportRetryInterval
			}
			if ctx.Err() == nil {
				nlog.Core().Warn("failed to sync device bans", "error", err)
			}
		case bans != nil:
			s.devices.ApplyDeviceBans(bans)
			s.devices.AcknowledgeDeviceBans(reports)
		}
		timer.Reset(delay)
	}
}
