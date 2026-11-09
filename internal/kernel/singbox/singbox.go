package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	singLog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	singJSON "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"golang.org/x/time/rate"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// drainTimeout is how long recycling waits for in-flight connections to finish
// naturally after closing all listen sockets, before hard-killing them.
const drainTimeout = 5 * time.Second

// SingBox implements kernel.Kernel by embedding sing-box as a Go library.
//
// User operations (AddUsers/RemoveUsers/UpdateUsers) use sing-box's native
// UpdatableInbound interface, which hot-swaps user credentials without
// restarting listeners — zero connection disruption.
type SingBox struct {
	cfg config.KernelConfig

	mu     sync.RWMutex
	box    *box.Box
	ctx    context.Context
	cancel context.CancelFunc

	users      []model.UserSpec
	nodeConfig *model.NodeSpec
	tls        kernel.TLSCert

	// connTracker is our lightweight in-process byte/IP tracker.
	// Created fresh on every Start (full restart).
	// Survives Reload (hot-swap) since live connections persist.
	connTracker *ConnTracker
	// Retain draining trackers until final accounting; retired totals remain
	// cumulative across full restarts and readable after Stop.
	draining   map[*box.Box]*drainingBox
	cumTraffic map[int][2]int64

	// devices is the admission state shared by every tracker of this kernel,
	// so a restart neither forgets draining connections nor the panel snapshot.
	devices *limiter.DeviceManager

	// speedLimitFunc resolves a user UUID to a *rate.Limiter.
	// Set once by SetSpeedLimitFunc and forwarded to every new ConnTracker.
	speedLimitFunc func(string) *rate.Limiter

	// deviceLimitFunc resolves a user UUID to (limit, hasLimit) for gate-keeping.
	// Set once by SetDeviceLimitFunc and forwarded to every new ConnTracker.
	deviceLimitFunc func(string) (int, bool)
}

type drainingBox struct {
	tracker *ConnTracker
	done    chan struct{}
}

func New(cfg config.KernelConfig) *SingBox {
	// A zero cooldown selects limiter.DefaultDeviceLimitCooldown.
	return NewWithDeviceManager(cfg, limiter.NewDeviceManager(time.Duration(cfg.DeviceLimitCooldown)*time.Second))
}

// NewWithDeviceManager preserves node admission state when switching kernels.
func NewWithDeviceManager(cfg config.KernelConfig, devices *limiter.DeviceManager) *SingBox {
	return &SingBox{
		cfg: cfg, devices: devices,
		draining: make(map[*box.Box]*drainingBox), cumTraffic: make(map[int][2]int64),
	}
}

var _ kernel.Kernel = (*SingBox)(nil)

func (s *SingBox) Name() string { return "sing-box" }

func (s *SingBox) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{
		PerUserSpeedLimit:    true,
		DeviceLimit:          true,
		BuiltInTrafficStats:  false,
		AliveIPTracking:      true,
		ForceCloseConnection: false,
		ForceCloseUser:       true,
	}
}

func (s *SingBox) Protocols() []string {
	return []string{
		"vmess", "vless", "trojan", "shadowsocks",
		"hysteria", "hysteria2", "tuic", "naive", "socks", "http", "anytls", "mieru",
	}
}

func (s *SingBox) Start(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	kernel.LogRealityTarget(nodeConfig, s.cfg.RealityTargets)
	ctx, cancel := context.WithCancel(context.Background())
	ctx = include.Context(ctx)

	// Save old state before creating the new instance.
	oldBox := s.box
	oldCancel := s.cancel
	oldCtx := s.ctx
	oldTracker := s.connTracker

	instance, err := s.buildBox(ctx, nodeConfig, users, tls)
	if err != nil {
		cancel()
		return err
	}

	// Attach a fresh tracker before Start so the first accepted connection is
	// already subject to device admission, speed limits and traffic accounting.
	// The Router keeps it across Reload; a full restart builds a new Router.
	tracker := NewConnTracker(s.devices.NewScope())
	tracker.SetUserMap(buildUserMap(users))
	if s.speedLimitFunc != nil {
		tracker.SetSpeedLimitFunc(s.speedLimitFunc)
	}
	if s.deviceLimitFunc != nil {
		tracker.SetDeviceLimitFunc(s.deviceLimitFunc)
	}
	if router := service.FromContext[adapter.Router](ctx); router != nil {
		router.AppendTracker(tracker)
	}

	if err := instance.Start(); err != nil {
		instance.Close()
		cancel()
		tracker.closeAll()
		return fmt.Errorf("start sing-box: %w", err)
	}

	// New instance started successfully — swap state.
	s.box = instance
	s.ctx = ctx
	s.cancel = cancel
	s.users = users
	s.nodeConfig = nodeConfig
	s.tls = tls
	s.connTracker = tracker
	s.devices.UpdateUsers(users)

	// Recycle old instance in background — drain then close.
	s.retireBoxLocked(oldBox, oldCancel, oldCtx, oldTracker)

	nlog.Core().Debug("sing-box started", "users", len(users))
	return nil
}

func (s *SingBox) buildBox(ctx context.Context, spec *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) (*box.Box, error) {
	data, err := json.Marshal(buildConfig(s.cfg, spec, users, tls))
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	nlog.Core().Debug("sing-box config generated", "len", len(data))
	opts, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, data)
	if err != nil {
		return nil, fmt.Errorf("parse sing-box options: %w", err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		return nil, fmt.Errorf("create sing-box instance: %w", err)
	}
	return instance, nil
}

// CheckConfig checks generated configuration without binding the proxy listener.
func (s *SingBox) CheckConfig(spec *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	instance, err := s.buildBox(include.Context(ctx), spec, users, tls)
	if err != nil {
		return err
	}
	_ = instance.Close()
	return nil
}

// retireBoxLocked keeps the instance owned by this kernel until its connections
// close and its counters have been added to the retired total. Requires s.mu.
func (s *SingBox) retireBoxLocked(oldBox *box.Box, oldCancel context.CancelFunc, oldCtx context.Context, oldTracker *ConnTracker) {
	if oldBox == nil {
		return
	}
	state := &drainingBox{tracker: oldTracker, done: make(chan struct{})}
	s.draining[oldBox] = state
	go s.recycleOldBox(oldBox, oldCancel, oldCtx, state)
}

// recycleOldBox gracefully shuts down a previous sing-box instance in the
// background. It closes listen sockets first, waits for connections to drain,
// then hard-closes. This avoids blocking the new instance's startup.
func (s *SingBox) recycleOldBox(oldBox *box.Box, oldCancel context.CancelFunc, oldCtx context.Context, state *drainingBox) {
	defer close(state.done)
	oldTracker := state.tracker
	// Step 1: close listen sockets so no new connections arrive on old ports.
	if im := service.FromContext[adapter.InboundManager](oldCtx); im != nil {
		_ = im.Close()
	}

	// Step 2: drain in-flight connections (best-effort).
	if oldTracker != nil {
		deadline := time.Now().Add(drainTimeout)
		for time.Now().Before(deadline) {
			if oldTracker.ActiveCount() == 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Step 3: hard-close everything.
	oldBox.Close()
	if oldCancel != nil {
		oldCancel()
	}
	if oldTracker != nil {
		oldTracker.closeAll()
	}
	s.mu.Lock()
	if oldTracker != nil {
		addTraffic(s.cumTraffic, oldTracker.trafficSnapshot())
	}
	delete(s.draining, oldBox)
	s.mu.Unlock()
	nlog.Core().Debug("sing-box: old instance recycled")
}

// Reload hot-swaps the inbound users and routing rules without restarting the box.
// Routes, outbounds, and the connTracker stay alive so in-flight connections
// continue to be tracked correctly.
func (s *SingBox) Reload(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return fmt.Errorf("not running")
	}

	kernel.LogRealityTarget(nodeConfig, s.cfg.RealityTargets)
	cfgMap := buildConfig(s.cfg, nodeConfig, users, tls)
	data, err := json.Marshal(cfgMap)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	opts, err := singJSON.UnmarshalExtendedContext[option.Options](s.ctx, data)
	if err != nil {
		return fmt.Errorf("parse options: %w", err)
	}

	im := service.FromContext[adapter.InboundManager](s.ctx)
	if im == nil {
		return fmt.Errorf("inbound manager not available")
	}

	router := service.FromContext[adapter.Router](s.ctx)
	if router == nil {
		return fmt.Errorf("router not available")
	}

	// Update routing rules
	if err := router.UpdateRules(opts.Route.Rules, opts.Route.RuleSet); err != nil {
		nlog.Core().Debug("routing reload failed", "error", err)
	} else {
		nlog.Core().Debug("sing-box routing reloaded")
	}

	nopFactory := singLog.NewNOPFactory()

	// Configuration hash check for inbound reconstruction
	tlsChanged := !bytes.Equal(s.tls.CertPEM, tls.CertPEM) || !bytes.Equal(s.tls.KeyPEM, tls.KeyPEM)
	configChanged := tlsChanged || s.nodeConfig == nil || kernel.ComputeHash(nodeConfig, users) != kernel.ComputeHash(s.nodeConfig, s.users)

	for _, inb := range opts.Inbounds {
		tag := inb.Tag
		if !configChanged {
			if existing, ok := im.Get(tag); ok && existing.Type() == inb.Type {
				var err error
				switch v := existing.(type) {
				case adapter.UpdatableInbound[option.VMessUser]:
					if opts, ok := inb.Options.(*option.VMessInboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableInbound[option.VLESSUser]:
					if opts, ok := inb.Options.(*option.VLESSInboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableInbound[option.TrojanUser]:
					if opts, ok := inb.Options.(*option.TrojanInboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableInbound[option.Hysteria2User]:
					if opts, ok := inb.Options.(*option.Hysteria2InboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableShadowsocksInbound:
					if opts, ok := inb.Options.(*option.ShadowsocksInboundOptions); ok {
						err = v.UpdateUsersByOptions(opts.Users)
					}
				case adapter.UpdatableInbound[option.TUICUser]:
					if opts, ok := inb.Options.(*option.TUICInboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableInbound[option.AnyTLSUser]:
					if opts, ok := inb.Options.(*option.AnyTLSInboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableInbound[option.MieruUser]:
					if opts, ok := inb.Options.(*option.MieruInboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableInbound[auth.User]:
					switch opts := inb.Options.(type) {
					case *option.NaiveInboundOptions:
						err = v.UpdateUsers(opts.Users)
					case *option.SocksInboundOptions:
						err = v.UpdateUsers(opts.Users)
					case *option.HTTPMixedInboundOptions:
						err = v.UpdateUsers(opts.Users)
					}
				}
				if err == nil {
					continue
				}
				nlog.Core().Warn("incremental update failed, falling back to recreate", "tag", tag, "error", err)
			}
		}

		// Config mismatch or incremental update failure: Reconstruct Inbound.
		// Remove the existing inbound first so im.Create() can bind the same port.
		// im.Create() cannot atomically swap a TCP listener — it tries to start the
		// new socket before the old one is closed, causing "address already in use".
		// The brief listen gap (< 1 ms) is far less disruptive than a full restart.
		_ = im.Remove(tag) // ignore error when tag doesn't exist yet
		logger := nopFactory.NewLogger(fmt.Sprintf("inbound/%s[%s]", inb.Type, tag))
		if err := im.Create(s.ctx, router, logger, tag, inb.Type, inb.Options); err != nil {
			return fmt.Errorf("recreate inbound %s: %w", tag, err)
		}
	}

	// Trackers remain registered on the Router (which survives ReloadUsers).
	// Only update the user map — do NOT re-register or traffic is double-counted.
	if s.connTracker != nil {
		s.connTracker.SetUserMap(buildUserMap(users))
	}

	nlog.Core().Debug("sing-box reloaded", "users", len(users))
	s.devices.UpdateUsers(users)
	s.users = users
	s.nodeConfig = nodeConfig
	s.tls = tls
	return nil
}

func (s *SingBox) Stop() {
	s.mu.Lock()
	s.retireBoxLocked(s.box, s.cancel, s.ctx, s.connTracker)
	s.box = nil
	s.cancel = nil
	s.ctx = nil
	s.connTracker = nil
	pending := make([]*drainingBox, 0, len(s.draining))
	for _, state := range s.draining {
		pending = append(pending, state)
	}
	s.mu.Unlock()
	// Every instance drains concurrently with the same bounded grace period.
	// Do not hold s.mu: recycling needs it to publish final counters.
	for _, state := range pending {
		<-state.done
	}
}

func (s *SingBox) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.box != nil
}

// connTrackerLocked returns the connTracker under a read-optimised lock.
func (s *SingBox) connTrackerSafe() *ConnTracker {
	s.mu.Lock()
	ct := s.connTracker
	s.mu.Unlock()
	return ct
}

// SetSpeedLimitFunc configures per-user bandwidth throttling.
func (s *SingBox) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.speedLimitFunc = fn
	if s.connTracker != nil {
		s.connTracker.SetSpeedLimitFunc(fn)
	}
}

// SetDeviceLimitFunc configures per-user device limit gate-keeping.
// Connections exceeding the limit are rejected at connect time.
func (s *SingBox) SetDeviceLimitFunc(fn func(uuid string) (int, bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceLimitFunc = fn
	if s.connTracker != nil {
		s.connTracker.SetDeviceLimitFunc(fn)
	}
}

// UpdateGlobalDevices updates the global device state from panel (for multi-node).
func (s *SingBox) UpdateGlobalDevices(users map[int][]string) {
	s.devices.UpdateGlobalDevices(users)
}

// ClearGlobalDevices clears the global device state (on WS disconnect).
func (s *SingBox) ClearGlobalDevices() {
	s.devices.ClearGlobalDevices()
}

// ─── User management (non-disruptive) ───────────────────────────────────────

// AddUsers hot-swaps users into running inbounds. Zero connection disruption.
func (s *SingBox) AddUsers(users []model.UserSpec) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return 0, fmt.Errorf("not running")
	}

	existing := make(map[int]struct{}, len(s.users))
	for _, u := range s.users {
		existing[u.ID] = struct{}{}
	}
	var toAdd []model.UserSpec
	for _, u := range users {
		if _, dup := existing[u.ID]; !dup {
			toAdd = append(toAdd, u)
		}
	}
	if len(toAdd) == 0 {
		return 0, nil
	}

	merged := append(append([]model.UserSpec{}, s.users...), toAdd...)
	if err := s.reloadInboundsLocked(merged); err != nil {
		return 0, err
	}
	s.devices.UpdateUsers(merged)
	s.users = merged
	return len(toAdd), nil
}

// RemoveUsers hot-swaps users out of running inbounds. Zero connection disruption
// for remaining users.
func (s *SingBox) RemoveUsers(users []model.UserSpec) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return 0, fmt.Errorf("not running")
	}

	removeSet := make(map[int]struct{}, len(users))
	for _, u := range users {
		removeSet[u.ID] = struct{}{}
	}
	var kept []model.UserSpec
	removed := 0
	for _, u := range s.users {
		if _, rm := removeSet[u.ID]; rm {
			removed++
		} else {
			kept = append(kept, u)
		}
	}
	if removed == 0 {
		return 0, nil
	}

	if err := s.reloadInboundsLocked(kept); err != nil {
		return 0, err
	}
	s.devices.UpdateUsers(kept)
	s.users = kept
	return removed, nil
}

// UpdateUsers replaces the entire user set atomically via hot-swap.
func (s *SingBox) UpdateUsers(users []model.UserSpec) (added, removed int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return 0, 0, fmt.Errorf("not running")
	}

	toAdd, toRemove := kernel.UserDiff(s.users, users)
	added, removed = len(toAdd), len(toRemove)

	if added == 0 && removed == 0 {
		// Only limits may have changed — update tracker map.
		if s.connTracker != nil {
			s.connTracker.SetUserMap(buildUserMap(users))
		}
		s.devices.UpdateUsers(users)
		s.users = users
		return 0, 0, nil
	}

	if err = s.reloadInboundsLocked(users); err != nil {
		return 0, 0, err
	}
	s.devices.UpdateUsers(users)
	s.users = users
	return
}

// reloadInboundsLocked hot-swaps inbound users using UpdatableInbound.
// Must be called with s.mu held.
func (s *SingBox) reloadInboundsLocked(users []model.UserSpec) error {
	cfgMap := buildConfig(s.cfg, s.nodeConfig, users, s.tls)
	data, err := json.Marshal(cfgMap)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	opts, err := singJSON.UnmarshalExtendedContext[option.Options](s.ctx, data)
	if err != nil {
		return fmt.Errorf("parse options: %w", err)
	}

	im := service.FromContext[adapter.InboundManager](s.ctx)
	if im == nil {
		return fmt.Errorf("inbound manager not available")
	}

	router := service.FromContext[adapter.Router](s.ctx)
	if router == nil {
		return fmt.Errorf("router not available")
	}

	nopFactory := singLog.NewNOPFactory()

	for _, inb := range opts.Inbounds {
		tag := inb.Tag
		if existing, ok := im.Get(tag); ok && existing.Type() == inb.Type {
			var err error
			switch v := existing.(type) {
			case adapter.UpdatableInbound[option.VMessUser]:
				if opts, ok := inb.Options.(*option.VMessInboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableInbound[option.VLESSUser]:
				if opts, ok := inb.Options.(*option.VLESSInboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableInbound[option.TrojanUser]:
				if opts, ok := inb.Options.(*option.TrojanInboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableInbound[option.Hysteria2User]:
				if opts, ok := inb.Options.(*option.Hysteria2InboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableShadowsocksInbound:
				if opts, ok := inb.Options.(*option.ShadowsocksInboundOptions); ok {
					err = v.UpdateUsersByOptions(opts.Users)
				}
			case adapter.UpdatableInbound[option.TUICUser]:
				if opts, ok := inb.Options.(*option.TUICInboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableInbound[option.AnyTLSUser]:
				if opts, ok := inb.Options.(*option.AnyTLSInboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableInbound[option.MieruUser]:
				if opts, ok := inb.Options.(*option.MieruInboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableInbound[auth.User]:
				switch opts := inb.Options.(type) {
				case *option.NaiveInboundOptions:
					err = v.UpdateUsers(opts.Users)
				case *option.SocksInboundOptions:
					err = v.UpdateUsers(opts.Users)
				case *option.HTTPMixedInboundOptions:
					err = v.UpdateUsers(opts.Users)
				}
			}
			if err == nil {
				continue
			}
			nlog.Core().Warn("incremental update failed, recreating inbound", "tag", tag, "error", err)
		}

		_ = im.Remove(tag)
		logger := nopFactory.NewLogger(fmt.Sprintf("inbound/%s[%s]", inb.Type, tag))
		if err := im.Create(s.ctx, router, logger, tag, inb.Type, inb.Options); err != nil {
			return fmt.Errorf("recreate inbound %s: %w", tag, err)
		}
	}

	if s.connTracker != nil {
		s.connTracker.SetUserMap(buildUserMap(users))
	}

	nlog.Core().Debug("sing-box users hot-swapped", "users", len(users))
	return nil
}

// ─── Observability ──────────────────────────────────────────────────────────
func (s *SingBox) GetUserTraffic(_ context.Context) (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int, err error) {
	s.mu.RLock()
	traffic = make(map[int][2]int64, len(s.cumTraffic))
	addTraffic(traffic, s.cumTraffic)
	if s.connTracker != nil {
		addTraffic(traffic, s.connTracker.trafficSnapshot())
	}
	for _, state := range s.draining {
		if state.tracker != nil {
			addTraffic(traffic, state.tracker.trafficSnapshot())
		}
	}
	s.mu.RUnlock()
	aliveIPs, connCount = s.devices.Snapshot()
	return traffic, aliveIPs, connCount, nil
}

func addTraffic(total, delta map[int][2]int64) {
	for uid, value := range delta {
		current := total[uid]
		total[uid] = [2]int64{current[0] + value[0], current[1] + value[1]}
	}
}

// CloseConnection force-closes a specific connection by its ID.
func (s *SingBox) CloseConnection(_ context.Context, connID string) error {
	ct := s.connTrackerSafe()
	if ct == nil {
		return fmt.Errorf("not running")
	}
	if !ct.CloseByID(connID) {
		nlog.Core().Debug("CloseConnection: connection not found (already closed?)", "id", connID)
	}
	return nil
}

// CloseUserConnections terminates all connections for a user UUID.
func (s *SingBox) CloseUserConnections(_ context.Context, uuid string) error {
	ct := s.connTrackerSafe()
	if ct == nil {
		return nil
	}
	ct.CloseByUUID(uuid)
	return nil
}

// buildUserMap creates a UUID→userID mapping used by ConnTracker to attribute
// connections to the correct user. All sing-box protocols use the user's UUID
// as the inbound name/username, so this covers every protocol.
func buildUserMap(users []model.UserSpec) map[string]int {
	m := make(map[string]int, len(users))
	for _, u := range users {
		m[u.UUID] = u.ID
	}
	return m
}
