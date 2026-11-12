package singbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
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
	// sharedKey identifies everything in the running config except the
	// inbounds and the route rules: outbounds, dns and the rest. Reload can
	// swap inbounds and rules in place; any other change needs a restart.
	sharedKey string
	// routeKey identifies the running route rules and rule sets.
	routeKey string
	// exclusive is set when the running config owns resources besides its
	// inbounds that a second instance cannot share (clash_api or v2ray_api
	// listeners, the cache_file lock, endpoints, services, certificate
	// providers, tor data directories). Releasing only the inbounds would not
	// let a replacement start.
	exclusive bool
	// released is set once ReleaseListeners closed the inbound manager. The
	// box must not be changed in place after that; only Start or Stop.
	released bool

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
	// A released instance normally keeps draining next to its replacement. One
	// that owns exclusive resources cannot: the replacement would wait for them
	// and fail. Listeners of such an instance are only released when a failed
	// in-place change could not be rolled back, so close it completely first.
	s.mu.Lock()
	blocked := s.box != nil && s.released && s.exclusive
	s.mu.Unlock()
	if blocked {
		s.Stop()
	}

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

	instance, keys, err := s.buildBox(ctx, nodeConfig, users, tls)
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
	s.sharedKey, s.routeKey, s.exclusive = keys.shared, keys.route, keys.exclusive
	s.released = false
	s.devices.UpdateUsers(users)

	// Recycle old instance in background — drain then close.
	s.retireBoxLocked(oldBox, oldCancel, oldCtx, oldTracker)

	nlog.Core().Debug("sing-box started", "users", len(users))
	return nil
}

func (s *SingBox) buildBox(ctx context.Context, spec *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) (*box.Box, configKeys, error) {
	cfgMap := buildConfig(s.cfg, spec, users, tls)
	data, err := json.Marshal(cfgMap)
	if err != nil {
		return nil, configKeys{}, fmt.Errorf("marshal config: %w", err)
	}
	nlog.Core().Debug("sing-box config generated", "len", len(data))
	opts, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, data)
	if err != nil {
		return nil, configKeys{}, fmt.Errorf("parse sing-box options: %w", err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		return nil, configKeys{}, fmt.Errorf("create sing-box instance: %w", err)
	}
	if err := checkDependencies(ctx, opts); err != nil {
		_ = instance.Close()
		return nil, configKeys{}, err
	}
	return instance, keysOf(cfgMap), nil
}

// The managers resolve dependencies during Start. Check their graphs before a
// same-port rebuild has to release the running listener.
func checkDependencies(ctx context.Context, opts option.Options) error {
	outbounds := service.FromContext[adapter.OutboundManager](ctx)
	endpoints := service.FromContext[adapter.EndpointManager](ctx)
	outboundGraph := make(map[string][]string)
	for _, outbound := range outbounds.Outbounds() {
		outboundGraph[outbound.Tag()] = outbound.Dependencies()
	}
	for _, endpoint := range endpoints.Endpoints() {
		outboundGraph[endpoint.Tag()] = endpoint.Dependencies()
	}
	var finalOutbound string
	if opts.Route != nil {
		finalOutbound = opts.Route.Final
	}
	if err := checkDependencyGraph("outbound", outboundGraph, finalOutbound); err != nil {
		return err
	}
	if opts.DNS == nil {
		return nil
	}
	dns := service.FromContext[adapter.DNSTransportManager](ctx)
	dnsGraph := make(map[string][]string)
	for _, transport := range dns.Transports() {
		dnsGraph[transport.Tag()] = transport.Dependencies()
		// DNS transport dependencies name resolvers. Its detour references
		// the separate outbound graph and is also resolved at startup.
		if referrer, ok := transport.(adapter.Referrer); ok {
			for _, tag := range referrer.References() {
				if err := dialer.InitializeDetour(dialer.NewDetour(outbounds, tag, false)); err != nil {
					return fmt.Errorf("DNS server %q: %w", transport.Tag(), err)
				}
			}
		}
	}
	return checkDependencyGraph("DNS server", dnsGraph, opts.DNS.Final)
}

func checkDependencyGraph(kind string, graph map[string][]string, final string) error {
	if _, ok := graph[final]; final != "" && !ok {
		return fmt.Errorf("default %s %q not found", kind, final)
	}
	finished := make(map[string]bool, len(graph))
	var visit func(string) error
	visit = func(tag string) error {
		if done, seen := finished[tag]; seen {
			if !done {
				return fmt.Errorf("circular %s dependency at %q", kind, tag)
			}
			return nil
		}
		finished[tag] = false
		for _, name := range graph[tag] {
			if _, ok := graph[name]; !ok {
				return fmt.Errorf("%s %q depends on missing %s %q", kind, tag, kind, name)
			}
			if err := visit(name); err != nil {
				return err
			}
		}
		finished[tag] = true
		return nil
	}
	for _, tag := range slices.Sorted(maps.Keys(graph)) {
		if err := visit(tag); err != nil {
			return err
		}
	}
	return nil
}

// configKeys splits a generated config into the parts Reload treats
// differently: route rules (swapped atomically) and everything else except
// the inbounds (which needs a restart).
type configKeys struct {
	shared    string
	route     string
	inbounds  string
	exclusive bool
}

func keysOf(cfgMap M) configKeys {
	shared := make(M, len(cfgMap))
	var rules M
	for k, v := range cfgMap {
		switch k {
		case "inbounds":
		case "route":
			route, _ := v.(M)
			rest := make(M, len(route))
			rules = M{}
			for rk, rv := range route {
				if rk == "rules" || rk == "rule_set" {
					rules[rk] = rv
				} else {
					rest[rk] = rv
				}
			}
			shared[k] = rest
		default:
			shared[k] = v
		}
	}
	sharedData, _ := json.Marshal(shared)
	routeData, _ := json.Marshal(rules)
	exclusive := false
	for _, key := range []string{"experimental", "endpoints", "services", "certificate_providers"} {
		if _, ok := cfgMap[key]; ok {
			exclusive = true
		}
	}
	if outbounds, err := json.Marshal(cfgMap["outbounds"]); err == nil {
		var list []struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(outbounds, &list)
		for _, outbound := range list {
			if outbound.Type == "tor" { // locks its data directory
				exclusive = true
			}
		}
	}
	return configKeys{
		shared:    string(sharedData),
		route:     string(routeData),
		inbounds:  inboundsKey(cfgMap["inbounds"]),
		exclusive: exclusive,
	}
}

// unchangedInbounds reports, per tag, whether an inbound's generated config
// is identical in both configs, users included.
func unchangedInbounds(next, prev M) map[string]bool {
	index := func(cfgMap M) map[string]string {
		list, _ := cfgMap["inbounds"].([]M)
		out := make(map[string]string, len(list))
		for _, inbound := range list {
			tag, _ := inbound["tag"].(string)
			data, _ := json.Marshal(inbound)
			out[tag] = string(data)
		}
		return out
	}
	after, before := index(next), index(prev)
	same := make(map[string]bool, len(after))
	for tag, data := range after {
		same[tag] = before[tag] == data
	}
	return same
}

// inboundsKey serializes the inbounds without their user lists, so it
// changes only when a listener itself has to be rebuilt.
func inboundsKey(v any) string {
	list, _ := v.([]M)
	stripped := make([]M, 0, len(list))
	for _, inbound := range list {
		copied := make(M, len(inbound))
		for k, val := range inbound {
			if k != "users" {
				copied[k] = val
			}
		}
		stripped = append(stripped, copied)
	}
	data, _ := json.Marshal(stripped)
	return string(data)
}

// errRestartRequired reports a change Reload cannot apply in place.
var errRestartRequired = errors.New("configuration beyond inbounds and route rules changed; full restart required")

// SetCustomConfig replaces the custom config snapshot used by later builds.
// The service calls it after validating the file for this kernel; a kernel
// that is rolled back keeps the snapshot it was running with.
func (s *SingBox) SetCustomConfig(data map[string]any) {
	s.mu.Lock()
	s.cfg.CustomConfigData = data
	s.mu.Unlock()
}

// CheckConfig checks generated configuration without binding the proxy listener.
func (s *SingBox) CheckConfig(spec *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	instance, _, err := s.buildBox(include.Context(ctx), spec, users, tls)
	if err != nil {
		return err
	}
	_ = instance.Close()
	return nil
}

// CanReplaceInPlace reports whether Start can bring up spec while the running
// instance keeps serving. sing-box cannot bind a port twice, and a config with
// exclusive resources cannot run twice at all.
func (s *SingBox) CanReplaceInPlace(spec *model.NodeSpec) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.box == nil {
		return true
	}
	if s.exclusive || s.released || s.nodeConfig == nil {
		return false
	}
	// The candidate may add a controller, cache lock or other exclusive
	// resource even when the running box has none.
	if keysOf(buildConfig(s.cfg, spec, s.users, s.tls)).exclusive {
		return false
	}
	// Generated sing-box inbounds bind the wildcard address.
	return spec.ServerPort != s.nodeConfig.ServerPort
}

// ReleaseListeners stops accepting new connections on the running instance
// without waiting for existing ones, so a replacement can bind the same
// ports. The next Start retires the released instance and drains it in the
// background. It reports false, and releases nothing, when the instance owns
// other resources a replacement cannot share; the caller must Stop instead.
// A released instance must only be replaced or stopped.
func (s *SingBox) ReleaseListeners() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.box == nil || s.ctx == nil || s.exclusive {
		return false
	}
	s.releaseListenersLocked()
	return true
}

func (s *SingBox) releaseListenersLocked() {
	if s.released {
		return
	}
	if im := service.FromContext[adapter.InboundManager](s.ctx); im != nil {
		_ = im.Close()
	}
	s.released = true
}

// parseOptionsLocked builds and parses the config for spec in the running
// box's context. Requires s.mu.
func (s *SingBox) parseOptionsLocked(spec *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) (M, option.Options, error) {
	cfgMap := buildConfig(s.cfg, spec, users, tls)
	data, err := json.Marshal(cfgMap)
	if err != nil {
		return nil, option.Options{}, fmt.Errorf("marshal config: %w", err)
	}
	opts, err := singJSON.UnmarshalExtendedContext[option.Options](s.ctx, data)
	if err != nil {
		return nil, option.Options{}, fmt.Errorf("parse options: %w", err)
	}
	return cfgMap, opts, nil
}

// updateInboundUsers swaps an inbound's users in place when it supports it.
func updateInboundUsers(existing adapter.Inbound, inb option.Inbound) (bool, error) {
	switch v := existing.(type) {
	case adapter.UpdatableInbound[option.VMessUser]:
		if opts, ok := inb.Options.(*option.VMessInboundOptions); ok {
			return true, v.UpdateUsers(opts.Users)
		}
	case adapter.UpdatableInbound[option.VLESSUser]:
		if opts, ok := inb.Options.(*option.VLESSInboundOptions); ok {
			return true, v.UpdateUsers(opts.Users)
		}
	case adapter.UpdatableInbound[option.TrojanUser]:
		if opts, ok := inb.Options.(*option.TrojanInboundOptions); ok {
			return true, v.UpdateUsers(opts.Users)
		}
	case adapter.UpdatableInbound[option.Hysteria2User]:
		if opts, ok := inb.Options.(*option.Hysteria2InboundOptions); ok {
			return true, v.UpdateUsers(opts.Users)
		}
	case adapter.UpdatableShadowsocksInbound:
		if opts, ok := inb.Options.(*option.ShadowsocksInboundOptions); ok {
			return true, v.UpdateUsersByOptions(opts.Users)
		}
	case adapter.UpdatableInbound[option.TUICUser]:
		if opts, ok := inb.Options.(*option.TUICInboundOptions); ok {
			return true, v.UpdateUsers(opts.Users)
		}
	case adapter.UpdatableInbound[option.AnyTLSUser]:
		if opts, ok := inb.Options.(*option.AnyTLSInboundOptions); ok {
			return true, v.UpdateUsers(opts.Users)
		}
	case adapter.UpdatableInbound[option.MieruUser]:
		if opts, ok := inb.Options.(*option.MieruInboundOptions); ok {
			return true, v.UpdateUsers(opts.Users)
		}
	case adapter.UpdatableInbound[auth.User]:
		switch opts := inb.Options.(type) {
		case *option.NaiveInboundOptions:
			return true, v.UpdateUsers(opts.Users)
		case *option.SocksInboundOptions:
			return true, v.UpdateUsers(opts.Users)
		case *option.HTTPMixedInboundOptions:
			return true, v.UpdateUsers(opts.Users)
		}
	}
	return false, nil
}

func inboundTags(inbounds []option.Inbound) map[string]string {
	tags := make(map[string]string, len(inbounds))
	for _, inb := range inbounds {
		tags[inb.Tag] = inb.Type
	}
	return tags
}

type inboundUpdateMode uint8

const (
	updateUsersOnly inboundUpdateMode = iota
	updateOrRecreate
	recreateInbound
)

var errInboundUserUpdateUnsupported = errors.New("inbound requires a rebuild to update users")

// applyInboundsLocked brings the running inbounds to next. User operations
// only use native user updates. A configuration reload may also rebind.
// If a step fails, restore every inbound already touched to prev. If
// restoration also fails, stop accepting on the broken instance.
// Requires s.mu.
func (s *SingBox) applyInboundsLocked(next, prev []option.Inbound, mode inboundUpdateMode, unchanged map[string]bool) error {
	im := service.FromContext[adapter.InboundManager](s.ctx)
	router := service.FromContext[adapter.Router](s.ctx)
	if im == nil || router == nil {
		return fmt.Errorf("inbound manager or router not available")
	}
	nopFactory := singLog.NewNOPFactory()
	apply := func(inb option.Inbound) error {
		if mode != recreateInbound {
			if existing, ok := im.Get(inb.Tag); ok && existing.Type() == inb.Type {
				handled, err := updateInboundUsers(existing, inb)
				if handled && (err == nil || mode == updateUsersOnly) {
					return err
				}
				if err != nil {
					nlog.Core().Warn("incremental update failed, recreating inbound", "tag", inb.Tag, "error", err)
				}
			}
		}
		if mode == updateUsersOnly {
			return errInboundUserUpdateUnsupported
		}
		_ = im.Remove(inb.Tag) // ignore error when tag doesn't exist yet
		logger := nopFactory.NewLogger(fmt.Sprintf("inbound/%s[%s]", inb.Type, inb.Tag))
		// The inbound manager closes a candidate that fails to start.
		return im.Create(s.ctx, router, logger, inb.Tag, inb.Type, inb.Options)
	}
	previous := make(map[string]option.Inbound, len(prev))
	for _, inb := range prev {
		previous[inb.Tag] = inb
	}
	for i, inb := range next {
		if unchanged[inb.Tag] {
			// Identical config: nothing to do. Inbounds without in-place user
			// updates (Hysteria v1) would otherwise be recreated for nothing,
			// closing every QUIC session on their socket.
			continue
		}
		err := apply(inb)
		if err == nil {
			continue
		}
		touchedCount := i + 1
		if errors.Is(err, errInboundUserUpdateUnsupported) {
			touchedCount = i // No native update was attempted for this inbound.
		}
		var restoreErr error
		for _, touched := range next[:touchedCount] {
			if unchanged[touched.Tag] {
				continue
			}
			if old, ok := previous[touched.Tag]; ok {
				restoreErr = errors.Join(restoreErr, apply(old))
			}
		}
		if restoreErr != nil {
			s.releaseListenersLocked()
			return fmt.Errorf("update inbound %s: %w; restore previous inbounds: %w", inb.Tag, err, restoreErr)
		}
		return fmt.Errorf("update inbound %s: %w", inb.Tag, err)
	}
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

// Reload hot-swaps the inbounds and route rules without restarting the box.
// Outbounds and the connTracker stay alive so in-flight connections continue
// to be tracked correctly. Any other change returns errRestartRequired
// without touching the running box; the caller rebuilds instead. A failed
// reload leaves the previous inbounds and rules in place.
func (s *SingBox) Reload(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return fmt.Errorf("not running")
	}
	if s.released {
		return errRestartRequired
	}

	kernel.LogRealityTarget(nodeConfig, s.cfg.RealityTargets)
	cfgMap, opts, err := s.parseOptionsLocked(nodeConfig, users, tls)
	if err != nil {
		return err
	}
	prevMap, prevOpts, err := s.parseOptionsLocked(s.nodeConfig, s.users, s.tls)
	if err != nil {
		return err
	}
	// Inbounds and route rules can be swapped in place. Outbounds, DNS and the
	// rest stay as built, so a change there needs a restart; so does a change
	// in which inbounds exist (a protocol switch).
	keys := keysOf(cfgMap)
	if keys.shared != s.sharedKey || !maps.Equal(inboundTags(opts.Inbounds), inboundTags(prevOpts.Inbounds)) {
		return errRestartRequired
	}
	// Validate the complete config before touching the running box, so a
	// rejected candidate leaves the running listeners exactly as they were.
	checkCtx, checkCancel := context.WithCancel(context.Background())
	check, _, err := s.buildBox(include.Context(checkCtx), nodeConfig, users, tls)
	if err != nil {
		checkCancel()
		return err
	}
	_ = check.Close()
	checkCancel()

	// Recreate a listener only when the listener itself changed (port, TLS,
	// transport, ...). Users are swapped in place, and a route-only change
	// leaves the inbound alone, so QUIC sessions on its socket survive.
	mode := updateOrRecreate
	if keys.inbounds != keysOf(prevMap).inbounds {
		mode = recreateInbound
	}
	unchanged := unchangedInbounds(cfgMap, prevMap)
	if err := s.applyInboundsLocked(opts.Inbounds, prevOpts.Inbounds, mode, unchanged); err != nil {
		return err
	}
	if keys.route != s.routeKey {
		router := service.FromContext[adapter.Router](s.ctx)
		// UpdateRules swaps all rules or none.
		if err := router.UpdateRules(opts.Route.Rules, opts.Route.RuleSet); err != nil {
			if restoreErr := s.applyInboundsLocked(prevOpts.Inbounds, opts.Inbounds, mode, unchanged); restoreErr != nil {
				s.releaseListenersLocked()
				return fmt.Errorf("update route rules: %w; restore previous inbounds: %w", err, restoreErr)
			}
			if errors.Is(err, adapter.ErrRestartRequired) {
				// The rules need a service the running box never set up.
				return fmt.Errorf("%w: %v", errRestartRequired, err)
			}
			return fmt.Errorf("update route rules: %w", err)
		}
		s.routeKey = keys.route
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
	return s.box != nil && !s.released
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
	if s.released {
		return 0, fmt.Errorf("listeners released")
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
	if s.released {
		return 0, fmt.Errorf("listeners released")
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
	if s.released {
		return 0, 0, fmt.Errorf("listeners released")
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
	cfgMap, opts, err := s.parseOptionsLocked(s.nodeConfig, users, s.tls)
	if err != nil {
		return err
	}
	prevMap, prevOpts, err := s.parseOptionsLocked(s.nodeConfig, s.users, s.tls)
	if err != nil {
		return err
	}
	if err := s.applyInboundsLocked(opts.Inbounds, prevOpts.Inbounds, updateUsersOnly, unchangedInbounds(cfgMap, prevMap)); err != nil {
		return err
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
