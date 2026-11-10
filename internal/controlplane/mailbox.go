package controlplane

import (
	"maps"
	"slices"
	"sync"

	"github.com/cedar2025/xboard-node/internal/model"
)

// MailboxState is the coalesced snapshot drained from a NodeMailbox.
type MailboxState struct {
	Config *model.NodeSpec
	// ConfigErr is set when the latest config event could not be applied to
	// this node; any earlier buffered config was withdrawn with it.
	ConfigErr      error
	Users          []model.UserSpec
	DeviceUsers    map[int][]string
	DeviceBans     map[int]int64
	HasConfig      bool
	HasUsers       bool
	HasDevices     bool
	NeedsReconcile bool
}

// NodeMailbox buffers WS events for a machine-mode node service that is not
// yet ready to process them. Events are coalesced (latest-wins) and drained
// as a single snapshot once the service marks the mailbox as ready.
type NodeMailbox struct {
	mu             sync.Mutex
	ready          bool
	config         *model.NodeSpec
	configErr      error
	users          []model.UserSpec // pending full snapshot, including an empty list
	userDeltas     map[int]mailboxUserDelta
	deviceUsers    map[int][]string
	deviceBans     map[int]int64
	dirtyConfig    bool
	dirtyDevices   bool
	needsReconcile bool
	notifyCh       chan struct{}
}

type mailboxUserDelta struct {
	user    model.UserSpec
	removed bool
}

func NewNodeMailbox() *NodeMailbox {
	return &NodeMailbox{notifyCh: make(chan struct{}, 1)}
}

func (m *NodeMailbox) MarkReady() {
	m.mu.Lock()
	m.ready = true
	m.mu.Unlock()
	m.notify()
}

func (m *NodeMailbox) Apply(event Event) {
	m.mu.Lock()
	changed := false

	switch event.Type {
	case EventSyncConfig:
		if event.ConfigErr != nil {
			// Latest wins: the panel replaced any buffered candidate with a
			// config this node cannot run.
			m.config = nil
			m.dirtyConfig = false
			m.configErr = event.ConfigErr
			changed = true
		} else if event.Config != nil {
			m.config = cloneNodeSpec(event.Config)
			m.dirtyConfig = true
			m.configErr = nil
			changed = true
		}
	case EventSyncUsers:
		if event.Users != nil {
			m.users = cloneUsers(event.Users)
			m.userDeltas = nil // This snapshot supersedes all earlier deltas.
			changed = true
		}
	case EventSyncDevices:
		if event.DeviceUsers != nil {
			m.deviceUsers = cloneDeviceUsers(event.DeviceUsers)
			m.dirtyDevices = true
			changed = true
		}
		if len(event.DeviceBans) > 0 {
			if m.deviceBans == nil {
				m.deviceBans = make(map[int]int64, len(event.DeviceBans))
			}
			for uid, deadline := range event.DeviceBans {
				m.deviceBans[uid] = max(m.deviceBans[uid], deadline)
			}
			changed = true
		}
	case EventSyncUserDelta:
		if len(event.DeltaUsers) > 0 {
			if event.DeltaAction != "add" && event.DeltaAction != "remove" {
				m.needsReconcile = true
			} else {
				if m.userDeltas == nil {
					m.userDeltas = make(map[int]mailboxUserDelta)
				}
				for _, user := range event.DeltaUsers {
					m.userDeltas[user.ID] = mailboxUserDelta{user: user, removed: event.DeltaAction == "remove"}
				}
			}
			changed = true
		}
	}
	m.mu.Unlock()

	if changed {
		m.notify()
	}
}

func (m *NodeMailbox) notify() {
	select {
	case m.notifyCh <- struct{}{}:
	default:
	}
}

func (m *NodeMailbox) NotifyCh() <-chan struct{} { return m.notifyCh }

// DrainIfReady applies pending deltas to the latest users known by the service
// unless the mailbox has a newer full WebSocket snapshot. A nil baseline means
// the service has not received a full user list yet.
func (m *NodeMailbox) DrainIfReady(users []model.UserSpec) MailboxState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.ready {
		return MailboxState{}
	}
	state := MailboxState{NeedsReconcile: m.needsReconcile}
	state.ConfigErr, m.configErr = m.configErr, nil
	if m.dirtyConfig && m.config != nil {
		state.Config = cloneNodeSpec(m.config)
		state.HasConfig = true
		m.dirtyConfig = false
	}
	if m.users != nil {
		users = m.users
		state.HasUsers = true
	}
	if len(m.userDeltas) > 0 && users == nil {
		state.NeedsReconcile = true
	} else if len(m.userDeltas) > 0 {
		state.Users = applyUserDeltas(users, m.userDeltas)
		state.HasUsers = true
	} else if state.HasUsers {
		state.Users = users
	}
	m.users, m.userDeltas = nil, nil
	if m.dirtyDevices && m.deviceUsers != nil {
		state.DeviceUsers = cloneDeviceUsers(m.deviceUsers)
		state.HasDevices = true
		m.dirtyDevices = false
	}
	state.DeviceBans, m.deviceBans = m.deviceBans, nil
	m.needsReconcile = false
	return state
}

func cloneNodeSpec(spec *model.NodeSpec) *model.NodeSpec {
	if spec == nil {
		return nil
	}
	clone := *spec
	if spec.NetworkSettings != nil {
		clone.NetworkSettings = make(map[string]interface{}, len(spec.NetworkSettings))
		for k, v := range spec.NetworkSettings {
			clone.NetworkSettings[k] = v
		}
	}
	if spec.TLSSettings != nil {
		clone.TLSSettings = make(map[string]interface{}, len(spec.TLSSettings))
		for k, v := range spec.TLSSettings {
			clone.TLSSettings[k] = v
		}
	}
	if spec.Routes != nil {
		clone.Routes = append([]model.RouteRule(nil), spec.Routes...)
	}
	if spec.CustomOutbounds != nil {
		clone.CustomOutbounds = append([]model.OutboundConfig(nil), spec.CustomOutbounds...)
	}
	if spec.CustomRoutes != nil {
		clone.CustomRoutes = make([]map[string]any, len(spec.CustomRoutes))
		for i, route := range spec.CustomRoutes {
			if route == nil {
				continue
			}
			copied := make(map[string]any, len(route))
			for k, v := range route {
				copied[k] = v
			}
			clone.CustomRoutes[i] = copied
		}
	}
	if spec.CustomRouteRules != nil {
		clone.CustomRouteRules = append([]model.CustomRouteRule(nil), spec.CustomRouteRules...)
	}
	if spec.CertConfig != nil {
		certCopy := *spec.CertConfig
		if spec.CertConfig.DNSEnv != nil {
			certCopy.DNSEnv = make(map[string]string, len(spec.CertConfig.DNSEnv))
			for k, v := range spec.CertConfig.DNSEnv {
				certCopy.DNSEnv[k] = v
			}
		}
		clone.CertConfig = &certCopy
	}
	if spec.Multiplex != nil {
		muxCopy := *spec.Multiplex
		if spec.Multiplex.Brutal != nil {
			brutalCopy := *spec.Multiplex.Brutal
			muxCopy.Brutal = &brutalCopy
		}
		clone.Multiplex = &muxCopy
	}
	return &clone
}

func cloneUsers(users []model.UserSpec) []model.UserSpec {
	if users == nil {
		return nil
	}
	cloned := make([]model.UserSpec, len(users))
	copy(cloned, users)
	return cloned
}

func cloneDeviceUsers(devices map[int][]string) map[int][]string {
	if devices == nil {
		return nil
	}
	cloned := make(map[int][]string, len(devices))
	for uid, ips := range devices {
		dup := make([]string, len(ips))
		copy(dup, ips)
		cloned[uid] = dup
	}
	return cloned
}

func applyUserDeltas(users []model.UserSpec, deltas map[int]mailboxUserDelta) []model.UserSpec {
	updated := make([]model.UserSpec, 0, len(users))
	for _, user := range users {
		if delta, ok := deltas[user.ID]; ok {
			delete(deltas, user.ID)
			if delta.removed {
				continue
			}
			user = delta.user
		}
		updated = append(updated, user)
	}
	for _, id := range slices.Sorted(maps.Keys(deltas)) {
		if delta := deltas[id]; !delta.removed {
			updated = append(updated, delta.user)
		}
	}
	return updated
}
