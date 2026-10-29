package limiter

import (
	"errors"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

const DefaultDeviceLimitCooldown = 180 * time.Second
const globalDeviceTTL = 300 * time.Second

var ErrDeviceLimit = errors.New("device limit exceeded")
var ErrConnectionClosed = errors.New("connection already closed")
var ErrUserRevoked = errors.New("user identity revoked")

type deviceUser struct {
	ips      map[string]int
	conns    map[string]*DeviceLease
	banUntil time.Time
}

// deviceState is the admission state shared by every scope of a manager.
type deviceState struct {
	mu           sync.Mutex
	users        map[int]*deviceUser
	conns        map[string]*DeviceLease
	global       map[int]map[string]bool
	globalUpdate time.Time
	cooldown     time.Duration
	identities   map[int]string // nil until the first successful user update
	nextID       uint64
	now          func() time.Time
}

// DeviceManager owns online IP admission and connection lifetimes for one node.
// Both kernels use it; transport and traffic accounting stay outside. Each
// kernel instance acquires through its own scope (NewScope), so connections
// still draining on a replaced instance keep counting against the new one.
type DeviceManager struct {
	*deviceState
	scoped map[string]*DeviceLease // leases acquired through this scope
}

func NewDeviceManager(cooldown time.Duration) *DeviceManager {
	if cooldown <= 0 {
		cooldown = DefaultDeviceLimitCooldown
	}
	return &DeviceManager{
		deviceState: &deviceState{
			users: make(map[int]*deviceUser), conns: make(map[string]*DeviceLease),
			global: make(map[int]map[string]bool), cooldown: cooldown, now: time.Now,
		},
		scoped: make(map[string]*DeviceLease),
	}
}

// NewScope returns a view sharing this manager's admission state. ActiveCount
// and CloseAll only cover leases acquired through the returned scope.
func (m *DeviceManager) NewScope() *DeviceManager {
	return &DeviceManager{deviceState: m.deviceState, scoped: make(map[string]*DeviceLease)}
}

func (m *DeviceManager) SetCooldown(d time.Duration) {
	if d > 0 {
		m.mu.Lock()
		m.cooldown = d
		m.mu.Unlock()
	}
}

func deviceIP(ip string) string {
	if addr, err := netip.ParseAddr(ip); err == nil {
		return addr.Unmap().String()
	}
	return ip
}

// deviceSet counts devices the way the panel does: devices behind one
// broadband line share its NAT IPv4 address but each has its own IPv6
// address, so the count is the larger of distinct IPv4 and distinct IPv6
// addresses. Unparsable strings count as IPv4 addresses.
type deviceSet struct {
	v4 map[string]struct{}
	v6 map[netip.Addr]struct{}
}

func (s *deviceSet) add(ip string) {
	addr, err := netip.ParseAddr(ip)
	if err == nil {
		addr = addr.Unmap()
		ip = addr.String()
	}
	if err == nil && addr.Is6() {
		if s.v6 == nil {
			s.v6 = make(map[netip.Addr]struct{})
		}
		s.v6[addr.WithZone("")] = struct{}{}
		return
	}
	if s.v4 == nil {
		s.v4 = make(map[string]struct{})
	}
	s.v4[ip] = struct{}{}
}

func (s *deviceSet) count() int {
	return max(len(s.v4), len(s.v6))
}

// CountDevices returns the device count of one user's online IPs.
func CountDevices(ips map[string]bool) int {
	var s deviceSet
	for ip := range ips {
		s.add(ip)
	}
	return s.count()
}

// Acquire checks and reserves a slot atomically, including for UDP. Bind must
// attach the transport closer afterwards. A kick between Acquire and Bind
// revokes the reservation, and Bind immediately closes the late transport.
func (m *DeviceManager) Acquire(userID int, uuid, ip string, limit int) (*DeviceLease, error) {
	ip = deviceIP(ip)
	m.mu.Lock()
	if !m.identityAllowedLocked(userID, uuid) {
		m.mu.Unlock()
		return nil, ErrUserRevoked
	}
	u := m.users[userID]
	if u == nil {
		u = &deviceUser{ips: make(map[string]int), conns: make(map[string]*DeviceLease)}
		m.users[userID] = u
	}
	closers, kicked, err := m.checkLocked(u, userID, ip, limit)
	if err != nil {
		m.mu.Unlock()
		if kicked {
			logDeviceKick(userID, ip, limit)
		}
		closeDevices(closers)
		return nil, err
	}
	m.nextID++
	l := &DeviceLease{manager: m, userID: userID, uuid: uuid, ip: ip, id: strconv.FormatUint(m.nextID, 36)}
	u.ips[ip]++
	u.conns[l.id] = l
	m.conns[l.id] = l
	m.scoped[l.id] = l
	m.mu.Unlock()
	return l, nil
}

// checkLocked punishes a new session that exceeds the shared IP-set policy.
// kicked reports a fresh breach, as opposed to a refusal during cooldown.
func (m *DeviceManager) checkLocked(u *deviceUser, uid int, ip string, limit int) (closers []func(), kicked bool, err error) {
	if limit <= 0 {
		return nil, false, nil
	}
	now := m.now()
	if now.Before(u.banUntil) {
		return nil, false, ErrDeviceLimit
	}
	if m.hasRoomLocked(u, uid, ip, limit, now) {
		return nil, false, nil
	}
	u.banUntil = now.Add(m.cooldown)
	return m.closeUserLocked(u), true, ErrDeviceLimit
}

// logDeviceKick reports a breach that arms the cooldown. Refusals during the
// cooldown are routine and left to the kernels' debug logs.
func logDeviceKick(uid int, ip string, limit int) {
	nlog.Core().Info("device limit exceeded, kicking user and rejecting connection",
		"userID", uid, "ip", ip, "limit", limit)
}

func (m *DeviceManager) hasRoomLocked(u *deviceUser, uid int, ip string, limit int, now time.Time) bool {
	global := m.global[uid]
	if m.globalUpdate.IsZero() || now.Sub(m.globalUpdate) > globalDeviceTTL {
		global = nil
	}
	// The union never counts fewer devices than either side, so an already
	// over-limit local or panel set is refused even for a known IP.
	var s deviceSet
	for ip := range u.ips {
		s.add(ip)
	}
	for ip := range global {
		s.add(ip)
	}
	s.add(ip)
	return s.count() <= limit
}

// UpdateGlobalDevices installs a panel snapshot. It lives in the state shared by
// every scope, so a kernel restart keeps it with its original freshness.
func (m *DeviceManager) UpdateGlobalDevices(users map[int][]string) {
	global := make(map[int]map[string]bool, len(users))
	for uid, ips := range users {
		set := make(map[string]bool, len(ips))
		for _, ip := range ips {
			set[deviceIP(ip)] = true
		}
		global[uid] = set
	}
	m.mu.Lock()
	m.global, m.globalUpdate = global, m.now()
	m.mu.Unlock()
}

func (m *DeviceManager) ClearGlobalDevices() {
	m.mu.Lock()
	m.global, m.globalUpdate = nil, time.Time{}
	m.mu.Unlock()
}

// Snapshot reports online IPs. It runs on every traffic report, so it also
// drops idle users whose cooldown has expired; the shared state outlives
// kernel restarts and would otherwise keep every user that ever connected.
func (m *DeviceManager) Snapshot() (map[int]map[string]bool, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	alive := make(map[int]map[string]bool)
	for uid, u := range m.users {
		if len(u.ips) == 0 {
			if !now.Before(u.banUntil) {
				delete(m.users, uid)
			}
			continue
		}
		ips := make(map[string]bool, len(u.ips))
		for ip := range u.ips {
			ips[ip] = true
		}
		alive[uid] = ips
	}
	return alive, len(m.conns)
}

// ActiveCount returns the number of live leases acquired through this scope.
func (m *DeviceManager) ActiveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.scoped)
}

func (m *DeviceManager) CloseByID(id string) bool {
	m.mu.Lock()
	l := m.conns[id]
	if l == nil {
		m.mu.Unlock()
		return false
	}
	closer := m.releaseLocked(l)
	m.mu.Unlock()
	if closer != nil {
		closer()
	}
	return true
}

// CloseUser closes current sessions without punishing subsequent reconnects.
func (m *DeviceManager) CloseUser(uid int) int {
	m.mu.Lock()
	u := m.users[uid]
	var closers []func()
	n := 0
	if u != nil {
		n = len(u.conns)
		closers = m.closeUserLocked(u)
	}
	m.mu.Unlock()
	closeDevices(closers)
	return n
}

// UpdateUsers publishes the identities accepted by every scope and revokes
// obsolete leases atomically with admission. A newly authenticated UUID must
// not be closed merely because it shares a user ID with the old credential.
func (m *DeviceManager) UpdateUsers(current []model.UserSpec) int {
	uuids := make(map[int]string, len(current))
	for _, u := range current {
		uuids[u.ID] = u.UUID
	}
	closed := 0
	m.mu.Lock()
	m.identities = uuids
	var closers []func()
	for _, l := range m.conns {
		if !m.identityAllowedLocked(l.userID, l.uuid) {
			closed++
			if closer := m.releaseLocked(l); closer != nil {
				closers = append(closers, closer)
			}
		}
	}
	m.mu.Unlock()
	closeDevices(closers)
	return closed
}

func (m *DeviceManager) identityAllowedLocked(uid int, uuid string) bool {
	if m.identities == nil {
		return true
	}
	current, ok := m.identities[uid]
	return ok && current == uuid
}

// CloseAll closes the leases acquired through this scope only.
func (m *DeviceManager) CloseAll() {
	m.mu.Lock()
	closers := make([]func(), 0, len(m.scoped))
	for _, l := range m.scoped {
		if closer := m.releaseLocked(l); closer != nil {
			closers = append(closers, closer)
		}
	}
	m.mu.Unlock()
	closeDevices(closers)
}

func (m *DeviceManager) closeUserLocked(u *deviceUser) []func() {
	closers := make([]func(), 0, len(u.conns))
	for _, l := range u.conns {
		if closer := m.releaseLocked(l); closer != nil {
			closers = append(closers, closer)
		}
	}
	return closers
}

func (m *DeviceManager) releaseLocked(l *DeviceLease) func() {
	if l.closed {
		return nil
	}
	l.closed = true
	u := m.users[l.userID]
	delete(u.conns, l.id)
	delete(m.conns, l.id)
	delete(l.manager.scoped, l.id)
	u.ips[l.ip]--
	if u.ips[l.ip] == 0 {
		delete(u.ips, l.ip)
	}
	return l.closer
}

// Transport closes may call back into Release or hold kernel-specific locks.
// Never execute them under the manager lock or on an admission call stack.
func closeDevices(closers []func()) {
	if len(closers) > 0 {
		go func() {
			for _, close := range closers {
				close()
			}
		}()
	}
}

type DeviceLease struct {
	manager *DeviceManager
	userID  int
	uuid    string
	ip      string
	id      string
	closed  bool
	closer  func()
}

func (l *DeviceLease) ID() string { return l.id }

func (l *DeviceLease) Bind(close func()) bool {
	m := l.manager
	m.mu.Lock()
	if l.closed {
		m.mu.Unlock()
		close()
		return false
	}
	l.closer = close
	m.mu.Unlock()
	return true
}

func (l *DeviceLease) Release() {
	m := l.manager
	m.mu.Lock()
	m.releaseLocked(l)
	m.mu.Unlock()
}

// Rebind rechecks an existing XUDP session against the current user's policy.
// Moving a session releases its old IP reference before reserving the new one.
func (l *DeviceLease) Rebind(uuid, ip string, limit int) error {
	m := l.manager
	ip = deviceIP(ip)
	m.mu.Lock()
	if l.closed {
		m.mu.Unlock()
		return ErrConnectionClosed
	}
	if uuid != l.uuid || !m.identityAllowedLocked(l.userID, uuid) {
		m.mu.Unlock()
		return ErrUserRevoked
	}
	u := m.users[l.userID]
	oldIP := l.ip
	u.ips[oldIP]--
	if u.ips[oldIP] == 0 {
		delete(u.ips, oldIP)
	}
	now := m.now()
	banned := limit > 0 && now.Before(u.banUntil)
	breach := limit > 0 && !banned && !m.hasRoomLocked(u, l.userID, ip, limit, now)
	u.ips[oldIP]++
	if banned || breach {
		var closers []func()
		if breach {
			u.banUntil = now.Add(m.cooldown)
			closers = m.closeUserLocked(u)
		}
		m.mu.Unlock()
		if breach {
			logDeviceKick(l.userID, ip, limit)
		}
		closeDevices(closers)
		return ErrDeviceLimit
	}
	u.ips[oldIP]--
	if u.ips[oldIP] == 0 {
		delete(u.ips, oldIP)
	}
	u.ips[ip]++
	l.ip = ip
	m.mu.Unlock()
	return nil
}
