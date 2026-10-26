package limiter

import (
	"errors"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

const DefaultDeviceLimitCooldown = 60 * time.Second
const globalDeviceTTL = 300 * time.Second

var ErrDeviceLimit = errors.New("device limit exceeded")
var ErrConnectionClosed = errors.New("connection already closed")

type deviceUser struct {
	ips      map[string]int
	conns    map[string]*DeviceLease
	banUntil time.Time
}

// DeviceManager owns online IP admission and connection lifetimes for one node
// instance. Both kernels use it; transport and traffic accounting stay outside.
type DeviceManager struct {
	mu           sync.Mutex
	users        map[int]*deviceUser
	conns        map[string]*DeviceLease
	global       map[int]map[string]bool
	globalUpdate time.Time
	cooldown     time.Duration
	nextID       uint64
	now          func() time.Time
}

func NewDeviceManager(cooldown time.Duration) *DeviceManager {
	if cooldown <= 0 {
		cooldown = DefaultDeviceLimitCooldown
	}
	return &DeviceManager{
		users: make(map[int]*deviceUser), conns: make(map[string]*DeviceLease),
		global: make(map[int]map[string]bool), cooldown: cooldown, now: time.Now,
	}
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

// Acquire checks and reserves a slot atomically, including for UDP. Bind must
// attach the transport closer afterwards. A kick between Acquire and Bind
// revokes the reservation, and Bind immediately closes the late transport.
func (m *DeviceManager) Acquire(userID int, ip string, limit int) (*DeviceLease, error) {
	ip = deviceIP(ip)
	m.mu.Lock()
	u := m.users[userID]
	if u == nil {
		u = &deviceUser{ips: make(map[string]int), conns: make(map[string]*DeviceLease)}
		m.users[userID] = u
	}
	closers, err := m.checkLocked(u, userID, ip, limit)
	if err != nil {
		m.mu.Unlock()
		closeDevices(closers)
		return nil, err
	}
	m.nextID++
	l := &DeviceLease{manager: m, userID: userID, ip: ip, id: strconv.FormatUint(m.nextID, 36)}
	u.ips[ip]++
	u.conns[l.id] = l
	m.conns[l.id] = l
	m.mu.Unlock()
	return l, nil
}

// checkLocked punishes a new session that exceeds the shared IP-set policy.
func (m *DeviceManager) checkLocked(u *deviceUser, uid int, ip string, limit int) ([]func(), error) {
	if limit <= 0 {
		return nil, nil
	}
	now := m.now()
	if now.Before(u.banUntil) {
		return nil, ErrDeviceLimit
	}
	if m.hasRoomLocked(u, uid, ip, limit, now) {
		return nil, nil
	}
	u.banUntil = now.Add(m.cooldown)
	return m.closeUserLocked(u), ErrDeviceLimit
}

func (m *DeviceManager) hasRoomLocked(u *deviceUser, uid int, ip string, limit int, now time.Time) bool {
	global := m.global[uid]
	if m.globalUpdate.IsZero() || now.Sub(m.globalUpdate) > globalDeviceTTL {
		global = nil
	}
	need := 0
	if u.ips[ip] == 0 && !global[ip] {
		need = 1
	}
	if len(u.ips) > limit || len(global) > limit {
		return false
	}
	if len(u.ips)+len(global)+need <= limit {
		return true
	}
	total := len(u.ips)
	for ip := range global {
		if u.ips[ip] == 0 {
			total++
		}
	}
	return total+need <= limit
}

func (m *DeviceManager) UpdateGlobalDevices(users map[int][]string) {
	m.UpdateGlobalDevicesAt(users, m.now())
}

// UpdateGlobalDevicesAt installs a panel snapshot received at `at`. Replaying a
// cached snapshot into a new manager must keep its original freshness window.
func (m *DeviceManager) UpdateGlobalDevicesAt(users map[int][]string, at time.Time) {
	global := make(map[int]map[string]bool, len(users))
	for uid, ips := range users {
		set := make(map[string]bool, len(ips))
		for _, ip := range ips {
			set[deviceIP(ip)] = true
		}
		global[uid] = set
	}
	m.mu.Lock()
	m.global, m.globalUpdate = global, at
	m.mu.Unlock()
}

func (m *DeviceManager) ClearGlobalDevices() {
	m.mu.Lock()
	m.global, m.globalUpdate = nil, time.Time{}
	m.mu.Unlock()
}

func (m *DeviceManager) Snapshot() (map[int]map[string]bool, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	alive := make(map[int]map[string]bool)
	for uid, u := range m.users {
		if len(u.ips) == 0 {
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

func (m *DeviceManager) ActiveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.conns)
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

func (m *DeviceManager) CloseAll() {
	m.mu.Lock()
	var closers []func()
	for _, u := range m.users {
		closers = append(closers, m.closeUserLocked(u)...)
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
func (l *DeviceLease) Rebind(ip string, limit int) error {
	m := l.manager
	ip = deviceIP(ip)
	m.mu.Lock()
	if l.closed {
		m.mu.Unlock()
		return ErrConnectionClosed
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
