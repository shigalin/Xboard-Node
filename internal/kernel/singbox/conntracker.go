package singbox

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	singM "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/time/rate"

	"github.com/cedar2025/xboard-node/internal/nlog"
)

// ipPool caches ipSnapshot maps to reduce allocations.
var ipPool = sync.Pool{
	New: func() interface{} {
		return make(map[string]struct{}, 16)
	},
}

// ─── Per-user statistics ────────────────────────────────────────────────────

// userStats holds per-user traffic counters and alive IP tracking.
// Traffic counters are lock-free atomics (read on every packet).
// IP tracking uses a lightweight mutex (only touched at connect/disconnect).
type userStats struct {
	upload   atomic.Int64
	download atomic.Int64

	mu        sync.RWMutex   // RWMutex for concurrent reads
	ips       map[string]int // sourceIP → refcount (number of active conns from that IP)
	connCount int            // total active connections

	// Sweep invariant: bump kickEpoch before adding an unserved request to
	// sweepReq; kicking permits one worker, which runs until sweepReq is zero.
	kicking  atomic.Bool
	sweepReq atomic.Int64

	// banUntil is the UnixNano deadline of the device-limit punishment window.
	// While it is in the future every connection of this user is refused.
	banUntil atomic.Int64

	// kickEpoch increments at the start of every per-user connection sweep.
	// Admission records the epoch before counting the connection and re-checks
	// it after registering in connMap: a change means a sweep snapshot may have
	// missed this connection, so it must close itself.
	kickEpoch atomic.Uint64
}

// addConn registers a new connection from sourceIP.
func (u *userStats) addConn(sourceIP string) {
	u.mu.Lock()
	u.connCount++
	u.ips[sourceIP]++
	u.mu.Unlock()
}

// removeConn unregisters a connection from sourceIP.
func (u *userStats) removeConn(sourceIP string) {
	u.mu.Lock()
	u.connCount--
	u.ips[sourceIP]--
	if u.ips[sourceIP] <= 0 {
		delete(u.ips, sourceIP)
	}
	u.mu.Unlock()
}

// distinctIPs returns the number of distinct IPs currently connected.
func (u *userStats) distinctIPs() int {
	u.mu.Lock()
	n := len(u.ips)
	u.mu.Unlock()
	return n
}

// ipSnapshot returns a pooled copy of the current IP set.
func (u *userStats) ipSnapshot() map[string]struct{} {
	cp := ipPool.Get().(map[string]struct{})
	for k := range cp {
		delete(cp, k)
	}
	u.mu.Lock()
	for ip := range u.ips {
		cp[ip] = struct{}{}
	}
	u.mu.Unlock()
	return cp
}

// releaseIPSnapshot returns the snapshot to pool.
// Large maps are discarded to prevent memory bloat.
func releaseIPSnapshot(m map[string]struct{}) {
	// Discard large maps to prevent pool memory bloat
	if len(m) > 64 {
		return
	}
	ipPool.Put(m)
}

// aliveIPList returns the set of alive IPs as a boolean map (for reporting).
func (u *userStats) aliveIPList() map[string]bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.ips) == 0 {
		return nil
	}
	result := make(map[string]bool, len(u.ips))
	for ip := range u.ips {
		result[ip] = true
	}
	return result
}

// connRef is a force-closable handle to a tracked connection (TCP or UDP),
// tagged with the owning user so all of a user's connections can be closed
// at once.
type connRef struct {
	userID int
	epoch  uint64 // kick epoch observed at admission; sweeps skip conns admitted after their kick
	closer io.Closer
}

// ─── ConnTracker ────────────────────────────────────────────────────────────

// ConnTracker provides per-user traffic counting, alive IP tracking, device
// limit gate-keeping, and per-user speed limiting for the sing-box kernel.
//
// Architecture: instead of maintaining a per-connection map (O(connections)),
// it maintains per-user atomic counters and IP refcount sets (O(users)).
// This means:
//   - GetUserTraffic is O(users), not O(connections)
//   - No Snapshot/pending buffer needed
//   - No per-connection map lock contention
//   - Bytes are counted directly into per-user atomics via CountFunc callbacks
//
// The per-connection wrapper (trackedConn) is still needed for:
//   - Hooking into sing's ReadCounter/WriteCounter for zero-copy byte counting
//   - Close callback to decrement IP refcounts
//   - Per-connection rate limit token accumulation (amortized WaitN)
type ConnTracker struct {
	usersMu sync.RWMutex
	users   map[int]*userStats // userID → stats
	uuidMap map[string]int     // UUID → userID (for lookup in RoutedConnection)
	connMap map[string]connRef // connID → conn ref (for force-close support)

	idCounter atomic.Int64

	// speedLimitFunc resolves a user UUID to a *rate.Limiter.
	speedLimitFunc atomic.Pointer[func(uuid string) *rate.Limiter]

	// deviceLimitFunc resolves a user UUID to their device limit.
	deviceLimitFunc atomic.Pointer[func(uuid string) (int, bool)]

	// deviceLimitCooldown is the punishment window (nanoseconds) applied after
	// a device-limit breach. 0 disables it.
	deviceLimitCooldown atomic.Int64

	// Multi-node device state from panel
	globalDevices    map[int]map[string]bool // userID → IP → exists
	globalMu         sync.RWMutex
	globalLastUpdate time.Time
}

// NewConnTracker creates a tracker.
func NewConnTracker(_ int) *ConnTracker {
	return &ConnTracker{
		users:         make(map[int]*userStats),
		uuidMap:       make(map[string]int),
		connMap:       make(map[string]connRef),
		globalDevices: make(map[int]map[string]bool),
	}
}

// SetSpeedLimitFunc configures the per-user speed limit lookup.
func (t *ConnTracker) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) {
	t.speedLimitFunc.Store(&fn)
}

// SetDeviceLimitFunc configures the per-user device limit lookup for gate-keeping.
func (t *ConnTracker) SetDeviceLimitFunc(fn func(uuid string) (int, bool)) {
	t.deviceLimitFunc.Store(&fn)
}

// SetDeviceLimitCooldown sets the punishment window applied after a device
// limit breach. A non-positive duration disables the window (kick only).
func (t *ConnTracker) SetDeviceLimitCooldown(d time.Duration) {
	if d < 0 {
		d = 0
	}
	t.deviceLimitCooldown.Store(int64(d))
}

// SetUserMap replaces the UUID→userID mapping and ensures per-user stats
// structs exist for all users. Old users that are no longer present keep
// their stats until their connections drain.
func (t *ConnTracker) SetUserMap(m map[string]int) {
	t.usersMu.Lock()
	t.uuidMap = m
	for _, uid := range m {
		if _, ok := t.users[uid]; !ok {
			t.users[uid] = &userStats{ips: make(map[string]int)}
		}
	}
	t.usersMu.Unlock()
}

// UpdateGlobalDevices syncs global device state from panel.
func (t *ConnTracker) UpdateGlobalDevices(users map[int][]string) {
	t.globalMu.Lock()
	t.globalDevices = make(map[int]map[string]bool, len(users))
	for uid, ips := range users {
		m := make(map[string]bool, len(ips))
		for _, ip := range ips {
			m[ip] = true
		}
		t.globalDevices[uid] = m
	}
	t.globalLastUpdate = time.Now()
	t.globalMu.Unlock()
	nlog.Core().Debug("global device state updated", "users", len(users))
}

// ClearGlobalDevices resets global device state (on WS disconnect).
func (t *ConnTracker) ClearGlobalDevices() {
	t.globalMu.Lock()
	t.globalDevices = make(map[int]map[string]bool)
	t.globalLastUpdate = time.Time{}
	t.globalMu.Unlock()
	nlog.Core().Debug("global device state cleared")
}

// ─── adapter.ConnectionTracker ──────────────────────────────────────────────

// RoutedConnection wraps a TCP conn to count bytes per-user, track IPs,
// and optionally rate-limit. Gate-keeps device limits at connection time.
func (t *ConnTracker) RoutedConnection(
	ctx context.Context, conn net.Conn,
	metadata adapter.InboundContext,
	_ adapter.Rule, _ adapter.Outbound,
) net.Conn {
	uuid := metadata.User
	sourceIP := metadata.Source.Addr.String()

	uid, us, epoch, ok := t.admitConn(uuid, sourceIP, "tcp")
	if !ok {
		conn.Close()
		return conn
	}

	connID := t.nextID()

	var lim *rate.Limiter
	if slf := t.speedLimitFunc.Load(); slf != nil {
		lim = (*slf)(uuid)
	}

	tc := &trackedConn{
		Conn:     conn,
		tracker:  t,
		us:       us,
		userID:   uid,
		connID:   connID,
		sourceIP: sourceIP,
		limiter:  lim,
		ctx:      ctx,
	}

	// Store the wrapper (not the raw conn) so a force-close also runs the
	// IP refcount bookkeeping in trackedConn.Close. If a sweep started while
	// we were between admission and registration, close ourselves — the sweep
	// snapshot may not have seen this connection.
	if !t.registerConn(us, uid, epoch, connID, tc) {
		tc.Close()
		return conn
	}

	return tc
}

// RoutedPacketConnection wraps UDP with per-user counting. Like TCP, the
// wrapper is registered in connMap so it can be force-closed by ID or as part
// of a per-user kick.
func (t *ConnTracker) RoutedPacketConnection(
	ctx context.Context, conn N.PacketConn,
	metadata adapter.InboundContext,
	_ adapter.Rule, _ adapter.Outbound,
) N.PacketConn {
	uuid := metadata.User
	sourceIP := metadata.Source.Addr.String()

	uid, us, epoch, ok := t.admitConn(uuid, sourceIP, "udp")
	if !ok {
		conn.Close()
		return conn
	}

	connID := t.nextID()

	var lim *rate.Limiter
	if slf := t.speedLimitFunc.Load(); slf != nil {
		lim = (*slf)(uuid)
	}

	tpc := &trackedPacketConn{
		PacketConn: conn,
		tracker:    t,
		us:         us,
		userID:     uid,
		connID:     connID,
		sourceIP:   sourceIP,
		limiter:    lim,
		ctx:        ctx,
	}

	if !t.registerConn(us, uid, epoch, connID, tpc) {
		tpc.Close()
		return conn
	}

	return tpc
}

// admitConn is the single admission path shared by the TCP and UDP trackers.
// It resolves the user, atomically performs the device-limit check together
// with the IP/conn accounting, and returns the kick epoch observed BEFORE the
// connection was counted (see registerConn). ok=false means the connection was
// refused; the breach kick (if any) has already been triggered.
func (t *ConnTracker) admitConn(uuid, sourceIP, network string) (uid int, us *userStats, epoch uint64, ok bool) {
	t.usersMu.RLock()
	uid = t.uuidMap[uuid]
	us = t.users[uid]
	t.usersMu.RUnlock()

	if us != nil {
		epoch = us.kickEpoch.Load()
	}

	var limit int
	if dlf := t.deviceLimitFunc.Load(); dlf != nil {
		if l, hasLimit := (*dlf)(uuid); hasLimit {
			limit = l
		}
	}

	if us == nil || limit <= 0 {
		// No stats to enforce against, or no device limit — count and admit.
		if us != nil {
			us.addConn(sourceIP)
		}
		return uid, us, epoch, true
	}

	// Punishment window: refuse everything, including IPs that previously
	// held a slot, until it expires.
	if until := us.banUntil.Load(); until > 0 {
		if time.Now().UnixNano() < until {
			return uid, us, epoch, false
		}
		us.banUntil.CompareAndSwap(until, 0)
	}

	if !t.admitDevice(us, uid, sourceIP, limit) {
		nlog.Core().Info("singbox: device limit exceeded, kicking user and rejecting connection",
			"user", uuid, "ip", sourceIP, "network", network, "limit", limit)
		t.kickUser(us, uid)
		return uid, us, epoch, false
	}
	return uid, us, epoch, true
}

// admitDevice atomically checks the device (distinct source IP) limit and, on
// success, records the connection (IP refcount + conn count) in the SAME
// critical section — so two IPs racing for the last slot can never both win.
//
// Policy: strict. An IP already holding a slot (locally, or globally on
// another node while the panel state is fresh) is always allowed. A new IP is
// admitted only while the merged IP set is strictly below the limit; the set
// can therefore never exceed the limit.
func (t *ConnTracker) admitDevice(us *userStats, userID int, sourceIP string, limit int) bool {
	// Snapshot global (multi-node) state first to keep lock scopes disjoint.
	t.globalMu.RLock()
	globalStale := time.Since(t.globalLastUpdate) > 60*time.Second
	globalIPs := t.globalDevices[userID]
	t.globalMu.RUnlock()
	globalFresh := !globalStale && globalIPs != nil

	us.mu.Lock()
	defer us.mu.Unlock()

	admitted := false
	if _, known := us.ips[sourceIP]; known {
		// Already holds a local slot.
		admitted = true
	} else if globalFresh && globalIPs[sourceIP] {
		// Already holds a slot in the global set (established on another node).
		admitted = true
	} else {
		total := len(us.ips)
		if globalFresh {
			for ip := range globalIPs {
				if _, dup := us.ips[ip]; !dup {
					total++
				}
			}
		}
		admitted = total < limit
	}

	if admitted {
		us.connCount++
		us.ips[sourceIP]++
	}
	return admitted
}

// registerConn stores the closable wrapper in connMap, then verifies no
// per-user sweep started since `epoch` was read (before the connection was
// counted). Returns false if the connection must close itself because a
// concurrent sweep's snapshot may have missed it; the caller closes the
// wrapper, which unwinds the accounting done by admitConn.
func (t *ConnTracker) registerConn(us *userStats, userID int, epoch uint64, connID string, closer io.Closer) bool {
	t.usersMu.Lock()
	t.connMap[connID] = connRef{userID: userID, epoch: epoch, closer: closer}
	t.usersMu.Unlock()

	if us != nil && us.kickEpoch.Load() != epoch {
		return false
	}
	return true
}

// kickUser applies the device-limit punishment: arms the cooldown window (if
// configured) and force-closes every tracked connection of the user.
func (t *ConnTracker) kickUser(us *userStats, userID int) {
	cooldown := time.Duration(t.deviceLimitCooldown.Load())
	if us != nil && cooldown > 0 {
		us.banUntil.Store(time.Now().Add(cooldown).UnixNano())
	}
	t.closeUserConns(us, userID)
}

// closeUserConns asynchronously schedules all tracked connections belonging to
// userID for closing.
func (t *ConnTracker) closeUserConns(us *userStats, userID int) {
	if us == nil {
		go t.sweepUserConns(userID, ^uint64(0))
		return
	}

	us.kickEpoch.Add(1)
	us.sweepReq.Add(1)
	if !us.kicking.CompareAndSwap(false, true) {
		return
	}

	go func() {
		for {
			pending := us.sweepReq.Load()
			// Cutoff loaded after pending: every counted request bumped the
			// epoch first, so this cutoff covers all of them, while conns
			// admitted after the latest bump keep their new epoch and survive.
			t.sweepUserConns(userID, us.kickEpoch.Load())
			us.sweepReq.Add(-pending)

			us.kicking.Store(false)
			if us.sweepReq.Load() == 0 {
				return
			}
			if !us.kicking.CompareAndSwap(false, true) {
				return
			}
		}
	}()
}

// sweepUserConns snapshots connMap and closes every connection of userID that
// was admitted before cutoff. A connection whose epoch is >= cutoff was
// admitted after the kick being served and must survive (e.g. an immediate
// reconnect after CloseByUUID or a cooldown-disabled kick).
func (t *ConnTracker) sweepUserConns(userID int, cutoff uint64) {
	t.usersMu.RLock()
	victims := make([]io.Closer, 0, len(t.connMap))
	for _, ref := range t.connMap {
		if ref.userID == userID && ref.epoch < cutoff && ref.closer != nil {
			victims = append(victims, ref.closer)
		}
	}
	t.usersMu.RUnlock()

	for _, c := range victims {
		_ = c.Close()
	}
	nlog.Core().Info("user connection sweep done", "userID", userID, "closed", len(victims))
}

func (t *ConnTracker) nextID() string {
	return "sb-" + formatInt36(t.idCounter.Add(1))
}

func formatInt36(n int64) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "0"
	}
	var buf [13]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%36]
		n /= 36
	}
	return string(buf[i:])
}

// ─── Public API ─────────────────────────────────────────────────────────────

// GetUserTraffic returns per-user cumulative traffic and alive IPs.
// This is O(users), not O(connections).
func (t *ConnTracker) GetUserTraffic() (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int) {
	t.usersMu.RLock()
	traffic = make(map[int][2]int64, len(t.users))
	aliveIPs = make(map[int]map[string]bool, len(t.users))
	for uid, us := range t.users {
		up := us.upload.Load()
		down := us.download.Load()
		if up > 0 || down > 0 {
			traffic[uid] = [2]int64{up, down}
		}

		ips := us.aliveIPList()
		if ips != nil {
			aliveIPs[uid] = ips
		}

		us.mu.Lock()
		connCount += us.connCount
		us.mu.Unlock()
	}
	t.usersMu.RUnlock()
	return
}

// CloseByID force-closes a connection by its ID.
func (t *ConnTracker) CloseByID(id string) bool {
	t.usersMu.RLock()
	ref, ok := t.connMap[id]
	t.usersMu.RUnlock()
	if !ok {
		return false
	}
	if ref.closer != nil {
		_ = ref.closer.Close()
	}
	return true
}

// CloseByUUID force-closes ALL connections for a given user UUID.
// Returns the number of connections scheduled for closing. Unlike a
// device-limit kick, this does NOT arm the cooldown window — the user may
// reconnect immediately.
func (t *ConnTracker) CloseByUUID(uuid string) int {
	t.usersMu.RLock()
	uid, ok := t.uuidMap[uuid]
	us := t.users[uid]
	n := 0
	for _, ref := range t.connMap {
		if ref.userID == uid {
			n++
		}
	}
	t.usersMu.RUnlock()
	if !ok {
		return 0
	}
	// Sweep even when the snapshot count is 0: a connection may have passed
	// admission but not yet registered in connMap. The sweep bumps the kick
	// epoch, which forces such a connection to close itself in registerConn.
	t.closeUserConns(us, uid)
	return n
}

// ActiveCount returns the total number of active connections.
func (t *ConnTracker) ActiveCount() int {
	t.usersMu.RLock()
	total := 0
	for _, us := range t.users {
		us.mu.Lock()
		total += us.connCount
		us.mu.Unlock()
	}
	t.usersMu.RUnlock()
	return total
}

// removeConnRef removes the connection reference from connMap on close.
func (t *ConnTracker) removeConnRef(connID string) {
	t.usersMu.Lock()
	delete(t.connMap, connID)
	t.usersMu.Unlock()
}

// ─── trackedConn (TCP) ──────────────────────────────────────────────────────

// RateLimitedWriter wraps a Writer with non-blocking rate limiting.
// Uses AllowN for instant checks and context-aware waiting when needed.
type RateLimitedWriter struct {
	writer  io.Writer
	limiter *rate.Limiter
	ctx     context.Context
}

// Write implements io.Writer with rate limiting.
func (w *RateLimitedWriter) Write(b []byte) (int, error) {
	// Truncate to burst size
	if burst := w.limiter.Burst(); len(b) > burst {
		b = b[:burst]
	}

	// Fast path: check if tokens available (non-blocking)
	if w.limiter.AllowN(time.Now(), len(b)) {
		return w.writer.Write(b)
	}

	// Slow path: wait for tokens with context cancellation support
	resv := w.limiter.ReserveN(time.Now(), len(b))
	if delay := resv.Delay(); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			// Tokens available, proceed
		case <-w.ctx.Done():
			resv.Cancel()
			return 0, w.ctx.Err()
		}
	}

	return w.writer.Write(b)
}

// RateLimitedReadCloser wraps a Reader with non-blocking rate limiting.
type RateLimitedReadCloser struct {
	reader  io.Reader
	limiter *rate.Limiter
	ctx     context.Context
}

// Read implements io.Reader with rate limiting.
func (r *RateLimitedReadCloser) Read(b []byte) (int, error) {
	// Truncate to burst size
	if burst := r.limiter.Burst(); len(b) > burst {
		b = b[:burst]
	}

	n, err := r.reader.Read(b)
	if n > 0 && r.limiter != nil {
		// Fast path: check if tokens available
		if !r.limiter.AllowN(time.Now(), n) {
			// Slow path: wait with context cancellation
			resv := r.limiter.ReserveN(time.Now(), n)
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-r.ctx.Done():
					resv.Cancel()
					return n, r.ctx.Err()
				}
			}
		}
	}
	return n, err
}

type trackedConn struct {
	net.Conn
	tracker  *ConnTracker
	us       *userStats // per-user stats (upload/download atomics + IP tracking)
	userID   int        // user ID for device tracking
	connID   string
	sourceIP string
	limiter  *rate.Limiter
	ctx      context.Context
	closed   atomic.Bool
}

func (c *trackedConn) Read(b []byte) (int, error) {
	if c.limiter != nil {
		if burst := c.limiter.Burst(); len(b) > burst {
			b = b[:burst]
		}
	}
	n, err := c.Conn.Read(b)
	if n > 0 {
		if c.us != nil {
			c.us.upload.Add(int64(n)) // 从入站读取 = 用户上传
		}
		if c.limiter != nil {
			// Non-blocking rate limiting
			if !c.limiter.AllowN(time.Now(), n) {
				resv := c.limiter.ReserveN(time.Now(), n)
				if delay := resv.Delay(); delay > 0 {
					timer := time.NewTimer(delay)
					defer timer.Stop()
					select {
					case <-timer.C:
						// Tokens available
					case <-c.ctx.Done():
						resv.Cancel()
						return n, c.ctx.Err()
					}
				}
			}
		}
	}
	return n, err
}

func (c *trackedConn) Write(b []byte) (int, error) {
	// Apply rate limiting before write
	if c.limiter != nil {
		if burst := c.limiter.Burst(); len(b) > burst {
			b = b[:burst]
		}
		// Non-blocking check first
		if !c.limiter.AllowN(time.Now(), len(b)) {
			resv := c.limiter.ReserveN(time.Now(), len(b))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
					return 0, c.ctx.Err()
				}
			}
		}
	}

	n, err := c.Conn.Write(b)
	if n > 0 && c.us != nil {
		c.us.download.Add(int64(n)) // 向入站写入 = 用户下载
	}
	return n, err
}

func (c *trackedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		if c.us != nil {
			c.us.removeConn(c.sourceIP)
		}
		c.tracker.removeConnRef(c.connID)
	}
	return c.Conn.Close()
}

// makeCountFunc builds a CountFunc for zero-copy byte counting via sing's
// ReadCounter/WriteCounter unwrap interfaces.
func (c *trackedConn) makeCountFunc(counter *atomic.Int64) N.CountFunc {
	if c.limiter == nil {
		return func(n int64) { counter.Add(n) }
	}
	return func(n int64) {
		counter.Add(n)
		// Non-blocking rate limiting with context cancellation
		if !c.limiter.AllowN(time.Now(), int(n)) {
			resv := c.limiter.ReserveN(time.Now(), int(n))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
				}
			}
		}
	}
}

func (c *trackedConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	if c.us == nil {
		return c.Conn, nil
	}
	return c.Conn, []N.CountFunc{c.makeCountFunc(&c.us.upload)} // 从入站读取 = 用户上传
}

func (c *trackedConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	if c.us == nil {
		return c.Conn, nil
	}
	return c.Conn, []N.CountFunc{c.makeCountFunc(&c.us.download)} // 向入站写入 = 用户下载
}

func (c *trackedConn) Upstream() any           { return c.Conn }
func (c *trackedConn) ReaderReplaceable() bool { return true }
func (c *trackedConn) WriterReplaceable() bool { return true }

// ─── trackedPacketConn (UDP / QUIC) ─────────────────────────────────────────

type trackedPacketConn struct {
	N.PacketConn
	tracker  *ConnTracker
	us       *userStats
	userID   int
	connID   string
	sourceIP string
	limiter  *rate.Limiter
	ctx      context.Context
	closed   atomic.Bool
}

func (c *trackedPacketConn) ReadPacket(buffer *buf.Buffer) (singM.Socksaddr, error) {
	dest, err := c.PacketConn.ReadPacket(buffer)
	if err == nil {
		n := int64(buffer.Len())
		if c.us != nil {
			c.us.upload.Add(n) // 从入站读取 = 用户上传
		}
		if c.limiter != nil {
			// Non-blocking rate limiting with context cancellation
			if !c.limiter.AllowN(time.Now(), int(n)) {
				resv := c.limiter.ReserveN(time.Now(), int(n))
				if delay := resv.Delay(); delay > 0 {
					timer := time.NewTimer(delay)
					defer timer.Stop()
					select {
					case <-timer.C:
						// Tokens available
					case <-c.ctx.Done():
						resv.Cancel()
						return dest, c.ctx.Err()
					}
				}
			}
		}
	}
	return dest, err
}

func (c *trackedPacketConn) WritePacket(buffer *buf.Buffer, dest singM.Socksaddr) error {
	n := int64(buffer.Len())

	// Apply rate limiting before write
	if c.limiter != nil {
		if !c.limiter.AllowN(time.Now(), int(n)) {
			resv := c.limiter.ReserveN(time.Now(), int(n))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
					return c.ctx.Err()
				}
			}
		}
	}

	err := c.PacketConn.WritePacket(buffer, dest)
	if err == nil && c.us != nil {
		c.us.download.Add(n) // 向入站写入 = 用户下载
	}
	return err
}

func (c *trackedPacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		if c.us != nil {
			c.us.removeConn(c.sourceIP)
		}
		c.tracker.removeConnRef(c.connID)
	}
	return c.PacketConn.Close()
}

func (c *trackedPacketConn) makeCountFunc(counter *atomic.Int64) N.CountFunc {
	if c.limiter == nil {
		return func(n int64) { counter.Add(n) }
	}
	return func(n int64) {
		counter.Add(n)
		// Non-blocking rate limiting with context cancellation
		if !c.limiter.AllowN(time.Now(), int(n)) {
			resv := c.limiter.ReserveN(time.Now(), int(n))
			if delay := resv.Delay(); delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					// Tokens available
				case <-c.ctx.Done():
					resv.Cancel()
				}
			}
		}
	}
}

func (c *trackedPacketConn) UnwrapPacketReader() (N.PacketReader, []N.CountFunc) {
	if c.us == nil {
		return c.PacketConn, nil
	}
	return c.PacketConn, []N.CountFunc{c.makeCountFunc(&c.us.download)}
}

func (c *trackedPacketConn) UnwrapPacketWriter() (N.PacketWriter, []N.CountFunc) {
	if c.us == nil {
		return c.PacketConn, nil
	}
	return c.PacketConn, []N.CountFunc{c.makeCountFunc(&c.us.upload)}
}

func (c *trackedPacketConn) Upstream() any           { return c.PacketConn }
func (c *trackedPacketConn) ReaderReplaceable() bool { return true }
func (c *trackedPacketConn) WriterReplaceable() bool { return true }
