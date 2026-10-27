package singbox

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	singM "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/time/rate"

	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// userStats contains only traffic counters. Online IPs and connection lifetimes
// are owned by the same DeviceManager used by the Xray adapter.
type userStats struct {
	upload   atomic.Int64
	download atomic.Int64
}

type ConnTracker struct {
	usersMu         sync.RWMutex
	users           map[int]*userStats
	uuidMap         map[string]int
	devices         *limiter.DeviceManager
	speedLimitFunc  atomic.Pointer[func(string) *rate.Limiter]
	deviceLimitFunc atomic.Pointer[func(string) (int, bool)]
}

// NewConnTracker uses devices for admission; nil creates a private manager.
func NewConnTracker(devices *limiter.DeviceManager) *ConnTracker {
	if devices == nil {
		devices = limiter.NewDeviceManager(0)
	}
	return &ConnTracker{
		users: make(map[int]*userStats), uuidMap: make(map[string]int),
		devices: devices,
	}
}

func (t *ConnTracker) SetSpeedLimitFunc(fn func(string) *rate.Limiter) { t.speedLimitFunc.Store(&fn) }
func (t *ConnTracker) SetDeviceLimitFunc(fn func(string) (int, bool))  { t.deviceLimitFunc.Store(&fn) }
func (t *ConnTracker) SetDeviceLimitCooldown(d time.Duration)          { t.devices.SetCooldown(d) }

func (t *ConnTracker) SetUserMap(users map[string]int) {
	t.usersMu.Lock()
	t.uuidMap = users
	for _, uid := range users {
		if t.users[uid] == nil {
			t.users[uid] = &userStats{}
		}
	}
	t.usersMu.Unlock()
}

func (t *ConnTracker) UpdateGlobalDevices(users map[int][]string, receivedAt time.Time) {
	t.devices.UpdateGlobalDevicesAt(users, receivedAt)
}
func (t *ConnTracker) ClearGlobalDevices() { t.devices.ClearGlobalDevices() }

func (t *ConnTracker) admit(uuid, ip string) (*userStats, *limiter.DeviceLease, bool) {
	t.usersMu.RLock()
	uid, known := t.uuidMap[uuid]
	us := t.users[uid]
	t.usersMu.RUnlock()
	if !known {
		return nil, nil, true
	}
	limit := 0
	if fn := t.deviceLimitFunc.Load(); fn != nil && *fn != nil {
		limit, _ = (*fn)(uuid)
	}
	lease, err := t.devices.Acquire(uid, ip, limit)
	if err != nil {
		nlog.Core().Debug("singbox: device admission rejected", "userID", uid)
		return us, nil, false
	}
	return us, lease, true
}

func (t *ConnTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	us, lease, ok := t.admit(metadata.User, metadata.Source.Addr.String())
	if !ok {
		conn.Close()
		return conn
	}
	tc := &trackedConn{Conn: conn, us: us, lease: lease, ctx: ctx}
	if fn := t.speedLimitFunc.Load(); fn != nil && *fn != nil {
		tc.limiter = (*fn)(metadata.User)
	}
	if lease != nil {
		tc.connID = lease.ID()
		if !lease.Bind(func() { tc.Close() }) {
			return conn
		}
	}
	return tc
}

func (t *ConnTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	us, lease, ok := t.admit(metadata.User, metadata.Source.Addr.String())
	if !ok {
		conn.Close()
		return conn
	}
	tc := &trackedPacketConn{PacketConn: conn, us: us, lease: lease, ctx: ctx}
	if fn := t.speedLimitFunc.Load(); fn != nil && *fn != nil {
		tc.limiter = (*fn)(metadata.User)
	}
	if lease != nil {
		tc.connID = lease.ID()
		if !lease.Bind(func() { tc.Close() }) {
			return conn
		}
	}
	return tc
}

// Panel proxy inbounds use the TCP and UDP callbacks, not tun offloaded flows.
func (t *ConnTracker) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}

func (t *ConnTracker) GetUserTraffic() (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int) {
	t.usersMu.RLock()
	traffic = make(map[int][2]int64, len(t.users))
	for uid, us := range t.users {
		up, down := us.upload.Load(), us.download.Load()
		if up > 0 || down > 0 {
			traffic[uid] = [2]int64{up, down}
		}
	}
	t.usersMu.RUnlock()
	aliveIPs, connCount = t.devices.Snapshot()
	return
}

func (t *ConnTracker) CloseByID(id string) bool { return t.devices.CloseByID(id) }
func (t *ConnTracker) CloseByUUID(uuid string) int {
	t.usersMu.RLock()
	uid, known := t.uuidMap[uuid]
	t.usersMu.RUnlock()
	if !known {
		return 0
	}
	return t.devices.CloseUser(uid)
}
func (t *ConnTracker) ActiveCount() int { return t.devices.ActiveCount() }

// closeAll releases this tracker's leases so a stopped instance cannot keep
// occupying IP slots in the admission state it shares with its successor.
func (t *ConnTracker) closeAll() { t.devices.CloseAll() }

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
	lease   *limiter.DeviceLease
	us      *userStats // per-user traffic counters
	connID  string
	limiter *rate.Limiter
	ctx     context.Context
	closed  atomic.Bool
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
		if c.lease != nil {
			c.lease.Release()
		}
		return c.Conn.Close()
	}
	return nil
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
	lease   *limiter.DeviceLease
	us      *userStats
	connID  string
	limiter *rate.Limiter
	ctx     context.Context
	closed  atomic.Bool
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
		if c.lease != nil {
			c.lease.Release()
		}
		return c.PacketConn.Close()
	}
	return nil
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
