package xray

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	_ "unsafe"

	xrayDispatcher "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"

	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// Access xray's internal config creator registry so we can replace the
// default dispatcher factory with ours. This runs AFTER xray's init()
// functions because our package imports xray (dependency order guarantee).
//
//go:linkname typeCreatorRegistry github.com/xtls/xray-core/common.typeCreatorRegistry
var typeCreatorRegistry map[reflect.Type]common.ConfigCreator

var origDispatcherFactory common.ConfigCreator

// globalLimitDispatcher is set when the factory creates a LimitDispatcher.
// The Xray kernel reads it to configure limits and get connections.
var globalLimitDispatcher atomic.Pointer[LimitDispatcher]

func init() {
	configType := reflect.TypeOf((*xrayDispatcher.Config)(nil))
	origDispatcherFactory = typeCreatorRegistry[configType]
	typeCreatorRegistry[configType] = limitDispatcherFactory
}

func limitDispatcherFactory(ctx context.Context, config interface{}) (interface{}, error) {
	orig, err := origDispatcherFactory(ctx, config)
	if err != nil {
		return nil, err
	}
	inner, ok := orig.(routing.Dispatcher)
	if !ok {
		return orig, nil
	}
	ld := &LimitDispatcher{
		inner:     orig,
		innerDisp: inner,
		devices:   limiter.NewDeviceManager(0),
	}
	globalLimitDispatcher.Store(ld)
	nlog.Core().Debug("xray: limit dispatcher installed")
	return ld, nil
}

// LimitDispatcher adapts Xray links to the shared online-IP policy. It never
// wraps link.Reader: Mux/XUDP rely on its concrete pipe reader type.
type LimitDispatcher struct {
	inner           interface{}
	innerDisp       routing.Dispatcher
	mu              sync.RWMutex
	devices         *limiter.DeviceManager
	emailToUID      map[string]int
	deviceLimits    map[string]int
	uuidByUID       map[int]string
	deviceLimitFunc func(string) (int, bool)
}

func (d *LimitDispatcher) identity(ctx context.Context) (uid int, credential, ip string, limit int, err error) {
	si := session.InboundFromContext(ctx)
	if si == nil || si.User == nil || si.User.Email == "" {
		return
	}
	d.mu.RLock()
	uid = d.emailToUID[si.User.Email]
	limit = d.deviceLimits[si.User.Email]
	uuid, fn := d.uuidByUID[uid], d.deviceLimitFunc
	d.mu.RUnlock()
	if uid == 0 || !accountMatchesUUID(si.User.Account, uuid) {
		err = limiter.ErrUserRevoked
		return
	}
	credential = uuid
	if fn != nil && uuid != "" {
		if l, ok := fn(uuid); ok {
			limit = l
		}
	}
	ip = si.Source.Address.IP().String()
	return
}

func (d *LimitDispatcher) acquire(ctx context.Context) (*limiter.DeviceLease, int, error) {
	uid, credential, ip, limit, err := d.identity(ctx)
	if err != nil {
		return nil, uid, err
	}
	if uid == 0 {
		return nil, 0, nil
	}
	lease, err := d.devices.Acquire(uid, credential, ip, limit)
	return lease, uid, err
}

func (d *LimitDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	lease, uid, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	var tracked *trackedSession
	if lease != nil {
		ctx, tracked = newTrackedSession(ctx, lease, false)
	}
	link, err := d.innerDisp.Dispatch(ctx, dest)
	if err != nil {
		if tracked != nil {
			tracked.terminate()
		}
		return nil, err
	}
	if tracked != nil {
		d.trackLink(link, uid, tracked, tracked.uplinkClosed)
	}
	return link, nil
}

func (d *LimitDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	lease, uid, err := d.acquire(ctx)
	if err != nil {
		return err
	}
	var tracked *trackedSession
	if lease != nil {
		// DispatchLink's writer is the downlink. The uplink is a raw reader the
		// outbound consumes, so it counts as finished only when the outbound
		// returns; cancellation also ends raw protocol readers/writers.
		ctx, tracked = newTrackedSession(ctx, lease, true)
		d.trackLink(link, uid, tracked, tracked.DownlinkClosed)
	}
	err = d.innerDisp.DispatchLink(ctx, dest, link)
	if err != nil && tracked != nil {
		tracked.terminate()
	}
	return err
}

func (d *LimitDispatcher) trackLink(link *transport.Link, uid int, tracked *trackedSession, onClose func()) {
	tracked.bind(link)
	link.Writer = &closeTrackingWriter{
		Writer: link.Writer, dispatcher: d, userID: uid, lease: tracked.lease,
		onClose: onClose,
	}
}

// A logical session reserves its IP until both directions finish, or until
// cancellation/force-close. The parent transport can remain open for Mux.
// Its context is cancelled only once the outbound has also returned, so an
// outbound still flushing buffered uplink data is not cut off.
type trackedSession struct {
	mu                                     sync.Mutex
	lease                                  *limiter.DeviceLease
	cancel                                 context.CancelFunc
	direct                                 bool // DispatchLink: uplink ends with the outbound
	uplinkDone, downlinkDone, outboundDone bool
	released, closed                       bool
	reader                                 buf.Reader
	writer                                 buf.Writer
}

var _ routing.OutboundObserver = (*trackedSession)(nil)

func newTrackedSession(ctx context.Context, lease *limiter.DeviceLease, direct bool) (context.Context, *trackedSession) {
	if session.TimeoutOnlyFromContext(ctx) {
		// Persistent XUDP sessions survive detach from their original Mux.
		ctx = context.WithoutCancel(ctx)
	}
	ctx, cancel := context.WithCancel(ctx)
	tracked := &trackedSession{lease: lease, cancel: cancel, direct: direct}
	context.AfterFunc(ctx, tracked.terminate)
	return routing.ContextWithSessionLifecycle(ctx, tracked), tracked
}

func (s *trackedSession) bind(link *transport.Link) {
	s.mu.Lock()
	s.reader, s.writer = link.Reader, link.Writer
	closed := s.closed
	s.mu.Unlock()
	if closed {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
	}
	s.lease.Bind(s.terminate)
}

func (s *trackedSession) uplinkClosed()   { s.settle(func() { s.uplinkDone = true }) }
func (s *trackedSession) DownlinkClosed() { s.settle(func() { s.downlinkDone = true }) }
func (s *trackedSession) OutboundReturned() {
	s.settle(func() {
		s.outboundDone = true
		if s.direct {
			s.uplinkDone = true
		}
	})
}

// settle releases the IP once both directions finished and cancels the
// context once the outbound has returned as well. Graceful completion never
// interrupts the link: its reader must still get buffered downlink data.
func (s *trackedSession) settle(mark func()) {
	s.mu.Lock()
	mark()
	both := s.uplinkDone && s.downlinkDone
	release := both && !s.released
	done := both && s.outboundDone && !s.closed
	s.released = s.released || both
	s.closed = s.closed || done
	s.mu.Unlock()
	if release {
		s.lease.Release()
	}
	if done {
		s.cancel()
	}
}

func (s *trackedSession) terminate() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed, s.released = true, true
	reader, writer := s.reader, s.writer
	s.mu.Unlock()
	s.lease.Release()
	s.cancel()
	common.Interrupt(reader)
	common.Interrupt(writer)
}

// RebindSession is called by Xray-core before reusing an XUDP link. A link
// belongs to one dispatcher and user, and its source IP is re-admitted before
// any packet is written through the reused session. A link this dispatcher
// does not track (e.g. from the instance before a hot reload) is reported as
// not owned, so Xray-core dispatches it anew instead of dropping the Mux.
func (d *LimitDispatcher) RebindSession(ctx context.Context, link *transport.Link) error {
	writer, ok := link.Writer.(*closeTrackingWriter)
	if ok && writer.dispatcher != d {
		return routing.ErrSessionNotOwned
	}
	uid, credential, ip, limit, err := d.identity(ctx)
	if err != nil {
		return err
	}
	if !ok && uid == 0 {
		return nil // neither session is subject to admission
	}
	if !ok || writer.dispatcher != d {
		return routing.ErrSessionNotOwned
	}
	if uid == 0 || writer.userID != uid {
		return errors.New("XUDP session user mismatch")
	}
	if err := writer.lease.Rebind(credential, ip, limit); err != nil {
		if errors.Is(err, limiter.ErrConnectionClosed) {
			// The session already ended (kick, close or expiry) while Xray-core
			// still caches it. Dispatching anew goes through admission again
			// and, unlike a hard error here, keeps the client's Mux alive.
			return routing.ErrSessionNotOwned
		}
		return fmt.Errorf("XUDP admission: %w", err)
	}
	return nil
}

func (d *LimitDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *LimitDispatcher) Start() error {
	if s, ok := d.inner.(interface{ Start() error }); ok {
		return s.Start()
	}
	return nil
}
func (d *LimitDispatcher) Close() error {
	d.ResetConns()
	if c, ok := d.inner.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

func (d *LimitDispatcher) UpdateLimits(emailToUID map[string]int, deviceLimits, _ map[string]int) {
	d.mu.Lock()
	d.emailToUID, d.deviceLimits = emailToUID, deviceLimits
	d.mu.Unlock()
}

func (d *LimitDispatcher) SetDeviceLimitFunc(fn func(string) (int, bool), uuids map[int]string) {
	d.mu.Lock()
	d.deviceLimitFunc, d.uuidByUID = fn, uuids
	d.mu.Unlock()
}

func (d *LimitDispatcher) ResetConns() { d.devices.CloseAll() }
func (d *LimitDispatcher) GetConnectionState() (map[int]map[string]bool, int) {
	return d.devices.Snapshot()
}

type closeTrackingWriter struct {
	buf.Writer
	dispatcher *LimitDispatcher
	userID     int
	lease      *limiter.DeviceLease
	onClose    func()
	closed     atomic.Bool
}

func (w *closeTrackingWriter) Close() error {
	if w.closed.CompareAndSwap(false, true) {
		w.onClose()
		return common.Close(w.Writer)
	}
	return nil
}
func (w *closeTrackingWriter) Interrupt() {
	if w.closed.CompareAndSwap(false, true) {
		w.onClose()
		common.Interrupt(w.Writer)
	}
}
