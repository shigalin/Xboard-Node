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

func (d *LimitDispatcher) identity(ctx context.Context) (uid int, ip string, limit int) {
	si := session.InboundFromContext(ctx)
	if si == nil || si.User == nil || si.User.Email == "" {
		return
	}
	d.mu.RLock()
	uid = d.emailToUID[si.User.Email]
	limit = d.deviceLimits[si.User.Email]
	uuid, fn := d.uuidByUID[uid], d.deviceLimitFunc
	d.mu.RUnlock()
	if fn != nil && uuid != "" {
		limit, _ = fn(uuid)
	}
	ip = si.Source.Address.IP().String()
	return
}

func (d *LimitDispatcher) acquire(ctx context.Context) (*limiter.DeviceLease, int, error) {
	uid, ip, limit := d.identity(ctx)
	if uid == 0 {
		return nil, 0, nil
	}
	lease, err := d.devices.Acquire(uid, ip, limit)
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
		// DispatchLink's writer is the downlink. The core closes it after
		// processing; cancellation also ends raw protocol readers/writers.
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
type trackedSession struct {
	mu                               sync.Mutex
	lease                            *limiter.DeviceLease
	cancel                           context.CancelFunc
	uplinkDone, downlinkDone, closed bool
	reader                           buf.Reader
	writer                           buf.Writer
}

func newTrackedSession(ctx context.Context, lease *limiter.DeviceLease, direct bool) (context.Context, *trackedSession) {
	if session.TimeoutOnlyFromContext(ctx) {
		// Persistent XUDP sessions survive detach from their original Mux.
		ctx = context.WithoutCancel(ctx)
	}
	ctx, cancel := context.WithCancel(ctx)
	tracked := &trackedSession{lease: lease, cancel: cancel, uplinkDone: direct}
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

func (s *trackedSession) uplinkClosed()   { s.directionClosed(true) }
func (s *trackedSession) DownlinkClosed() { s.directionClosed(false) }
func (s *trackedSession) directionClosed(up bool) {
	s.mu.Lock()
	if up {
		s.uplinkDone = true
	} else {
		s.downlinkDone = true
	}
	done := s.uplinkDone && s.downlinkDone
	s.mu.Unlock()
	if done {
		s.finish(false)
	}
}

func (s *trackedSession) terminate() { s.finish(true) }

func (s *trackedSession) finish(interrupt bool) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	reader, writer := s.reader, s.writer
	s.mu.Unlock()
	s.lease.Release()
	s.cancel()
	// Graceful completion must retain buffered downlink data for its reader.
	if interrupt {
		common.Interrupt(reader)
		common.Interrupt(writer)
	}
}

// RebindSession is called by Xray-core before reusing an XUDP link. A link
// belongs to one dispatcher and user, and its source IP is re-admitted before
// any packet is written through the reused session. A link this dispatcher
// does not track (e.g. from the instance before a hot reload) is reported as
// not owned, so Xray-core dispatches it anew instead of dropping the Mux.
func (d *LimitDispatcher) RebindSession(ctx context.Context, link *transport.Link) error {
	uid, ip, limit := d.identity(ctx)
	writer, ok := link.Writer.(*closeTrackingWriter)
	if !ok && uid == 0 {
		return nil // neither session is subject to admission
	}
	if !ok || writer.dispatcher != d {
		return routing.ErrSessionNotOwned
	}
	if uid == 0 || writer.userID != uid {
		return errors.New("XUDP session user mismatch")
	}
	if err := writer.lease.Rebind(ip, limit); err != nil {
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
