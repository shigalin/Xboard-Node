package xray

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func newTestDispatcher() *LimitDispatcher {
	return &LimitDispatcher{devices: limiter.NewDeviceManager(0)}
}

type nopReader struct{}

func (nopReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, nil }

type signalWriter struct {
	once   sync.Once
	closed chan struct{}
}

func (w *signalWriter) WriteMultiBuffer(mb buf.MultiBuffer) error { buf.ReleaseMulti(mb); return nil }
func (w *signalWriter) Close() error                              { w.once.Do(func() { close(w.closed) }); return nil }
func (w *signalWriter) Interrupt()                                { w.Close() }

type testInnerDispatcher struct {
	link         *transport.Link
	err          error
	beforeReturn func()
	observer     routing.SessionLifecycle
	ctx          context.Context
	onLink       func(context.Context) error
}

func (d *testInnerDispatcher) Type() interface{} { return nil }
func (d *testInnerDispatcher) Start() error      { return nil }
func (d *testInnerDispatcher) Close() error      { return nil }
func (d *testInnerDispatcher) Dispatch(ctx context.Context, _ net.Destination) (*transport.Link, error) {
	d.observer = routing.SessionLifecycleFromContext(ctx)
	d.ctx = ctx
	if d.beforeReturn != nil {
		d.beforeReturn()
	}
	return d.link, d.err
}
func (d *testInnerDispatcher) DispatchLink(ctx context.Context, _ net.Destination, _ *transport.Link) error {
	if d.onLink != nil {
		return d.onLink(ctx)
	}
	return d.err
}

func userContext(uid int, ip string) context.Context {
	return session.ContextWithInbound(context.Background(), &session.Inbound{
		User:   &protocol.MemoryUser{Email: userEmail(uid)},
		Source: net.TCPDestination(net.ParseAddress(ip), 12345),
	})
}
func target(udp bool) net.Destination {
	if udp {
		return net.UDPDestination(net.ParseAddress("8.8.8.8"), 53)
	}
	return net.TCPDestination(net.ParseAddress("8.8.8.8"), 443)
}
func testLink() (*transport.Link, *signalWriter) {
	reader, _ := pipe.New()
	writer := &signalWriter{closed: make(chan struct{})}
	return &transport.Link{Reader: reader, Writer: writer}, writer
}
func waitWriter(t *testing.T, writer *signalWriter) {
	t.Helper()
	select {
	case <-writer.closed:
	case <-time.After(time.Second):
		t.Fatal("active link was not terminated")
	}
}

func TestLimitDispatcherTCPAndUDPShareStrictAdmission(t *testing.T) {
	for _, udp := range []bool{false, true} {
		for _, direct := range []bool{false, true} {
			name := "tcp"
			if udp {
				name = "udp"
			}
			if direct {
				name += "-DispatchLink"
			}
			t.Run(name, func(t *testing.T) {
				ld := newTestDispatcher()
				ld.UpdateLimits(map[string]int{userEmail(1): 1}, map[string]int{userEmail(1): 1}, nil)
				link, raw := testLink()
				reader := link.Reader
				ld.innerDisp = &testInnerDispatcher{link: link}
				var err error
				if direct {
					err = ld.DispatchLink(userContext(1, "9.9.9.9"), target(udp), link)
				} else {
					_, err = ld.Dispatch(userContext(1, "9.9.9.9"), target(udp))
				}
				if err != nil {
					t.Fatal(err)
				}
				if link.Reader != reader {
					t.Fatal("concrete pipe reader was replaced")
				}
				ips, count := ld.GetConnectionState()
				if count != 1 || !ips[1]["9.9.9.9"] {
					t.Fatalf("source not tracked: %v, %d", ips, count)
				}
				if _, err := ld.Dispatch(userContext(1, "1.1.1.1"), target(udp)); !errors.Is(err, limiter.ErrDeviceLimit) {
					t.Fatal("lower-sorting IP bypassed strict limit")
				}
				waitWriter(t, raw)
				if _, err := ld.Dispatch(userContext(1, "9.9.9.9"), target(udp)); !errors.Is(err, limiter.ErrDeviceLimit) {
					t.Fatal("old IP bypassed punishment window")
				}
			})
		}
	}
}

func TestLimitDispatcherLifecycleAndFailureRollback(t *testing.T) {
	ld := newTestDispatcher()
	ld.UpdateLimits(map[string]int{userEmail(1): 1}, nil, nil)
	link, _ := testLink()
	ld.innerDisp = &testInnerDispatcher{link: link}
	result, err := ld.Dispatch(userContext(1, "1.1.1.1"), target(false))
	if err != nil {
		t.Fatal(err)
	}
	writer := result.Writer.(*closeTrackingWriter)
	writer.Close()
	writer.Interrupt()
	writer.Close()
	if _, count := ld.GetConnectionState(); count != 1 {
		t.Fatal("upload half-close released the IP before download completed")
	}
	ld.innerDisp.(*testInnerDispatcher).observer.DownlinkClosed()
	if _, count := ld.GetConnectionState(); count != 0 {
		t.Fatal("normal close leaked connection state")
	}
	for _, direct := range []bool{false, true} {
		ld.innerDisp = &testInnerDispatcher{err: errors.New("failed")}
		var err error
		if direct {
			link, _ := testLink()
			err = ld.DispatchLink(userContext(1, "2.2.2.2"), target(false), link)
		} else {
			_, err = ld.Dispatch(userContext(1, "2.2.2.2"), target(false))
		}
		if err == nil {
			t.Fatal("expected dispatch failure")
		}
		if _, count := ld.GetConnectionState(); count != 0 {
			t.Fatal("failed dispatch leaked a reservation")
		}
	}
}

func TestDispatchLinkForceCloseCancelsRawProtocolProcessing(t *testing.T) {
	ld := newTestDispatcher()
	ld.UpdateLimits(map[string]int{userEmail(1): 1}, nil, nil)
	entered := make(chan struct{})
	ld.innerDisp = &testInnerDispatcher{onLink: func(ctx context.Context) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}}
	done := make(chan error, 1)
	go func() {
		done <- ld.DispatchLink(userContext(1, "1.1.1.1"), target(false), &transport.Link{Reader: nopReader{}, Writer: buf.Discard})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("protocol processing did not start")
	}
	ld.devices.CloseUser(1)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want canceled protocol processing", err)
		}
	case <-time.After(time.Second):
		t.Fatal("force-close did not cancel a protocol with non-closable readers/writers")
	}
}

func TestLimitDispatcherContextCancellationAndLateBind(t *testing.T) {
	ld := newTestDispatcher()
	ld.UpdateLimits(map[string]int{userEmail(1): 1}, nil, nil)
	link, raw := testLink()
	ctx, cancel := context.WithCancel(userContext(1, "1.1.1.1"))
	ld.innerDisp = &testInnerDispatcher{link: link}
	if _, err := ld.Dispatch(ctx, target(false)); err != nil {
		t.Fatal(err)
	}
	cancel()
	waitWriter(t, raw)
	// The closer can finish just before its Release callback.
	deadline := time.Now().Add(time.Second)
	for ld.devices.ActiveCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if ld.devices.ActiveCount() != 0 {
		t.Fatal("cancellation leaked reservation")
	}

	link, raw = testLink()
	ld.innerDisp = &testInnerDispatcher{link: link, beforeReturn: func() { ld.devices.CloseUser(1) }}
	if _, err := ld.Dispatch(userContext(1, "2.2.2.2"), target(false)); err != nil {
		t.Fatal(err)
	}
	waitWriter(t, raw)
	if ld.devices.ActiveCount() != 0 {
		t.Fatal("late bind escaped user sweep")
	}
}

func TestLimitDispatcherRebindChecksIPUserAndOwner(t *testing.T) {
	ld := newTestDispatcher()
	ld.UpdateLimits(map[string]int{userEmail(1): 1, userEmail(2): 2}, map[string]int{userEmail(1): 1}, nil)
	link, raw := testLink()
	ld.innerDisp = &testInnerDispatcher{link: link}
	if _, err := ld.Dispatch(userContext(1, "1.1.1.1"), target(true)); err != nil {
		t.Fatal(err)
	}
	if err := ld.RebindSession(userContext(1, "2.2.2.2"), link); err != nil {
		t.Fatal(err)
	}
	ips, count := ld.GetConnectionState()
	if count != 1 || !ips[1]["2.2.2.2"] || ips[1]["1.1.1.1"] {
		t.Fatalf("bad rebind state: %v", ips)
	}
	if err := ld.RebindSession(userContext(2, "2.2.2.2"), link); err == nil || errors.Is(err, routing.ErrSessionNotOwned) {
		t.Fatalf("other user reused session: %v", err)
	}
	if err := newTestDispatcher().RebindSession(userContext(1, "2.2.2.2"), link); !errors.Is(err, routing.ErrSessionNotOwned) {
		t.Fatalf("other node instance must report the session as not owned: %v", err)
	}
	ld.devices.CloseUser(1)
	waitWriter(t, raw)
	// Xray-core must dispatch anew (admission again) rather than drop the Mux.
	if err := ld.RebindSession(userContext(1, "2.2.2.2"), link); !errors.Is(err, routing.ErrSessionNotOwned) {
		t.Fatalf("kicked XUDP session: got %v, want ErrSessionNotOwned", err)
	}
}

func TestXUDPLeaseOutlivesOuterMuxContext(t *testing.T) {
	ld := newTestDispatcher()
	ld.UpdateLimits(map[string]int{userEmail(1): 1}, map[string]int{userEmail(1): 1}, nil)
	link, raw := testLink()
	ld.innerDisp = &testInnerDispatcher{link: link}
	ctx, cancel := context.WithCancel(userContext(1, "1.1.1.1"))
	ctx = session.ContextWithTimeoutOnly(ctx, true)
	if _, err := ld.Dispatch(ctx, target(true)); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := ld.RebindSession(userContext(1, "2.2.2.2"), link); err != nil {
		t.Fatalf("live XUDP link did not survive Mux detach: %v", err)
	}
	select {
	case <-raw.closed:
		t.Fatal("old context terminated the rebound session")
	default:
	}
	ld.devices.CloseUser(1)
	waitWriter(t, raw)
	if err := ld.RebindSession(userContext(1, "2.2.2.2"), link); err == nil {
		t.Fatal("explicitly kicked XUDP session was reused")
	}
}

func TestLimitDispatcherRebindUntrackedLink(t *testing.T) {
	ld := newTestDispatcher()
	ld.UpdateLimits(map[string]int{userEmail(1): 1}, map[string]int{userEmail(1): 1}, nil)
	untracked, _ := testLink()
	if err := ld.RebindSession(userContext(9, "2.2.2.2"), untracked); err != nil {
		t.Fatalf("unadmitted user could not reuse an untracked link: %v", err)
	}
	if err := ld.RebindSession(userContext(1, "2.2.2.2"), untracked); !errors.Is(err, routing.ErrSessionNotOwned) {
		t.Fatalf("tracked user must get a fresh, admitted session: %v", err)
	}
	if ld.devices.ActiveCount() != 0 {
		t.Fatal("rebind of an untracked link reserved an IP slot")
	}
}

func TestTrackedSessionCancelsOnlyAfterOutboundReturns(t *testing.T) {
	for _, outboundFirst := range []bool{false, true} {
		ld := newTestDispatcher()
		ld.UpdateLimits(map[string]int{userEmail(1): 1}, nil, nil)
		link, _ := testLink()
		inner := &testInnerDispatcher{link: link}
		ld.innerDisp = inner
		result, err := ld.Dispatch(userContext(1, "1.1.1.1"), target(false))
		if err != nil {
			t.Fatal(err)
		}
		returned := inner.observer.(routing.OutboundObserver).OutboundReturned
		if outboundFirst { // e.g. an outbound that hands the link to a Mux client
			returned()
			if inner.ctx.Err() != nil {
				t.Fatal("context cancelled while both directions were open")
			}
		}
		common.Close(result.Writer)
		inner.observer.DownlinkClosed()
		if _, count := ld.GetConnectionState(); count != 0 {
			t.Fatal("finished session kept its IP")
		}
		if !outboundFirst {
			if inner.ctx.Err() != nil {
				t.Fatal("context cancelled while the outbound may still flush uplink data")
			}
			returned()
		}
		if inner.ctx.Err() == nil {
			t.Fatal("context outlived the finished session")
		}
	}
}

// A direct (DispatchLink) session keeps its IP after the downlink closes while
// the outbound still forwards uploads; only the outbound's return ends it.
func TestDirectSessionHoldsLeaseUntilOutboundReturns(t *testing.T) {
	ld := newTestDispatcher()
	ld.UpdateLimits(map[string]int{userEmail(1): 1}, nil, nil)
	link, _ := testLink()
	var observer routing.SessionLifecycle
	ld.innerDisp = &testInnerDispatcher{onLink: func(ctx context.Context) error {
		observer = routing.SessionLifecycleFromContext(ctx)
		return nil
	}}
	if err := ld.DispatchLink(userContext(1, "1.1.1.1"), target(false), link); err != nil {
		t.Fatal(err)
	}
	common.Close(link.Writer)
	if _, count := ld.GetConnectionState(); count != 1 {
		t.Fatal("downlink close released the IP while the upload may continue")
	}
	observer.(routing.OutboundObserver).OutboundReturned()
	if _, count := ld.GetConnectionState(); count != 0 {
		t.Fatal("finished direct session kept its IP")
	}
}
