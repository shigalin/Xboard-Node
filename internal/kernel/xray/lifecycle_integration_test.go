package xray

import (
	"context"
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	xrayCore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

func liveTestDispatcher(t *testing.T) (*LimitDispatcher, context.Context) {
	t.Helper()
	cfg, err := serial.LoadJSONConfig(strings.NewReader(`{"log":{"loglevel":"none"},"outbounds":[{"protocol":"freedom"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	xrayCreationMu.Lock()
	inst, err := xrayCore.New(cfg)
	xrayCreationMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inst.Close() })
	ld, ok := inst.GetFeature(routing.DispatcherType()).(*LimitDispatcher)
	if !ok {
		t.Fatal("core instance did not use the node admission adapter")
	}
	ld.UpdateLimits(map[string]int{userEmail(1): 1}, map[string]int{userEmail(1): 1}, nil)
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	// XrayKey is exported by core for tests that exercise internal dispatch.
	ctx := context.WithValue(userContext(1, "1.1.1.1"), xrayCore.XrayKey(1), inst)
	return ld, ctx
}

func testTCPListener(t *testing.T) stdnet.Listener {
	t.Helper()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener
}

func awaitSignal(t *testing.T, done <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal(description)
	}
}

func TestCoreDispatchKeepsIPThroughUploadHalfClose(t *testing.T) {
	ld, ctx := liveTestDispatcher(t)
	listener := testTCPListener(t)
	uploadEnded := make(chan struct{})
	allowDownload := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		request := make([]byte, len("request"))
		if _, err = io.ReadFull(conn, request); err != nil {
			serverDone <- err
			return
		}
		close(uploadEnded)
		select {
		case <-allowDownload:
		case <-time.After(3 * time.Second):
			serverDone <- context.DeadlineExceeded
			return
		}
		_, err = conn.Write([]byte("reply"))
		serverDone <- err
	}()
	link, err := ld.Dispatch(ctx, net.DestinationFromAddr(listener.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { common.Interrupt(link.Reader); common.Interrupt(link.Writer) })
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("request"))}); err != nil {
		t.Fatal(err)
	}
	if err := common.Close(link.Writer); err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, uploadEnded, "target did not receive the request")
	ips, count := ld.GetConnectionState()
	if count != 1 || !ips[1]["1.1.1.1"] {
		t.Fatal("upload half-close released a still-downloading user's IP")
	}
	close(allowDownload)
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for ld.devices.ActiveCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if ld.devices.ActiveCount() != 0 {
		t.Fatal("core did not release the IP after both directions completed")
	}
	// Delay reading until core has finished, so discarding unread buffers on
	// graceful completion is caught deterministically rather than by timing.
	response, err := link.Reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	content := response.String()
	buf.ReleaseMulti(response)
	if content != "reply" {
		t.Fatalf("half-close interrupted download: %q", content)
	}
}

func TestCoreDispatchLinkForceCloseCancelsRawStreams(t *testing.T) {
	ld, ctx := liveTestDispatcher(t)
	listener := testTCPListener(t)
	forwarded := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		// Far beyond the assertion windows below, so the copy ends because
		// force-close shut the socket rather than because the read expired.
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		request := make([]byte, len("request"))
		if _, err := io.ReadFull(conn, request); err != nil {
			serverDone <- err
			return
		}
		close(forwarded)
		_, err = io.Copy(io.Discard, conn)
		serverDone <- err
	}()
	client, peer := stdnet.Pipe()
	t.Cleanup(func() { client.Close(); peer.Close() })
	done := make(chan error, 1)
	go func() {
		done <- ld.DispatchLink(ctx, net.DestinationFromAddr(listener.Addr()), &transport.Link{Reader: buf.NewReader(client), Writer: buf.NewWriter(client)})
	}()
	peer.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := peer.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	// Accept can precede the dial returning. Wait for forwarded data so the
	// close exercises active streams rather than cancellation during dialing.
	awaitSignal(t, forwarded, "outbound did not forward the request")
	ld.devices.CloseUser(1)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("core kept processing raw streams after force-close")
	}
	// The pipe stays open on purpose: the outbound socket must be closed by
	// force-close, not by the client going away.
	select {
	case err := <-serverDone:
		if errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("force-close did not close the outbound socket: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("force-close did not close the outbound socket")
	}
	if ld.devices.ActiveCount() != 0 {
		t.Fatal("closed raw session retained its IP")
	}
}

// blockingDialer stalls every dial until its context ends, so force-close can
// be exercised while the outbound is still connecting.
type blockingDialer struct {
	once    sync.Once
	dialing chan struct{}
}

func (d *blockingDialer) Dial(ctx context.Context, _ net.Address, _ net.Destination, _ *internet.SocketConfig) (net.Conn, error) {
	d.once.Do(func() { close(d.dialing) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func (d *blockingDialer) DestIpAddress() net.IP { return nil }

func TestCoreDispatchLinkForceCloseEndsDialingSession(t *testing.T) {
	ld, ctx := liveTestDispatcher(t)
	dialer := &blockingDialer{dialing: make(chan struct{})}
	internet.UseAlternativeSystemDialer(dialer)
	t.Cleanup(func() { internet.UseAlternativeSystemDialer(nil) })
	client, peer := stdnet.Pipe()
	t.Cleanup(func() { client.Close(); peer.Close() })
	done := make(chan error, 1)
	go func() {
		done <- ld.DispatchLink(ctx, net.TCPDestination(net.LocalHostIP, net.Port(9)), &transport.Link{Reader: buf.NewReader(client), Writer: buf.NewWriter(client)})
	}()
	awaitSignal(t, dialer.dialing, "outbound never started dialing")
	ld.devices.CloseUser(1)
	// The stub dialer only returns once the context is done, so DispatchLink
	// returning at all proves the cancellation landed; its error says nothing
	// because the outbound handler swallows dial failures. Cancelling a dial
	// then waits out the outbound's retry backoff, which sleeps about a second
	// without watching the context, so this path needs a wider window than
	// force-closing active streams does.
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("core kept dialing after force-close")
	}
	if ld.devices.ActiveCount() != 0 {
		t.Fatal("closed dialing session retained its IP")
	}
}

func TestStopAcceptingKeepsEstablishedConnections(t *testing.T) {
	target := testTCPListener(t)
	probe := testTCPListener(t)
	port := probe.Addr().(*stdnet.TCPAddr).Port
	probe.Close()
	cfg, err := serial.LoadJSONConfig(strings.NewReader(fmt.Sprintf(`{"log":{"loglevel":"none"},
		"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"tunnel","settings":{"address":"127.0.0.1","port":%d,"network":"tcp"}}],
		"outbounds":[{"protocol":"freedom"}]}`, port, target.Addr().(*stdnet.TCPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	xrayCreationMu.Lock()
	inst, err := xrayCore.New(cfg)
	xrayCreationMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inst.Close() })
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	client, err := stdnet.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := target.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.SetDeadline(time.Now().Add(3 * time.Second))

	stopAccepting(inst)

	if _, err := client.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(server, got); err != nil || string(got) != "ok" {
		t.Fatalf("established connection stopped forwarding: %q, %v", got, err)
	}
	if conn, err := stdnet.DialTimeout("tcp", addr, time.Second); err == nil {
		conn.Close()
		t.Fatal("old instance still accepted a new connection")
	}
}

// UDP inbounds cannot refuse new flows without closing their socket, so a
// replaced instance must stop serving UDP entirely.
func TestStopAcceptingClosesUDPInbound(t *testing.T) {
	target, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	probe, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*stdnet.UDPAddr).Port
	probe.Close()
	cfg, err := serial.LoadJSONConfig(strings.NewReader(fmt.Sprintf(`{"log":{"loglevel":"none"},
		"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"tunnel","settings":{"address":"127.0.0.1","port":%d,"network":"udp"}}],
		"outbounds":[{"protocol":"freedom"}]}`, port, target.LocalAddr().(*stdnet.UDPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	xrayCreationMu.Lock()
	inst, err := xrayCore.New(cfg)
	xrayCreationMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inst.Close() })
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	client, err := stdnet.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	got := make([]byte, 16)
	if _, err := client.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	target.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, _, err := target.ReadFrom(got); err != nil || string(got[:n]) != "before" {
		t.Fatalf("UDP inbound did not forward before stop: %q, %v", got[:n], err)
	}

	stopAccepting(inst)

	client.Write([]byte("after"))
	target.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _, err := target.ReadFrom(got); err == nil {
		t.Fatalf("stopped UDP inbound still forwarded %q", got[:n])
	}
}
