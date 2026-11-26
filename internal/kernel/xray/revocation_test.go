package xray

import (
	"context"
	"encoding/binary"
	"io"
	stdnet "net"
	"strings"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	xrayCore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/vless/multiplex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestRevokedMuxIdentityCannotDispatch(t *testing.T) {
	ld := newTestDispatcher()
	ld.UpdateLimits(map[string]int{userEmail(1): 1}, nil, nil)
	oldContext := userContext(1, "1.1.1.1")
	ld.UpdateLimits(map[string]int{userEmail(2): 2}, nil, nil)
	link, _ := testLink()
	ld.innerDisp = &testInnerDispatcher{link: link}
	if _, err := ld.Dispatch(oldContext, target(false)); err == nil {
		t.Fatal("revoked Mux identity dispatched a new session")
	}
}

func TestMuxWorkerRejectsRevokedOuterIdentity(t *testing.T) {
	for _, transition := range []string{"removed", "draining instance", "changed UUID"} {
		t.Run(transition, func(t *testing.T) {
			old := model.UserSpec{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}
			next := model.UserSpec{ID: 1, UUID: "22222222-2222-4222-8222-222222222222"}
			ld, ctx := liveTestDispatcher(t)
			ld.SetDeviceLimitFunc(nil, map[int]string{old.ID: old.UUID})
			ld.devices.UpdateUsers([]model.UserSpec{old})
			user, err := toMemoryUser("vless", &model.NodeSpec{}, old)
			if err != nil {
				t.Fatal(err)
			}
			si := *session.InboundFromContext(ctx)
			si.User = user
			ctx = session.ContextWithInbound(ctx, &si)
			reader, writer := pipe.New()
			worker := multiplex.NewServerWorker(ctx, ld.DispatchLink, &transport.Link{Reader: reader, Writer: buf.Discard}, ld)
			t.Cleanup(func() { worker.Close(); writer.Close() })
			listener := testTCPListener(t)
			listener.(*stdnet.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
			dest := net.DestinationFromAddr(listener.Addr())
			send := func(id uint16) {
				const payload = "hello"
				meta := multiplex.FrameMetadata{SessionID: id, Target: dest, SessionStatus: multiplex.SessionStatusNew}
				meta.Option.Set(multiplex.OptionData)
				frame := buf.New()
				if err := meta.WriteTo(frame); err != nil {
					frame.Release()
					t.Fatal(err)
				}
				binary.BigEndian.PutUint16(frame.Extend(2), uint16(len(payload)))
				frame.WriteString(payload)
				if err := writer.WriteMultiBuffer(buf.MultiBuffer{frame}); err != nil {
					t.Fatal(err)
				}
			}
			send(1)
			conn, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			payload := make([]byte, 5)
			if _, err := io.ReadFull(conn, payload); err != nil || string(payload) != "hello" {
				t.Fatalf("initial Mux session did not work: %q, %v", payload, err)
			}
			switch transition {
			case "removed":
				ld.UpdateLimits(nil, nil, nil)
				ld.devices.UpdateUsers(nil)
			case "draining instance":
				ld.devices.UpdateUsers(nil) // old dispatcher's identity map stays stale
			case "changed UUID":
				ld.SetDeviceLimitFunc(nil, map[int]string{next.ID: next.UUID})
				ld.devices.UpdateUsers([]model.UserSpec{next})
			}
			if _, err := conn.Read(payload); err != io.EOF {
				t.Fatalf("old session survived revocation: %v", err)
			}
			// Send a real new Mux frame on the original authenticated carrier.
			send(2)
			awaitSignal(t, worker.WaitClosed(), "revoked outer Mux accepted another session")
			if ld.devices.ActiveCount() != 0 {
				t.Fatal("revoked Mux acquired a lease")
			}
		})
	}
}

func TestXrayRekeyUpdatesRealAuthenticator(t *testing.T) {
	for _, method := range []string{"UpdateUsers", "AddUsers", "invalid replacement"} {
		t.Run(method, func(t *testing.T) {
			probe := testTCPListener(t)
			port := probe.Addr().(*stdnet.TCPAddr).Port
			probe.Close()
			x := New(config.KernelConfig{Type: "xray", LogLevel: "error"})
			old := model.UserSpec{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}
			next := model.UserSpec{ID: 1, UUID: "22222222-2222-4222-8222-222222222222"}
			nc := &model.NodeSpec{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: port}
			if err := x.Start(nc, []model.UserSpec{old}, kernel.TLSCert{}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { x.devices.UpdateUsers(nil); x.Stop() })
			um, err := x.getUserManager()
			if err != nil {
				t.Fatal(err)
			}
			oldAccount := um.GetUser(context.Background(), userEmail(old.ID))
			if oldAccount == nil {
				t.Fatal("initial account missing")
			}
			if method == "invalid replacement" {
				next.UUID = strings.Repeat("z", 36) // short strings are valid custom Xray IDs
			}
			if method != "AddUsers" {
				_, _, err = x.UpdateUsers([]model.UserSpec{next})
			} else {
				_, err = x.AddUsers([]model.UserSpec{next})
			}
			if method == "invalid replacement" {
				if err == nil {
					t.Fatal("invalid replacement reported success")
				}
				if um.GetUser(context.Background(), userEmail(old.ID)) != oldAccount || x.users[0].UUID != old.UUID {
					t.Fatal("failed rekey lost the valid old account")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			current := um.GetUser(context.Background(), userEmail(next.ID))
			if current == nil || !accountMatchesUUID(current.Account, next.UUID) {
				t.Fatal("new credential was not installed")
			}
			ctx := userContext(1, "1.1.1.1")
			si := session.InboundFromContext(ctx)
			si.User = oldAccount
			if _, _, _, err := x.limitDispatcher.acquire(ctx); err == nil {
				t.Fatal("old authenticated account still admitted")
			}
			si.User = current
			lease, _, _, err := x.limitDispatcher.acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
		})
	}
}

func TestRemoveLastUserRevokesAllScopesBeforeReturning(t *testing.T) {
	x := New(config.KernelConfig{Type: "xray"})
	x.instance = new(xrayCore.Instance)
	x.users = []model.UserSpec{{ID: 1, UUID: "old"}}
	x.running.Store(true)
	for i := 0; i < 2; i++ {
		ld := newTestDispatcher()
		x.attachDispatcher(ld)
		x.configureDispatcher(ld, x.users)
		link, raw := testLink()
		ld.innerDisp = &testInnerDispatcher{link: link}
		if _, err := ld.Dispatch(userContext(1, "1.1.1.1"), target(false)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ld.ResetConns(); waitWriter(t, raw) })
		if i == 1 {
			x.limitDispatcher = ld
		}
	}
	start := time.Now()
	if removed, err := x.RemoveUsers(x.users); err != nil || removed != 1 {
		t.Fatalf("RemoveUsers = %d, %v", removed, err)
	}
	if _, count := x.devices.Snapshot(); count != 0 {
		t.Fatalf("last user's sessions still active: %d (elapsed %v)", count, time.Since(start))
	}
	if time.Since(start) >= drainTimeout {
		t.Fatal("user revocation waited for graceful drain")
	}
}

func TestXUDPCrossUserReusePreservesOwnerSessionAndLease(t *testing.T) {
	u1 := model.UserSpec{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}
	u2 := model.UserSpec{ID: 2, UUID: "22222222-2222-4222-8222-222222222222"}
	ld, baseCtx := liveTestDispatcher(t)
	ld.UpdateLimits(
		map[string]int{userEmail(u1.ID): u1.ID, userEmail(u2.ID): u2.ID},
		map[string]int{userEmail(u1.ID): 1, userEmail(u2.ID): 1},
		nil,
	)
	ld.SetDeviceLimitFunc(nil, map[int]string{u1.ID: u1.UUID, u2.ID: u2.UUID})
	ld.devices.UpdateUsers([]model.UserSpec{u1, u2})
	t.Cleanup(func() { ld.devices.UpdateUsers(nil) })

	pc, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
	dest := net.DestinationFromAddr(pc.LocalAddr())
	gid := [8]byte{0xca, 0xfe, 0xba, 0xbe, 1, 2, 3, 4}

	startWorker := func(u model.UserSpec, ip string) (*multiplex.ServerWorker, *pipe.Writer, *pipe.Reader) {
		memUser, err := toMemoryUser("vless", &model.NodeSpec{}, u)
		if err != nil {
			t.Fatal(err)
		}
		si := *session.InboundFromContext(baseCtx)
		si.User = memUser
		si.Source = net.TCPDestination(net.ParseAddress(ip), 12345)
		wctx := session.ContextWithInbound(baseCtx, &si)
		inR, inW := pipe.New()
		outR, outW := pipe.New()
		worker := multiplex.NewServerWorker(wctx, ld.DispatchLink, &transport.Link{Reader: inR, Writer: outW}, ld)
		t.Cleanup(func() {
			worker.Close()
			_ = inW.Close()
			outR.Interrupt()
		})
		return worker, inW, outR
	}

	sendXUDP := func(inW *pipe.Writer, payload string) {
		meta := multiplex.FrameMetadata{
			SessionID:     1,
			Target:        dest,
			SessionStatus: multiplex.SessionStatusNew,
			GlobalID:      gid,
		}
		meta.Option.Set(multiplex.OptionData)
		frame := buf.New()
		frame.UDP = &dest
		if err := meta.WriteTo(frame); err != nil {
			frame.Release()
			t.Fatal(err)
		}
		binary.BigEndian.PutUint16(frame.Extend(2), uint16(len(payload)))
		_, _ = frame.WriteString(payload)
		if err := inW.WriteMultiBuffer(buf.MultiBuffer{frame}); err != nil {
			t.Fatal(err)
		}
	}

	w1, inW1, _ := startWorker(u1, "1.1.1.1")
	sendXUDP(inW1, "ping1")

	recvBuf := make([]byte, 64)
	n, firstNATAddr, err := pc.ReadFrom(recvBuf)
	if err != nil || string(recvBuf[:n]) != "ping1" {
		t.Fatalf("backend read 1 = %q, %v", recvBuf[:n], err)
	}

	// Detach u1's outer Mux carrier while keeping u1's XUDP flow cached, then buffer a reply.
	_ = inW1.Close()
	awaitSignal(t, w1.WaitClosed(), "u1 initial outer Mux did not close")
	if _, err := pc.WriteTo([]byte("secret-reply"), firstNATAddr); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)

	// u2 attempts to hijack u1's GlobalID: u2 must be rejected with zero downlink, and u1's session must survive.
	w2, inW2, outR2 := startWorker(u2, "2.2.2.2")
	sendXUDP(inW2, "forged")
	awaitSignal(t, w2.WaitClosed(), "foreign user Mux worker did not close on XUDP hijack")
	if mb, err := outR2.ReadMultiBuffer(); !mb.IsEmpty() {
		defer buf.ReleaseMulti(mb)
		t.Fatalf("foreign user received %d bytes of buffered downlink (err=%v)", mb.Len(), err)
	}

	ips, count := ld.GetConnectionState()
	if count != 1 || !ips[u1.ID]["1.1.1.1"] || len(ips[u2.ID]) != 0 {
		t.Fatalf("connection state corrupted by foreign XUDP attempt: count=%d, ips=%v", count, ips)
	}

	// u1 reconnects from a new IP and reuses the intact XUDP socket + receives the buffered downlink.
	_, inW1b, outR1b := startWorker(u1, "1.1.1.2")
	sendXUDP(inW1b, "ping2")

	n, secondNATAddr, err := pc.ReadFrom(recvBuf)
	if err != nil || string(recvBuf[:n]) != "ping2" {
		t.Fatalf("backend read 2 = %q, %v", recvBuf[:n], err)
	}
	if secondNATAddr.String() != firstNATAddr.String() {
		t.Fatalf("owner XUDP backend socket was replaced: %v -> %v", firstNATAddr, secondNATAddr)
	}

	downMB, err := outR1b.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("owner did not receive buffered downlink after rebind: %v", err)
	}
	var rawDown strings.Builder
	for _, b := range downMB {
		rawDown.Write(b.Bytes())
	}
	buf.ReleaseMulti(downMB)
	if !strings.Contains(rawDown.String(), "secret-reply") {
		t.Fatalf("owner downlink frame missing buffered reply: %q", rawDown.String())
	}

	ips, count = ld.GetConnectionState()
	if count != 1 || !ips[u1.ID]["1.1.1.2"] || ips[u1.ID]["1.1.1.1"] {
		t.Fatalf("owner lease did not rebind cleanly to 1.1.1.2: count=%d, ips=%v", count, ips)
	}
}
