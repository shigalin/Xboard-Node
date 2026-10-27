package xray

import (
	"context"
	"io"
	stdnet "net"
	"strings"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	xrayCore "github.com/xtls/xray-core/core"
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
			worker, err := mux.NewServerWorker(ctx, ld, &transport.Link{Reader: reader, Writer: buf.Discard})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { worker.Close(); writer.Close() })
			listener := testTCPListener(t)
			listener.(*stdnet.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
			dest := net.DestinationFromAddr(listener.Addr())
			send := func(id uint16) {
				w := mux.NewWriter(id, dest, writer, protocol.TransferTypeStream, [8]byte{}, &session.Inbound{})
				if err := w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("hello"))}); err != nil {
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
			if _, _, err := x.limitDispatcher.acquire(ctx); err == nil {
				t.Fatal("old authenticated account still admitted")
			}
			si.User = current
			lease, _, err := x.limitDispatcher.acquire(ctx)
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
