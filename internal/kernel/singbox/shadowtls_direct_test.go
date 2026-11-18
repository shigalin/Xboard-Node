package singbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	singJSON "github.com/sagernet/sing/common/json"
	Mtd "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

// Dial the generated inner listener with the correct PSK but without going
// through ShadowTLS. A TCP handshake alone must not grant proxy access.
func TestSnellShadowTLSRejectsDirectInnerPort(t *testing.T) {
	for _, version := range []int{5, 6} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			const psk = "inner-port-regression-psk"
			user := model.UserSpec{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}
			spec := &model.NodeSpec{Protocol: "snell", Version: version, ServerKey: psk, ServerPort: freePort(t), ShadowTLSServer: "127.0.0.1", ShadowTLSPort: startTLSServer(t)}
			cfg := buildConfig(config.KernelConfig{LogLevel: "error", CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}}}, spec, []model.UserSpec{user}, kernel.TLSCert{})
			// Assign only the ephemeral test port; preserve the generated tag and auth options.
			innerPort := freePort(t)
			for _, in := range cfg["inbounds"].([]M) {
				if in["type"] == "snell" {
					in["listen_port"] = innerPort
				}
			}
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(include.Context(context.Background()))
			defer cancel()
			opts, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, data)
			if err != nil {
				t.Fatal(err)
			}
			server, err := box.New(box.Options{Context: ctx, Options: opts})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			tracker := NewConnTracker(nil)
			tracker.SetUserMap(buildUserMap([]model.UserSpec{user}))
			server.Router().AppendTracker(tracker)
			if err = server.Start(); err != nil {
				t.Fatal(err)
			}
			target, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			udp, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			received := make(chan string, 8)
			go func() {
				for {
					c, e := target.Accept()
					if e != nil {
						return
					}
					go func() {
						defer c.Close()
						c.SetDeadline(time.Now().Add(3 * time.Second))
						b := make([]byte, 4)
						if _, e := io.ReadFull(c, b); e == nil {
							received <- "tcp"
							c.Write(b)
						}
					}()
				}
			}()
			go func() {
				b := make([]byte, 64)
				for {
					n, a, e := udp.ReadFrom(b)
					if e != nil {
						return
					}
					received <- "udp"
					udp.WriteTo(b[:n], a)
				}
			}()
			var method interface {
				DialConn(net.Conn, Mtd.Socksaddr) (net.Conn, error)
				DialPacketConn(net.Conn) (N.NetPacketConn, error)
			}
			if version == 5 {
				method, err = snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(psk)})
			} else {
				method, err = snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(psk)})
			}
			if err != nil {
				t.Fatal(err)
			}
			tcpExchange := func(c net.Conn) error {
				c.SetDeadline(time.Now().Add(time.Second))
				if _, e := c.Write([]byte("test")); e != nil {
					return e
				}
				_, e := io.ReadFull(c, make([]byte, 4))
				return e
			}
			udpExchange := func(c net.PacketConn) error {
				c.SetDeadline(time.Now().Add(time.Second))
				if _, e := c.WriteTo([]byte("test"), udp.LocalAddr()); e != nil {
					return e
				}
				_, _, e := c.ReadFrom(make([]byte, 64))
				return e
			}
			for _, network := range []string{"tcp", "udp"} {
				raw, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", innerPort), time.Second)
				if e != nil {
					t.Fatalf("inner listener not reachable: %v", e)
				}
				raw.SetDeadline(time.Now().Add(time.Second))
				if network == "tcp" {
					c, err := method.DialConn(raw, Mtd.ParseSocksaddr(target.Addr().String()))
					e = err
					if e == nil {
						e = tcpExchange(c)
						c.Close()
					}
				} else {
					c, err := method.DialPacketConn(raw)
					e = err
					if e == nil {
						e = udpExchange(c)
						c.Close()
					}
				}
				raw.Close()
				if e == nil {
					t.Fatalf("PSK-only %s request bypassed ShadowTLS", network)
				}
				if ne, ok := e.(net.Error); ok && ne.Timeout() {
					t.Fatalf("%s stalled instead of being rejected: %v", network, e)
				}
			}
			select {
			case protocol := <-received:
				t.Fatalf("direct %s payload reached destination", protocol)
			case <-time.After(50 * time.Millisecond):
			}
			// Positive control: the same generated server and PSK work after authentication.
			cv := version
			if cv == 5 {
				cv = 4
			}
			port := startShadowTLSClients(t, spec.ServerPort, cv, psk, user)[0]
			client := socks.NewClient(N.SystemDialer, Mtd.ParseSocksaddrHostPort("127.0.0.1", uint16(port)), socks.Version5, "", "")
			c, err := client.DialContext(ctx, "tcp", Mtd.ParseSocksaddr(target.Addr().String()))
			if err != nil {
				t.Fatal(err)
			}
			err = tcpExchange(c)
			c.Close()
			if err != nil {
				t.Fatalf("authenticated TCP failed: %v", err)
			}
			pc, err := client.ListenPacket(ctx, Mtd.ParseSocksaddr(udp.LocalAddr().String()))
			if err != nil {
				t.Fatal(err)
			}
			err = udpExchange(pc)
			pc.Close()
			if err != nil {
				t.Fatalf("authenticated UDP failed: %v", err)
			}
		})
	}
}

func TestSnellUserKeyDetourRequiresAuthenticatedShadowTLS(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	logger := log.NewNOPFactory().NewLogger("snell-test")
	opts := option.SnellInboundOptions{Version: 6, AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{
		PSK:        "snell-detour-test-psk",
		AuthDetour: shadowTLSInboundTag,
		Users:      []option.SnellUser{{Name: "alice", UserKey: "alice-test-userkey"}},
		ListenOptions: option.ListenOptions{
			ListenPort: uint16(occupied.Addr().(*net.TCPAddr).Port),
		},
	}}
	inbound, err := newSnellInbound(context.Background(), nil, logger, snellDetourTag, opts)
	if err != nil {
		t.Fatal(err)
	}
	scope := adapter.NewScope(context.Background(), logger)
	defer scope.Close()
	if err := scope.Start(snellDetourTag, inbound, adapter.StartStateStart); err != nil {
		t.Fatalf("injectable inbound tried to bind a TCP port: %v", err)
	}
	for _, tc := range []struct {
		name, source, kind, user string
	}{
		{"other detour", "other-in", C.TypeShadowTLS, "alice"},
		{"other type", shadowTLSInboundTag, C.TypeSOCKS, "alice"},
		{"no authenticated user", shadowTLSInboundTag, C.TypeShadowTLS, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			server.SetReadDeadline(time.Now().Add(time.Second))
			var rejected error
			metadata := adapter.InboundContext{LastInbound: tc.source, InboundType: tc.kind, User: tc.user}
			inbound.(adapter.TCPInjectableInbound).NewConnection(context.Background(), server, metadata, func(err error) { rejected = err })
			if !errors.Is(rejected, os.ErrPermission) {
				t.Fatalf("wanted rejection before the Snell handshake, got %v", rejected)
			}
			client.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("rejected connection was not closed: %v", err)
			}
		})
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	inbound.(*trackedSnellInbound).closeConnections()
}

func TestSnellShadowTLSUserKeyUDP(t *testing.T) {
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			n, addr, err := target.ReadFrom(buf)
			if err != nil {
				return
			}
			target.WriteTo(buf[:n], addr)
		}
	}()
	for _, version := range []int{5, 6} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			psk := "snell-udp-test-psk"
			if version == 5 {
				psk = "v5-key"
			}
			user := model.UserSpec{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}
			handshakePort := startTLSServer(t)
			spec := &model.NodeSpec{Protocol: "snell", Version: version, PSKMode: "shared_userkey", ServerKey: psk,
				ShadowTLSServer: "127.0.0.1", ShadowTLSPort: handshakePort, ShadowTLSPassword: testSharedShadowTLSPassword}
			s := New(config.KernelConfig{LogLevel: "error", ConfigDir: t.TempDir(),
				CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}},
			})
			defer s.Stop()
			startSnellTestNode(t, s, spec, []model.UserSpec{user})
			clientVersion := version
			if version == 5 {
				clientVersion = 4
			}
			port := startSnellClients(t, spec.ServerPort, clientVersion, psk, spec.PSKMode, true, spec.ShadowTLSPassword, user)[0]
			client := socks.NewClient(N.SystemDialer, Mtd.ParseSocksaddrHostPort("127.0.0.1", uint16(port)), socks.Version5, "", "")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			pc, err := client.ListenPacket(ctx, Mtd.ParseSocksaddr(target.LocalAddr().String()))
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			pc.SetDeadline(time.Now().Add(3 * time.Second))
			const payload = "snell udp echo"
			if _, err := pc.WriteTo([]byte(payload), target.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 64)
			n, _, err := pc.ReadFrom(reply)
			if err != nil || string(reply[:n]) != payload {
				t.Fatalf("did not receive UDP echo: %v", err)
			}
			traffic, _, _, err := s.GetUserTraffic(ctx)
			if err != nil || traffic[user.ID] != [2]int64{int64(len(payload)), int64(len(payload))} {
				t.Fatalf("UDP traffic was not attributed to the Snell user: %v, err=%v", traffic, err)
			}
			shadow := newTestShadowTLSClient(t, spec.ServerPort, spec.ShadowTLSPassword)
			raw, err := shadow.DialContext(ctx)
			if err != nil {
				t.Fatalf("ShadowTLS must authenticate before testing UDP userkey rejection: %v", err)
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(3 * time.Second))
			method := newTestSnellMethod(t, version, psk, "unknown-test-userkey")
			rejected, err := method.DialPacketConn(raw)
			if err != nil {
				t.Fatal(err)
			}
			defer rejected.Close()
			if _, err := rejected.WriteTo([]byte(payload), target.LocalAddr()); !testSnellPeerClosed(err) {
				t.Fatalf("expected Snell to close the UDP transport with an unknown userkey, got %v", err)
			}
		})
	}
}
