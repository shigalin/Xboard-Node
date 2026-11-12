package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
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
