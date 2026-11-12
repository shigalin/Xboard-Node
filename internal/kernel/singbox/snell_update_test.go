package singbox

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	singM "github.com/sagernet/sing/common/metadata"
)

// Exercise the node's public user operations over real Snell connections.
// Starting empty must still permit later hot updates without accepting PSK alone.
func TestSnellUserHotUpdate(t *testing.T) {
	for _, version := range []int{5, 6} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			target, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			go func() {
				for {
					conn, err := target.Accept()
					if err != nil {
						return
					}
					go func() {
						defer conn.Close()
						conn.SetDeadline(time.Now().Add(15 * time.Second))
						io.Copy(conn, conn)
					}()
				}
			}()
			const psk = "snell-node-update-test"
			alice := model.UserSpec{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}
			bob := model.UserSpec{ID: 2, UUID: "22222222-2222-4222-8222-222222222222"}
			s := New(config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error",
				CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}},
			})
			defer s.Stop()
			spec := &model.NodeSpec{Protocol: "snell", ListenIP: "127.0.0.1", ServerPort: freePort(t), Version: version, ServerKey: psk}
			if err := s.Start(spec, nil, kernel.TLSCert{}); err != nil {
				t.Fatal(err)
			}
			before := runningInbound(t, s, "snell-in")
			boxBefore := s.box
			dial := func(key string) (net.Conn, error) {
				raw, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", spec.ServerPort), time.Second)
				if err != nil {
					return nil, err
				}
				raw.SetDeadline(time.Now().Add(2 * time.Second))
				dest := singM.ParseSocksaddr(target.Addr().String())
				var conn net.Conn
				if version == 5 {
					client, e := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(psk), UserKey: []byte(key)})
					if e != nil {
						raw.Close()
						return nil, e
					}
					conn, err = client.DialConn(raw, dest)
				} else {
					client, e := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(psk), UserKey: []byte(key)})
					if e != nil {
						raw.Close()
						return nil, e
					}
					conn, err = client.DialConn(raw, dest)
				}
				if err != nil {
					raw.Close()
				}
				return conn, err
			}
			exchange := func(conn net.Conn) error {
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err := conn.Write([]byte("hello")); err != nil {
					return err
				}
				reply := make([]byte, 5)
				if _, err := io.ReadFull(conn, reply); err != nil {
					return err
				}
				if string(reply) != "hello" {
					return fmt.Errorf("bad echo: %q", reply)
				}
				return nil
			}
			check := func(key string, allowed bool) {
				t.Helper()
				conn, err := dial(key)
				if err == nil {
					defer conn.Close()
					err = exchange(conn)
				}
				if (err == nil) != allowed {
					t.Fatalf("allowed=%v, connection error=%v", allowed, err)
				}
			}
			unchanged := func() {
				t.Helper()
				if s.box != boxBefore || runningInbound(t, s, "snell-in") != before {
					t.Fatal("user update rebuilt the box or inbound")
				}
			}
			check("", false)
			check(alice.UUID, false)
			if n, err := s.AddUsers([]model.UserSpec{alice}); err != nil || n != 1 {
				t.Fatalf("add Alice: n=%d err=%v", n, err)
			}
			held, err := dial(alice.UUID)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			if err := exchange(held); err != nil {
				t.Fatal(err)
			}
			if n, err := s.AddUsers([]model.UserSpec{bob}); err != nil || n != 1 {
				t.Fatalf("add Bob: n=%d err=%v", n, err)
			}
			unchanged()
			if err := exchange(held); err != nil {
				t.Fatalf("adding Bob interrupted Alice: %v", err)
			}
			check(bob.UUID, true)
			if _, _, err := s.UpdateUsers([]model.UserSpec{bob, alice}); err != nil {
				t.Fatal(err)
			}
			check(alice.UUID, true)
			// A rejected update must leave the previous users and their sessions intact.
			bad := model.UserSpec{ID: 3, UUID: strings.Repeat("x", 256)}
			if _, _, err := s.UpdateUsers([]model.UserSpec{bad}); err == nil {
				t.Fatal("invalid user key accepted")
			}
			unchanged()
			check(bob.UUID, true)
			if err := exchange(held); err != nil {
				t.Fatalf("rejected update interrupted Alice: %v", err)
			}
			if n, err := s.RemoveUsers([]model.UserSpec{bob}); err != nil || n != 1 {
				t.Fatalf("remove Bob: n=%d err=%v", n, err)
			}
			check(bob.UUID, false)
			if err := exchange(held); err != nil {
				t.Fatalf("removing Bob interrupted Alice: %v", err)
			}
			traffic, _, _, err := s.GetUserTraffic(context.Background())
			if err != nil || traffic[1][0] == 0 || traffic[2][0] == 0 {
				t.Fatalf("missing per-user traffic: %v, err=%v", traffic, err)
			}
			if _, _, err := s.UpdateUsers(nil); err != nil {
				t.Fatal(err)
			}
			unchanged()
			check(alice.UUID, false)
			check("", false)
			if err := exchange(held); err == nil {
				t.Fatal("cleared user's existing connection still works")
			}
			if _, _, err := s.UpdateUsers([]model.UserSpec{alice}); err != nil {
				t.Fatal(err)
			}
			unchanged()
			check(alice.UUID, true)
		})
	}
}
