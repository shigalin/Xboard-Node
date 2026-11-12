package singbox

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singJSON "github.com/sagernet/sing/common/json"
	singM "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

// The Snell inbound behind ShadowTLS has no users of its own, so a connection
// that reaches it without one did not pass ShadowTLS.
func TestSnellDetourRejectsMissingUser(t *testing.T) {
	tracker := NewConnTracker(nil)
	closed := func(inbound string) bool {
		t.Helper()
		local, remote := net.Pipe()
		defer remote.Close()
		metadata := testInboundContext("", "1.1.1.1")
		metadata.Inbound = inbound
		defer tracker.RoutedConnection(context.Background(), local, metadata, nil, nil).Close()
		remote.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, err := remote.Read(make([]byte, 1))
		return !errors.Is(err, os.ErrDeadlineExceeded)
	}
	if !closed(snellDetourTag) {
		t.Fatal("connection without a user was admitted on the Snell detour")
	}
	if closed("custom-in") {
		t.Fatal("unauthenticated inbound was rejected")
	}

	packetConn := &devicePacketConn{closed: make(chan struct{})}
	metadata := testInboundContext("", "1.1.1.1")
	metadata.Inbound = snellDetourTag
	tracker.RoutedPacketConnection(context.Background(), packetConn, metadata, nil, nil)
	select {
	case <-packetConn.closed:
	default:
		t.Fatal("packet session without a user was admitted on the Snell detour")
	}
}

// startTLSServer runs the TLS 1.3 server ShadowTLS relays handshakes to.
func startTLSServer(t *testing.T) int {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "handshake.test"},
		DNSNames:     []string{"handshake.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

// startShadowTLSClients runs a sing-box client with one SOCKS port per user,
// each reaching the node through ShadowTLS v3 with that user's password.
func startShadowTLSClients(t *testing.T, serverPort int, snellVersion int, psk string, users ...model.UserSpec) []int {
	t.Helper()
	var inbounds, outbounds, rules []M
	ports := make([]int, 0, len(users))
	for index, user := range users {
		port := freePort(t)
		ports = append(ports, port)
		mixed, snell, shadowTLS := fmt.Sprint("mixed-", index), fmt.Sprint("snell-", index), fmt.Sprint("shadowtls-", index)
		inbounds = append(inbounds, M{"type": "mixed", "tag": mixed, "listen": "127.0.0.1", "listen_port": port})
		outbounds = append(outbounds,
			M{"type": "snell", "tag": snell, "server": "127.0.0.1", "server_port": serverPort, "version": snellVersion, "psk": psk, "reuse": true, "detour": shadowTLS},
			M{"type": "shadowtls", "tag": shadowTLS, "server": "127.0.0.1", "server_port": serverPort, "version": 3, "password": user.UUID,
				"tls": M{"enabled": true, "server_name": "handshake.test", "insecure": true}},
		)
		rules = append(rules, M{"inbound": mixed, "action": "route", "outbound": snell})
	}
	data, err := json.Marshal(M{"log": M{"disabled": true}, "inbounds": inbounds, "outbounds": outbounds, "route": M{"rules": rules}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	t.Cleanup(cancel)
	options, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	client, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	return ports
}

// Exercise the node's user operations over real connections: ShadowTLS
// authenticates the user and Snell requests are accounted to that user.
func TestSnellShadowTLSUserHotUpdate(t *testing.T) {
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
			const psk = "snell-shadowtls-update-test"
			alice := model.UserSpec{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}
			bob := model.UserSpec{ID: 2, UUID: "22222222-2222-4222-8222-222222222222"}
			s := New(config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error",
				CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}},
			})
			defer s.Stop()
			spec := &model.NodeSpec{
				Protocol: "snell", ServerPort: freePort(t), Version: version, ServerKey: psk,
				ShadowTLSServer: "127.0.0.1", ShadowTLSPort: startTLSServer(t),
			}
			if err := s.Start(spec, nil, kernel.TLSCert{}); err != nil {
				t.Fatal(err)
			}
			shadowTLSBefore, snellBefore := runningInbound(t, s, shadowTLSInboundTag), runningInbound(t, s, snellDetourTag)
			boxBefore := s.box
			clientVersion := version
			if version == 5 {
				clientVersion = 4 // a v5 server speaks the v4 wire protocol
			}
			ports := startShadowTLSClients(t, spec.ServerPort, clientVersion, psk, alice, bob)
			alicePort, bobPort := ports[0], ports[1]

			dial := func(port int) (net.Conn, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				client := socks.NewClient(N.SystemDialer, singM.ParseSocksaddrHostPort("127.0.0.1", uint16(port)), socks.Version5, "", "")
				return client.DialContext(ctx, "tcp", singM.ParseSocksaddr(target.Addr().String()))
			}
			exchange := func(conn net.Conn) error {
				conn.SetDeadline(time.Now().Add(3 * time.Second))
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
			check := func(port int, allowed bool) {
				t.Helper()
				conn, err := dial(port)
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
				if s.box != boxBefore || runningInbound(t, s, shadowTLSInboundTag) != shadowTLSBefore || runningInbound(t, s, snellDetourTag) != snellBefore {
					t.Fatal("user update rebuilt the box or an inbound")
				}
			}

			check(alicePort, false)
			if n, err := s.AddUsers([]model.UserSpec{alice}); err != nil || n != 1 {
				t.Fatalf("add Alice: n=%d err=%v", n, err)
			}
			unchanged()
			check(bobPort, false)
			held, err := dial(alicePort)
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
			check(bobPort, true)
			if n, err := s.RemoveUsers([]model.UserSpec{bob}); err != nil || n != 1 {
				t.Fatalf("remove Bob: n=%d err=%v", n, err)
			}
			unchanged()
			check(bobPort, false)
			if err := exchange(held); err != nil {
				t.Fatalf("removing Bob interrupted Alice: %v", err)
			}
			check(alicePort, true)
			traffic, _, _, err := s.GetUserTraffic(context.Background())
			if err != nil || traffic[alice.ID][0] == 0 || traffic[bob.ID][0] == 0 {
				t.Fatalf("missing per-user traffic: %v, err=%v", traffic, err)
			}
			if _, _, err := s.UpdateUsers(nil); err != nil {
				t.Fatal(err)
			}
			unchanged()
			check(alicePort, false)
			if err := exchange(held); err == nil {
				t.Fatal("cleared user's existing connection still works")
			}
			if _, _, err := s.UpdateUsers([]model.UserSpec{alice}); err != nil {
				t.Fatal(err)
			}
			unchanged()
			check(alicePort, true)
		})
	}
}
