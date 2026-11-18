package singbox

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	Mtd "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestSnellReloadRevokesReuse(t *testing.T) {
	const firstPSK = "snell-reload-test-first"
	const secondPSK = "snell-reload-test-second"
	user := model.UserSpec{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}
	users := []model.UserSpec{user}
	for _, tc := range []struct {
		name, before, after, psk, mode string
		version                        int
		direct                         bool
	}{
		{"v5-require-userkey", "shared", "shared_userkey", firstPSK, "", 5, false},
		{"v5-rotate-psk", "shared_userkey", "shared_userkey", secondPSK, "", 5, false},
		{"v6-require-userkey", "shared", "shared_userkey", firstPSK, "default", 6, false},
		{"v6-rotate-psk", "shared_userkey", "shared_userkey", secondPSK, "default", 6, false},
		{"v6-change-mode", "shared_userkey", "shared_userkey", firstPSK, "unshaped", 6, false},
		{"v6-independent-psk", "user", "user", firstPSK, "unshaped", 6, false},
		{"v5-direct-rotate-psk", "shared_userkey", "shared_userkey", secondPSK, "", 5, true},
		{"v6-direct-rotate-psk", "shared_userkey", "shared_userkey", secondPSK, "default", 6, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest := startSnellEcho(t)
			s := newSnellTestKernel(t)
			spec := &model.NodeSpec{Protocol: "snell", Version: tc.version, ServerKey: firstPSK,
				PSKMode: tc.before, Mode: "default"}
			if !tc.direct {
				spec.ShadowTLSServer = "127.0.0.1"
				spec.ShadowTLSPort = startTLSServer(t)
			}
			if !tc.direct && tc.before != "shared" {
				spec.ShadowTLSPassword = testSharedShadowTLSPassword
			}
			startSnellTestNode(t, s, spec, users)
			old := newSnellReloadClient(t, spec, user.UUID)
			defer old.Close()
			for range 2 {
				if err := exchangeReusableSnell(old, dest); err != nil {
					t.Fatalf("reusable connection before reload: %v", err)
				}
			}
			next := *spec
			next.PSKMode, next.ServerKey, next.Mode = tc.after, tc.psk, tc.mode
			if err := s.Reload(&next, users, kernel.TLSCert{}); err != nil {
				t.Fatal(err)
			}
			err := exchangeReusableSnell(old, dest)
			if err == nil {
				t.Fatal("a pre-reload session still carried a Snell request")
			}
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				t.Fatalf("the pre-reload session stalled instead of closing: %v", err)
			}
			fresh := newSnellReloadClient(t, &next, user.UUID)
			defer fresh.Close()
			if err := exchangeReusableSnell(fresh, dest); err != nil {
				t.Fatalf("updated credentials did not work: %v", err)
			}
		})
	}
}

func TestSnellShadowTLSRebindClosesRetiredConnections(t *testing.T) {
	user := model.UserSpec{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}
	users := []model.UserSpec{user}
	dest := startSnellEcho(t)
	s := newSnellTestKernel(t)
	spec := &model.NodeSpec{Protocol: "snell", Version: 6, ServerKey: "snell-reload-test-psk", PSKMode: "shared_userkey",
		ShadowTLSServer: "127.0.0.1", ShadowTLSPort: startTLSServer(t), ShadowTLSPassword: testSharedShadowTLSPassword}
	startSnellTestNode(t, s, spec, users)
	conn := openSnellTestStream(t, spec, user.UUID, dest)
	requireSnellEcho(t, conn, "before reload")

	next := *spec
	next.ShadowTLSPassword = "replacement-shadowtls-test-password"
	next.ShadowTLSPort = startTLSServer(t)
	if err := s.Reload(&next, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	// Observe closure without sending any more data on the retiring connection.
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); !testSnellPeerClosed(err) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("expected the retired ShadowTLS connection to close, got %v", err)
	}
	replacement := openSnellTestStream(t, &next, user.UUID, dest)
	requireSnellEcho(t, replacement, "after reload")
}

func TestSnellSharedPSKDrainsActiveConnections(t *testing.T) {
	for _, tc := range []struct {
		name    string
		replace bool
	}{
		{"stop-direct", false},
		{"replace-shadowtls", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := model.UserSpec{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}
			users := []model.UserSpec{user}
			dest := startSnellEcho(t)
			s := newSnellTestKernel(t)
			spec := &model.NodeSpec{Protocol: "snell", Version: 6, ServerKey: "snell-drain-test-psk", PSKMode: "shared"}
			if tc.replace {
				spec.ShadowTLSServer = "127.0.0.1"
				spec.ShadowTLSPort = startTLSServer(t)
			}
			startSnellTestNode(t, s, spec, users)
			conn := openSnellTestStream(t, spec, user.UUID, dest)
			const before = "before releasing listener"
			const during = "during drain"
			requireSnellEcho(t, conn, before)

			if tc.replace {
				if !s.ReleaseListeners() {
					t.Fatal("failed to release the shared PSK listener")
				}
				if err := s.Start(spec, users, kernel.TLSCert{}); err != nil {
					t.Fatalf("replace on the same port: %v", err)
				}
			} else {
				go s.Stop()
				addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(spec.ServerPort))
				deadline := time.Now().Add(2 * time.Second)
				for {
					probe, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
					if errors.Is(err, syscall.ECONNREFUSED) {
						break
					}
					if err != nil || time.Now().After(deadline) {
						t.Fatalf("listener failed to close before draining: %v", err)
					}
					probe.Close()
					time.Sleep(10 * time.Millisecond)
				}
			}
			requireSnellEcho(t, conn, during)
			conn.Close()
			s.Stop()
			traffic, _, _, err := s.GetUserTraffic(t.Context())
			want := int64(len(before) + len(during))
			if err != nil || traffic[user.ID] != [2]int64{want, want} {
				t.Fatalf("final traffic = %v, err = %v, want %d bytes each way", traffic[user.ID], err, want)
			}
		})
	}
}

func startSnellEcho(t *testing.T) Mtd.Socksaddr {
	t.Helper()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { target.Close() })
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				io.Copy(conn, conn)
			}()
		}
	}()
	return Mtd.ParseSocksaddr(target.Addr().String())
}

func newSnellTestKernel(t *testing.T) *SingBox {
	t.Helper()
	s := New(config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error",
		CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}},
	})
	t.Cleanup(s.Stop)
	return s
}

func openSnellTestStream(t *testing.T, spec *model.NodeSpec, uuid string, dest Mtd.Socksaddr) net.Conn {
	t.Helper()
	client := newSnellReloadClient(t, spec, uuid)
	t.Cleanup(func() { client.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func requireSnellEcho(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("write %q: %v", payload, err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != payload {
		t.Fatalf("echo %q: got %q, err = %v", payload, reply, err)
	}
}

type snellReloadClient interface {
	DialContext(context.Context, Mtd.Socksaddr) (net.Conn, error)
	Close() error
}

func newSnellReloadClient(t *testing.T, spec *model.NodeSpec, uuid string) snellReloadClient {
	t.Helper()
	password, psk, userkey := uuid, spec.ServerKey, ""
	if spec.ShadowTLSPassword != "" {
		password = spec.ShadowTLSPassword
	}
	if spec.PSKMode == "user" {
		psk = uuid
	} else if spec.PSKMode == "shared_userkey" || spec.ShadowTLSServer == "" {
		userkey = uuid
	}
	server := Mtd.ParseSocksaddrHostPort("127.0.0.1", uint16(spec.ServerPort))
	dialer := &singleSnellDialer{}
	if spec.ShadowTLSServer != "" {
		dialer.client = newTestShadowTLSClient(t, spec.ServerPort, password)
	}
	if spec.Version == 5 {
		client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(psk), UserKey: []byte(userkey), Reuse: true, Server: server, Dialer: dialer})
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	mode, err := snellv6.ParseMode(spec.Mode)
	if err != nil {
		t.Fatal(err)
	}
	client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(psk), UserKey: []byte(userkey), Mode: mode,
		Reuse: true, Server: server, Dialer: dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// A second successful request proves the same transport was reused.
type singleSnellDialer struct {
	N.Dialer
	client *shadowtls.Client
	dialed bool
}

func (d *singleSnellDialer) DialContext(ctx context.Context, network string, server Mtd.Socksaddr) (net.Conn, error) {
	if d.dialed {
		return nil, errors.New("test permits only one transport")
	}
	d.dialed = true
	if d.client == nil {
		return (&net.Dialer{}).DialContext(ctx, network, server.String())
	}
	return d.client.DialContext(ctx)
}

func exchangeReusableSnell(client snellReloadClient, dest Mtd.Socksaddr) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, dest)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(conn, "echo"); err != nil {
		return err
	}
	if err := conn.(N.WriteCloser).CloseWrite(); err != nil {
		return err
	}
	reply, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	if string(reply) != "echo" {
		return errors.New("Snell did not return the echo payload")
	}
	return conn.Close()
}
