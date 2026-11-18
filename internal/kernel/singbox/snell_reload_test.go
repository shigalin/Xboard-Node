package singbox

import (
	"context"
	"errors"
	"io"
	"net"
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
						conn.SetDeadline(time.Now().Add(5 * time.Second))
						io.Copy(conn, conn)
					}()
				}
			}()
			s := New(config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error",
				CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}},
			})
			defer s.Stop()
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
			dest := Mtd.ParseSocksaddr(target.Addr().String())
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
			err = exchangeReusableSnell(old, dest)
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
	if spec.PSKMode == "shared_userkey" {
		userkey = uuid
	} else if spec.PSKMode == "user" {
		psk = uuid
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
