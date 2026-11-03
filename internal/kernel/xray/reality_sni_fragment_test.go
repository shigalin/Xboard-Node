package xray

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

type fragmentedHelloConn struct {
	net.Conn
	sent bool
}

type delayedHelloConn struct {
	net.Conn
	sent bool
}

func (c *delayedHelloConn) Write(p []byte) (int, error) {
	if !c.sent && len(p) > 1 {
		c.sent = true
		n, err := c.Conn.Write(p[:1])
		if err != nil {
			return n, err
		}
		// Longer than the generic Xray sniffer's 200 ms collection window.
		time.Sleep(300 * time.Millisecond)
		m, err := c.Conn.Write(p[1:])
		return n + m, err
	}
	return c.Conn.Write(p)
}

func (c *fragmentedHelloConn) Write(p []byte) (int, error) {
	if !c.sent && len(p) > 20 && p[0] == 22 {
		c.sent = true
		n := int(binary.BigEndian.Uint16(p[3:5]))
		if n+5 <= len(p) {
			cut := 20 // split ClientHello before SNI, into two valid TLS records
			a := append([]byte(nil), p[:5]...)
			binary.BigEndian.PutUint16(a[3:5], uint16(cut))
			a = append(a, p[5:5+cut]...)
			b := append([]byte(nil), p[:5]...)
			binary.BigEndian.PutUint16(b[3:5], uint16(n-cut))
			b = append(b, p[5+cut:5+n]...)
			a = append(a, b...)
			a = append(a, p[5+n:]...)
			_, err := c.Conn.Write(a)
			if err != nil {
				return 0, err
			}
			return len(p), nil
		}
	}
	return c.Conn.Write(p)
}
func TestRealitySNIFragmentedClientHello(t *testing.T) {
	site := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer site.Close()
	r, err := startRealitySNIRouter(map[string]string{"one.example.com": site.Listener.Addr().String()}, site.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	target := r.listener.Addr().String()
	for _, tt := range []struct {
		name, net, addr string
		fragmented      bool
	}{{"direct fragmented", "tcp", site.Listener.Addr().String(), true}, {"router normal", "unix", target, false}, {"router fragmented", "unix", target, true}} {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.Dial(tt.net, tt.addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			if tt.fragmented {
				conn = &fragmentedHelloConn{Conn: conn}
			}
			tlsconn := tls.Client(conn, &tls.Config{ServerName: "one.example.com", InsecureSkipVerify: true})
			if err := tlsconn.Handshake(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRealitySNIPublicFragmentedClientHello(t *testing.T) {
	site := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	site.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	site.StartTLS()
	defer site.Close()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, enable := range []bool{false, true} {
		label := "without_router"
		if enable {
			label = "with_router"
		}
		t.Run(label, func(t *testing.T) {
			reserve, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := reserve.Addr().(*net.TCPAddr).Port
			addr := reserve.Addr().String()
			reserve.Close()
			kc := config.KernelConfig{Type: "xray", LogLevel: "error"}
			if enable {
				kc.RealityTargets = map[string]string{"one.example.com": site.Listener.Addr().String(), "two.example.com": site.Listener.Addr().String()}
			}
			server := New(kc)
			nc := &model.NodeSpec{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: port, Network: "tcp", TLS: 2, TLSSettings: M{"server_name": "one.example.com", "private_key": base64.RawURLEncoding.EncodeToString(key.Bytes()), "short_id": "abcd", "dest": site.Listener.Addr().String()}}
			if enable {
				nc.TLSSettings["server_name"] = "one.example.com,two.example.com"
			}
			if err := server.Start(nc, []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}}, kernel.TLSCert{}); err != nil {
				t.Fatal(err)
			}
			defer server.Stop()
			for _, name := range []string{"normal", "fragmented", "delayed"} {
				t.Run(name, func(t *testing.T) {
					conn, err := net.Dial("tcp", addr)
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					if name == "fragmented" {
						conn = &fragmentedHelloConn{Conn: conn}
					} else if name == "delayed" {
						conn = &delayedHelloConn{Conn: conn}
					}
					tlsconn := tls.Client(conn, &tls.Config{ServerName: "one.example.com", InsecureSkipVerify: true})
					if err := tlsconn.Handshake(); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}
