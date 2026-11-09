package singbox

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"golang.org/x/net/proxy"
)

func TestSingBoxTrafficSurvivesFullRestartAndRepeatedStop(t *testing.T) {
	ctx := context.Background()
	const uuid = "11111111-1111-4111-8111-111111111111"
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
	s := New(config.KernelConfig{
		Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error",
		CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}},
	})
	defer s.Stop()
	start := func() net.Conn {
		t.Helper()
		reserve, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := reserve.Addr().(*net.TCPAddr).Port
		reserve.Close()
		if err := s.Start(&model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: port}, []model.UserSpec{{ID: 1, UUID: uuid}}, kernel.TLSCert{}); err != nil {
			t.Fatal(err)
		}
		dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: uuid, Password: uuid}, &net.Dialer{Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		conn, err := dialer.Dial("tcp", target.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		return conn
	}
	transfer := func(conn net.Conn, size int) {
		t.Helper()
		if n, err := conn.Write(make([]byte, size)); err != nil || n != size {
			t.Fatalf("write = %d, err = %v; want %d bytes", n, err, size)
		}
		if _, err := io.ReadFull(conn, make([]byte, size)); err != nil {
			t.Fatal(err)
		}
	}
	assertTraffic := func(want int64) {
		t.Helper()
		traffic, _, _, err := s.GetUserTraffic(ctx)
		if err != nil || traffic[1] != [2]int64{want, want} {
			t.Fatalf("traffic = %v, err = %v; want [%d %d]", traffic, err, want, want)
		}
	}
	old := start()
	transfer(old, 17)
	current := start()
	transfer(old, 4096)
	transfer(current, 23)
	// A client read can finish before the server's Write counter update.
	// Wait only for the live snapshot; Stop must settle final counters itself.
	deadline := time.Now().Add(time.Second)
	for {
		traffic, _, _, err := s.GetUserTraffic(ctx)
		if err == nil && traffic[1] == [2]int64{4136, 4136} {
			break
		}
		if err != nil || time.Now().After(deadline) {
			t.Fatalf("live traffic = %v, err = %v; want [4136 4136]", traffic, err)
		}
		time.Sleep(time.Millisecond)
	}
	current.Close()
	// Leave the old session open: Stop must also hard-close instances replaced
	// by Start, then publish all their final counters before returning.
	s.Stop()
	assertTraffic(4136)
	old.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := old.Read(make([]byte, 1)); err == nil {
		t.Fatal("previous instance connection remained open after Stop")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("Stop returned before closing the previous instance connection")
	}
	_, _, count, err := s.GetUserTraffic(ctx)
	if err != nil || count != 0 || s.IsRunning() {
		t.Fatalf("stopped kernel: connections = %d, err = %v", count, err)
	}
	s.Stop()
	assertTraffic(4136)
	restarted := start()
	transfer(restarted, 7)
	restarted.Close()
	s.Stop()
	assertTraffic(4143)
}
