package service

import (
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	"golang.org/x/net/proxy"
)

// Panel moves a sing-box node to a port another process holds. Both the first
// failed attempt and a retry inside the backoff window must keep the old
// listener serving.
func TestSingBoxMoveToBusyPortKeepsListenerDuringBackoff(t *testing.T) {
	ctx := context.Background()
	const uuid = "11111111-1111-4111-8111-111111111111"
	target := echoTarget(t)
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	busy, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	busyPort := busy.Addr().(*net.TCPAddr).Port

	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error",
		CustomConfig: filepath.Join(t.TempDir(), "none.json"),
		CustomRoute:  []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}}}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	defer s.kernel.Stop()
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: uuid}})
	spec := &model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: port}
	if err := s.applyNodeConfig(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if !socksReaches(port, uuid, target) {
		t.Fatal("initial node does not relay")
	}

	moved := *spec
	moved.ServerPort = busyPort
	s.applyConfigUpdate(ctx, &moved)
	t.Logf("after attempt 1: running=%v relays=%v pending=%v", s.kernel.IsRunning(), socksReaches(port, uuid, target), s.pendingConfig != nil)
	if !socksReaches(port, uuid, target) {
		t.Fatal("first failed attempt did not keep the old listener")
	}
	// Next poll retries the pending config inside the backoff window.
	s.applyConfigUpdate(ctx, s.pendingConfig)
	if !socksReaches(port, uuid, target) {
		t.Fatalf("retry inside backoff left the node without a listener: running=%v appliedPort=%d", s.kernel.IsRunning(), s.appliedState.Config.ServerPort)
	}
}

// A panel route-only change on a sing-box node is applied with
// router.UpdateRules: no restart, live connections survive.
func TestSingBoxRouteOnlyChangeIsHotApplied(t *testing.T) {
	ctx := context.Background()
	const uuid = "11111111-1111-4111-8111-111111111111"
	target := echoTarget(t)
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error",
		CustomRoute: []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}}}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	defer s.kernel.Stop()
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: uuid}})
	spec := &model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: port}
	if err := s.applyNodeConfig(ctx, spec); err != nil {
		t.Fatal(err)
	}
	dialer, _ := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: uuid, Password: uuid}, &net.Dialer{Timeout: time.Second})
	live, err := dialer.Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()

	changed := *spec
	changed.Routes = []model.RouteRule{{ID: 1, Match: []string{"domain:blocked.example"}, Action: "block"}}
	began := time.Now()
	if err := s.applyNodeConfig(ctx, &changed); err != nil {
		t.Fatal(err)
	}
	took := time.Since(began)
	live.SetDeadline(time.Now().Add(2 * time.Second))
	_, werr := live.Write([]byte("ping"))
	buf := make([]byte, 4)
	_, rerr := io.ReadFull(live, buf)
	t.Logf("route-only change took %v; live connection after: write=%v read=%v", took, werr, rerr)
	if took > time.Second || rerr != nil {
		t.Fatalf("route-only change was disruptive: main loop blocked %v, live connection err=%v", took, rerr)
	}
}

// A failed rebuild whose new listener cannot bind (port held by another
// process) must restore the previous listener within milliseconds: no
// drain-length gap on the old port and no blocked service loop.
func TestSingBoxFailedRebuildRestoresWithoutGap(t *testing.T) {
	ctx := context.Background()
	const uuid = "11111111-1111-4111-8111-111111111111"
	target := echoTarget(t)
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	busy, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error",
		CustomConfig: filepath.Join(t.TempDir(), "none.json"),
		CustomRoute:  []map[string]any{{"ip_cidr": []string{"127.0.0.1/32"}, "outbound": "direct"}}}}
	s := NewWithControlPlane(cfg, &kernelTestControlPlane{})
	defer s.kernel.Stop()
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: uuid}})
	spec := &model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: port}
	if err := s.applyNodeConfig(ctx, spec); err != nil {
		t.Fatal(err)
	}
	// One user with an open connection.
	dialer, _ := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: uuid, Password: uuid}, &net.Dialer{Timeout: time.Second})
	live, err := dialer.Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()

	var refused atomic.Int32
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
			if err != nil {
				refused.Add(1)
			} else {
				c.Close()
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	moved := *spec
	moved.ServerPort = busy.Addr().(*net.TCPAddr).Port
	began := time.Now()
	s.applyConfigUpdate(ctx, &moved)
	took := time.Since(began)
	close(stop)
	<-done
	t.Logf("failed rebuild took %v; refused dials to the old port during it: %d; running=%v relays=%v",
		took, refused.Load(), s.kernel.IsRunning(), socksReaches(port, uuid, target))
	if took > time.Second || refused.Load() > 0 {
		t.Fatalf("failed attempt blocked the loop %v and left the old port closed (%d refused dials)", took, refused.Load())
	}
}
