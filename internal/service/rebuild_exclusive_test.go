//go:build with_clash_api

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
)

// A config that binds or locks resources besides its inbounds (clash_api
// controller, cache_file) cannot be replaced by releasing only the listeners.
// A valid rebuild must still succeed and keep the node serving.
func testRebuildWithNonInboundResource(t *testing.T, custom string) {
	ctx := context.Background()
	const uuid = "11111111-1111-4111-8111-111111111111"
	target := echoTarget(t)
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "custom.json")
	if err := os.WriteFile(path, []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox", ConfigDir: dir, LogLevel: "error",
		CustomConfig: path,
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

	// A custom_config content change always rebuilds: add an outbound.
	updated := custom[:len(custom)-1] + `,"outbounds":[{"type":"direct","tag":"exit-b"}]}`
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	err = s.applyNodeConfig(ctx, spec)
	t.Logf("rebuild result: %v", err)
	if !s.kernel.IsRunning() || !socksReaches(port, uuid, target) {
		t.Fatalf("rebuild left the node without a listener: running=%v err=%v", s.kernel.IsRunning(), err)
	}
	if err != nil {
		t.Fatalf("a valid change could not be applied: %v", err)
	}
}

func TestSingBoxRebuildWithClashAPI(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	testRebuildWithNonInboundResource(t, fmt.Sprintf(`{"experimental":{"clash_api":{"external_controller":"127.0.0.1:%d"}}}`, p))
}

func TestSingBoxRebuildWithCacheFile(t *testing.T) {
	cachePath, _ := json.Marshal(filepath.Join(t.TempDir(), "cache.db"))
	testRebuildWithNonInboundResource(t, fmt.Sprintf(`{"experimental":{"cache_file":{"enabled":true,"path":%s}}}`, cachePath))
}
