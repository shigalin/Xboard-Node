//go:build with_clash_api

package singbox

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

// Moving the inbound away from a port does not make an in-place Start safe
// when the candidate's Clash API controller needs that old inbound port.
func TestCanReplaceInPlaceWithNewClashAPIOnOldInboundPort(t *testing.T) {
	users := []model.UserSpec{{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}}
	s := New(config.KernelConfig{Type: "singbox", ConfigDir: t.TempDir(), LogLevel: "error", CustomConfigData: map[string]any{}})
	defer s.Stop()
	oldPort := freePort(t)
	oldSpec := &model.NodeSpec{Protocol: "socks", ListenIP: "127.0.0.1", ServerPort: oldPort}
	if err := s.Start(oldSpec, users, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}

	moved := *oldSpec
	moved.ServerPort = freePort(t)
	for moved.ServerPort == oldPort {
		moved.ServerPort = freePort(t)
	}
	s.SetCustomConfig(map[string]any{"experimental": map[string]any{
		"clash_api": map[string]any{"external_controller": fmt.Sprintf("[::]:%d", oldPort)},
	}})
	if s.CanReplaceInPlace(&moved) {
		// A wrong yes must exercise the same Start path the rebuild caller uses.
		if err := s.Start(&moved, users, kernel.TLSCert{}); err != nil {
			t.Fatalf("in-place replacement offered but Start could not bind the new controller: %v", err)
		}
		t.Fatal("new exclusive config must not be replaced in place")
	}
	// The old box has no exclusive resources, so releasing its inbound alone
	// frees the port for the new controller without stopping the entire box.
	if !s.ReleaseListeners() {
		t.Fatal("old box should release its inbound listener")
	}
	if err := s.Start(&moved, users, kernel.TLSCert{}); err != nil {
		t.Fatalf("replacement after releasing the old inbound failed: %v", err)
	}
	if !s.IsRunning() {
		t.Fatal("replacement is not running")
	}
	for _, port := range []int{oldPort, moved.ServerPort} {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err != nil {
			t.Fatalf("replacement is not listening on port %d: %v", port, err)
		}
		conn.Close()
	}
}
