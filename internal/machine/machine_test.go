package machine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestMachineCustomConfigOverrideAppliesToRESTAndWebSocket(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/server/config":
			fmt.Fprint(w, `{"protocol":"hysteria","version":2,"server_port":8388}`)
		case "/api/v2/server/user":
			fmt.Fprint(w, `{"users":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	defaultPath, nodePath := filepath.Join(dir, "xray.json"), filepath.Join(dir, "sing-box.json")
	for path, body := range map[string]string{defaultPath: `{"routing":{}}`, nodePath: `{"route":{}}`} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "config.yml")
	body := fmt.Sprintf(`panel:
  url: %q
machine:
  machine_id: 1
  token: test-token
kernel:
  type: xray
  config_dir: %q
  custom_config: %q
nodes:
  - node_id: 2
    kernel:
      custom_config: %q
`, server.URL, dir, defaultPath, nodePath)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateStartupLayout([]*config.Config{cfg}); err != nil {
		t.Fatal(err)
	}
	nodeCfg := cfg.ExpandMachineNode(2, "hysteria")
	if nodeCfg.Kernel.CustomConfig != nodePath || nodeCfg.Kernel.ConfigDir != filepath.Join(dir, "node-2") {
		t.Fatalf("wrong config for discovered node: %q, %q", nodeCfg.Kernel.CustomConfig, nodeCfg.Kernel.ConfigDir)
	}
	if other := cfg.ExpandMachineNode(3, "vless"); other.Kernel.CustomConfig != defaultPath {
		t.Fatal("node-specific config replaced the machine default")
	}
	o := New(cfg)
	cp := controlplane.NewMachinePanelControlPlane(o.client.ForNode(2), nodeCfg.Kernel, nil, nil)
	snapshot, err := cp.Poll(context.Background())
	if err != nil || snapshot.Config == nil || snapshot.Config.KernelType != "singbox" {
		t.Fatalf("REST did not accept the node-specific config: poll=%v config=%v", err, snapshot.CurrentConfigErr)
	}
	mb := controlplane.NewNodeMailbox()
	mb.MarkReady()
	o.mailboxes[2] = mb
	o.onWSEvent(panel.WSEvent{Type: panel.WSEventSyncConfig, NodeID: 2,
		Config: &panel.NodeConfig{Protocol: "hysteria", Version: 2, ServerPort: 8388}})
	state := mb.DrainIfReady(nil)
	if !state.HasConfig || state.Config.KernelType != "singbox" {
		t.Fatalf("WebSocket did not use the same override as REST: %v", state.ConfigErr)
	}
}
