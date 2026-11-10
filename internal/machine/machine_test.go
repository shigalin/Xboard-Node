package machine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/panel"
	"github.com/gorilla/websocket"
)

// A WS sync.nodes can arrive before initial nodes have started. Initial startup
// must serialize with rediscovery so the empty list cannot be applied first.
func TestMachineInitialNodesAppliedBeforeWSRediscovery(t *testing.T) {
	var requests atomic.Int32
	startupSerialized := make(chan bool, 1)
	wsConnected := make(chan struct{}, 1)
	rediscovered := make(chan struct{}, 1)
	releaseConfig := make(chan struct{})
	var closeConfigOnce sync.Once
	upgrader := websocket.Upgrader{}
	var o *Orchestrator
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/server/machine/nodes":
			if requests.Add(1) == 1 {
				fmt.Fprint(w, `{"nodes":[{"id":2,"type":"vless"}]}`)
			} else {
				fmt.Fprint(w, `{"nodes":[]}`)
				select {
				case rediscovered <- struct{}{}:
				default:
				}
			}
		case "/api/v2/server/handshake":
			unlocked := o.discoveryMu.TryLock()
			if unlocked {
				o.discoveryMu.Unlock()
			}
			startupSerialized <- !unlocked
			fmt.Fprintf(w, `{"websocket":{"enabled":true,"ws_url":%q}}`, "ws"+strings.TrimPrefix(server.URL, "http")+"/ws")
		case "/ws":
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			wsConnected <- struct{}{}
			if err := conn.WriteJSON(map[string]any{"event": "auth.success"}); err != nil {
				return
			}
			if err := conn.WriteJSON(map[string]any{"event": panel.WSEventSyncNodes, "data": map[string]any{}}); err != nil {
				return
			}
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		case "/api/v2/server/config":
			<-releaseConfig // keep the initial node alive through the handshake
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := &config.Config{Panel: config.PanelConfig{URL: server.URL}, Machine: &config.MachineConfig{MachineID: 1, Token: "test-token"}, Kernel: config.KernelConfig{Type: "xray", ConfigDir: t.TempDir()}}
	o = New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- o.Run(ctx) }()
	defer func() {
		closeConfigOnce.Do(func() { close(releaseConfig) })
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Run did not stop")
		}
	}()

	select {
	case serialized := <-startupSerialized:
		if !serialized {
			t.Fatal("initial node startup is not serialized with WS rediscovery")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("machine WS handshake did not run")
	}
	select {
	case <-wsConnected:
	case <-time.After(5 * time.Second):
		t.Fatal("machine WS did not connect")
	}
	select {
	case <-rediscovered:
	case <-time.After(5 * time.Second):
		t.Fatal("sync.nodes did not trigger rediscovery")
	}
	// Release the blocked service so stopNode can complete, then observe the
	// empty rediscovery after it has finished reconciling.
	closeConfigOnce.Do(func() { close(releaseConfig) })
	o.discoveryMu.Lock()
	o.discoveryMu.Unlock()
	o.mu.Lock()
	_, present := o.nodes[2]
	o.mu.Unlock()
	if present {
		t.Fatal("node removed by sync.nodes is still tracked")
	}
}

func TestEmptyMachineStartsWebSocket(t *testing.T) {
	connected := make(chan struct{}, 1)
	upgrader := websocket.Upgrader{}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/server/machine/nodes":
			fmt.Fprint(w, `{"nodes":[]}`)
		case "/api/v2/server/handshake":
			fmt.Fprintf(w, `{"websocket":{"enabled":true,"ws_url":%q}}`, "ws"+strings.TrimPrefix(server.URL, "http")+"/ws")
		case "/ws":
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			connected <- struct{}{}
			if err := conn.WriteJSON(map[string]any{"event": "auth.success"}); err != nil {
				return
			}
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := &config.Config{Panel: config.PanelConfig{URL: server.URL}, Machine: &config.MachineConfig{MachineID: 1, Token: "test-token"}}
	o := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- o.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Run did not stop")
		}
	}()
	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		t.Fatal("empty machine did not connect its WS")
	}
}

func TestRediscoveredMachineNodeSharedCertDirNotStarted(t *testing.T) {
	for _, alias := range []bool{false, true} {
		name := "direct"
		if alias {
			name = "symlink"
		}
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			certDir := filepath.Join(base, "node-2", "certs")
			configuredDir := certDir
			if alias {
				if err := os.MkdirAll(filepath.Dir(certDir), 0o755); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(base, "alias")
				if err := os.Symlink(filepath.Dir(certDir), link); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				configuredDir = filepath.Join(link, "certs") // leaf does not yet exist
			}
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v2/server/machine/nodes":
					fmt.Fprint(w, `{"nodes":[{"id":1,"type":"vless"},{"id":2,"type":"vless"}]}`)
				case "/api/v2/server/config":
					select {
					case <-release:
					case <-r.Context().Done():
					}
					http.Error(w, "unavailable", http.StatusServiceUnavailable)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			path := filepath.Join(base, "config.yml")
			body := fmt.Sprintf("panel:\n  url: %q\nmachine:\n  machine_id: 1\n  token: test-token\nkernel:\n  type: xray\n  config_dir: %q\nnodes:\n  - node_id: 1\n    cert:\n      cert_dir: %q\n", server.URL, base, configuredDir)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			o := New(cfg)
			ctx, cancel := context.WithCancel(context.Background())
			defer func() {
				cancel()
				close(release)
				o.stopAll()
			}()
			o.rediscover(ctx)
			o.mu.Lock()
			_, first := o.nodes[1]
			_, second := o.nodes[2]
			o.mu.Unlock()
			if !first || second {
				t.Fatalf("discovered shared cert_dir started duplicate service: first=%v second=%v", first, second)
			}
		})
	}
}

func TestFailedMachineNodeRestartsOnRediscovery(t *testing.T) {
	configRequests := make(chan struct{}, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/server/machine/nodes":
			fmt.Fprint(w, `{"nodes":[{"id":2,"type":"vless","name":"test"}]}`)
		case "/api/v2/server/config":
			configRequests <- struct{}{}
			http.Error(w, "initial config unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := &config.Config{
		Panel:   config.PanelConfig{URL: server.URL},
		Machine: &config.MachineConfig{MachineID: 1, Token: "test-token"},
		Kernel:  config.KernelConfig{Type: "xray", ConfigDir: t.TempDir()},
	}
	o := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer o.stopAll()

	mn := panel.MachineNode{ID: 2, Type: "vless", Name: "test"}
	o.startNode(ctx, mn)
	select {
	case <-configRequests:
	case <-time.After(5 * time.Second):
		t.Fatal("first node did not reach Initial")
	}
	o.mu.Lock()
	first := o.nodes[mn.ID]
	o.mu.Unlock()
	if first == nil {
		t.Fatal("first node handle missing before exit")
	}
	select {
	case <-first.done:
	case <-time.After(5 * time.Second):
		t.Fatal("first node did not exit after Initial failed")
	}

	o.mu.Lock()
	_, retained := o.nodes[mn.ID]
	o.mu.Unlock()
	if retained {
		t.Fatal("failed node still tracked after exit")
	}
	o.eventsMu.RLock()
	_, retained = o.mailboxes[mn.ID]
	o.eventsMu.RUnlock()
	if retained {
		t.Fatal("failed node mailbox still registered after exit")
	}

	o.rediscover(ctx)
	select {
	case <-configRequests:
	case <-time.After(5 * time.Second):
		t.Fatal("rediscovery did not restart failed node")
	}
}

func TestConcurrentRediscoveryDoesNotLoseReaddedNode(t *testing.T) {
	var discoveries atomic.Int32
	configRequests := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/server/machine/nodes":
			if discoveries.Add(1) == 1 {
				fmt.Fprint(w, `{"nodes":[]}`)
			} else {
				fmt.Fprint(w, `{"nodes":[{"id":2,"type":"vless","name":"test"}]}`)
			}
		case "/api/v2/server/config":
			configRequests <- struct{}{}
			http.Error(w, "initial config unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := &config.Config{Panel: config.PanelConfig{URL: server.URL}, Machine: &config.MachineConfig{MachineID: 1, Token: "test-token"}, Kernel: config.KernelConfig{Type: "xray", ConfigDir: t.TempDir()}}
	o := New(cfg)
	cancelled := make(chan struct{})
	old := &nodeHandle{cancel: func() { close(cancelled) }, done: make(chan struct{}), mailbox: controlplane.NewNodeMailbox()}
	o.nodes[2] = old
	o.mailboxes[2] = old.mailbox
	ctx := context.Background()
	firstDone := make(chan struct{})
	go func() { o.rediscover(ctx); close(firstDone) }()
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("first rediscovery did not start stopping the old node")
	}
	secondDone := make(chan struct{})
	go func() { o.rediscover(ctx); close(secondDone) }()
	// Give an uncoordinated second discovery time to observe the stale handle.
	deadline := time.After(100 * time.Millisecond)
	for discoveries.Load() < 2 {
		select {
		case <-deadline:
			goto finishStop
		default:
			time.Sleep(time.Millisecond)
		}
	}
finishStop:
	o.unregisterNode(2, old)
	close(old.done)
	for _, done := range []<-chan struct{}{firstDone, secondDone} {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("rediscovery did not finish")
		}
	}
	select {
	case <-configRequests:
	case <-time.After(5 * time.Second):
		t.Fatal("node re-added during shutdown was not restarted")
	}
	o.stopAll()
}

func TestStaleMachineNodeCleanupDoesNotRemoveReplacement(t *testing.T) {
	o := New(&config.Config{Machine: &config.MachineConfig{MachineID: 1}})
	old := &nodeHandle{mailbox: controlplane.NewNodeMailbox()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	replacement := &nodeHandle{cancel: cancel, mailbox: controlplane.NewNodeMailbox()}
	status := make(chan controlplane.StatusChange, 1)
	o.nodes[2] = replacement
	o.mailboxes[2] = replacement.mailbox
	o.statuses[2] = status

	o.unregisterNode(2, old)
	o.registerNode(2, old, make(chan controlplane.StatusChange, 1))
	o.stopNode(2, old)

	if o.nodes[2] != replacement || o.mailboxes[2] != replacement.mailbox || o.statuses[2] != status {
		t.Fatal("stale node altered replacement mappings")
	}
	select {
	case <-ctx.Done():
		t.Fatal("stale removal cancelled replacement")
	default:
	}
}

func TestMachineStopAllWaitsForCleanupAndPreventsRestarts(t *testing.T) {
	o := New(&config.Config{Machine: &config.MachineConfig{MachineID: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := &nodeHandle{cancel: cancel, done: make(chan struct{}), mailbox: controlplane.NewNodeMailbox()}
	o.nodes[2] = h
	o.mailboxes[2] = h.mailbox
	o.statuses[2] = make(chan controlplane.StatusChange, 1)
	go func() {
		<-ctx.Done()
		o.unregisterNode(2, h)
		close(h.done)
	}()

	o.stopAll()
	if len(o.nodes) != 0 || len(o.mailboxes) != 0 || len(o.statuses) != 0 {
		t.Fatal("stopAll returned before node mappings were cleaned up")
	}
	o.startNode(context.Background(), panel.MachineNode{ID: 2})
	if len(o.nodes) != 0 {
		t.Fatal("node started after stopAll")
	}
}

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
