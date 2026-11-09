//go:build with_quic

package service

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/cert"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/model"
)

func TestKernelSwitchWaitsForCertificateAndRetriesREST304(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "late.pem"), filepath.Join(dir, "late.key")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	const uuid = "11111111-1111-4111-8111-111111111111"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/config"):
			if r.Header.Get("If-None-Match") == `"cert-v1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"cert-v1"`)
			json.NewEncoder(w).Encode(map[string]any{
				"protocol": "hysteria", "version": 2, "listen_ip": "127.0.0.1", "server_port": port,
				"cert_config": map[string]any{"cert_mode": "file", "cert_file": certPath, "key_file": keyPath},
			})
		case strings.HasSuffix(r.URL.Path, "/user"):
			json.NewEncoder(w).Encode(map[string]any{"users": []map[string]any{{"id": 1, "uuid": uuid}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cfg := &config.Config{
		Panel:  config.PanelConfig{URL: server.URL, NodeID: 1},
		Kernel: config.KernelConfig{Type: "xray", ConfigDir: t.TempDir(), LogLevel: "error"},
		Cert:   config.CertConfig{CertDir: t.TempDir()},
	}
	s := NewWithControlPlane(cfg, controlplane.NewPanelControlPlane(cfg.Panel, cfg.WS, cfg.Kernel))
	defer func() { s.kernel.Stop() }()
	previous := &model.NodeSpec{Protocol: "vless", Network: "tcp", ListenIP: "127.0.0.1", ServerPort: port}
	s.lastConfig = previous
	s.updateUserState([]model.UserSpec{{ID: 1, UUID: uuid}})
	if !s.startKernel(previous, s.lastUsers) {
		t.Fatal("start original Xray kernel")
	}
	old := s.kernel
	defer old.Stop()
	pull := func() pullResult {
		t.Helper()
		s.pullViaAPIAsync(ctx)
		select {
		case result := <-s.pullResults:
			s.applyPullResult(ctx, result)
			return result
		case <-time.After(10 * time.Second):
			t.Fatal("poll timed out")
			return pullResult{}
		}
	}
	if result := pull(); result.config == nil {
		t.Fatal("expected initial config response")
	}
	if s.kernel != old || !old.IsRunning() || s.lastConfig != previous {
		t.Error("unavailable certificate replaced the running kernel or accepted config")
	}

	generated := cert.NewManager(config.CertConfig{CertMode: "self"})
	if err := generated.Start(ctx); err != nil {
		t.Fatal(err)
	}
	material := generated.TLSCert()
	if err := os.WriteFile(certPath, material.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, material.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if result := pull(); result.config != nil {
		t.Fatal("expected HTTP 304 to suppress the unchanged config")
	}
	if s.kernel.Name() != "sing-box" || !s.kernel.IsRunning() || !s.cert.HasCert() || old.IsRunning() {
		t.Fatal("304 retry did not prepare the certificate and complete the kernel switch")
	}
	recovered := s.kernel
	pull()
	if s.kernel != recovered || !s.kernel.IsRunning() || s.lastConfigHash != computeConfigHash(s.lastConfig) {
		t.Fatal("unchanged poll disrupted the recovered kernel")
	}
}
