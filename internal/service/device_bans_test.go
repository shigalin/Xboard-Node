package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/cedar2025/xboard-node/internal/panel"
)

type recoveringBanControlPlane struct {
	*kernelTestControlPlane
	calls int
}

func (p *recoveringBanControlPlane) SyncDeviceBans(context.Context, map[int]int64) (map[int]int64, error) {
	p.calls++
	if p.calls == 1 {
		return nil, errors.New("device ban API unavailable")
	}
	return map[int]int64{42: time.Now().Add(3 * time.Minute).UnixMilli()}, nil
}

func TestDeviceBanSyncFailureDoesNotAbortStartupAndCanRecover(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := &config.Config{Kernel: config.KernelConfig{Type: "singbox"}}
		cp := &recoveringBanControlPlane{
			kernelTestControlPlane: &kernelTestControlPlane{node: panel.NodeConfig{Protocol: "vless"}, kcfg: cfg.Kernel},
		}
		s := NewWithControlPlane(cfg, cp)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := s.initialSetup(ctx); err != nil || s.lastConfig == nil {
			t.Fatalf("failed to start after optional API failure: %v", err)
		}
		lease, err := s.devices.Acquire(42, "", "192.0.2.1", 1)
		if err != nil {
			t.Fatal(err)
		}
		closed := make(chan struct{})
		lease.Bind(func() { close(closed) })
		go s.syncDeviceBans(ctx, cp)
		synctest.Wait()
		time.Sleep(time.Minute)
		synctest.Wait()
		select {
		case <-closed:
		default:
			t.Fatal("background recovery did not apply the ban")
		}
	})
}

func TestDeviceBanReporterSendsLocalBreachImmediately(t *testing.T) {
	const uid = 42
	sent := make(chan int64, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report struct {
			NodeID int           `json:"node_id"`
			Bans   map[int]int64 `json:"device_bans"`
		}
		if r.Method != http.MethodPost || r.URL.Path != "/api/v2/server/device-bans" {
			t.Errorf("unexpected device ban request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil || report.NodeID != 1 || len(report.Bans) != 1 {
			t.Errorf("incorrect local ban report: node=%d bans=%v error=%v", report.NodeID, report.Bans, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"device_bans": report.Bans})
		sent <- report.Bans[uid]
	}))
	defer server.Close()
	cp := controlplane.NewPanelControlPlane(config.PanelConfig{URL: server.URL, NodeID: 1}, config.WSConfig{}, config.KernelConfig{})
	s := &Service{devices: limiter.NewDeviceManager(0)}
	s.devices.ApplyDeviceBans(map[int]int64{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.syncDeviceBans(ctx, cp)
	}()
	defer func() { cancel(); <-done }()

	lease, err := s.devices.Acquire(uid, "", "192.0.2.1", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	start := time.Now()
	if _, err := s.devices.Acquire(uid, "", "198.51.100.2", 1); !errors.Is(err, limiter.ErrDeviceLimit) {
		t.Fatalf("could not trigger local ban: %v", err)
	}
	select {
	case deadline := <-sent:
		if deadline < start.Add(180*time.Second).UnixMilli() ||
			deadline > time.Now().Add(180*time.Second).UnixMilli() {
			t.Fatalf("reported deadline %d is outside the expected 180-second window", deadline)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("device ban was not reported immediately")
	}
}
