package xray

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	appstats "github.com/xtls/xray-core/app/stats"
	xrayCore "github.com/xtls/xray-core/core"
	featurebandwidth "github.com/xtls/xray-core/features/bandwidth"
	xraystats "github.com/xtls/xray-core/features/stats"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"golang.org/x/time/rate"
)

func TestToMemoryUserSS2022MatchesInitialConfig(t *testing.T) {
	user := model.UserSpec{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}
	for _, cipher := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		t.Run(cipher, func(t *testing.T) {
			nc := &model.NodeSpec{Cipher: cipher}
			inbound := buildShadowsocks(M{}, nc, []model.UserSpec{user})
			clients := inbound["settings"].(M)["clients"].([]M)
			initialKey, err := base64.StdEncoding.DecodeString(clients[0]["password"].(string))
			if err != nil {
				t.Fatal(err)
			}
			memoryUser, err := toMemoryUser("shadowsocks", nc, user)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(memoryUser.Account.(*ss2022.MemoryAccount).Key, initialKey) {
				t.Fatal("dynamic SS2022 user key differs from initial config")
			}
		})
	}
}

func TestToMemoryUserRejectsRemovedShadowsocksCiphers(t *testing.T) {
	for _, cipher := range []string{"none", "plain"} {
		t.Run(cipher, func(t *testing.T) {
			_, err := toMemoryUser("shadowsocks", &model.NodeSpec{Cipher: cipher}, model.UserSpec{ID: 1, UUID: "test"})
			if err == nil {
				t.Fatal("expected removed Shadowsocks cipher to be rejected")
			}
		})
	}
}

func newStatsManager(t *testing.T) xraystats.Manager {
	t.Helper()
	mgr, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatalf("stats.NewManager() error = %v", err)
	}
	return mgr
}

func mustRegisterCounter(t *testing.T, mgr xraystats.Manager, name string) xraystats.Counter {
	t.Helper()
	counter, err := mgr.RegisterCounter(name)
	if err != nil {
		t.Fatalf("RegisterCounter(%q) error = %v", name, err)
	}
	return counter
}

func counterName(userID int, direction string) string {
	return fmt.Sprintf("user>>>%s>>>traffic>>>%s", userEmail(userID), direction)
}

func newStatsBackedXray(t *testing.T, users []model.UserSpec, ld *LimitDispatcher) (*Xray, xraystats.Manager) {
	t.Helper()
	mgr := newStatsManager(t)
	inst := new(xrayCore.Instance)
	if err := inst.AddFeature(mgr); err != nil {
		t.Fatalf("Instance.AddFeature(stats) error = %v", err)
	}
	x := New(config.KernelConfig{Type: "xray"})
	x.instance = inst
	x.limitDispatcher = ld
	x.users = users
	x.cumTraffic = make(map[int][2]int64)
	x.running.Store(true)
	return x, mgr
}

func TestXrayGetUserTrafficUsesBuiltInStatsAndDispatcherState(t *testing.T) {
	users := []model.UserSpec{
		{ID: 1, UUID: "uuid-1"},
		{ID: 2, UUID: "uuid-2"},
	}

	ld := newTestDispatcher()
	email1 := userEmail(1)
	email2 := userEmail(2)
	ld.UpdateLimits(map[string]int{email1: 1, email2: 2}, nil, nil)
	for i := 0; i < 7; i++ {
		uid, ip := 1, "1.1.1.1"
		if i == 6 {
			uid, ip = 2, "2.2.2.2"
		}
		if _, err := ld.devices.Acquire(uid, ip, 0); err != nil {
			t.Fatal(err)
		}
	}

	x, mgr := newStatsBackedXray(t, users, ld)
	up1 := mustRegisterCounter(t, mgr, counterName(1, "uplink"))
	down1 := mustRegisterCounter(t, mgr, counterName(1, "downlink"))
	up2 := mustRegisterCounter(t, mgr, counterName(2, "uplink"))
	down2 := mustRegisterCounter(t, mgr, counterName(2, "downlink"))
	up1.Add(100)
	down1.Add(200)
	up2.Add(50)
	down2.Add(80)

	traffic, aliveIPs, connCount, err := x.GetUserTraffic(context.Background())
	if err != nil {
		t.Fatalf("GetUserTraffic() error = %v", err)
	}
	if connCount != 7 {
		t.Fatalf("connCount = %d, want 7", connCount)
	}
	if got := traffic[1]; got != [2]int64{100, 200} {
		t.Fatalf("traffic[1] = %v, want [100 200]", got)
	}
	if got := traffic[2]; got != [2]int64{50, 80} {
		t.Fatalf("traffic[2] = %v, want [50 80]", got)
	}
	if !aliveIPs[1]["1.1.1.1"] {
		t.Fatal("expected limited-user IP to be reported")
	}
	if !aliveIPs[2]["2.2.2.2"] {
		t.Fatal("expected unlimited-user IP to be reported")
	}

	up1.Add(30)
	down1.Add(40)
	traffic, _, _, err = x.GetUserTraffic(context.Background())
	if err != nil {
		t.Fatalf("second GetUserTraffic() error = %v", err)
	}
	if got := traffic[1]; got != [2]int64{130, 240} {
		t.Fatalf("traffic[1] after second poll = %v, want [130 240]", got)
	}
	if got := traffic[2]; got != [2]int64{50, 80} {
		t.Fatalf("traffic[2] after second poll = %v, want [50 80]", got)
	}
}

func TestXrayUpdateDispatcherLimitsPropagatesDeviceMetadata(t *testing.T) {
	x := New(config.KernelConfig{Type: "xray"})
	ld := newTestDispatcher()
	x.limitDispatcher = ld

	users := []model.UserSpec{
		{ID: 7, UUID: "uuid-7", DeviceLimit: 2, SpeedLimit: 12},
		{ID: 9, UUID: "uuid-9", DeviceLimit: 0, SpeedLimit: 0},
	}

	x.updateDispatcherLimits(users)

	if got := ld.deviceLimits[userEmail(7)]; got != 2 {
		t.Fatalf("deviceLimits[email] = %d, want 2", got)
	}
	if got := ld.deviceLimits["uuid-7"]; got != 2 {
		t.Fatalf("deviceLimits[uuid] = %d, want 2", got)
	}
	if _, ok := ld.deviceLimits[userEmail(9)]; ok {
		t.Fatal("unexpected device limit entry for unlimited user")
	}
}

func TestXraySetSpeedLimitFuncUsesPatchedCorePath(t *testing.T) {
	x := New(config.KernelConfig{Type: "xray"})
	called := false

	x.SetSpeedLimitFunc(func(string) *rate.Limiter {
		called = true
		return rate.NewLimiter(rate.Limit(1), 1)
	})

	if called {
		t.Fatal("patched xray path should not consult external speed-limit callbacks")
	}

	mu, err := toMemoryUser("vless", &model.NodeSpec{Protocol: "vless"}, model.UserSpec{ID: 1, UUID: "11111111-1111-1111-1111-111111111111", SpeedLimit: 8})
	if err != nil {
		t.Fatalf("toMemoryUser() error = %v", err)
	}
	if mu.Level != 0 {
		t.Fatalf("MemoryUser.Level = %d, want 0", mu.Level)
	}
}

func TestXrayCapabilities(t *testing.T) {
	x := New(config.KernelConfig{Type: "xray"})
	caps := x.Capabilities()
	if !caps.PerUserSpeedLimit || !caps.DeviceLimit || !caps.BuiltInTrafficStats || !caps.AliveIPTracking {
		t.Fatalf("unexpected positive xray capabilities: %+v", caps)
	}
	if caps.ForceCloseConnection || !caps.ForceCloseUser {
		t.Fatalf("unexpected force-close xray capabilities: %+v", caps)
	}
}

func TestXrayUpdateBandwidthLimitsWritesPatchedCoreFeature(t *testing.T) {
	inst := new(xrayCore.Instance)
	bm := featurebandwidth.New()
	if err := inst.AddFeature(bm); err != nil {
		t.Fatalf("Instance.AddFeature(bandwidth) error = %v", err)
	}
	x := New(config.KernelConfig{Type: "xray"})
	x.instance = inst
	x.updateBandwidthLimits([]model.UserSpec{{ID: 1, UUID: "uuid-1", SpeedLimit: 8}})
	lim := bm.GetUserLimiter(userEmail(1))
	if lim == nil {
		t.Fatal("expected patched bandwidth feature to receive user limiter")
	}
}

func TestXrayUpdateBandwidthLimitsUsesSpeedLimitFunc(t *testing.T) {
	inst := new(xrayCore.Instance)
	bm := featurebandwidth.New()
	if err := inst.AddFeature(bm); err != nil {
		t.Fatalf("Instance.AddFeature(bandwidth) error = %v", err)
	}
	x := New(config.KernelConfig{Type: "xray"})
	x.instance = inst
	x.users = []model.UserSpec{{ID: 1, UUID: "uuid-1", SpeedLimit: 8}}
	shared := rate.NewLimiter(7, 7)
	x.SetSpeedLimitFunc(func(uuid string) *rate.Limiter {
		if uuid != "uuid-1" {
			t.Fatalf("unexpected uuid: %s", uuid)
		}
		return shared
	})
	lim := bm.GetUserLimiter(userEmail(1))
	if lim != shared {
		t.Fatal("expected patched bandwidth feature to consume shared limiter from callback")
	}
}

func TestXrayUpdateBandwidthLimitsFallsBackToUserSpeed(t *testing.T) {
	inst := new(xrayCore.Instance)
	bm := featurebandwidth.New()
	if err := inst.AddFeature(bm); err != nil {
		t.Fatalf("Instance.AddFeature(bandwidth) error = %v", err)
	}
	x := New(config.KernelConfig{Type: "xray"})
	x.instance = inst
	x.users = []model.UserSpec{{ID: 2, UUID: "uuid-2", SpeedLimit: 16}}
	x.updateBandwidthLimits(nil)
	if bm.GetUserLimiter(userEmail(2)) == nil {
		t.Fatal("expected fallback limiter derived from user speed")
	}
}

func TestXrayDropBandwidthLimits(t *testing.T) {
	first := model.UserSpec{ID: 1, UUID: "uuid-1"}
	second := model.UserSpec{ID: 2, UUID: "uuid-2"}
	replacement := model.UserSpec{ID: 1, UUID: "uuid-1-new"}

	for _, tc := range []struct {
		name    string
		removed []model.UserSpec
		current []model.UserSpec
		want    map[int]string // user ID to the UUID supplying its limiter
	}{
		{
			name:    "deletes removed user",
			removed: []model.UserSpec{first},
			current: []model.UserSpec{second},
			want:    map[int]string{2: second.UUID},
		},
		{
			name:    "preserves retained user",
			removed: []model.UserSpec{second},
			current: []model.UserSpec{first},
			want:    map[int]string{1: first.UUID},
		},
		{
			name:    "preserves new limiter for same ID with changed UUID",
			removed: []model.UserSpec{first},
			current: []model.UserSpec{replacement, second},
			want:    map[int]string{1: replacement.UUID, 2: second.UUID},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inst := new(xrayCore.Instance)
			bm := featurebandwidth.New()
			if err := inst.AddFeature(bm); err != nil {
				t.Fatalf("Instance.AddFeature(bandwidth) error = %v", err)
			}
			x := New(config.KernelConfig{Type: "xray"})
			x.instance = inst
			limiters := map[string]*rate.Limiter{
				first.UUID:       rate.NewLimiter(100, 100),
				second.UUID:      rate.NewLimiter(200, 200),
				replacement.UUID: rate.NewLimiter(300, 300),
			}
			x.SetSpeedLimitFunc(func(uuid string) *rate.Limiter { return limiters[uuid] })
			x.updateBandwidthLimits([]model.UserSpec{first, second})
			for _, user := range []model.UserSpec{first, second} {
				if bm.GetUserLimiter(userEmail(user.ID)) != limiters[user.UUID] {
					t.Fatalf("initial limiter for user %d was not installed", user.ID)
				}
			}

			// User updates configure the current set before dropping removed users.
			x.updateBandwidthLimits(tc.current)
			x.dropBandwidthLimits(tc.removed, tc.current)

			for _, id := range []int{1, 2} {
				want := limiters[tc.want[id]] // nil for a removed user
				if got := bm.GetUserLimiter(userEmail(id)); got != want {
					t.Errorf("user %d limiter = %p, want %p", id, got, want)
				}
			}
		})
	}
}

func TestXrayUpdateUsersLimitOnlyRefreshesDispatcherAndBandwidth(t *testing.T) {
	x := New(config.KernelConfig{Type: "xray"})
	ld := newTestDispatcher()
	inst := new(xrayCore.Instance)
	bm := featurebandwidth.New()
	if err := inst.AddFeature(bm); err != nil {
		t.Fatalf("Instance.AddFeature(bandwidth) error = %v", err)
	}
	x.instance = inst
	x.limitDispatcher = ld
	x.users = []model.UserSpec{{ID: 1, UUID: "uuid-1", DeviceLimit: 1, SpeedLimit: 8}}

	added, removed, err := x.UpdateUsers([]model.UserSpec{{ID: 1, UUID: "uuid-1", DeviceLimit: 3, SpeedLimit: 16}})
	if err != nil {
		t.Fatalf("UpdateUsers() error = %v", err)
	}
	if added != 0 || removed != 0 {
		t.Fatalf("UpdateUsers() counts = (%d, %d), want (0, 0)", added, removed)
	}
	if got := ld.deviceLimits[userEmail(1)]; got != 3 {
		t.Fatalf("device limit after refresh = %d, want 3", got)
	}
	if bm.GetUserLimiter(userEmail(1)) == nil {
		t.Fatal("expected bandwidth limiter to be refreshed for unchanged user set")
	}
}

func TestXrayRemoveUsersStopsKernelWhenLastUserRemoved(t *testing.T) {
	x := New(config.KernelConfig{Type: "xray"})
	x.instance = new(xrayCore.Instance)
	ld := newTestDispatcher()
	x.limitDispatcher = ld
	x.users = []model.UserSpec{{ID: 1, UUID: "uuid-1"}}
	x.running.Store(true)

	removed, err := x.RemoveUsers([]model.UserSpec{{ID: 1, UUID: "uuid-1"}})
	if err != nil {
		t.Fatalf("RemoveUsers() error = %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	if x.IsRunning() {
		t.Fatal("expected xray to stop when last user is removed")
	}
}

func TestXrayBandwidthConfiguredBeforeSwapAndNeverEmptied(t *testing.T) {
	inst := new(xrayCore.Instance)
	bm := featurebandwidth.New()
	if err := inst.AddFeature(bm); err != nil {
		t.Fatalf("Instance.AddFeature(bandwidth) error = %v", err)
	}
	x := New(config.KernelConfig{Type: "xray"})
	users := []model.UserSpec{{ID: 1, UUID: "uuid-1", SpeedLimit: 8}}
	// Start configures the new instance before it becomes x.instance.
	x.configureBandwidth(inst, users)
	if bm.GetUserLimiter(userEmail(1)) == nil {
		t.Fatal("new instance was not limited before it started accepting")
	}

	x.instance, x.users = inst, users
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			x.updateBandwidthLimits(nil)
		}
	}()
	for {
		select {
		case <-done:
			return
		default:
			if bm.GetUserLimiter(userEmail(1)) == nil {
				t.Fatal("limiter disappeared while limits were refreshed")
			}
		}
	}
}

// A replaced instance keeps feeding cumulative traffic, including for users no
// longer configured, up to and including the read after its hard close.
func TestXrayCountsDrainingInstanceTraffic(t *testing.T) {
	x, mgr := newStatsBackedXray(t, []model.UserSpec{{ID: 1, UUID: "uuid-1"}}, nil)
	mustRegisterCounter(t, mgr, counterName(1, "uplink")).Add(10)
	oldMgr := newStatsManager(t)
	old := new(xrayCore.Instance)
	if err := old.AddFeature(oldMgr); err != nil {
		t.Fatal(err)
	}
	x.draining[old] = []model.UserSpec{{ID: 1, UUID: "uuid-1"}, {ID: 2, UUID: "uuid-2"}}
	mustRegisterCounter(t, oldMgr, counterName(1, "uplink")).Add(5)
	removed := mustRegisterCounter(t, oldMgr, counterName(2, "downlink"))
	removed.Add(7)

	traffic, _, _, err := x.GetUserTraffic(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if traffic[1] != [2]int64{15, 0} || traffic[2] != [2]int64{0, 7} {
		t.Fatalf("traffic = %v, want user 1 up 15 and user 2 down 7", traffic)
	}

	removed.Add(3) // sent after the last report, before the hard close
	x.closeOld(old, nil)
	deadline := time.Now().Add(time.Second)
	for {
		x.mu.Lock()
		pending := len(x.draining)
		x.mu.Unlock()
		if pending == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closed instance was not collected")
		}
		time.Sleep(time.Millisecond)
	}
	traffic, _, _, _ = x.GetUserTraffic(context.Background())
	if traffic[2] != [2]int64{0, 10} {
		t.Fatalf("final traffic of the closed instance = %v, want down 10", traffic[2])
	}
}
