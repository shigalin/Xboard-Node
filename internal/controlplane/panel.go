package controlplane

import (
	"context"
	"fmt"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/cedar2025/xboard-node/internal/panel"
)

type PanelControlPlane struct {
	cfg    config.PanelConfig
	wsCfg  config.WSConfig
	kcfg   config.KernelConfig
	client *panel.Client
}

type panelPushClient struct {
	inner *panel.WSClient
}

func NewPanelControlPlane(panelCfg config.PanelConfig, wsCfg config.WSConfig, kcfg config.KernelConfig) *PanelControlPlane {
	return &PanelControlPlane{
		cfg:    panelCfg,
		wsCfg:  wsCfg,
		kcfg:   kcfg,
		client: panel.NewClient(panelCfg),
	}
}

func (p *PanelControlPlane) SupportsPolling() bool       { return true }
func (p *PanelControlPlane) SupportsDiscovery() bool     { return true }
func (p *PanelControlPlane) SupportsReporting() bool     { return true }
func (p *PanelControlPlane) SupportsDeviceReports() bool { return true }

func (p *PanelControlPlane) Initial(ctx context.Context, metricsFn func() map[string]interface{}, events chan<- Event, statuses chan<- StatusChange) (Bootstrap, error) {
	hs, err := p.client.HandshakeWithDeviceSequence()
	if err != nil {
		return Bootstrap{}, fmt.Errorf("handshake: %w", err)
	}

	bootstrap := Bootstrap{
		PushInterval:       hs.Settings.PushInterval,
		PullInterval:       hs.Settings.PullInterval,
		DeviceSequenceBase: hs.DeviceSequenceBase,
	}
	if hs.WebSocket.Enabled && hs.WebSocket.WSURL != "" {
		bootstrap.Push = p.newPushClient(metricsFn, events, statuses, hs.WebSocket.WSURL)
		return bootstrap, nil
	}

	nlog.Core().Info("websocket disabled, using REST API")
	configSnapshot, err := p.client.GetConfig()
	if err != nil {
		return Bootstrap{}, fmt.Errorf("initial config fetch: %w", err)
	}
	if configSnapshot == nil {
		return Bootstrap{}, fmt.Errorf("initial config is nil")
	}
	users, err := p.client.GetUsers()
	if err != nil {
		return Bootstrap{}, fmt.Errorf("initial user fetch: %w", err)
	}
	bootstrap.Config, err = model.NodeSpecFromPanelValidated(configSnapshot, p.kcfg)
	if err != nil {
		return Bootstrap{}, fmt.Errorf("initial config normalize: %w", err)
	}
	bootstrap.Users = model.UserSpecsFromPanel(users)
	bootstrap.DeviceUsers, err = p.client.GetDevices()
	if err != nil {
		return Bootstrap{}, fmt.Errorf("initial devices fetch: %w", err)
	}
	return bootstrap, nil
}

func (p *PanelControlPlane) Poll(ctx context.Context) (Snapshot, error) {
	configSnapshot, err := p.client.GetConfig()
	if err != nil {
		return Snapshot{}, fmt.Errorf("poll config: %w", err)
	}
	users, err := p.client.GetUsers()
	if err != nil {
		return Snapshot{}, fmt.Errorf("poll users: %w", err)
	}
	select {
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	default:
	}
	snapshot := Snapshot{Users: model.UserSpecsFromPanel(users)}
	if configSnapshot == nil {
		snapshot.CurrentConfig, snapshot.CurrentConfigErr = cachedConfig(p.client, p.kcfg)
	} else {
		snapshot.Config, snapshot.CurrentConfig, snapshot.CurrentConfigErr = resolveConfig(configSnapshot, p.kcfg)
	}
	return snapshot, nil
}

func (p *PanelControlPlane) ForgetUserETag() { p.client.ForgetUserETag() }

func (p *PanelControlPlane) FetchDevices(ctx context.Context) (map[int][]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	return p.client.GetDevices()
}

func (p *PanelControlPlane) SyncDeviceBans(ctx context.Context, reports map[int]int64) (map[int]int64, error) {
	return p.client.SyncDeviceBans(ctx, reports)
}

func (p *PanelControlPlane) Discover(ctx context.Context, metricsFn func() map[string]interface{}, events chan<- Event, statuses chan<- StatusChange) (PushClient, error) {
	hs, err := p.client.Handshake()
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if hs.WebSocket.Enabled && hs.WebSocket.WSURL != "" {
		return p.newPushClient(metricsFn, events, statuses, hs.WebSocket.WSURL), nil
	}
	return nil, nil
}

func (p *PanelControlPlane) Report(payload ReportPayload) error {
	return p.client.Report(payload.Traffic, payload.Alive, payload.Online, payload.CPU, payload.Mem, payload.Swap, payload.Disk, payload.Metrics)
}

func (p *PanelControlPlane) ReportAlive(alive map[int][]string, sequence int64, fullSnapshot bool) error {
	return p.client.ReportAlive(alive, sequence, fullSnapshot)
}

func (p *PanelControlPlane) ReportDevices(push PushClient, devices map[int][]string, sequence int64) bool {
	return push != nil && push.SendDeviceReport(devices, sequence)
}

func (p *PanelControlPlane) Metrics() APIMetrics {
	api := p.client.SnapshotMetrics()
	return APIMetrics{Success: api.Success, Failure: api.Failure}
}

func (p *PanelControlPlane) newPushClient(metricsFn func() map[string]interface{}, events chan<- Event, statuses chan<- StatusChange, wsURL string) PushClient {
	cfg := panel.WSClientConfig{
		StatusInterval:   time.Duration(p.wsCfg.StatusInterval) * time.Second,
		HandshakeTimeout: time.Duration(p.wsCfg.HandshakeTimeout) * time.Second,
		BackoffInitial:   time.Duration(p.wsCfg.BackoffInitial) * time.Second,
		BackoffMax:       time.Duration(p.wsCfg.BackoffMax) * time.Second,
	}
	inner := panel.NewWSClient(
		wsURL,
		p.cfg.Token,
		p.cfg.NodeID,
		cfg,
		func(event panel.WSEvent) {
			translated, err := TranslateWSEvent(event, p.kcfg)
			if err != nil {
				nlog.Core().Warn("invalid ws event config, dropping event", "type", event.Type, "error", err)
				return
			}
			select {
			case events <- translated:
			default:
				nlog.Core().Warn("ws event channel full, dropping event", "type", translated.Type)
				select {
				case statuses <- StatusChange{Connected: true, NeedsResync: true}:
				default:
				}
			}
		},
		func(status panel.WSStatusChange) {
			select {
			case statuses <- StatusChange{Connected: status.Connected}:
			default:
			}
		},
		metricsFn,
	)
	return &panelPushClient{inner: inner}
}

func TranslateWSEvent(event panel.WSEvent, kcfg config.KernelConfig) (Event, error) {
	translated := Event{Type: EventType(event.Type), DeltaAction: event.DeltaAction, DeviceUsers: event.DeviceUsers, DeviceBans: event.DeviceBans}
	if event.Config != nil {
		var err error
		translated.Config, _, err = resolveConfig(event.Config, kcfg)
		if err != nil {
			// The service must still learn that the panel moved on: an
			// earlier candidate is stale even though this one is unusable.
			translated.ConfigErr = fmt.Errorf("translate node config: %w", err)
		}
	}
	if event.Users != nil {
		translated.Users = model.UserSpecsFromPanel(event.Users)
	}
	if event.DeltaUsers != nil {
		translated.DeltaUsers = model.UserSpecsFromPanel(event.DeltaUsers)
	}
	return translated, nil
}

func (p *panelPushClient) Run(ctx context.Context) { p.inner.Run(ctx) }
func (p *panelPushClient) IsConnected() bool       { return p.inner.IsConnected() }
func (p *panelPushClient) SendDeviceReport(devices map[int][]string, sequence int64) bool {
	return p.inner.SendDeviceReport(devices, sequence)
}

// resolveConfig normalizes a panel config for the selected kernel. A valid
// config is returned as applicable; one that fails validation is returned
// as the config the panel currently serves, together with the error, so the
// caller can tell that the panel replaced its config with one this node
// cannot run.
func resolveConfig(nc *panel.NodeConfig, kcfg config.KernelConfig) (applicable, current *model.NodeSpec, err error) {
	spec, kcfg := model.NodeSpecFromPanelResolved(nc, kcfg)
	if err := model.ValidateNodeSpec(spec, kcfg); err != nil {
		return nil, spec, err
	}
	return spec, nil, nil
}

// cachedConfig resolves an HTTP 304 to the config behind the client's ETag.
// A body that no longer decodes is reported as unknown.
func cachedConfig(client *panel.Client, kcfg config.KernelConfig) (*model.NodeSpec, error) {
	cached, err := client.CachedConfig()
	if err != nil || cached == nil {
		return nil, nil
	}
	applicable, current, err := resolveConfig(cached, kcfg)
	if err != nil {
		return current, err
	}
	return applicable, nil
}
