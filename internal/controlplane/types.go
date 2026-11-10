package controlplane

import (
	"context"

	"github.com/cedar2025/xboard-node/internal/model"
)

type EventType string

const (
	EventSyncConfig    EventType = "sync.config"
	EventSyncUsers     EventType = "sync.users"
	EventSyncUserDelta EventType = "sync.user.delta"
	EventSyncDevices   EventType = "sync.devices"
)

type Event struct {
	Type   EventType
	Config *model.NodeSpec
	// ConfigErr is set on a config event whose config does not validate for
	// the selected kernel. Config is nil; the node keeps its active config.
	ConfigErr   error
	Users       []model.UserSpec
	DeltaAction string
	DeltaUsers  []model.UserSpec
	DeviceUsers map[int][]string
	DeviceBans  map[int]int64 // user ID -> Unix milliseconds
}

type StatusChange struct {
	Connected   bool
	NeedsResync bool
}

type APIMetrics struct {
	Success uint64
	Failure uint64
}

type Bootstrap struct {
	PushInterval       int
	PullInterval       int
	DeviceSequenceBase int64
	Push               PushClient
	Config             *model.NodeSpec
	Users              []model.UserSpec
	DeviceUsers        map[int][]string
	Mailbox            *NodeMailbox
}

type Snapshot struct {
	Config      *model.NodeSpec
	Users       []model.UserSpec
	DeviceUsers map[int][]string
	// CurrentConfig is the config the panel serves when Config is nil: the
	// body behind an HTTP 304, a config from a partial poll, or a body that
	// failed validation. Nil when the source cannot tell.
	CurrentConfig *model.NodeSpec
	// CurrentConfigErr means the panel returned an unusable config. It can
	// be set without CurrentConfig when the body could not be decoded.
	CurrentConfigErr error
}

type ReportPayload struct {
	Traffic map[int][2]int64
	Alive   map[int][]string
	Online  map[int]int
	CPU     float64
	Mem     [2]uint64
	Swap    [2]uint64
	Disk    [2]uint64
	Metrics map[string]interface{}
}

type PushClient interface {
	Run(ctx context.Context)
	IsConnected() bool
	// SendDeviceReport queues a device snapshot for the panel.
	// Returns false if it could not be queued (caller should retry later).
	SendDeviceReport(devices map[int][]string, sequence int64) bool
}

type Source interface {
	Initial(ctx context.Context, metricsFn func() map[string]interface{}, events chan<- Event, statuses chan<- StatusChange) (Bootstrap, error)
	// Poll may return a partial snapshot with an error from one request.
	Poll(ctx context.Context) (Snapshot, error)
	Discover(ctx context.Context, metricsFn func() map[string]interface{}, events chan<- Event, statuses chan<- StatusChange) (PushClient, error)
	Metrics() APIMetrics
	SupportsPolling() bool
	SupportsDiscovery() bool
}

// DeviceSnapshotSource provides a lightweight REST refresh for global device
// state. It is intentionally optional so standalone and third-party control
// planes do not need to implement an endpoint they cannot use.
type DeviceSnapshotSource interface {
	FetchDevices(ctx context.Context) (map[int][]string, error)
}

// UserRefetcher makes the next poll return the panel's full user list even if
// it is unchanged. The service uses it after it failed to apply a list the
// panel has already cached behind an ETag. Called only between polls.
type UserRefetcher interface {
	ForgetUserETag()
}

type DeviceBanSync interface {
	SyncDeviceBans(ctx context.Context, reports map[int]int64) (map[int]int64, error)
}

type Sink interface {
	Report(payload ReportPayload) error
	// ReportAlive sends only the REST alive-device payload, without changing
	// the panel's independently scheduled node status report.
	ReportAlive(alive map[int][]string, sequence int64, fullSnapshot bool) error
	// ReportDevices sends a device snapshot via the push client.
	// Returns false if the report was not queued (caller should retry later).
	ReportDevices(push PushClient, devices map[int][]string, sequence int64) bool
	SupportsReporting() bool
	SupportsDeviceReports() bool
}

type ControlPlane interface {
	Source
	Sink
}
