package tracker

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cedar2025/xboard-node/internal/nlog"
)

// snapshot is an immutable point-in-time view of tracker state.
// It is swapped atomically so readers never block writers.
type snapshot struct {
	traffic   map[int][2]int64        // userID → [upload, download] delta
	aliveIPs  map[int]map[string]bool // userID → set of source IPs
	online    map[int]int             // userID → distinct IP count
	connCount int
	inSpeed   int64
	outSpeed  int64
}

// Tracker computes per-user traffic deltas from cumulative counters
// provided by the kernel, and accumulates totals for panel reporting.
//
// Architecture: the kernel maintains per-user atomic counters and IP sets.
// Each tick, the service calls Process() with cumulative per-user traffic.
// Tracker computes deltas against the previous cycle's values — O(users),
// not O(connections).
//
// Thread safety: Process() acquires mu, then publishes a snapshot.
// CurrentOnline, LogStats, *Speed, and SnapshotAliveIPs read lock-free.
// FlushTraffic and FlushAliveIPs take mu for cursor/buffer updates.
type Tracker struct {
	mu sync.Mutex

	// lastSeen stores the cumulative traffic from the previous Process() call.
	// Protected by mu — only written by Process.
	lastSeen map[int][2]int64 // userID → [upload, download] cumulative

	// pending accumulates deltas between flushes.
	// Protected by mu — written by Process, drained by FlushTraffic.
	pendingTraffic map[int][2]int64

	// live holds the current snapshot, swapped atomically.
	// Readers load this pointer without any lock.
	live atomic.Pointer[snapshot]

	// lastAliveIPsHash detects changes to avoid duplicate reports.
	lastAliveIPsHash string

	// lastAliveFlush is when FlushAliveIPs last returned a snapshot. Unchanged
	// snapshots are still resent once aliveResendInterval elapses so the
	// panel-side device TTL keeps being refreshed.
	lastAliveFlush time.Time

	// lastAliveUsers is the set of users included in the last flushed
	// snapshot. A user present here but absent from the current snapshot gets
	// an explicit empty entry (tombstone): the REST panel handler only
	// processes users it receives and never deletes absent ones, so without
	// the tombstone a fully-offline user would linger until the panel TTL.
	lastAliveUsers map[int]struct{}

	// forceAliveReport makes the next FlushAliveIPs return the snapshot even
	// when unchanged. Set after a failed/possibly-lost report so it is retried.
	forceAliveReport bool
}

// aliveResendInterval bounds how long an unchanged snapshot may go unreported.
// The panel keeps device entries under a 300s TTL that is refreshed only by
// incoming reports, so the full snapshot must be resent well within that
// window or long-lived devices expire out of the global device state.
const aliveResendInterval = 120 * time.Second

func New() *Tracker {
	t := &Tracker{
		lastSeen:       make(map[int][2]int64),
		pendingTraffic: make(map[int][2]int64),
	}
	// Publish initial empty snapshot.
	t.live.Store(&snapshot{
		traffic:  make(map[int][2]int64),
		aliveIPs: make(map[int]map[string]bool),
		online:   make(map[int]int),
	})
	return t
}

// Process computes per-user traffic deltas from cumulative kernel counters.
// Also stores alive IPs and connection count. O(users).
//
// This is the only writer to lastSeen and pendingTraffic.
// After computing deltas, it publishes a new snapshot for lock-free reads.
func (t *Tracker) Process(
	cumTraffic map[int][2]int64,
	kernelAliveIPs map[int]map[string]bool,
	connCount int,
) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var cycleIn, cycleOut int64

	for uid, cum := range cumTraffic {
		prev := t.lastSeen[uid]
		deltaUp := cum[0] - prev[0]
		deltaDown := cum[1] - prev[1]

		// Guard against counter reset (kernel restart).
		if deltaUp < 0 {
			deltaUp = cum[0]
		}
		if deltaDown < 0 {
			deltaDown = cum[1]
		}

		t.lastSeen[uid] = cum

		if deltaUp > 0 || deltaDown > 0 {
			cur := t.pendingTraffic[uid]
			cur[0] += deltaUp
			cur[1] += deltaDown
			t.pendingTraffic[uid] = cur

			cycleOut += deltaUp
			cycleIn += deltaDown
		}
	}

	// Compute online from alive IPs.
	online := make(map[int]int, len(kernelAliveIPs))
	for uid, ips := range kernelAliveIPs {
		online[uid] = len(ips)
	}

	// Publish new snapshot (readers will see this atomically).
	t.live.Store(&snapshot{
		traffic:   copyTrafficMap(t.pendingTraffic),
		aliveIPs:  kernelAliveIPs, // kernel provides fresh copy each tick
		online:    online,
		connCount: connCount,
		inSpeed:   cycleIn,
		outSpeed:  cycleOut,
	})
}

// FlushTraffic returns accumulated per-user traffic and resets the pending buffer.
// Lock-free: reads from live snapshot, then acquires mu only to drain.
func (t *Tracker) FlushTraffic() map[int][2]int64 {
	t.mu.Lock()
	data := t.pendingTraffic
	t.pendingTraffic = make(map[int][2]int64, len(data))
	t.mu.Unlock()
	return data
}

// RestoreTraffic adds traffic back (used when push to panel fails).
func (t *Tracker) RestoreTraffic(data map[int][2]int64) {
	t.mu.Lock()
	for uid, d := range data {
		cur := t.pendingTraffic[uid]
		cur[0] += d[0]
		cur[1] += d[1]
		t.pendingTraffic[uid] = cur
	}
	t.mu.Unlock()
}

// HasTraffic returns true if there is accumulated traffic to report.
func (t *Tracker) HasTraffic() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pendingTraffic) > 0
}

// FlushAliveIPs returns per-user alive IPs, or nil if unchanged since the last
// flush. Unchanged snapshots are still returned after aliveResendInterval or a
// forced resend. Users missing since the last flush are empty-array tombstones:
// REST processAlive never deletes omitted users. WS uses SnapshotAliveIPs.
func (t *Tracker) FlushAliveIPs() map[int][]string {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Load under mu: Process publishes the snapshot while holding mu, so this
	// cannot observe a stale snapshot after a concurrent Process completes.
	s := t.live.Load()

	// Calculate hash of current aliveIPs
	currentHash := calcAliveIPsHash(s.aliveIPs)

	// If no changes, return nil to avoid duplicate reporting
	if !t.forceAliveReport && currentHash == t.lastAliveIPsHash &&
		time.Since(t.lastAliveFlush) < aliveResendInterval {
		return nil
	}

	t.forceAliveReport = false
	t.lastAliveIPsHash = currentHash
	t.lastAliveFlush = time.Now()

	// Build a fresh snapshot: callers hand it to async senders, so returning
	// a shared buffer would race with the next flush.
	out := make(map[int][]string, len(s.aliveIPs))
	for uid, ips := range s.aliveIPs {
		list := make([]string, 0, len(ips))
		for ip := range ips {
			list = append(list, ip)
		}
		out[uid] = list
	}

	// Tombstones for users that dropped out of the snapshot entirely.
	for uid := range t.lastAliveUsers {
		if _, ok := out[uid]; !ok {
			out[uid] = []string{}
		}
	}

	// Record the real (non-tombstone) users of this flush.
	t.lastAliveUsers = make(map[int]struct{}, len(s.aliveIPs))
	for uid := range s.aliveIPs {
		t.lastAliveUsers[uid] = struct{}{}
	}

	return out
}

// SnapshotAliveIPs returns the current alive IPs without moving the REST flush
// cursor. WS reports this every tick; the panel diffs, so no tombstones.
func (t *Tracker) SnapshotAliveIPs() map[int][]string {
	s := t.live.Load()
	out := make(map[int][]string, len(s.aliveIPs))
	for uid, ips := range s.aliveIPs {
		list := make([]string, 0, len(ips))
		for ip := range ips {
			list = append(list, ip)
		}
		out[uid] = list
	}
	return out
}

// CommitAliveIPsSnapshot advances the REST delta cursor after a full snapshot
// is accepted. Committing only after success preserves tombstones on retries.
func (t *Tracker) CommitAliveIPsSnapshot(aliveIPs map[int][]string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.lastAliveIPsHash = calcAliveIPListsHash(aliveIPs)
	t.lastAliveFlush = time.Now()
	t.forceAliveReport = false
	t.lastAliveUsers = make(map[int]struct{}, len(aliveIPs))
	for uid, ips := range aliveIPs {
		if len(ips) > 0 {
			t.lastAliveUsers[uid] = struct{}{}
		}
	}
}

func calcAliveIPListsHash(aliveIPs map[int][]string) string {
	sets := make(map[int]map[string]bool, len(aliveIPs))
	for uid, ips := range aliveIPs {
		set := make(map[string]bool, len(ips))
		for _, ip := range ips {
			set[ip] = true
		}
		if len(set) > 0 {
			sets[uid] = set
		}
	}
	return calcAliveIPsHash(sets)
}

// calcAliveIPsHash computes a deterministic hash for change detection.
func calcAliveIPsHash(aliveIPs map[int]map[string]bool) string {
	if len(aliveIPs) == 0 {
		return ""
	}

	h := sha256.New()

	// Sort user IDs for consistent hashing
	userIDs := make([]int, 0, len(aliveIPs))
	for uid := range aliveIPs {
		userIDs = append(userIDs, uid)
	}
	sort.Ints(userIDs)

	for _, uid := range userIDs {
		ips := aliveIPs[uid]
		// Sort IPs for consistent hashing
		ipList := make([]string, 0, len(ips))
		for ip := range ips {
			ipList = append(ipList, ip)
		}
		sort.Strings(ipList)

		// Write user ID and IPs to hash
		h.Write([]byte{byte(uid >> 24), byte(uid >> 16), byte(uid >> 8), byte(uid)})
		for _, ip := range ipList {
			h.Write([]byte(ip))
		}
	}

	return hex.EncodeToString(h.Sum(nil))
}

// CurrentOnline returns a snapshot copy of user_id → device count (distinct IPs).
// Lock-free: reads from live snapshot.
func (t *Tracker) CurrentOnline() map[int]int {
	s := t.live.Load()
	cp := make(map[int]int, len(s.online))
	for k, v := range s.online {
		cp[k] = v
	}
	return cp
}

// RestoreAliveIPs retries a failed REST flush: force the next FlushAliveIPs
// and keep failed-payload users so their tombstones are re-emitted.
func (t *Tracker) RestoreAliveIPs(data map[int][]string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.forceAliveReport = true
	if t.lastAliveUsers == nil {
		t.lastAliveUsers = make(map[int]struct{}, len(data))
	}
	for uid := range data {
		t.lastAliveUsers[uid] = struct{}{}
	}
}

// LogStats logs current tracking statistics.
// Lock-free: reads from live snapshot.
func (t *Tracker) LogStats() {
	s := t.live.Load()
	nlog.TrackerStats(s.connCount, len(s.online))
}

// ActiveConnections returns the last observed active connection count.
// Lock-free: reads from live snapshot.
func (t *Tracker) ActiveConnections() int {
	return t.live.Load().connCount
}

// TotalConnections is deprecated — no longer tracked per-connection.
// Returns 0 for backward compatibility.
func (t *Tracker) TotalConnections() int64 {
	return 0
}

// InboundSpeed returns the last observed inbound (download) speed in bytes/second.
// Lock-free: reads from live snapshot.
func (t *Tracker) InboundSpeed() int64 {
	return t.live.Load().inSpeed / 10
}

// OutboundSpeed returns the last observed outbound (upload) speed in bytes/second.
// Lock-free: reads from live snapshot.
func (t *Tracker) OutboundSpeed() int64 {
	return t.live.Load().outSpeed / 10
}

// copyTrafficMap creates a shallow copy of the traffic map.
func copyTrafficMap(src map[int][2]int64) map[int][2]int64 {
	dst := make(map[int][2]int64, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
