package xray

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
)

const realityHelloTimeout = 15 * time.Second

// realitySNIRouter belongs to one main Xray instance, including its drain
// period. It forwards TLS bytes without terminating TLS or creating another
// Xray instance (whose logger would replace the process-global log handler).
type realitySNIRouter struct {
	listener net.Listener
	dir      string
	targets  map[string]string
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	closed   bool
	refs     int
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
	once     sync.Once
	closeErr error
}

// One lease per Xray generation. Sharing an unchanged router also preserves
// its dest, the key used by REALITY's process-global target-probe caches.
type realitySNIRouterLease struct {
	*realitySNIRouter
	once sync.Once
	err  error
}

func (*realitySNIRouterLease) Type() interface{} { return (*realitySNIRouterLease)(nil) }
func (*realitySNIRouterLease) Start() error      { return nil }

func (r *realitySNIRouter) acquire(targets map[string]string) *realitySNIRouterLease {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !maps.Equal(r.targets, targets) {
		return nil
	}
	r.refs++
	return &realitySNIRouterLease{realitySNIRouter: r}
}

func (l *realitySNIRouterLease) Close() error {
	l.once.Do(func() {
		r := l.realitySNIRouter
		r.mu.Lock()
		r.refs--
		last := r.refs == 0
		if last {
			r.closed = true // prevent acquisition between the last release and Close
		}
		r.mu.Unlock()
		if last {
			l.err = r.Close()
		}
	})
	return l.err
}

func (r *realitySNIRouter) Close() error {
	r.once.Do(func() {
		r.cancel()
		r.mu.Lock()
		r.closed = true
		r.listener.Close()
		for conn := range r.conns {
			conn.Close()
		}
		r.mu.Unlock()
		r.wg.Wait()
		r.closeErr = os.RemoveAll(r.dir)
	})
	return r.closeErr
}

// prepareRealitySNIRouting derives the allowlist and targets from the panel's
// comma-separated server_name and shared server_port. The existing loopback
// website map can still override individual targets. Single-name nodes retain
// their existing configuration; no second local SNI list is required.
func prepareRealitySNIRouting(cfg M, nc *model.NodeSpec, localTargets map[string]string, previous *realitySNIRouter) (*realitySNIRouterLease, error) {
	if nc == nil || nc.TLS != 2 {
		return nil, nil
	}
	raw, _ := nc.TLSSettings["server_name"].(string)
	if !strings.Contains(raw, ",") {
		return nil, nil
	}
	inbounds, _ := cfg["inbounds"].([]M)
	if len(inbounds) != 1 {
		return nil, fmt.Errorf("multiple REALITY SNI names require a REALITY inbound")
	}
	stream, _ := inbounds[0]["streamSettings"].(M)
	reality, _ := stream["realitySettings"].(M)
	if stream["security"] != "reality" || reality == nil {
		return nil, fmt.Errorf("multiple REALITY SNI names require a REALITY inbound")
	}
	names, targets, err := panelRealitySNITargets(raw, nc.TLSSettings["server_port"], localTargets)
	if err != nil {
		return nil, err
	}
	lease := previous.acquire(targets)
	if lease == nil {
		router, err := startRealitySNIRouter(targets)
		if err != nil {
			return nil, err
		}
		lease = router.acquire(targets)
	}
	reality["dest"] = lease.listener.Addr().String()
	reality["serverNames"] = names
	return lease, nil
}

func panelRealitySNITargets(raw string, value any, localTargets map[string]string) ([]string, map[string]string, error) {
	port := 443
	if value != nil && strings.TrimSpace(fmt.Sprint(value)) != "" {
		var err error
		port, err = strconv.Atoi(strings.TrimSpace(fmt.Sprint(value)))
		if err != nil || port < 1 || port > 65535 {
			return nil, nil, fmt.Errorf("REALITY server_port must be one port between 1 and 65535")
		}
	}
	var names []string
	targets := make(map[string]string)
	for _, item := range strings.Split(raw, ",") {
		name := config.NormalizeRealitySNI(item)
		if !realityDNSName(name) || net.ParseIP(name) != nil {
			return nil, nil, fmt.Errorf("REALITY server_name must contain comma-separated DNS names, without ports or empty entries")
		}
		if _, exists := targets[name]; exists {
			continue
		}
		names = append(names, name)
		dest := net.JoinHostPort(name, strconv.Itoa(port))
		if local := localTargets[name]; local != "" {
			dest = local
		}
		targets[name] = dest
	}
	return names, targets, nil
}

func realityDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !('a' <= ch && ch <= 'z' || '0' <= ch && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

func startRealitySNIRouter(targets map[string]string) (*realitySNIRouter, error) {
	dir, err := os.MkdirTemp("", "xb-sni-")
	if err != nil {
		return nil, fmt.Errorf("create REALITY SNI socket directory: %w", err)
	}
	listener, err := net.Listen("unix", filepath.Join(dir, "route.sock"))
	if err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("listen for REALITY SNI routing: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &realitySNIRouter{listener: listener, dir: dir, targets: targets, ctx: ctx, cancel: cancel, conns: make(map[net.Conn]struct{})}
	r.wg.Add(1)
	go r.serve()
	return r, nil
}

func (r *realitySNIRouter) track(conn net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		conn.Close()
		return false
	}
	r.conns[conn] = struct{}{}
	return true
}

func (r *realitySNIRouter) release(conn net.Conn) {
	conn.Close()
	r.mu.Lock()
	delete(r.conns, conn)
	r.mu.Unlock()
}

func (r *realitySNIRouter) serve() {
	defer r.wg.Done()
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			return
		}
		if !r.track(conn) {
			return
		}
		r.wg.Add(1) // the accept loop remains counted until all handlers are added
		go func() {
			defer r.wg.Done()
			defer r.release(conn)
			r.forward(conn)
		}()
	}
}

func (r *realitySNIRouter) forward(client net.Conn) {
	client.SetReadDeadline(time.Now().Add(realityHelloTimeout))
	name, hello, err := readRealityClientHello(r.ctx, client)
	if err != nil {
		return
	}
	dest := r.targets[name]
	if dest == "" { // never dial an address derived from unlisted client input
		return
	}
	upstream, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(r.ctx, "tcp", dest)
	if err != nil || !r.track(upstream) {
		return
	}
	defer r.release(upstream)
	upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.Copy(upstream, bytes.NewReader(hello)); err != nil {
		return
	}
	upstream.SetWriteDeadline(time.Time{})
	client.SetReadDeadline(time.Time{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		copyRealityStream(upstream, client)
	}()
	copyRealityStream(client, upstream)
	<-done
}

func copyRealityStream(dst, src net.Conn) {
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		src.Close()
		return
	}
	if conn, ok := dst.(interface{ CloseWrite() error }); ok {
		conn.CloseWrite()
	}
}

var errRealityHelloCaptured = errors.New("REALITY ClientHello captured")

// Let crypto/tls reassemble TLS records and parse ClientHello, but stop before
// sending any TLS response. Replay every captured byte unchanged to the target.
// Unlike generic sniffing, this supports fragmented records and slow arrivals.
func readRealityClientHello(ctx context.Context, conn net.Conn) (string, []byte, error) {
	recording := &realityHelloConn{Conn: conn}
	var name string
	server := tls.Server(recording, &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		name = hello.ServerName
		return nil, errRealityHelloCaptured
	}})
	err := server.HandshakeContext(ctx)
	if !errors.Is(err, errRealityHelloCaptured) || name == "" {
		return "", nil, fmt.Errorf("missing or invalid REALITY SNI")
	}
	return name, recording.data, nil
}

type realityHelloConn struct {
	net.Conn
	data []byte
}

func (c *realityHelloConn) Read(p []byte) (int, error) {
	// Bound unauthenticated buffering, including record headers. Go also
	// enforces its own TLS handshake size limit while parsing the message.
	remaining := 256*1024 - len(c.data)
	if remaining == 0 {
		return 0, fmt.Errorf("REALITY ClientHello exceeds the buffer limit")
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	n, err := c.Conn.Read(p)
	c.data = append(c.data, p[:n]...)
	return n, err
}

func (*realityHelloConn) Write([]byte) (int, error) { return 0, errRealityHelloCaptured }
