package singbox

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/snell"
	N "github.com/sagernet/sing/common/network"
)

func boxContext(ctx context.Context) context.Context {
	registry := include.InboundRegistry()
	inbound.Register(registry, C.TypeSnell, newSnellInbound)
	return box.Context(ctx, registry, include.OutboundRegistry(), include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry(), include.CertificateProviderRegistry())
}

func newSnellInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, opts option.SnellInboundOptions) (adapter.Inbound, error) {
	// Independent PSKs already support auth_detour and close their own connections.
	if opts.UserPSK {
		return snell.NewInbound(ctx, router, logger, tag, opts)
	}
	source := opts.AuthDetour
	if source != "" && len(opts.Users) == 0 {
		return nil, errors.New("snell: auth_detour requires userkeys with a shared PSK")
	}
	opts.AuthDetour = ""
	inner, err := snell.NewInbound(ctx, router, logger, tag, opts)
	if err != nil {
		return nil, err
	}
	h := &trackedSnellInbound{Inbound: inner.(*snell.Inbound), source: source, conns: interrupt.NewGroup()}
	if source == "" {
		// Send accepted sockets through the same tracker as injected connections.
		h.listener = listener.New(listener.Options{
			Context: ctx, Logger: logger, Network: []string{N.NetworkTCP},
			Listen: opts.ListenOptions, ConnectionHandler: h,
		})
	}
	return h, nil
}

type trackedSnellInbound struct {
	*snell.Inbound
	listener *listener.Listener
	source   string
	access   sync.Mutex
	conns    *interrupt.Group // nil after the inbound has stopped
}

func (h *trackedSnellInbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	scope.Add(h.closeConnections)
	if h.listener != nil {
		if err := h.listener.Start(); err != nil {
			return err
		}
		scope.Add(h.listener.Close)
	}
	return nil
}

func (h *trackedSnellInbound) closeConnections() error {
	h.access.Lock()
	conns := h.conns
	h.conns = nil
	h.access.Unlock()
	// Idle reusable Snell sessions have no active route to close them.
	if conns != nil {
		conns.Interrupt(true)
	}
	return nil
}

func (h *trackedSnellInbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.source != "" {
		if metadata.LastInbound != h.source || metadata.InboundType != C.TypeShadowTLS || metadata.User == "" {
			N.CloseOnHandshakeFailure(conn, onClose, os.ErrPermission)
			return
		}
		// Snell supplies the user identity when a userkey is required.
		metadata.User = ""
	}
	h.access.Lock()
	if h.conns == nil {
		h.access.Unlock()
		N.CloseOnHandshakeFailure(conn, onClose, net.ErrClosed)
		return
	}
	tracked := h.conns.NewConn(conn, false)
	h.access.Unlock()
	onClose = N.OnceClose(N.AppendClose(onClose, func(error) { tracked.Close() }))
	h.Inbound.NewConnection(ctx, tracked, metadata, onClose)
}
