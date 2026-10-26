package singbox

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	singM "github.com/sagernet/sing/common/metadata"
)

type devicePacketConn struct {
	once   sync.Once
	closed chan struct{}
}

func (*devicePacketConn) ReadPacket(*buf.Buffer) (singM.Socksaddr, error) {
	return singM.Socksaddr{}, io.EOF
}
func (*devicePacketConn) WritePacket(b *buf.Buffer, _ singM.Socksaddr) error { b.Release(); return nil }
func (c *devicePacketConn) Close() error                                     { c.once.Do(func() { close(c.closed) }); return nil }
func (*devicePacketConn) LocalAddr() net.Addr                                { return &net.UDPAddr{} }
func (*devicePacketConn) SetDeadline(time.Time) error                        { return nil }
func (*devicePacketConn) SetReadDeadline(time.Time) error                    { return nil }
func (*devicePacketConn) SetWriteDeadline(time.Time) error                   { return nil }

func TestSingBoxUDPAdmissionKicksAndPunishes(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"user-1": 1})
	tracker.SetDeviceLimitFunc(func(string) (int, bool) { return 1, true })
	first := &devicePacketConn{closed: make(chan struct{})}
	wrapped := tracker.RoutedPacketConnection(context.Background(), first, testInboundContext("user-1", "9.9.9.9"), nil, nil)
	if wrapped == first {
		t.Fatal("first UDP source was not admitted")
	}
	_, ips, count := tracker.GetUserTraffic()
	if count != 1 || !ips[1]["9.9.9.9"] {
		t.Fatalf("UDP not counted: %v, %d", ips, count)
	}
	second := &devicePacketConn{closed: make(chan struct{})}
	tracker.RoutedPacketConnection(context.Background(), second, testInboundContext("user-1", "1.1.1.1"), nil, nil)
	for _, c := range []*devicePacketConn{first, second} {
		select {
		case <-c.closed:
		case <-time.After(time.Second):
			t.Fatal("UDP session escaped the kick")
		}
	}
	retry := &devicePacketConn{closed: make(chan struct{})}
	tracker.RoutedPacketConnection(context.Background(), retry, testInboundContext("user-1", "9.9.9.9"), nil, nil)
	select {
	case <-retry.closed:
	default:
		t.Fatal("old UDP IP bypassed cooldown")
	}
	wrapped.Close()
	if tracker.ActiveCount() != 0 {
		t.Fatal("kicked UDP connection leaked a reference")
	}
}
