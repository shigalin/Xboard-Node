package singbox

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	singM "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type trafficPacketConn struct {
	*devicePacketConn
	packets [][]byte
	written int
}

func (c *trafficPacketConn) ReadPacket(buffer *buf.Buffer) (singM.Socksaddr, error) {
	if len(c.packets) == 0 {
		return singM.Socksaddr{}, io.EOF
	}
	_, err := buffer.Write(c.packets[0])
	c.packets = c.packets[1:]
	return singM.ParseSocksaddr("127.0.0.1:53"), err
}

func (c *trafficPacketConn) WritePacket(buffer *buf.Buffer, _ singM.Socksaddr) error {
	c.written += buffer.Len()
	buffer.Release()
	return nil
}

func packetTrafficFixture(sizes ...int) *trafficPacketConn {
	c := &trafficPacketConn{devicePacketConn: &devicePacketConn{closed: make(chan struct{})}}
	for _, n := range sizes {
		c.packets = append(c.packets, make([]byte, n))
	}
	return c
}

// CopyPacket is the kernel's forwarding path. Use unequal upload/download
// lengths and a cached first packet so swapped or bypassed counters cannot pass.
func TestPacketTrafficCountsBothDirections(t *testing.T) {
	for _, fast := range []bool{false, true} {
		name := "direct"
		if fast {
			name = "copy_packet"
		}
		t.Run(name, func(t *testing.T) {
			tracker := NewConnTracker(nil)
			tracker.SetUserMap(map[string]int{"alice": 1, "bob": 2})
			assertTraffic := func(up, down int64) {
				t.Helper()
				got, _, _ := tracker.GetUserTraffic()
				if got[1] != [2]int64{up, down} || got[2] != [2]int64{} {
					t.Fatalf("traffic=%v want alice=[%d %d], bob=[0 0]", got, up, down)
				}
			}
			raw := packetTrafficFixture(11, 7)
			first := buf.NewSize(137)
			first.Extend(137)
			inbound := bufio.NewCachedPacketConn(raw, first, singM.ParseSocksaddr("127.0.0.1:53"))
			tracked := tracker.RoutedPacketConnection(context.Background(), inbound, testInboundContext("alice", "127.0.0.1"), nil, nil)
			defer tracked.Close()
			sink := packetTrafficFixture()
			copyPackets := func(dst N.PacketWriter, src N.PacketReader) {
				t.Helper()
				if fast {
					_, err := bufio.CopyPacket(dst, src)
					if err != nil && !errors.Is(err, io.EOF) {
						t.Fatal(err)
					}
					return
				}
				for {
					b := buf.NewPacket()
					addr, err := src.ReadPacket(b)
					if err != nil {
						b.Release()
						if !errors.Is(err, io.EOF) {
							t.Fatal(err)
						}
						return
					}
					if err = dst.WritePacket(b, addr); err != nil {
						t.Fatal(err)
					}
				}
			}
			copyPackets(sink, tracked)
			if sink.written != 155 {
				t.Fatalf("uploaded %d bytes, want 155", sink.written)
			}
			assertTraffic(155, 0)
			copyPackets(tracked, packetTrafficFixture(257, 13))
			if raw.written != 270 {
				t.Fatalf("downloaded %d bytes, want 270", raw.written)
			}
			assertTraffic(155, 270)
		})
	}
}
