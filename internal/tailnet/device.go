package tailnet

import (
	"os"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
)

// queueDepth bounds the packets waiting for the node to read. Deep enough to
// absorb a burst from the host, shallow enough that a node that has stopped
// reading drops packets instead of holding them without limit; dropping is
// what a network device does.
const queueDepth = 1024

// batchSize is how many packets the node may read at once.
const batchSize = 64

// Deliver receives packets the node took from the tailnet. bufs[i][offset:]
// is one packet; the buffers belong to the caller and are reused once
// Deliver returns.
type Deliver func(bufs [][]byte, offset int)

// device is the tun.Device the node is given in place of an operating
// system's. With one, tsnet hands every packet it does not handle itself to
// the device, and sends whatever the device produces as though the operating
// system had. Here there is no operating system: what the node writes goes to
// the gateway, and what the gateway sends the node reads.
//
// tsnet still handles a few things itself, by looking for one of its own
// sockets before releasing a packet: its PeerAPI, and anything the process
// listens on or dials through the tsnet.Server. Everything else for the
// node's addresses, the virtual IPs of the Services it hosts in TUN mode,
// and the routes it advertises comes here.
type device struct {
	deliver  Deliver
	outbound chan []byte
	events   chan tun.Event

	// pending is a packet the last Read had no room for, which the next one
	// reads first. Only Read touches it, and the node reads from one
	// goroutine.
	pending []byte

	closeOnce sync.Once
	closed    chan struct{}
}

func newDevice(deliver Deliver) *device {
	return &device{
		deliver:  deliver,
		outbound: make(chan []byte, queueDepth),
		events:   make(chan tun.Event, 1),
		closed:   make(chan struct{}),
	}
}

// send queues a packet for the node to read and send on the tailnet. It
// takes ownership of pkt. It drops rather than blocks when the node is not
// keeping up, so one slow tailnet never stalls the host's packets for the
// others.
func (d *device) send(pkt []byte) bool {
	select {
	case d.outbound <- pkt:
		return true
	case <-d.closed:
		return false
	default:
		return false
	}
}

// Read hands the node packets to send, as many as are waiting and fit, after
// blocking for the first.
func (d *device) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	if len(packets) == 0 || len(slab) < 2*tun.ReadPacketSpacing {
		return 0, nil
	}

	pkt := d.pending
	d.pending = nil
	if pkt == nil {
		select {
		case <-d.closed:
			return 0, os.ErrClosed
		case pkt = <-d.outbound:
		}
	}

	off, n := tun.ReadPacketSpacing, 0
	for {
		end := off + len(pkt)
		if end+tun.ReadPacketSpacing > len(slab) {
			if n == 0 {
				// Larger than anything the node reads. Drop it rather than
				// wedge the queue behind it.
				return 0, nil
			}
			d.pending = pkt
			return n, nil
		}
		copy(slab[off:end], pkt)
		packets[n] = tun.ReadPacket{Offset: off, Size: len(pkt)}
		n++
		off = end + tun.ReadPacketSpacing

		if n == len(packets) {
			return n, nil
		}
		select {
		case pkt = <-d.outbound:
		default:
			return n, nil
		}
	}
}

// Write takes packets the node has for the host.
func (d *device) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-d.closed:
		return 0, os.ErrClosed
	default:
	}
	d.deliver(bufs, offset)
	return len(bufs), nil
}

// File has no meaning for a device that is not a file. Nothing on this path
// calls it; tsnet's own fake device panics.
func (d *device) File() *os.File { return nil }

// MTU is Tailscale's own: the packets a node sends and expects to receive.
func (d *device) MTU() (int, error)        { return MTU, nil }
func (d *device) Name() (string, error)    { return "multits", nil }
func (d *device) Events() <-chan tun.Event { return d.events }
func (d *device) BatchSize() int           { return batchSize }

func (d *device) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
		close(d.events)
	})
	return nil
}
