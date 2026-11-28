package tailnet

import (
	"os"
	"sync"
	"sync/atomic"

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

// Batch is packets from the host for a node to send, as the host's device
// read them: still the host's, untranslated. They stay in the buffer they
// were read into, so a whole read reaches the node in one piece and each
// packet is translated once, straight into the buffer the node reads with.
type Batch struct {
	// Slab holds the packets, and Packets says where in it each one is.
	Slab    []byte
	Packets []tun.ReadPacket
	// Done, when set, is called once the node has finished with the batch,
	// with the buffers its owner may then reuse.
	Done func(*Batch)
}

// Translate turns one of the host's packets into what the tailnet carries.
// out is at least as long as pkt, and at least MTU bytes. What it returns is
// what the node sends: the first n bytes of out; or fragments, which replace
// it and are sent in order; or nothing, with n zero, for a packet that was
// dropped or answered instead.
type Translate func(pkt, out []byte) (n int, fragments [][]byte)

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
	deliver   Deliver
	translate Translate
	outbound  chan *Batch
	// queued counts the packets in outbound, which is what bounds it.
	queued atomic.Int64
	events chan tun.Event

	// What the last Read left behind, which the next one reads first: the
	// batch it was in the middle of and where, and the fragments of a
	// packet it had no room for. Only Read touches these, and the node
	// reads from one goroutine.
	current   *Batch
	next      int
	fragments [][]byte

	closeOnce sync.Once
	closed    chan struct{}
}

func newDevice(deliver Deliver, translate Translate) *device {
	return &device{
		deliver:   deliver,
		translate: translate,
		// One slot per packet: a batch has at least one, so a batch that
		// the packet count admits always has a slot.
		outbound: make(chan *Batch, queueDepth),
		events:   make(chan tun.Event, 1),
		closed:   make(chan struct{}),
	}
}

// send queues a batch for the node to read and send on the tailnet. It
// reports whether it took the batch: it refuses rather than blocks when the
// node is not keeping up, so one slow tailnet never stalls the host's packets
// for the others. A batch it refuses is still the caller's.
func (d *device) send(b *Batch) bool {
	n := int64(len(b.Packets))
	if n == 0 {
		return false
	}
	select {
	case <-d.closed:
		return false
	default:
	}
	if d.queued.Add(n) > queueDepth {
		d.queued.Add(-n)
		return false
	}
	select {
	case d.outbound <- b:
		return true
	default:
		d.queued.Add(-n)
		return false
	}
}

// Read hands the node packets to send, as many as are waiting and fit, after
// blocking for the first. It translates each one as it goes, into the slab
// the node reads with.
func (d *device) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	if len(packets) == 0 || len(slab) < 2*tun.ReadPacketSpacing {
		return 0, nil
	}

	off, n := tun.ReadPacketSpacing, 0
	// fits reports whether the read has room for another packet of size
	// bytes, with the spacing the node wants after it.
	fits := func(size int) bool {
		return n < len(packets) && off+size+tun.ReadPacketSpacing <= len(slab)
	}
	placed := func(size int) {
		packets[n] = tun.ReadPacket{Offset: off, Size: size}
		n++
		off += size + tun.ReadPacketSpacing
	}

	for {
		switch {
		case len(d.fragments) > 0:
			f := d.fragments[0]
			if !fits(len(f)) {
				if n > 0 {
					return n, nil
				}
				// Larger than anything the node reads. Drop it rather
				// than wedge the queue behind it.
			} else {
				copy(slab[off:], f)
				placed(len(f))
			}
			if d.fragments = d.fragments[1:]; len(d.fragments) == 0 {
				d.fragments = nil
			}

		case d.current != nil && d.next < len(d.current.Packets):
			p := d.current.Packets[d.next]
			pkt := d.current.Slab[p.Offset : p.Offset+p.Size]
			// Room to translate into, which is more than the translation
			// may come to.
			room := max(len(pkt), MTU)
			if !fits(room) {
				if n > 0 {
					return n, nil
				}
				d.next++
				continue
			}
			d.next++
			size, fragments := d.translate(pkt, slab[off:off+room])
			if len(fragments) > 0 {
				d.fragments = fragments
			} else if size > 0 {
				placed(size)
			}

		case d.current != nil:
			if d.current.Done != nil {
				d.current.Done(d.current)
			}
			d.current = nil

		case n > 0:
			select {
			case b := <-d.outbound:
				d.take(b)
			default:
				return n, nil
			}

		default:
			select {
			case <-d.closed:
				return 0, os.ErrClosed
			case b := <-d.outbound:
				d.take(b)
			}
		}
	}
}

// take starts reading a batch.
func (d *device) take(b *Batch) {
	d.queued.Add(-int64(len(b.Packets)))
	d.current, d.next = b, 0
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
