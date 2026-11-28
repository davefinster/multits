// Package gateway joins the pieces: a node per tailnet, the host's device,
// and the translator between them. Packets from a tailnet are translated and
// written to the host; packets the host routes into the device go to the
// node of the tailnet their destination names, which translates them as it
// reads them.
package gateway

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/davefinster/multits/internal/addr"
	"github.com/davefinster/multits/internal/config"
	"github.com/davefinster/multits/internal/dns"
	"github.com/davefinster/multits/internal/hostnet"
	"github.com/davefinster/multits/internal/tailnet"
	"github.com/davefinster/multits/internal/xlat"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/net/dns/dnsmessage"
)

// hostOffset is the headroom left ahead of each packet written to the host
// device, which the Linux device needs for its virtio header.
const hostOffset = 16

// withdrawTimeout bounds withdrawing every node at shutdown.
const withdrawTimeout = 5 * time.Second

// Host is the host's side, which is hostnet.Interface outside of tests.
type Host interface {
	Device() tun.Device
	SetLocal(tailnet uint8, self, others []netip.Addr) error
	AddGatewayAddress(ip netip.Addr) error
	Close() error
}

// Gateway is a running gateway.
type Gateway struct {
	cfg    *config.Config
	scheme *addr.Scheme
	xlat   *xlat.Translator
	host   Host
	log    *slog.Logger

	nodes  map[string]*tailnet.Node
	byID   [256]*tailnet.Node
	counts [256]*counters
	// unrouted counts packets from the host that went to no tailnet.
	unrouted counters

	// queues are the host device's, each read by its own goroutine, and
	// queueReads counts the packets each has read. writeTo writes to the
	// queue a flow maps to.
	queues     []tun.Queue
	queueReads []atomic.Uint64
	writeTo    func(flow int, bufs [][]byte, offset int) (int, error)
	bufs       *buffers

	dns *dns.Server

	withdrawOnce sync.Once
}

// New builds a gateway from its configuration. It opens the host device,
// which needs CAP_NET_ADMIN in the application's network namespace, unless
// host is given.
func New(cfg *config.Config, host Host, log *slog.Logger) (*Gateway, error) {
	g := &Gateway{
		cfg:    cfg,
		scheme: cfg.Scheme,
		xlat:   xlat.New(cfg.Scheme, cfg.TailnetMTU),
		log:    log,
		nodes:  map[string]*tailnet.Node{},
	}

	ids := make([]uint8, 0, len(cfg.Tailnets))
	for _, tc := range cfg.Tailnets {
		ids = append(ids, tc.ID)
	}
	slices.Sort(ids)

	if host == nil {
		iface, err := hostnet.Open(cfg.Scheme, ids, hostnet.Options{
			Name:       cfg.Device.Name,
			TailnetMTU: cfg.TailnetMTU,
			Queues:     cfg.Device.Queues,
			FitTailnet: cfg.Device.FitTailnet,
		}, log)
		if err != nil {
			return nil, err
		}
		host = iface
	}
	g.host = host

	dev := host.Device()
	g.queues = tun.QueuesOf(dev)
	g.queueReads = make([]atomic.Uint64, len(g.queues))
	g.writeTo = tun.WriteToOf(dev)
	mtu, _ := dev.MTU()
	g.bufs = newBuffers(max(dev.BatchSize(), 1), mtu)

	for _, tc := range cfg.Tailnets {
		id := tc.ID
		c := &counters{}
		g.counts[id] = c
		node := tailnet.New(tc, g.fromTailnet(id, c), g.toTailnet(id, c), func(a tailnet.Addresses) { g.addressesChanged(id, a) }, log)
		g.nodes[tc.Name] = node
		g.byID[id] = node
	}

	if len(cfg.DNS.Listen) > 0 {
		upstream := cfg.DNS.Upstream
		if upstream == nil {
			var err error
			upstream, err = dns.ResolvConf(cfg.DNS.ResolvConf, cfg.DNS.Listen, cfg.Scheme.Prefix())
			if err != nil {
				log.Warn("Cannot read the upstream resolvers", "resolvConf", cfg.DNS.ResolvConf, "err", err)
			}
		}
		if len(upstream) == 0 {
			log.Warn("No upstream resolvers: names in no tailnet are refused; set dns.upstream")
		}
		tailnets := make([]dns.Tailnet, 0, len(g.nodes))
		for _, node := range g.nodes {
			tailnets = append(tailnets, dnsTailnet{node})
		}
		g.dns = dns.New(cfg.Scheme, tailnets, upstream, log.With("component", "dns"))
	}
	return g, nil
}

// dnsTailnet is a node as the resolver sees it.
type dnsTailnet struct{ node *tailnet.Node }

func (d dnsTailnet) ID() uint8                  { return d.node.Config().ID }
func (d dnsTailnet) Zones() []string            { return d.node.Zones() }
func (d dnsTailnet) IsLocal(ip netip.Addr) bool { return d.node.IsLocal(ip) }
func (d dnsTailnet) Query(ctx context.Context, name string, qtype dnsmessage.Type) ([]byte, error) {
	return d.node.QueryDNS(ctx, name, qtype)
}

// listenDNS starts the resolver. It starts before the nodes join: in a pod
// whose resolver it is, their own lookups of the control plane come here.
func (g *Gateway) listenDNS() (closeAll func(), err error) {
	var closers []io.Closer
	closeAll = func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}
	if g.dns == nil {
		return closeAll, nil
	}
	for _, ap := range g.cfg.DNS.Listen {
		if g.scheme.TailnetPrefix(0).Contains(ap.Addr()) {
			if err := g.host.AddGatewayAddress(ap.Addr()); err != nil {
				closeAll()
				return nil, fmt.Errorf("dns: %w", err)
			}
		}
		pc, err := net.ListenPacket("udp", ap.String())
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("dns: %w", err)
		}
		closers = append(closers, pc)
		ln, err := net.Listen("tcp", ap.String())
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("dns: %w", err)
		}
		closers = append(closers, ln)
		go func() { _ = g.dns.ServeUDP(pc) }()
		go func() { _ = g.dns.ServeTCP(ln) }()
	}
	g.log.Info("Resolver listening", "listen", g.cfg.DNS.Listen, "upstream", g.dns.Upstream())
	return closeAll, nil
}

// Run serves until ctx is done, then withdraws from the tailnets, waits for
// the drain delay, and closes everything.
func (g *Gateway) Run(ctx context.Context) error {
	closeDNS, err := g.listenDNS()
	if err != nil {
		_ = g.host.Close()
		return err
	}
	// Last: the application may resolve names while it drains.
	defer closeDNS()

	nodeCtx, stopNodes := context.WithCancel(context.WithoutCancel(ctx))
	defer stopNodes()

	var wg sync.WaitGroup
	for _, node := range g.nodes {
		wg.Go(func() { node.Run(nodeCtx) })
	}

	pumps := sync.WaitGroup{}
	for i, q := range g.queues {
		pumps.Go(func() { g.fromHost(i, q) })
	}

	var api *http.Server
	if g.cfg.API.Listen != "" {
		ln, err := net.Listen("tcp", g.cfg.API.Listen)
		if err != nil {
			g.shutdown(stopNodes, &wg, &pumps)
			return fmt.Errorf("api: %w", err)
		}
		api = &http.Server{Handler: g.Handler(), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if err := api.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				g.log.Error("The API stopped", "err", err)
			}
		}()
		g.log.Info("API listening", "addr", ln.Addr().String())
	}

	<-ctx.Done()
	g.log.Info("Shutting down")

	g.Withdraw(context.Background())
	if d := g.cfg.Shutdown.DrainDelay; d > 0 {
		g.log.Info("Draining before closing", "delay", d)
		time.Sleep(d)
	}
	if api != nil {
		_ = api.Close()
	}
	g.shutdown(stopNodes, &wg, &pumps)
	return nil
}

func (g *Gateway) shutdown(stopNodes func(), nodes, pumps *sync.WaitGroup) {
	stopNodes()
	var closing sync.WaitGroup
	for _, node := range g.nodes {
		// Together: closing an ephemeral node logs it out, which takes a
		// while each.
		closing.Go(node.Close)
	}
	closing.Wait()
	nodes.Wait()
	if err := g.host.Close(); err != nil {
		g.log.Warn("Closing the host device", "err", err)
	}
	pumps.Wait()
}

// Withdraw stops every node publishing its routes and Services, once.
func (g *Gateway) Withdraw(ctx context.Context) {
	g.withdrawOnce.Do(func() {
		ctx, cancel := context.WithTimeout(ctx, withdrawTimeout)
		defer cancel()
		var wg sync.WaitGroup
		for _, node := range g.nodes {
			wg.Go(func() { node.Withdraw(ctx) })
		}
		wg.Wait()
	})
}

// addressesChanged puts a node's addresses on the host device.
func (g *Gateway) addressesChanged(id uint8, a tailnet.Addresses) {
	var others []netip.Addr
	for _, ips := range a.Services {
		others = append(others, ips...)
	}
	// A host route's address too. The AnyIP route already makes it the
	// host's own for accepting, but a reply sent from it with IPV6_PKTINFO,
	// as quic-go sends every one, is refused (EINVAL) unless the address is
	// assigned to an interface: HTTP/3 to a routed address went unanswered
	// while TCP worked. A wider route's addresses are not assigned, there
	// being too many.
	for _, p := range g.byID[id].Config().Routes {
		if p.IsSingleIP() {
			others = append(others, p.Addr())
		}
	}
	if err := g.host.SetLocal(id, a.Self, others); err != nil {
		g.log.Error("Cannot put the tailnet's addresses on the host device", "tailnet", id, "err", err)
	}
}

// fromTailnet is the Deliver for one tailnet's node: it translates what the
// node took from the tailnet and writes it to the host.
//
// With more than one device queue, each packet is written to the queue its
// flow maps to. Writes to one queue wait for each other, so this is what
// lets the tailnets' peers write side by side; and the kernel sends a flow's
// packets for the gateway to the queue the flow was last written to, so it is
// also what spreads the host's packets over the queues' readers. Written to
// one queue, every flow a peer has sent anything on is read from that queue.
func (g *Gateway) fromTailnet(id uint8, c *counters) tailnet.Deliver {
	pool := sync.Pool{New: func() any { return new(batch) }}
	queues := len(g.queues)

	return func(bufs [][]byte, offset int) {
		b := pool.Get().(*batch)
		defer pool.Put(b)
		b.reset(queues)

		for _, buf := range bufs {
			pkt := buf[offset:]
			out := b.next(len(pkt) + xlat.Growth)
			res := g.xlat.ToHost(id, pkt, out[hostOffset:])
			if res.Verdict != xlat.Forward {
				c.drop(inbound, res.Reason)
				continue
			}
			c.pass(inbound, len(res.Packet))
			q := 0
			if queues > 1 {
				q = int(flowOf(res.Packet) % uint32(queues))
			}
			b.out[q] = append(b.out[q], out[:hostOffset+len(res.Packet)])
		}
		for q, out := range b.out {
			if len(out) == 0 {
				continue
			}
			if _, err := g.writeTo(q, out, hostOffset); err != nil && !errors.Is(err, os.ErrClosed) {
				g.log.Debug("Writing to the host device", "tailnet", id, "err", err)
			}
		}
	}
}

// flowOf is a number the packets of one flow share: of an IPv6 packet's
// addresses, and its ports when it is TCP or UDP with nothing before them.
// A flow has to keep to one queue: the kernel moves the host's side of it to
// whichever queue it was last written to, and a flow that moved between two
// would be read by two goroutines, out of order.
func flowOf(pkt []byte) uint32 {
	if len(pkt) < 40 {
		return 0
	}
	h := binary.BigEndian.Uint64(pkt[8:])
	h = h*0x9e3779b97f4a7c15 ^ binary.BigEndian.Uint64(pkt[16:])
	h = h*0x9e3779b97f4a7c15 ^ binary.BigEndian.Uint64(pkt[24:])
	h = h*0x9e3779b97f4a7c15 ^ binary.BigEndian.Uint64(pkt[32:])
	if (pkt[6] == 6 || pkt[6] == 17) && len(pkt) >= 44 {
		h = h*0x9e3779b97f4a7c15 ^ uint64(binary.BigEndian.Uint32(pkt[40:]))
	}
	h *= 0x9e3779b97f4a7c15
	return uint32(h >> 32)
}

// batch holds the buffers one Deliver translates into, and which of them go
// to each of the device's queues.
type batch struct {
	bufs [][]byte
	used int
	out  [][][]byte
}

func (b *batch) reset(queues int) {
	b.used = 0
	if len(b.out) != queues {
		b.out = make([][][]byte, queues)
	}
	for q := range b.out {
		b.out[q] = b.out[q][:0]
	}
}

func (b *batch) next(size int) []byte {
	size += hostOffset
	if b.used < len(b.bufs) && cap(b.bufs[b.used]) >= size {
		buf := b.bufs[b.used][:size]
		b.used++
		return buf
	}
	buf := make([]byte, size, max(size, 2048))
	if b.used < len(b.bufs) {
		b.bufs[b.used] = buf
	} else {
		b.bufs = append(b.bufs, buf)
	}
	b.used++
	return buf
}

// handoffMin is the least a read from the host carries for the buffer it was
// read into to go to the node as it is. A smaller read is copied out to a
// buffer its own size instead, so that what waits for a node that is not
// keeping up is about the size of the packets waiting, not a read buffer for
// each of them.
const handoffMin = 32 << 10

// buffers are the buffers the host's packets wait for their nodes in: the
// slabs the device is read into, and smaller ones by size, each a
// tailnet.Batch that comes back here when its node is done with it.
type buffers struct {
	slabSize, packets int
	slabs             sync.Pool
	// compact[i] holds buffers of compactMin<<i bytes, up to handoffMin.
	compact [compactClasses]sync.Pool
}

const (
	compactMin     = 2 << 10
	compactClasses = 5
)

// The largest compact buffer holds any read too small to hand off.
const _ = uint(compactMin<<(compactClasses-1) - handoffMin)

func newBuffers(batchSize, mtu int) *buffers {
	return &buffers{
		// Room for a whole offloaded segment as the kernel hands it over,
		// and for every packet it splits into.
		slabSize: max(65536+2*tun.ReadPacketSpacing+16, batchSize*(mtu+tun.ReadPacketSpacing)+tun.ReadPacketSpacing),
		packets:  batchSize,
	}
}

// slab returns a batch to read the device into.
func (f *buffers) slab() *tailnet.Batch {
	if b, ok := f.slabs.Get().(*tailnet.Batch); ok {
		b.Packets = b.Packets[:cap(b.Packets)]
		return b
	}
	return &tailnet.Batch{
		Slab:    make([]byte, f.slabSize),
		Packets: make([]tun.ReadPacket, f.packets),
		Done:    f.put,
	}
}

// compactFor returns an empty batch with room for size bytes of packets.
func (f *buffers) compactFor(size int) *tailnet.Batch {
	class := compactClass(size)
	if class == compactClasses {
		// Larger than a read too small to hand off ever is: its own
		// buffer, which nothing takes back.
		return &tailnet.Batch{Slab: make([]byte, size)}
	}
	if b, ok := f.compact[class].Get().(*tailnet.Batch); ok {
		b.Packets = b.Packets[:0]
		return b
	}
	return &tailnet.Batch{Slab: make([]byte, compactMin<<class), Done: f.put}
}

// compactClass is the smallest class of compact buffer that holds size
// bytes, or compactClasses when none does.
func compactClass(size int) int {
	class := 0
	for class < compactClasses && compactMin<<class < size {
		class++
	}
	return class
}

// put takes back a batch that came from here, once its packets are finished
// with.
func (f *buffers) put(b *tailnet.Batch) {
	if len(b.Slab) == f.slabSize {
		f.slabs.Put(b)
		return
	}
	if class := compactClass(len(b.Slab)); class < compactClasses && len(b.Slab) == compactMin<<class {
		f.compact[class].Put(b)
	}
}

// fromHost reads what the host routed into one of the device's queues and
// sends each read to the node of the tailnet it is for, which translates it.
func (g *Gateway) fromHost(queue int, q tun.Queue) {
	// For the packets answered here: room for one, or for an ICMPv6 error
	// about it.
	mtu, _ := g.host.Device().MTU()
	scratch := make([]byte, hostOffset+max(mtu, 1280))

	b := g.bufs.slab()
	for {
		n, err := q.Read(b.Slab, b.Packets[:cap(b.Packets)])
		b.Packets = b.Packets[:n]
		if n > 0 {
			g.queueReads[queue].Add(uint64(n))
			if g.forward(queue, b, scratch) {
				b = g.bufs.slab()
			}
		}

		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			if errors.Is(err, tun.ErrTooManySegments) {
				g.log.Warn("The host device produced more segments than a read holds", "err", err)
				continue
			}
			g.log.Error("Reading the host device", "err", err)
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// forward sends one read's packets on. It reports whether b went to a node
// as it is, in which case the next read needs another.
//
// A read is one packet, or the segments of one that the kernel left whole for
// the gateway to split: one flow's either way, and so one tailnet's. That
// tailnet's node gets the read in one piece. Anything else is taken a packet
// at a time.
func (g *Gateway) forward(queue int, b *tailnet.Batch, scratch []byte) bool {
	first := b.Packets[0]
	id, same := g.xlat.Tailnet(b.Slab[first.Offset : first.Offset+first.Size])
	total := first.Size
	for _, p := range b.Packets[1:] {
		total += p.Size
		if same {
			t, ok := g.xlat.Tailnet(b.Slab[p.Offset : p.Offset+p.Size])
			same = ok && t == id
		}
	}

	if same && g.byID[id] != nil {
		if total >= handoffMin {
			if g.byID[id].Send(b) {
				return true
			}
			g.counts[id].dropN(outbound, xlat.NumReasons, len(b.Packets)) // not up, or not keeping up
			return false
		}
		g.sendCopy(id, b.Slab, b.Packets, total)
		return false
	}

	for i, p := range b.Packets {
		pkt := b.Slab[p.Offset : p.Offset+p.Size]
		if id, ok := g.xlat.Tailnet(pkt); ok && g.byID[id] != nil {
			g.sendCopy(id, b.Slab, b.Packets[i:i+1], p.Size)
			continue
		}
		// For no tailnet: translating it says what is wrong with it, and
		// whether the host is told.
		res := g.xlat.ToTailnet(pkt, scratch[hostOffset:])
		switch res.Verdict {
		case xlat.Reply:
			g.countHost(res.Reason)
			g.reply(queue, res.Packet)
		case xlat.Forward:
			g.unrouted.drop(outbound, xlat.NumReasons)
		default:
			g.countHost(res.Reason)
		}
	}
	return false
}

// sendCopy sends a tailnet's node a copy of some of a read's packets, in a
// buffer of about their size.
func (g *Gateway) sendCopy(id uint8, slab []byte, packets []tun.ReadPacket, total int) {
	c := g.bufs.compactFor(total)
	off := 0
	for _, p := range packets {
		copy(c.Slab[off:], slab[p.Offset:p.Offset+p.Size])
		c.Packets = append(c.Packets, tun.ReadPacket{Offset: off, Size: p.Size})
		off += p.Size
	}
	if !g.byID[id].Send(c) {
		g.counts[id].dropN(outbound, xlat.NumReasons, len(packets)) // not up, or not keeping up
		if c.Done != nil {
			c.Done(c)
		}
	}
}

// toTailnet is the Translate for one tailnet's node: it translates what the
// host sent for the tailnet as the node reads it, into the node's own buffer.
// A packet the host is to be told about is answered from here.
func (g *Gateway) toTailnet(id uint8, c *counters) tailnet.Translate {
	return func(pkt, out []byte) (int, [][]byte) {
		res := g.xlat.ToTailnet(pkt, out)
		switch {
		case res.Verdict == xlat.Forward && res.Tailnet != id:
			// Not this node's, which the destination it was sent here by
			// rules out.
			c.drop(outbound, xlat.NumReasons)
		case res.Verdict == xlat.Forward && res.Fragments != nil:
			c.fragmented.Add(1)
			for _, f := range res.Fragments {
				c.pass(outbound, len(f))
			}
			return 0, res.Fragments
		case res.Verdict == xlat.Forward:
			c.pass(outbound, len(res.Packet))
			return len(res.Packet), nil
		case res.Verdict == xlat.Reply:
			g.countHost(res.Reason)
			g.reply(int(id), res.Packet)
		default:
			g.countHost(res.Reason)
		}
		return 0, nil
	}
}

// reply writes the host an ICMPv6 error about a packet it sent.
func (g *Gateway) reply(flow int, pkt []byte) {
	buf := make([]byte, hostOffset+len(pkt))
	copy(buf[hostOffset:], pkt)
	if _, err := g.writeTo(flow, [][]byte{buf}, hostOffset); err != nil && !errors.Is(err, os.ErrClosed) {
		g.log.Debug("Writing an error to the host device", "err", err)
	}
}

// countHost counts a packet from the host that went to no tailnet.
func (g *Gateway) countHost(r xlat.Reason) { g.unrouted.drop(outbound, r) }

// Node returns a tailnet's node by name.
func (g *Gateway) Node(name string) (*tailnet.Node, bool) {
	n, ok := g.nodes[name]
	return n, ok
}

// NodeByID returns a tailnet's node by number.
func (g *Gateway) NodeByID(id uint8) *tailnet.Node { return g.byID[id] }

// Scheme returns the addressing scheme.
func (g *Gateway) Scheme() *addr.Scheme { return g.scheme }
