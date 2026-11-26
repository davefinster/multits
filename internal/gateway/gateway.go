// Package gateway joins the pieces: a node per tailnet, the host's device,
// and the translator between them. Packets from a tailnet are translated and
// written to the host; packets the host routes into the device are
// translated and sent to the tailnet their destination names.
package gateway

import (
	"context"
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

	for _, tc := range cfg.Tailnets {
		id := tc.ID
		c := &counters{}
		g.counts[id] = c
		node := tailnet.New(tc, g.fromTailnet(id, c), func(a tailnet.Addresses) { g.addressesChanged(id, a) }, log)
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

	dev := g.host.Device()
	queues := []tun.Queue{dev}
	if mq, ok := dev.(tun.MultiQueueDevice); ok {
		queues = mq.Queues()
	}
	pumps := sync.WaitGroup{}
	for _, q := range queues {
		pumps.Go(func() { g.fromHost(q) })
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
func (g *Gateway) fromTailnet(id uint8, c *counters) tailnet.Deliver {
	dev := func() tun.Device { return g.host.Device() }
	pool := sync.Pool{New: func() any { return new(batch) }}

	return func(bufs [][]byte, offset int) {
		b := pool.Get().(*batch)
		defer pool.Put(b)
		b.reset()

		for _, buf := range bufs {
			pkt := buf[offset:]
			out := b.next(len(pkt) + xlat.Growth)
			res := g.xlat.ToHost(id, pkt, out[hostOffset:])
			if res.Verdict != xlat.Forward {
				c.drop(inbound, res.Reason)
				continue
			}
			c.pass(inbound, len(res.Packet))
			b.out = append(b.out, out[:hostOffset+len(res.Packet)])
		}
		if len(b.out) == 0 {
			return
		}
		if _, err := dev().Write(b.out, hostOffset); err != nil && !errors.Is(err, os.ErrClosed) {
			g.log.Debug("Writing to the host device", "tailnet", id, "err", err)
		}
	}
}

// batch holds the buffers one Deliver translates into.
type batch struct {
	bufs [][]byte
	used int
	out  [][]byte
}

func (b *batch) reset() { b.used, b.out = 0, b.out[:0] }

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

// fromHost reads what the host routed into the device and sends each packet
// to the tailnet its destination names.
func (g *Gateway) fromHost(q tun.Queue) {
	dev := g.host.Device()
	batchSize := max(dev.BatchSize(), 1)
	mtu, _ := dev.MTU()
	// Room for a whole offloaded segment as the kernel hands it over, and
	// for every packet it splits into.
	slab := make([]byte, max(65536+2*tun.ReadPacketSpacing+16, batchSize*(mtu+tun.ReadPacketSpacing)+tun.ReadPacketSpacing))
	packets := make([]tun.ReadPacket, batchSize)
	var replies [][]byte

	for {
		n, err := q.Read(slab, packets)
		replies = replies[:0]
		for _, p := range packets[:n] {
			pkt := slab[p.Offset : p.Offset+p.Size]
			out := make([]byte, hostOffset+max(len(pkt), 1280))
			res := g.xlat.ToTailnet(pkt, out[hostOffset:])
			switch res.Verdict {
			case xlat.Forward:
				c, node := g.counts[res.Tailnet], g.byID[res.Tailnet]
				pkts := res.Fragments
				if pkts == nil {
					pkts = [][]byte{res.Packet}
				} else {
					c.fragmented.Add(1)
				}
				for _, p := range pkts {
					if node.Send(p) {
						c.pass(outbound, len(p))
					} else {
						c.drop(outbound, xlat.NumReasons) // not up, or not keeping up
					}
				}
			case xlat.Reply:
				g.countHost(res.Reason)
				replies = append(replies, out[:hostOffset+len(res.Packet)])
			default:
				g.countHost(res.Reason)
			}
		}
		if len(replies) > 0 {
			if _, werr := dev.Write(replies, hostOffset); werr != nil && !errors.Is(werr, os.ErrClosed) {
				g.log.Debug("Writing an error to the host device", "err", werr)
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
