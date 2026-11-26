// Package hostnet is the host's side of the gateway: a TUN device in the
// network namespace the application runs in, and the routes and addresses
// that bring the application's packets for the tailnets to it.
//
// Nothing intercepts the application's packets. The gateway's pseudo
// addresses are ordinary routes:
//
//   - Each tailnet's local side, the /44 of the gateway's own addresses on
//     it, is an AnyIP route: a "local" route in the local table, which makes
//     every address in it the host's own. A connection to any of them is
//     accepted by a socket on the wildcard address, with no address
//     assigned.
//   - Each tailnet's remote side, its peers, routes into the device. That
//     is where the application's replies go, and anything it dials.
//   - The whole /32 routes into the device too, beneath those, so that a
//     packet for a tailnet that is not configured, or not up, is answered
//     with an ICMPv6 error by the gateway instead of leaking out of the
//     default route.
//
// The node's own addresses and its Services' virtual IPs are also assigned to
// the device, as /128s, for an application that binds one of them, and each
// remote route carries the gateway's address in its family as its preferred
// source, so a connection the application dials leaves from it.
//
// The device's MTU is the tailnet's plus 48, and so are its routes'. That is
// room for an IPv6 packet carrying 1280 bytes of UDP, which is what quic-go,
// and so Traefik's HTTP/3, sends its first packets with, and with the
// don't-fragment bit: on an interface of the tailnet's own 1280 the kernel
// refuses every one. Anything the tailnet cannot carry whole is fragmented
// by the gateway (package xlat). TCP never is: the gateway clamps each SYN's
// MSS to what the tailnet carries, so neither end sends a larger segment.
package hostnet

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"

	"github.com/davefinster/multits/internal/addr"
	"github.com/tailscale/wireguard-go/tun"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// routeProtocol marks the routes the gateway installs, so that ones left
// behind by a gateway that did not exit cleanly are found and replaced.
const routeProtocol = netlink.RouteProtocol(77)

// headroom is how much larger than the tailnets' MTU the device's is: an
// IPv6 and a UDP header on top of a 1280-byte QUIC packet.
const headroom = 48

// addrGenModeNone is IN6_ADDR_GEN_MODE_NONE, which x/sys does not name.
const addrGenModeNone = 1

// Options configure the device.
type Options struct {
	// Name is the device's name.
	Name string
	// TailnetMTU is the largest packet the tailnets carry.
	TailnetMTU int
	// Queues is how many queues the device has, each read by its own
	// goroutine.
	Queues int
}

// Interface is the device and what the gateway has configured on it.
type Interface struct {
	dev    tun.Device
	link   netlink.Link
	lo     netlink.Link
	scheme *addr.Scheme
	opts   Options
	log    *slog.Logger

	mu       sync.Mutex
	assigned map[netip.Addr]bool
	routes   []*netlink.Route
}

// Open creates the device and its routes for the tailnets.
func Open(scheme *addr.Scheme, tailnets []uint8, opts Options, log *slog.Logger) (*Interface, error) {
	if err := ensureTunNode(); err != nil {
		return nil, err
	}

	var tunOpts []tun.Option
	if opts.Queues > 1 {
		tunOpts = append(tunOpts, tun.WithQueues(opts.Queues))
	}
	dev, err := tun.CreateTUN(opts.Name, opts.TailnetMTU+headroom, tunOpts...)
	if err != nil {
		return nil, fmt.Errorf("creating %s: %w", opts.Name, err)
	}

	i := &Interface{dev: dev, scheme: scheme, opts: opts, log: log, assigned: map[netip.Addr]bool{}}
	if err := i.setup(tailnets); err != nil {
		_ = i.Close()
		return nil, err
	}
	return i, nil
}

// ensureTunNode makes /dev/net/tun when a container runtime left it out.
// It needs CAP_MKNOD, which most runtimes grant, and a device cgroup that
// allows the TUN device, which most runtimes do.
func ensureTunNode() error {
	const path = "/dev/net/tun"
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll("/dev/net", 0o755); err != nil {
		return fmt.Errorf("%s is missing and cannot be made: %w", path, err)
	}
	if err := unix.Mknod(path, unix.S_IFCHR|0o600, int(unix.Mkdev(10, 200))); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s is missing and cannot be made: %w", path, err)
	}
	return nil
}

func (i *Interface) setup(tailnets []uint8) error {
	name, err := i.dev.Name()
	if err != nil {
		return err
	}
	if i.link, err = netlink.LinkByName(name); err != nil {
		return fmt.Errorf("finding %s: %w", name, err)
	}
	if i.lo, err = netlink.LinkByName("lo"); err != nil {
		return fmt.Errorf("finding lo: %w", err)
	}
	// The loopback carries the AnyIP routes, and an interface that is down
	// takes its routes with it.
	if err := netlink.LinkSetUp(i.lo); err != nil {
		return fmt.Errorf("bringing lo up: %w", err)
	}

	// No link-local address, so the kernel has nothing to solicit routers
	// or report multicast listeners from; there is no link to do either on.
	if err := netlink.LinkSetIP6AddrGenMode(i.link, addrGenModeNone); err != nil {
		i.log.Warn("Cannot turn off link-local addressing on the device; its chatter is dropped instead", "err", err)
	}
	if err := netlink.LinkSetUp(i.link); err != nil {
		return fmt.Errorf("bringing %s up: %w", name, err)
	}

	if err := i.removeStaleRoutes(); err != nil {
		return err
	}

	i.routes = append(i.routes, &netlink.Route{
		LinkIndex: i.link.Attrs().Index,
		Dst:       ipNet(i.scheme.Prefix()),
		MTU:       i.opts.TailnetMTU + headroom,
		Protocol:  routeProtocol,
		Priority:  1024,
	})
	for _, t := range tailnets {
		i.routes = append(i.routes, i.localRoute(t), i.remoteRoute4(t, netip.Addr{}), i.remoteRoute6(t, netip.Addr{}))
	}
	for _, r := range i.routes {
		if err := netlink.RouteReplace(r); err != nil {
			return fmt.Errorf("adding route %s: %w", r, err)
		}
	}

	i.log.Info("Host device is up", "device", name, "mtu", i.opts.TailnetMTU+headroom, "prefix", i.scheme.Prefix())
	return nil
}

// localRoute is the AnyIP route that makes a tailnet's local side the
// host's own.
func (i *Interface) localRoute(t uint8) *netlink.Route {
	return &netlink.Route{
		LinkIndex: i.lo.Attrs().Index,
		Dst:       ipNet(i.scheme.SidePrefix(t, addr.Local)),
		Table:     unix.RT_TABLE_LOCAL,
		Type:      unix.RTN_LOCAL,
		Scope:     netlink.SCOPE_HOST,
		Protocol:  routeProtocol,
	}
}

// remoteRoute4 routes a tailnet's IPv4 peers into the device, from src if
// it is known.
func (i *Interface) remoteRoute4(t uint8, src netip.Addr) *netlink.Route {
	return i.remoteRoute(i.scheme.SpacePrefix(t, addr.Remote, addr.SpaceIPv4), i.opts.TailnetMTU+headroom, src)
}

// remoteRoute6 routes a tailnet's IPv6 peers, every other space of its
// remote side, into the device.
func (i *Interface) remoteRoute6(t uint8, src netip.Addr) *netlink.Route {
	return i.remoteRoute(i.scheme.SidePrefix(t, addr.Remote), i.opts.TailnetMTU+headroom, src)
}

func (i *Interface) remoteRoute(dst netip.Prefix, mtu int, src netip.Addr) *netlink.Route {
	r := &netlink.Route{
		LinkIndex: i.link.Attrs().Index,
		Dst:       ipNet(dst),
		MTU:       mtu,
		Protocol:  routeProtocol,
		Priority:  1024,
	}
	if src.IsValid() {
		r.Src = net.IP(src.AsSlice())
	}
	return r
}

// removeStaleRoutes deletes routes a previous gateway installed and did not
// remove. Those through its device went with it; the AnyIP routes on the
// loopback did not.
func (i *Interface) removeStaleRoutes() error {
	stale, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Protocol: routeProtocol, Table: unix.RT_TABLE_UNSPEC},
		netlink.RT_FILTER_PROTOCOL|netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("listing routes: %w", err)
	}
	for _, r := range stale {
		if err := netlink.RouteDel(&r); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("removing stale route %s: %w", r, err)
		}
	}
	return nil
}

// SetLocal makes the device hold a tailnet's local addresses, given as
// addresses on the tailnet: the node's own, which become the preferred
// sources of the tailnet's routes, and others such as its Services' virtual
// IPs.
func (i *Interface) SetLocal(t uint8, self, others []netip.Addr) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	want := map[netip.Addr]bool{}
	var src4, src6 netip.Addr
	for n, ip := range slices.Concat(self, others) {
		p, err := i.scheme.Encode(t, addr.Local, ip)
		if err != nil {
			i.log.Warn("A local address has no pseudo address", "tailnet", t, "ip", ip, "err", err)
			continue
		}
		want[p] = true
		if n >= len(self) {
			continue
		}
		if ip.Is4() && !src4.IsValid() {
			src4 = p
		}
		if ip.Is6() && !src6.IsValid() {
			src6 = p
		}
	}

	var errs []error
	for p := range want {
		if i.assigned[p] {
			continue
		}
		a := &netlink.Addr{
			IPNet: ipNet(netip.PrefixFrom(p, 128)),
			Flags: unix.IFA_F_NODAD | unix.IFA_F_NOPREFIXROUTE,
			Scope: unix.RT_SCOPE_UNIVERSE,
		}
		if err := netlink.AddrReplace(i.link, a); err != nil {
			errs = append(errs, fmt.Errorf("assigning %s: %w", p, err))
			continue
		}
		i.assigned[p] = true
	}

	tailnet := i.scheme.TailnetPrefix(t)
	for p := range i.assigned {
		if !tailnet.Contains(p) || want[p] {
			continue
		}
		if err := netlink.AddrDel(i.link, &netlink.Addr{IPNet: ipNet(netip.PrefixFrom(p, 128))}); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
			errs = append(errs, fmt.Errorf("removing %s: %w", p, err))
			continue
		}
		delete(i.assigned, p)
	}

	// The preferred sources go after the addresses: the kernel refuses one
	// that is not yet assigned.
	for _, r := range []*netlink.Route{i.remoteRoute4(t, src4), i.remoteRoute6(t, src6)} {
		if err := netlink.RouteReplace(r); err != nil {
			errs = append(errs, fmt.Errorf("pointing %s at %s: %w", r.Dst, r.Src, err))
		}
	}

	if len(errs) == 0 {
		addrs := slices.Collect(func(yield func(string) bool) {
			for p := range want {
				if !yield(p.String()) {
					return
				}
			}
		})
		slices.Sort(addrs)
		i.log.Info("Host addresses for the tailnet", "tailnet", t, "addresses", addrs)
	}
	return errors.Join(errs...)
}

// AddGatewayAddress assigns one of the gateway's own addresses to the
// device, for a socket of its own to bind: its resolver's.
func (i *Interface) AddGatewayAddress(ip netip.Addr) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	a := &netlink.Addr{
		IPNet: ipNet(netip.PrefixFrom(ip, ip.BitLen())),
		Flags: unix.IFA_F_NODAD | unix.IFA_F_NOPREFIXROUTE,
		Scope: unix.RT_SCOPE_UNIVERSE,
	}
	if err := netlink.AddrReplace(i.link, a); err != nil {
		return fmt.Errorf("assigning %s: %w", ip, err)
	}
	return nil
}

// Device is the TUN device, for reading and writing packets.
func (i *Interface) Device() tun.Device { return i.dev }

// Name is the device's name.
func (i *Interface) Name() string { return i.opts.Name }

// Close removes the routes and the device.
func (i *Interface) Close() error {
	// The AnyIP routes are on the loopback and outlive the device; the
	// rest go with it.
	for _, r := range i.routes {
		if r.Type == unix.RTN_LOCAL {
			_ = netlink.RouteDel(r)
		}
	}
	return i.dev.Close()
}

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}
