// Package tailnet runs the gateway's embedded Tailscale nodes, one per
// tailnet. Each is a tsnet.Server given an in-memory device in place of an
// operating system's, so that the packets addressed to it come to the
// gateway as packets rather than being terminated in tsnet's own stack, and
// what the gateway sends goes out over WireGuard as though the node's host
// had sent it.
//
// Joining, retrying on a fresh server, and withdrawing ahead of shutdown
// follow the traefik-tsnet tailnets, which run the same nodes in-process.
package tailnet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	// Registers workload identity federation, which mints the auth key for
	// a clientID from an ID token. Without it, tsnet ignores the client ID.
	_ "tailscale.com/feature/identityfederation"
	// Registers OAuth client secrets (tskey-client-...) as auth keys.
	// Without it, tsnet would send the secret to the control plane as
	// though it were an auth key, and the join would be refused.
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/tailscale/apitype"
	_ "tailscale.com/feature/oauthkey"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tsnet"
)

// MTU is the largest packet a node sends or receives: Tailscale's default,
// which every peer uses unless told otherwise.
const MTU = 1280

const (
	retryInitial = time.Second
	retryMax     = 30 * time.Second
	// zonesRefresh is how often the tailnet's DNS zones are read again.
	zonesRefresh = 30 * time.Second
	// prefsTimeout bounds the local API calls that publish routes and
	// Services, so a wedged backend is a retry rather than a hang.
	prefsTimeout = 30 * time.Second
)

// Config is one tailnet's node.
type Config struct {
	// Name is how the configuration and the logs refer to the tailnet.
	Name string
	// ID is the tailnet's number in the pseudo addresses.
	ID uint8

	Hostname    string
	StateDir    string
	AuthKey     string
	AuthKeyFile string
	ClientID    string
	IDTokenFile string
	ControlURL  string
	Ephemeral   bool
	Port        uint16

	AdvertiseTags []string
	// Routes are advertised as this node's subnet routes. Their addresses
	// arrive at the host as the gateway's own.
	Routes []netip.Prefix
	// AcceptRoutes uses other nodes' subnet routes, so the host can reach
	// what is behind them.
	AcceptRoutes bool
	// Services are Tailscale Services this node hosts, in TUN mode: every
	// port and protocol of their virtual IPs arrives at the host.
	Services []tailcfg.ServiceName
	// DNSDomains are resolved through the tailnet's resolver as well as
	// the domains it routes itself.
	DNSDomains []string
}

// Addresses are the node's own addresses on its tailnet.
type Addresses struct {
	// Self is the node's address in each family.
	Self []netip.Addr
	// Services are the virtual IPs assigned to each Service it hosts.
	Services map[tailcfg.ServiceName][]netip.Addr
}

// Equal reports whether two sets of addresses are the same.
func (a Addresses) Equal(b Addresses) bool {
	if !slices.Equal(a.Self, b.Self) || len(a.Services) != len(b.Services) {
		return false
	}
	for name, ips := range a.Services {
		if !slices.Equal(ips, b.Services[name]) {
			return false
		}
	}
	return true
}

// All returns every address in a.
func (a Addresses) All() []netip.Addr {
	all := slices.Clone(a.Self)
	for _, ips := range a.Services {
		all = append(all, ips...)
	}
	slices.SortFunc(all, func(x, y netip.Addr) int { return x.Compare(y) })
	return slices.Compact(all)
}

// Node is one embedded Tailscale node.
type Node struct {
	cfg       Config
	deliver   Deliver
	translate Translate
	changed   func(Addresses)
	log       *slog.Logger

	// startMu serializes joins. It is not mu: tsnet.Server.Start takes no
	// context, and Close must not queue behind it.
	startMu sync.Mutex

	mu        sync.Mutex
	srv       *tsnet.Server
	dev       *device
	addrs     Addresses
	zones     []string
	state     string
	closed    bool
	withdrawn bool
	hosted    bool
}

// New prepares a node. deliver receives the packets it takes from the
// tailnet; translate turns each of the host's packets it is sent into the
// tailnet's, as the node reads it; changed is told its addresses whenever
// they change.
func New(cfg Config, deliver Deliver, translate Translate, changed func(Addresses), log *slog.Logger) *Node {
	return &Node{
		cfg:       cfg,
		deliver:   deliver,
		translate: translate,
		changed:   changed,
		log:       log.With("tailnet", cfg.Name),
		state:     "Starting",
		zones:     slices.Clone(cfg.DNSDomains),
	}
}

// Config returns the node's configuration.
func (n *Node) Config() Config { return n.cfg }

// Send queues a batch of the host's packets for the tailnet. It reports
// whether it took the batch, which is then the node's until it calls the
// batch's Done. It refuses when the node is not up, or not keeping up, and
// the batch is still the caller's.
func (n *Node) Send(b *Batch) bool {
	n.mu.Lock()
	dev := n.dev
	n.mu.Unlock()
	if dev == nil {
		return false
	}
	return dev.send(b)
}

// Addresses returns the node's addresses as last seen.
func (n *Node) Addresses() Addresses {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.addrs
}

// State is the node's backend state as last seen: Starting, NeedsLogin,
// Running and so on.
func (n *Node) State() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.state
}

// Status returns the node's full status, if it has started.
func (n *Node) Status(ctx context.Context) (*ipnstate.Status, error) {
	srv, err := n.current()
	if err != nil {
		return nil, err
	}
	client, err := srv.LocalClient()
	if err != nil {
		return nil, err
	}
	return client.Status(ctx)
}

// WhoIs asks the node who is behind an address on its tailnet.
func (n *Node) WhoIs(ctx context.Context, remote netip.AddrPort) (*apitype.WhoIsResponse, error) {
	srv, err := n.current()
	if err != nil {
		return nil, err
	}
	client, err := srv.LocalClient()
	if err != nil {
		return nil, err
	}
	who := remote.Addr().String()
	if remote.Port() != 0 {
		who = remote.String()
	}
	return client.WhoIs(ctx, who)
}

// Zones are the domains the tailnet's resolver answers for: its MagicDNS
// suffix, its split-DNS domains, the names of its extra records, and the
// configured DNSDomains. They are lowercase, without trailing dots.
func (n *Node) Zones() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.zones
}

// QueryDNS asks the tailnet's resolver, MagicDNS, returning its raw answer.
func (n *Node) QueryDNS(ctx context.Context, name string, qtype dnsmessage.Type) ([]byte, error) {
	srv, err := n.current()
	if err != nil {
		return nil, err
	}
	client, err := srv.LocalClient()
	if err != nil {
		return nil, err
	}
	res, _, err := client.QueryDNS(ctx, name, strings.TrimPrefix(qtype.String(), "Type"))
	return res, err
}

// IsLocal reports whether ip is the node's own on the tailnet: one of its
// addresses, a Service's it hosts, or in a route it advertises.
func (n *Node) IsLocal(ip netip.Addr) bool {
	if slices.Contains(n.Addresses().All(), ip) {
		return true
	}
	for _, p := range n.cfg.Routes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// refreshZones reads the domains the tailnet's resolver answers for.
func (n *Node) refreshZones(ctx context.Context, srv *tsnet.Server) {
	client, err := srv.LocalClient()
	if err != nil {
		return
	}
	zones := slices.Clone(n.cfg.DNSDomains)
	add := func(name string) {
		name = strings.TrimSuffix(strings.ToLower(name), ".")
		// Reverse zones are for the tailnet's own addresses, which the
		// host never asks about: it knows only their pseudo addresses.
		if name != "" && !strings.HasSuffix(name, ".arpa") {
			zones = append(zones, name)
		}
	}

	status, err := client.StatusWithoutPeers(ctx)
	if err != nil {
		return
	}
	if tn := status.CurrentTailnet; tn != nil && tn.MagicDNSEnabled {
		add(tn.MagicDNSSuffix)
	}
	if cfg, err := client.DNSConfig(ctx); err == nil && cfg != nil {
		for domain := range cfg.Routes {
			add(domain)
		}
		for _, rec := range cfg.ExtraRecords {
			add(rec.Name)
		}
	}
	slices.Sort(zones)
	zones = slices.Compact(zones)

	n.mu.Lock()
	same := slices.Equal(n.zones, zones)
	n.zones = zones
	n.mu.Unlock()
	if !same {
		n.log.Info("DNS zones", "zones", zones)
	}
}

var errNotStarted = errors.New("not joined yet")

func (n *Node) current() (*tsnet.Server, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	switch {
	case n.closed:
		return nil, net.ErrClosed
	case n.srv == nil:
		return nil, errNotStarted
	}
	return n.srv, nil
}

// Run joins the tailnet, retrying until it can, and then follows the node's
// state until ctx is done or the node is closed. A tailnet that cannot be
// reached costs only its own traffic.
func (n *Node) Run(ctx context.Context) {
	for interval := retryInitial; ; interval = min(interval*2, retryMax) {
		err := n.join(ctx)
		if err == nil {
			break
		}
		if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
			return
		}
		n.log.Warn("Cannot join the tailnet yet, retrying", "err", err, "retryIn", interval)
		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return
		}
	}

	for ctx.Err() == nil {
		err := n.watch(ctx)
		if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
			return
		}
		n.log.Warn("Lost the node's state, watching again", "err", err)
		select {
		case <-time.After(retryInitial):
		case <-ctx.Done():
			return
		}
	}
}

// join builds a node, starts it, and publishes its routes.
func (n *Node) join(ctx context.Context) error {
	n.startMu.Lock()
	defer n.startMu.Unlock()

	if _, err := n.current(); !errors.Is(err, errNotStarted) {
		return err
	}

	srv, dev, err := n.build()
	if err != nil {
		return err
	}

	// tsnet caches a failed start forever on the server it happened to, so
	// a retry has to be a fresh one; and a server that failed to start
	// cleaned up after itself.
	if err := srv.Start(); err != nil {
		_ = dev.Close()
		return fmt.Errorf("joining: %w", err)
	}

	// Routes are preferences, which tsnet does not carry on its Server, so
	// they are applied once it has started. A node that advertises nothing
	// it was told to would look healthy and route nothing, so a failure
	// here is a retry too.
	if err := n.applyPrefs(ctx, srv); err != nil {
		_ = srv.Close()
		return err
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		_ = srv.Close()
		return net.ErrClosed
	}
	n.srv, n.dev = srv, dev
	return nil
}

// build assembles an unstarted server. The auth key and ID token are read
// now rather than at startup, so that a key delivered late is picked up on a
// retry and a rotated token is the current one.
func (n *Node) build() (*tsnet.Server, *device, error) {
	authKey := n.cfg.AuthKey
	if n.cfg.AuthKeyFile != "" {
		b, err := os.ReadFile(n.cfg.AuthKeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("reading authKeyFile: %w", err)
		}
		authKey = strings.TrimSpace(string(b))
	}
	var idToken string
	if n.cfg.IDTokenFile != "" {
		b, err := os.ReadFile(n.cfg.IDTokenFile)
		if err != nil {
			return nil, nil, fmt.Errorf("reading idTokenFile: %w", err)
		}
		idToken = strings.TrimSpace(string(b))
	}

	dev := newDevice(n.deliver, n.translate)
	srv := &tsnet.Server{
		Hostname:      n.cfg.Hostname,
		Dir:           n.cfg.StateDir,
		AuthKey:       authKey,
		ClientID:      federatedClientID(n.cfg.ClientID, n.cfg.Ephemeral),
		IDToken:       idToken,
		ControlURL:    n.cfg.ControlURL,
		Ephemeral:     n.cfg.Ephemeral,
		AdvertiseTags: n.cfg.AdvertiseTags,
		Port:          n.cfg.Port,
		Tun:           dev,
		UserLogf: func(format string, args ...any) {
			n.log.Info(fmt.Sprintf(format, args...))
		},
		Logf: func(format string, args ...any) {
			n.log.Debug(fmt.Sprintf(format, args...))
		},
	}
	return srv, dev, nil
}

// federatedClientID carries the node's ephemerality to the auth key its
// federated identity mints. Tailscale assumes ephemeral when the client ID
// says nothing, so a persistent node would otherwise be removed from the
// tailnet the next time it went offline.
func federatedClientID(clientID string, ephemeral bool) string {
	if clientID == "" || strings.Contains(clientID, "?") {
		return clientID
	}
	return clientID + "?ephemeral=" + strconv.FormatBool(ephemeral)
}

// applyPrefs sets the preferences tsnet has no field for.
func (n *Node) applyPrefs(ctx context.Context, srv *tsnet.Server) error {
	if len(n.cfg.Routes) == 0 && !n.cfg.AcceptRoutes {
		return nil
	}
	client, err := srv.LocalClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, prefsTimeout)
	defer cancel()

	prefs := &ipn.MaskedPrefs{
		RouteAllSet: true,
		Prefs:       ipn.Prefs{RouteAll: n.cfg.AcceptRoutes},
	}
	if len(n.cfg.Routes) > 0 && !n.isWithdrawn() {
		prefs.AdvertiseRoutesSet = true
		prefs.AdvertiseRoutes = n.cfg.Routes
	}
	if _, err := client.EditPrefs(ctx, prefs); err != nil {
		return fmt.Errorf("setting preferences: %w", err)
	}
	if prefs.AdvertiseRoutesSet {
		n.log.Info("Advertised routes; they need approval in the tailnet policy", "routes", n.cfg.Routes)
	}
	return nil
}

// watch follows the node's notifications: its state, and whenever its own
// node changes, its addresses. It hosts the Services once the node is running.
func (n *Node) watch(ctx context.Context) error {
	srv, err := n.current()
	if err != nil {
		return err
	}
	client, err := srv.LocalClient()
	if err != nil {
		return err
	}

	watcher, err := client.WatchIPNBus(ctx, ipn.NotifyInitialState|ipn.NotifyInitialStatus)
	if err != nil {
		return err
	}
	defer watcher.Close()

	// The DNS configuration comes with the network map, which the watcher
	// no longer carries, so it is read again now and then as well as on
	// every change to the node.
	watching, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		for {
			select {
			case <-time.After(zonesRefresh):
				n.refreshZones(watching, srv)
			case <-watching.Done():
				return
			}
		}
	}()

	for {
		notify, err := watcher.Next()
		if err != nil {
			if _, cerr := n.current(); cerr != nil {
				return cerr
			}
			return err
		}

		if notify.State != nil {
			state := notify.State.String()
			n.mu.Lock()
			prev := n.state
			n.state = state
			n.mu.Unlock()
			if state != prev {
				n.log.Info("Node state", "state", state)
			}
			if *notify.State == ipn.Running {
				n.hostServices(ctx, srv)
			}
		}
		if notify.BrowseToURL != nil {
			n.log.Warn("The node needs an interactive login, which a gateway cannot do: give it an auth key", "url", *notify.BrowseToURL)
		}
		// The node's own addresses and capabilities, which carry the
		// Services' virtual IPs, change only with a SelfChange, and the
		// first of those is the initial status.
		if notify.InitialStatus != nil || notify.SelfChange != nil {
			n.refresh(ctx, srv)
			n.refreshZones(ctx, srv)
		}
	}
}

// refresh reads the node's addresses and reports them if they changed.
func (n *Node) refresh(ctx context.Context, srv *tsnet.Server) {
	client, err := srv.LocalClient()
	if err != nil {
		return
	}
	status, err := client.Status(ctx)
	if err != nil || status.Self == nil {
		return
	}

	addrs := Addresses{Services: map[tailcfg.ServiceName][]netip.Addr{}}
	for _, ip := range status.TailscaleIPs {
		if ip.IsValid() {
			addrs.Self = append(addrs.Self, ip)
		}
	}
	slices.SortFunc(addrs.Self, func(a, b netip.Addr) int { return a.Compare(b) })

	if maps, err := tailcfg.UnmarshalNodeCapJSON[tailcfg.ServiceIPMappings](status.Self.CapMap, nodecap.ServiceHost); err == nil {
		for _, m := range maps {
			for _, name := range n.cfg.Services {
				if ips := m[name]; len(ips) > 0 {
					ips = slices.Clone(ips)
					slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
					addrs.Services[name] = ips
				}
			}
		}
	}

	n.mu.Lock()
	same := n.addrs.Equal(addrs)
	n.addrs = addrs
	n.mu.Unlock()
	if same {
		return
	}

	n.log.Info("Node addresses", "self", addrs.Self, "services", fmt.Sprint(addrs.Services))
	if n.changed != nil {
		n.changed(addrs)
	}
}

// hostServices puts the configured Services in TUN mode and advertises
// them, once. TUN mode advertises every port and protocol of a Service, and
// in exchange tsnet stops handling its packets, which is what brings them
// here. The control plane assigns the virtual IPs after approving the
// advertisement, and they arrive in a later network map.
func (n *Node) hostServices(ctx context.Context, srv *tsnet.Server) {
	n.mu.Lock()
	done := n.hosted || n.withdrawn || len(n.cfg.Services) == 0
	n.hosted = true
	n.mu.Unlock()
	if done {
		return
	}

	if err := n.advertiseServices(ctx, srv); err != nil {
		n.log.Error("Cannot host the Tailscale Services", "err", err)
		n.mu.Lock()
		n.hosted = false
		n.mu.Unlock()
		return
	}
	n.log.Info("Hosting Tailscale Services in TUN mode; their addresses arrive once the tailnet policy approves them", "services", n.cfg.Services)
}

func (n *Node) advertiseServices(ctx context.Context, srv *tsnet.Server) error {
	client, err := srv.LocalClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, prefsTimeout)
	defer cancel()

	// Read-modify-write: the serve configuration is the node's, and another
	// Service's entry in it is not ours to drop.
	sc, err := client.GetServeConfig(ctx)
	if err != nil {
		return fmt.Errorf("reading serve config: %w", err)
	}
	if sc == nil {
		sc = &ipn.ServeConfig{}
	}
	if sc.Services == nil {
		sc.Services = map[tailcfg.ServiceName]*ipn.ServiceConfig{}
	}
	for _, name := range n.cfg.Services {
		// TUN mode excludes TCP and web handlers; an entry left from some
		// earlier configuration is replaced, not merged.
		sc.Services[name] = &ipn.ServiceConfig{Tun: true}
	}
	if err := client.SetServeConfig(ctx, sc); err != nil {
		return fmt.Errorf("setting serve config: %w", err)
	}

	names := make([]string, 0, len(n.cfg.Services))
	for _, name := range n.cfg.Services {
		names = append(names, name.String())
	}
	if _, err := client.EditPrefs(ctx, &ipn.MaskedPrefs{
		AdvertiseServicesSet: true,
		Prefs:                ipn.Prefs{AdvertiseServices: names},
	}); err != nil {
		return fmt.Errorf("advertising: %w", err)
	}
	return nil
}

func (n *Node) isWithdrawn() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.withdrawn
}

// Withdraw stops the node publishing its routes and Services while leaving
// it joined, so peers move to another node that publishes them while this
// one still answers what arrives meanwhile. It is the first step of a
// graceful shutdown. A join or a Service still being set up does not
// publish them again afterwards.
func (n *Node) Withdraw(ctx context.Context) {
	n.mu.Lock()
	n.withdrawn = true
	srv := n.srv
	n.mu.Unlock()
	if srv == nil {
		return
	}

	client, err := srv.LocalClient()
	if err != nil {
		return
	}
	prefs, err := client.GetPrefs(ctx)
	if err != nil {
		n.log.Warn("Could not withdraw ahead of shutdown", "err", err)
		return
	}
	if len(prefs.AdvertiseRoutes) == 0 && len(prefs.AdvertiseServices) == 0 {
		return
	}
	if _, err := client.EditPrefs(ctx, &ipn.MaskedPrefs{AdvertiseRoutesSet: true, AdvertiseServicesSet: true}); err != nil {
		n.log.Warn("Could not withdraw ahead of shutdown", "err", err)
		return
	}
	n.log.Info("Withdrew routes and Services; the node stays joined until it closes",
		"routes", prefs.AdvertiseRoutes, "services", prefs.AdvertiseServices)
}

// Close shuts the node down.
func (n *Node) Close() {
	n.mu.Lock()
	srv := n.srv
	n.srv, n.dev = nil, nil
	n.closed = true
	n.mu.Unlock()

	if srv != nil {
		if err := srv.Close(); err != nil {
			n.log.Debug("Closing the node", "err", err)
		}
	}
}
