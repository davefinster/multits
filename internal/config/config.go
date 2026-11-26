// Package config reads and validates the gateway's configuration.
//
// Everything that can be checked without a tailnet is checked here, so that
// a mistake is an error at startup naming the setting rather than a node
// that never comes up.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/davefinster/multits/internal/addr"
	"github.com/davefinster/multits/internal/tailnet"
	"gopkg.in/yaml.v3"
	"tailscale.com/tailcfg"
)

// DefaultPrefix is the prefix when the configuration names none: a /32 of
// the unique local range, picked at random once.
const DefaultPrefix = "fdcc:79e6::/32"

// Defaults.
const (
	DefaultDevice     = "multits0"
	DefaultAPI        = "127.0.0.1:9099"
	DefaultDrainDelay = 5 * time.Second
)

// File is the configuration as written.
type File struct {
	// Prefix is the /32 the pseudo addresses are in.
	Prefix string `yaml:"prefix"`
	// TailnetMTU is the largest packet the tailnets carry.
	TailnetMTU int `yaml:"tailnetMTU"`

	Device struct {
		Name   string `yaml:"name"`
		Queues int    `yaml:"queues"`
	} `yaml:"device"`

	API struct {
		// Listen is where the local API listens; "off" turns it off.
		Listen string `yaml:"listen"`
	} `yaml:"api"`

	Shutdown struct {
		// DrainDelay is how long the gateway stays joined after withdrawing
		// its routes and Services, for peers to move elsewhere.
		DrainDelay string `yaml:"drainDelay"`
	} `yaml:"shutdown"`

	DNS struct {
		// Disabled turns the resolver off.
		Disabled bool `yaml:"disabled"`
		// Listen is where it listens, UDP and TCP: by default the
		// prefix's ::53, which the gateway puts on its device.
		Listen []string `yaml:"listen"`
		// Upstream resolves every name that is no tailnet's. By default it
		// is the name servers in ResolvConf other than the gateway's own.
		Upstream []string `yaml:"upstream"`
		// ResolvConf is where the default upstream comes from.
		ResolvConf string `yaml:"resolvConf"`
	} `yaml:"dns"`

	Tailnets map[string]*Tailnet `yaml:"tailnets"`
}

// Tailnet is one tailnet as written.
type Tailnet struct {
	ID            int            `yaml:"id"`
	Hostname      string         `yaml:"hostname"`
	StateDir      string         `yaml:"stateDir"`
	AuthKey       string         `yaml:"authKey"`
	AuthKeyFile   string         `yaml:"authKeyFile"`
	ClientID      string         `yaml:"clientID"`
	IDTokenFile   string         `yaml:"idTokenFile"`
	ControlURL    string         `yaml:"controlURL"`
	Ephemeral     bool           `yaml:"ephemeral"`
	Port          uint16         `yaml:"port"`
	AdvertiseTags []string       `yaml:"advertiseTags"`
	Routes        []string       `yaml:"routes"`
	AcceptRoutes  bool           `yaml:"acceptRoutes"`
	Services      []string       `yaml:"services"`
	IPv6Spaces    map[int]string `yaml:"ipv6Spaces"`
	DNSDomains    []string       `yaml:"dnsDomains"`
}

// Config is the configuration, validated and resolved.
type Config struct {
	Scheme     *addr.Scheme
	TailnetMTU int
	Device     Device
	API        API
	Shutdown   Shutdown
	DNS        DNS
	// Tailnets are in order of their numbers.
	Tailnets []tailnet.Config
}

// Device is the host's device.
type Device struct {
	Name   string
	Queues int
}

// API is the local API.
type API struct {
	// Listen is empty when the API is off.
	Listen string
}

// Shutdown is how the gateway stops.
type Shutdown struct {
	DrainDelay time.Duration
}

// DNS is the gateway's resolver.
type DNS struct {
	// Listen is empty when the resolver is off.
	Listen []netip.AddrPort
	// Upstream is nil when it comes from ResolvConf at startup.
	Upstream   []netip.AddrPort
	ResolvConf string
}

// DefaultResolvConf is where the resolver's upstream comes from by default.
const DefaultResolvConf = "/etc/resolv.conf"

// Load reads a configuration file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse reads a configuration.
func Parse(b []byte) (*Config, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	return f.Resolve()
}

// Resolve validates a configuration and fills in its defaults.
func (f *File) Resolve() (*Config, error) {
	cfg := &Config{
		TailnetMTU: f.TailnetMTU,
		Device:     Device{Name: f.Device.Name, Queues: f.Device.Queues},
		API:        API{Listen: f.API.Listen},
		Shutdown:   Shutdown{DrainDelay: DefaultDrainDelay},
	}

	prefix := f.Prefix
	if prefix == "" {
		prefix = DefaultPrefix
	}
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("prefix: %w", err)
	}
	if cfg.Scheme, err = addr.NewScheme(p); err != nil {
		return nil, fmt.Errorf("prefix: %w", err)
	}

	if cfg.TailnetMTU == 0 {
		cfg.TailnetMTU = tailnet.MTU
	}
	if cfg.TailnetMTU < 1280 || cfg.TailnetMTU > 9000 {
		return nil, fmt.Errorf("tailnetMTU %d: must be between 1280 and 9000", cfg.TailnetMTU)
	}
	if cfg.Device.Name == "" {
		cfg.Device.Name = DefaultDevice
	}
	if len(cfg.Device.Name) > 15 {
		return nil, fmt.Errorf("device.name %q: interface names are at most 15 bytes", cfg.Device.Name)
	}
	if cfg.Device.Queues == 0 {
		cfg.Device.Queues = 1
	}
	if cfg.Device.Queues < 1 || cfg.Device.Queues > 64 {
		return nil, fmt.Errorf("device.queues %d: must be between 1 and 64", cfg.Device.Queues)
	}
	switch cfg.API.Listen {
	case "":
		cfg.API.Listen = DefaultAPI
	case "off":
		cfg.API.Listen = ""
	}
	if f.Shutdown.DrainDelay != "" {
		if cfg.Shutdown.DrainDelay, err = time.ParseDuration(f.Shutdown.DrainDelay); err != nil || cfg.Shutdown.DrainDelay < 0 {
			return nil, fmt.Errorf("shutdown.drainDelay %q: not a duration", f.Shutdown.DrainDelay)
		}
	}

	if err := resolveDNS(cfg, f); err != nil {
		return nil, err
	}

	if len(f.Tailnets) == 0 {
		return nil, errors.New("no tailnets configured")
	}
	stateDirs := map[string]string{}
	for name, tn := range f.Tailnets {
		tc, err := resolveTailnet(cfg.Scheme, name, tn)
		if err != nil {
			return nil, fmt.Errorf("tailnet %q: %w", name, err)
		}
		if other, ok := stateDirs[tc.StateDir]; ok {
			return nil, fmt.Errorf("tailnets %q and %q share stateDir %s", other, name, tc.StateDir)
		}
		stateDirs[tc.StateDir] = name
		cfg.Tailnets = append(cfg.Tailnets, tc)
	}
	slices.SortFunc(cfg.Tailnets, func(a, b tailnet.Config) int { return int(a.ID) - int(b.ID) })
	return cfg, nil
}

func resolveTailnet(scheme *addr.Scheme, name string, tn *Tailnet) (tailnet.Config, error) {
	if tn == nil {
		return tailnet.Config{}, errors.New("missing configuration")
	}
	if tn.ID < 1 || tn.ID > 255 {
		return tailnet.Config{}, fmt.Errorf("id %d: must be between 1 and 255, and it is part of every pseudo address on the tailnet, so it should not change", tn.ID)
	}
	if err := scheme.AddTailnet(uint8(tn.ID)); err != nil {
		return tailnet.Config{}, fmt.Errorf("id %d: %w", tn.ID, err)
	}

	tc := tailnet.Config{
		Name:          name,
		ID:            uint8(tn.ID),
		Hostname:      tn.Hostname,
		StateDir:      tn.StateDir,
		AuthKey:       tn.AuthKey,
		AuthKeyFile:   tn.AuthKeyFile,
		ClientID:      tn.ClientID,
		IDTokenFile:   tn.IDTokenFile,
		ControlURL:    tn.ControlURL,
		Ephemeral:     tn.Ephemeral,
		Port:          tn.Port,
		AdvertiseTags: tn.AdvertiseTags,
		AcceptRoutes:  tn.AcceptRoutes,
	}
	if tc.Hostname == "" {
		tc.Hostname = name
	}
	if tc.StateDir == "" {
		// tsnet's default is derived from the binary's name, which every
		// tailnet in this process shares.
		return tc, errors.New("stateDir is required")
	}

	if tn.AuthKey != "" && tn.AuthKeyFile != "" {
		return tc, errors.New("authKey and authKeyFile are mutually exclusive")
	}
	// tsnet prefers an auth key and would silently skip the federated
	// identity.
	if tn.ClientID != "" && (tn.AuthKey != "" || tn.AuthKeyFile != "") {
		return tc, errors.New("clientID is mutually exclusive with authKey and authKeyFile")
	}
	if tn.IDTokenFile != "" && tn.ClientID == "" {
		return tc, errors.New("idTokenFile requires clientID")
	}
	if tn.ClientID != "" && len(tn.AdvertiseTags) == 0 {
		return tc, errors.New("clientID requires advertiseTags: a federated identity only mints tagged auth keys")
	}

	for key, prefix := range tn.IPv6Spaces {
		p, err := netip.ParsePrefix(prefix)
		if err != nil {
			return tc, fmt.Errorf("ipv6Spaces %d: %w", key, err)
		}
		if key < int(addr.FirstConfigured) || key > int(addr.LastConfigured) {
			return tc, fmt.Errorf("ipv6Spaces %d: spaces are numbered %d to %d", key, addr.FirstConfigured, addr.LastConfigured)
		}
		if err := scheme.SetSpace(tc.ID, addr.Space(key), p); err != nil {
			return tc, fmt.Errorf("ipv6Spaces: %w", err)
		}
	}

	for _, route := range tn.Routes {
		p, err := netip.ParsePrefix(route)
		if err != nil {
			return tc, fmt.Errorf("route %q: %w", route, err)
		}
		if p.Masked() != p {
			return tc, fmt.Errorf("route %q has bits set past its length, did you mean %q?", route, p.Masked())
		}
		// Every address in an advertised route arrives as the gateway's
		// own, and an IPv6 one needs a space to have a pseudo address.
		if p.Addr().Is6() && !inSpace(scheme, tc.ID, p) {
			return tc, fmt.Errorf("route %s: IPv6 outside %s needs an ipv6Spaces entry covering it", p, addr.TailscaleULA)
		}
		tc.Routes = append(tc.Routes, p)
	}

	for _, svc := range tn.Services {
		if !strings.HasPrefix(svc, "svc:") {
			svc = "svc:" + svc
		}
		sn := tailcfg.ServiceName(svc)
		if err := sn.Validate(); err != nil {
			return tc, fmt.Errorf("service %q: %w", svc, err)
		}
		tc.Services = append(tc.Services, sn)
	}
	if len(tc.Services) > 0 && len(tc.AdvertiseTags) == 0 {
		return tc, errors.New("hosting a Tailscale Service requires advertiseTags: only tagged nodes may host one")
	}

	for _, domain := range tn.DNSDomains {
		d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
		if d == "" || strings.ContainsAny(d, " /:@") || strings.HasPrefix(d, ".") {
			return tc, fmt.Errorf("dnsDomains %q: not a domain", domain)
		}
		tc.DNSDomains = append(tc.DNSDomains, d)
	}

	return tc, nil
}

// resolveDNS fills in the resolver's addresses.
func resolveDNS(cfg *Config, f *File) error {
	cfg.DNS.ResolvConf = f.DNS.ResolvConf
	if cfg.DNS.ResolvConf == "" {
		cfg.DNS.ResolvConf = DefaultResolvConf
	}
	if f.DNS.Disabled {
		return nil
	}

	listen := f.DNS.Listen
	if len(listen) == 0 {
		listen = []string{netip.AddrPortFrom(cfg.Scheme.Resolver(), 53).String()}
	}
	for _, l := range listen {
		ap, err := parseServer(l)
		if err != nil {
			return fmt.Errorf("dns.listen %q: %w", l, err)
		}
		// In the prefix, only the gateway's own block is the gateway's to
		// listen on: the rest is the tailnets'.
		if cfg.Scheme.Prefix().Contains(ap.Addr()) && !cfg.Scheme.TailnetPrefix(0).Contains(ap.Addr()) {
			return fmt.Errorf("dns.listen %q: in the prefix, only %s is the gateway's own", l, cfg.Scheme.TailnetPrefix(0))
		}
		cfg.DNS.Listen = append(cfg.DNS.Listen, ap)
	}

	if f.DNS.Upstream != nil {
		cfg.DNS.Upstream = []netip.AddrPort{}
	}
	for _, u := range f.DNS.Upstream {
		ap, err := parseServer(u)
		if err != nil {
			return fmt.Errorf("dns.upstream %q: %w", u, err)
		}
		if cfg.Scheme.Prefix().Contains(ap.Addr()) || slices.Contains(cfg.DNS.Listen, ap) {
			return fmt.Errorf("dns.upstream %q: is the gateway itself", u)
		}
		cfg.DNS.Upstream = append(cfg.DNS.Upstream, ap)
	}
	return nil
}

// parseServer takes an address with or without a port, which is then 53.
func parseServer(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	ip, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, 53), nil
}

func inSpace(scheme *addr.Scheme, tailnet uint8, p netip.Prefix) bool {
	if addr.TailscaleULA.Bits() <= p.Bits() && addr.TailscaleULA.Contains(p.Addr()) {
		return true
	}
	for _, space := range scheme.Spaces(tailnet) {
		if space.Bits() <= p.Bits() && space.Contains(p.Addr()) {
			return true
		}
	}
	return false
}
