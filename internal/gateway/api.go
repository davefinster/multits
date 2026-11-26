package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/davefinster/multits/internal/addr"
	"github.com/davefinster/multits/internal/tailnet"
	"tailscale.com/client/tailscale/apitype"
)

// Handler is the local API:
//
//	GET  /status            every tailnet: state, addresses, counters
//	GET  /healthz           200 when every node is running, 503 otherwise
//	GET  /whois?addr=A      who is behind a peer's pseudo address, [A]:port too
//	GET  /identify          Traefik forwardAuth: who the client in X-Forwarded-For
//	                        is, as Multits-* headers (identify.go)
//	GET  /decode?addr=A     what a pseudo address says
//	GET  /encode?tailnet=T&ip=I&side=local|remote
//	POST /withdraw          stop publishing routes and Services, for a preStop hook
//
// It is meant for the application beside the gateway, and listens on the
// loopback by default: whois answers with identities on every tailnet.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", g.handleStatus)
	mux.HandleFunc("GET /healthz", g.handleHealth)
	mux.HandleFunc("GET /whois", g.handleWhoIs)
	mux.HandleFunc("GET /identify", g.handleIdentify)
	mux.HandleFunc("GET /decode", g.handleDecode)
	mux.HandleFunc("GET /encode", g.handleEncode)
	mux.HandleFunc("POST /withdraw", func(w http.ResponseWriter, r *http.Request) {
		g.Withdraw(r.Context())
		writeJSON(w, http.StatusOK, map[string]string{"withdrawn": "true"})
	})
	return mux
}

// Mapped is an address on a tailnet with its pseudo address.
type Mapped struct {
	IP     netip.Addr `json:"ip"`
	Pseudo netip.Addr `json:"pseudo"`
}

// TailnetStatus is one tailnet in /status.
type TailnetStatus struct {
	Name     string              `json:"name"`
	ID       uint8               `json:"id"`
	State    string              `json:"state"`
	Prefix   netip.Prefix        `json:"prefix"`
	Peers    netip.Prefix        `json:"peers"`
	Local    netip.Prefix        `json:"local"`
	Self     []Mapped            `json:"self"`
	Services map[string][]Mapped `json:"services,omitempty"`
	Routes   []netip.Prefix      `json:"routes,omitempty"`
	Zones    []string            `json:"dnsZones,omitempty"`
	Spaces   map[int]string      `json:"ipv6Spaces,omitempty"`
	Inbound  Counts              `json:"inbound"`
	Outbound Counts              `json:"outbound"`
}

// DNSStatus is the resolver in /status.
type DNSStatus struct {
	Listen   []netip.AddrPort `json:"listen"`
	Upstream []netip.AddrPort `json:"upstream"`
}

// Status is /status.
type Status struct {
	Prefix   netip.Prefix    `json:"prefix"`
	Gateway  netip.Addr      `json:"gateway"`
	DNS      *DNSStatus      `json:"dns,omitempty"`
	Tailnets []TailnetStatus `json:"tailnets"`
	// Unrouted counts packets from the host that went to no tailnet.
	Unrouted Counts `json:"unrouted"`
}

// Status reports every tailnet.
func (g *Gateway) Status() Status {
	st := Status{Prefix: g.scheme.Prefix(), Gateway: g.scheme.Gateway(), Unrouted: g.unrouted.snapshot(outbound)}
	if g.dns != nil {
		st.DNS = &DNSStatus{Listen: g.cfg.DNS.Listen, Upstream: g.dns.Upstream()}
	}
	for _, tc := range g.cfg.Tailnets {
		node := g.byID[tc.ID]
		a := node.Addresses()
		ts := TailnetStatus{
			Name:     tc.Name,
			ID:       tc.ID,
			State:    node.State(),
			Prefix:   g.scheme.TailnetPrefix(tc.ID),
			Peers:    g.scheme.SidePrefix(tc.ID, addr.Remote),
			Local:    g.scheme.SidePrefix(tc.ID, addr.Local),
			Self:     g.mapped(tc.ID, a.Self),
			Routes:   tc.Routes,
			Zones:    node.Zones(),
			Inbound:  g.counts[tc.ID].snapshot(inbound),
			Outbound: g.counts[tc.ID].snapshot(outbound),
		}
		for name, ips := range a.Services {
			if ts.Services == nil {
				ts.Services = map[string][]Mapped{}
			}
			ts.Services[name.String()] = g.mapped(tc.ID, ips)
		}
		for sp, p := range g.scheme.Spaces(tc.ID) {
			if ts.Spaces == nil {
				ts.Spaces = map[int]string{}
			}
			ts.Spaces[int(sp)] = p.String()
		}
		st.Tailnets = append(st.Tailnets, ts)
	}
	return st
}

func (g *Gateway) mapped(id uint8, ips []netip.Addr) []Mapped {
	out := make([]Mapped, 0, len(ips))
	for _, ip := range ips {
		p, err := g.scheme.Encode(id, addr.Local, ip)
		if err != nil {
			continue
		}
		out = append(out, Mapped{IP: ip, Pseudo: p})
	}
	return out
}

func (g *Gateway) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, g.Status())
}

func (g *Gateway) handleHealth(w http.ResponseWriter, _ *http.Request) {
	states := map[string]string{}
	code := http.StatusOK
	for name, node := range g.nodes {
		states[name] = node.State()
		if states[name] != "Running" {
			code = http.StatusServiceUnavailable
		}
	}
	writeJSON(w, code, states)
}

// WhoIs is /whois.
type WhoIs struct {
	Tailnet string                 `json:"tailnet"`
	ID      uint8                  `json:"id"`
	IP      netip.Addr             `json:"ip"`
	WhoIs   *apitype.WhoIsResponse `json:"whois"`
}

func (g *Gateway) handleWhoIs(w http.ResponseWriter, r *http.Request) {
	ap, err := parseAddrPort(r.URL.Query().Get("addr"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a, err := g.scheme.Decode(ap.Addr())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if a.Side != addr.Remote {
		writeError(w, http.StatusBadRequest, errors.New("is the gateway's own address, not a peer's"))
		return
	}
	node := g.byID[a.Tailnet]
	who, err := node.WhoIs(r.Context(), netip.AddrPortFrom(a.IP, ap.Port()))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, WhoIs{Tailnet: node.Config().Name, ID: a.Tailnet, IP: a.IP, WhoIs: who})
}

// Decoded is /decode.
type Decoded struct {
	Tailnet string     `json:"tailnet"`
	ID      uint8      `json:"id"`
	Side    string     `json:"side"`
	Space   uint8      `json:"space"`
	IP      netip.Addr `json:"ip"`
}

func (g *Gateway) handleDecode(w http.ResponseWriter, r *http.Request) {
	ap, err := parseAddrPort(r.URL.Query().Get("addr"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a, err := g.scheme.Decode(ap.Addr())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, Decoded{Tailnet: g.byID[a.Tailnet].Config().Name, ID: a.Tailnet, Side: a.Side.String(), Space: uint8(a.Space), IP: a.IP})
}

func (g *Gateway) handleEncode(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	node := g.lookup(q.Get("tailnet"))
	if node == nil {
		writeError(w, http.StatusBadRequest, errors.New("unknown tailnet"))
		return
	}
	ip, err := netip.ParseAddr(q.Get("ip"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	side := addr.Remote
	switch q.Get("side") {
	case "", "remote":
	case "local":
		side = addr.Local
	default:
		writeError(w, http.StatusBadRequest, errors.New("side is local or remote"))
		return
	}
	p, err := g.scheme.Encode(node.Config().ID, side, ip)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, Mapped{IP: ip, Pseudo: p})
}

// lookup finds a tailnet by name or number.
func (g *Gateway) lookup(s string) *tailnet.Node {
	if n, ok := g.nodes[s]; ok {
		return n
	}
	if id, err := strconv.ParseUint(s, 10, 8); err == nil {
		return g.byID[id]
	}
	return nil
}

// parseAddrPort takes an address with or without a port.
func parseAddrPort(s string) (netip.AddrPort, error) {
	if strings.HasPrefix(s, "[") {
		return netip.ParseAddrPort(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(a, 0), nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
