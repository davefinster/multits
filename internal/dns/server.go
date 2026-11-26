// Package dns is the gateway's resolver: the application's name server, in
// place of whatever it used before.
//
// A name in one of a tailnet's zones is asked of that tailnet's own resolver
// (MagicDNS, through the node), and the answer comes back on pseudo
// addresses: every A and AAAA record becomes an AAAA record of the address's
// pseudo address on that tailnet. A query for A gets none, because a
// tailnet's IPv4 addresses are not reachable from the host as themselves.
// A peer's pseudo address resolves back to its name.
//
// A tailnet's zones are its MagicDNS suffix, its split-DNS domains, the
// names of its extra records, and whatever the configuration adds. When two
// tailnets claim the same name, the longer zone wins, then the lower
// tailnet number.
//
// Any other name goes to the upstream resolvers unchanged, so the
// application resolves everything else as it did.
package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/davefinster/multits/internal/addr"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	// queryTimeout bounds answering one query, tailnet or upstream.
	queryTimeout = 5 * time.Second
	// maxUDPSize is the most the server sends over UDP, whatever a client
	// says it accepts: what fits in an unfragmented IPv6 packet.
	maxUDPSize = 1232
	// minUDPSize is what a client without EDNS accepts.
	minUDPSize = 512
)

// Tailnet is what the server needs of one tailnet.
type Tailnet interface {
	// ID is the tailnet's number.
	ID() uint8
	// Zones are the domains its resolver answers for: lowercase, without
	// the trailing dot.
	Zones() []string
	// Query asks the tailnet's resolver, returning its raw response.
	Query(ctx context.Context, name string, qtype dnsmessage.Type) ([]byte, error)
	// IsLocal reports whether ip is the gateway's own address on the
	// tailnet: its node's, a Service it hosts, or in a route it
	// advertises.
	IsLocal(ip netip.Addr) bool
}

// Server answers queries.
type Server struct {
	scheme   *addr.Scheme
	tailnets []Tailnet
	upstream []netip.AddrPort
	log      *slog.Logger
}

// New returns a server for the tailnets, forwarding every other name to
// upstream, or refusing it when there is none.
func New(scheme *addr.Scheme, tailnets []Tailnet, upstream []netip.AddrPort, log *slog.Logger) *Server {
	tailnets = slices.Clone(tailnets)
	slices.SortFunc(tailnets, func(a, b Tailnet) int { return int(a.ID()) - int(b.ID()) })
	return &Server{scheme: scheme, tailnets: tailnets, upstream: upstream, log: log}
}

// Upstream returns the resolvers other names go to.
func (s *Server) Upstream() []netip.AddrPort { return s.upstream }

// ServeUDP answers queries on a packet conn until it is closed.
func (s *Server) ServeUDP(pc net.PacketConn) error {
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		query := slices.Clone(buf[:n])
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
			defer cancel()
			if res := s.Handle(ctx, query, false); res != nil {
				_, _ = pc.WriteTo(res, from)
			}
		}()
	}
}

// ServeTCP answers queries on a listener until it is closed.
func (s *Server) ServeTCP(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.serveConn(conn)
	}
}

// serveConn answers the queries on one TCP connection, each prefixed by
// its length, until the client stops sending them.
func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()
	var mu sync.Mutex
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		var l [2]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
			defer cancel()
			res := s.Handle(ctx, query, true)
			if res == nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			_ = conn.SetWriteDeadline(time.Now().Add(queryTimeout))
			_, _ = conn.Write(binary.BigEndian.AppendUint16(nil, uint16(len(res))))
			_, _ = conn.Write(res)
		}()
	}
}

// Handle answers one query. overTCP lifts the size limit of a UDP answer.
// It returns nil when the query is not one to answer at all.
func (s *Server) Handle(ctx context.Context, query []byte, overTCP bool) []byte {
	var q dnsmessage.Message
	if err := q.Unpack(query); err != nil {
		// Without a header there is nothing to answer to.
		if len(query) < 12 {
			return nil
		}
		return errorResponse(query, dnsmessage.RCodeFormatError)
	}
	if q.Header.Response {
		return nil
	}
	if q.Header.OpCode != 0 || len(q.Questions) != 1 {
		return s.pack(&q, reply(&q, dnsmessage.RCodeNotImplemented), overTCP)
	}

	question := q.Questions[0]
	name := strings.TrimSuffix(strings.ToLower(question.Name.String()), ".")

	if a, ok := s.reverse(name); ok {
		return s.pack(&q, s.answerReverse(ctx, &q, a), overTCP)
	}
	if t := s.route(name); t != nil {
		return s.pack(&q, s.answerTailnet(ctx, &q, t, name), overTCP)
	}
	return s.forward(ctx, &q, query, overTCP)
}

// route finds the tailnet whose zone holds name.
func (s *Server) route(name string) Tailnet {
	var best Tailnet
	bestLen := -1
	for _, t := range s.tailnets {
		for _, zone := range t.Zones() {
			if len(zone) > bestLen && (name == zone || strings.HasSuffix(name, "."+zone)) {
				best, bestLen = t, len(zone)
			}
		}
	}
	return best
}

// reply starts the response to q.
func reply(q *dnsmessage.Message, rcode dnsmessage.RCode) *dnsmessage.Message {
	return &dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 q.Header.ID,
			Response:           true,
			OpCode:             q.Header.OpCode,
			RecursionDesired:   q.Header.RecursionDesired,
			RecursionAvailable: true,
			RCode:              rcode,
		},
		Questions: q.Questions,
	}
}

// answerTailnet answers a name in a tailnet's zone from that tailnet.
func (s *Server) answerTailnet(ctx context.Context, q *dnsmessage.Message, t Tailnet, name string) *dnsmessage.Message {
	question := q.Questions[0]
	switch question.Type {
	case dnsmessage.TypeAAAA, dnsmessage.TypeALL:
		return s.answerAddresses(ctx, q, t, name)

	case dnsmessage.TypeA:
		// The name's IPv4 addresses are not ones the host can reach. Its
		// CNAMEs still are, and whether it exists at all.
		res, err := s.ask(ctx, t, name, dnsmessage.TypeA)
		if err != nil {
			return reply(q, dnsmessage.RCodeServerFailure)
		}
		out := reply(q, res.Header.RCode)
		out.Answers = s.rewrite(t, res.Answers, false)
		return out

	case dnsmessage.TypeCNAME, dnsmessage.TypeMX, dnsmessage.TypeNS, dnsmessage.TypePTR,
		dnsmessage.TypeSOA, dnsmessage.TypeSRV, dnsmessage.TypeTXT:
		res, err := s.ask(ctx, t, name, question.Type)
		if err != nil {
			return reply(q, dnsmessage.RCodeServerFailure)
		}
		out := reply(q, res.Header.RCode)
		out.Answers = s.rewrite(t, res.Answers, false)
		out.Authorities = s.rewrite(t, res.Authorities, false)
		// An SRV or MX answer's targets come with their addresses: on
		// pseudo addresses, those are worth keeping.
		out.Additionals = s.rewrite(t, res.Additionals, true)
		return out

	default:
		// A type the tailnet's resolver does not take, such as HTTPS:
		// say the name has none, or that there is no such name.
		res, err := s.ask(ctx, t, name, dnsmessage.TypeA)
		if err != nil {
			return reply(q, dnsmessage.RCodeServerFailure)
		}
		return reply(q, res.Header.RCode)
	}
}

// answerAddresses answers AAAA for a tailnet name: the pseudo addresses of
// its IPv4 addresses, then of its IPv6 ones.
func (s *Server) answerAddresses(ctx context.Context, q *dnsmessage.Message, t Tailnet, name string) *dnsmessage.Message {
	var res4, res6 *dnsmessage.Message
	var err4, err6 error
	var wg sync.WaitGroup
	wg.Go(func() { res4, err4 = s.ask(ctx, t, name, dnsmessage.TypeA) })
	wg.Go(func() { res6, err6 = s.ask(ctx, t, name, dnsmessage.TypeAAAA) })
	wg.Wait()

	var answers []dnsmessage.Resource
	var cnames map[string]bool
	exists, failed := false, false
	for _, r := range []struct {
		res *dnsmessage.Message
		err error
	}{{res4, err4}, {res6, err6}} {
		switch {
		case r.err != nil || r.res.Header.RCode == dnsmessage.RCodeServerFailure:
			failed = true
		case r.res.Header.RCode == dnsmessage.RCodeSuccess:
			exists = true
			for _, rr := range s.rewrite(t, r.res.Answers, true) {
				// Both answers carry any CNAME on the way; once is enough.
				if rr.Header.Type == dnsmessage.TypeCNAME {
					key := rr.Header.Name.String() + " " + rr.Body.(*dnsmessage.CNAMEResource).CNAME.String()
					if cnames[key] {
						continue
					}
					if cnames == nil {
						cnames = map[string]bool{}
					}
					cnames[key] = true
				}
				answers = append(answers, rr)
			}
		}
	}

	switch {
	case exists:
		out := reply(q, dnsmessage.RCodeSuccess)
		out.Answers = answers
		return out
	case failed:
		return reply(q, dnsmessage.RCodeServerFailure)
	default:
		return reply(q, res4.Header.RCode)
	}
}

// ask queries a tailnet's resolver.
func (s *Server) ask(ctx context.Context, t Tailnet, name string, qtype dnsmessage.Type) (*dnsmessage.Message, error) {
	raw, err := t.Query(ctx, name, qtype)
	if err != nil {
		s.log.Debug("Tailnet resolver failed", "tailnet", t.ID(), "name", name, "type", qtype, "err", err)
		return nil, err
	}
	var res dnsmessage.Message
	if err := res.Unpack(raw); err != nil {
		return nil, fmt.Errorf("unpacking the tailnet's answer: %w", err)
	}
	return &res, nil
}

// rewrite puts a tailnet's records on pseudo addresses. Address records
// become AAAA records of pseudo addresses when addresses is set, and are
// left out otherwise; records without addresses pass as they are.
func (s *Server) rewrite(t Tailnet, rrs []dnsmessage.Resource, addresses bool) []dnsmessage.Resource {
	var out []dnsmessage.Resource
	for _, rr := range rrs {
		var ip netip.Addr
		switch body := rr.Body.(type) {
		case *dnsmessage.AResource:
			ip = netip.AddrFrom4(body.A)
		case *dnsmessage.AAAAResource:
			ip = netip.AddrFrom16(body.AAAA)
		case *dnsmessage.OPTResource:
			continue
		default:
			out = append(out, rr)
			continue
		}
		if !addresses {
			continue
		}
		pseudo, ok := s.pseudo(t, ip)
		if !ok {
			continue
		}
		h := rr.Header
		h.Type, h.Length = dnsmessage.TypeAAAA, 0
		out = append(out, dnsmessage.Resource{Header: h, Body: &dnsmessage.AAAAResource{AAAA: pseudo.As16()}})
	}
	return out
}

// pseudo is the pseudo address of an address on a tailnet, on whichever
// side of the gateway it is.
func (s *Server) pseudo(t Tailnet, ip netip.Addr) (netip.Addr, bool) {
	ip = ip.Unmap()
	side := addr.Remote
	if t.IsLocal(ip) {
		side = addr.Local
	}
	p, err := s.scheme.Encode(t.ID(), side, ip)
	return p, err == nil
}

// reverse reports whether name is the reverse name of a pseudo address, and
// which.
func (s *Server) reverse(name string) (netip.Addr, bool) {
	const suffix = ".ip6.arpa"
	if !strings.HasSuffix(name, suffix) {
		return netip.Addr{}, false
	}
	labels := strings.Split(strings.TrimSuffix(name, suffix), ".")
	if len(labels) != 32 {
		return netip.Addr{}, false
	}
	var b [16]byte
	for i, label := range labels {
		if len(label) != 1 {
			return netip.Addr{}, false
		}
		var v byte
		switch c := label[0]; {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		default:
			return netip.Addr{}, false
		}
		// The first label is the last nibble.
		pos := 31 - i
		if pos%2 == 0 {
			b[pos/2] |= v << 4
		} else {
			b[pos/2] |= v
		}
	}
	a := netip.AddrFrom16(b)
	return a, s.scheme.Prefix().Contains(a)
}

// answerReverse answers for the reverse name of a pseudo address: the name
// its tailnet gives the address it stands for.
func (s *Server) answerReverse(ctx context.Context, q *dnsmessage.Message, pseudo netip.Addr) *dnsmessage.Message {
	a, err := s.scheme.Decode(pseudo)
	if err != nil {
		return reply(q, dnsmessage.RCodeNameError)
	}
	t := s.tailnet(a.Tailnet)
	if t == nil {
		return reply(q, dnsmessage.RCodeNameError)
	}
	if q.Questions[0].Type != dnsmessage.TypePTR && q.Questions[0].Type != dnsmessage.TypeALL {
		return reply(q, dnsmessage.RCodeSuccess)
	}

	res, err := s.ask(ctx, t, reverseName(a.IP), dnsmessage.TypePTR)
	if err != nil {
		return reply(q, dnsmessage.RCodeServerFailure)
	}
	out := reply(q, res.Header.RCode)
	for _, rr := range res.Answers {
		if rr.Header.Type != dnsmessage.TypePTR {
			continue
		}
		rr.Header.Name = q.Questions[0].Name
		rr.Header.Length = 0
		out.Answers = append(out.Answers, rr)
	}
	return out
}

func (s *Server) tailnet(id uint8) Tailnet {
	for _, t := range s.tailnets {
		if t.ID() == id {
			return t
		}
	}
	return nil
}

// reverseName is an address's name in in-addr.arpa or ip6.arpa.
func reverseName(ip netip.Addr) string {
	var sb strings.Builder
	if ip.Is4() {
		b := ip.As4()
		fmt.Fprintf(&sb, "%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0])
		return sb.String()
	}
	const hex = "0123456789abcdef"
	b := ip.As16()
	for i := 15; i >= 0; i-- {
		sb.WriteByte(hex[b[i]&0xf])
		sb.WriteByte('.')
		sb.WriteByte(hex[b[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa")
	return sb.String()
}

// pack finishes a response: EDNS if the query had it, and for UDP, cut to
// what the client accepts.
func (s *Server) pack(q, out *dnsmessage.Message, overTCP bool) []byte {
	limit := minUDPSize
	for _, rr := range q.Additionals {
		if rr.Header.Type != dnsmessage.TypeOPT {
			continue
		}
		limit = min(max(int(rr.Header.Class), minUDPSize), maxUDPSize)
		var opt dnsmessage.Resource
		root, _ := dnsmessage.NewName(".")
		opt.Header.Name = root
		_ = opt.Header.SetEDNS0(maxUDPSize, dnsmessage.RCodeSuccess, false)
		opt.Body = &dnsmessage.OPTResource{}
		out.Additionals = append(out.Additionals, opt)
		break
	}

	b, err := out.Pack()
	if err != nil {
		s.log.Debug("Packing a response", "err", err)
		b, _ = reply(q, dnsmessage.RCodeServerFailure).Pack()
		return b
	}
	if !overTCP && len(b) > limit {
		out.Header.Truncated = true
		out.Answers, out.Authorities = nil, nil
		out.Additionals = slices.DeleteFunc(out.Additionals, func(rr dnsmessage.Resource) bool {
			return rr.Header.Type != dnsmessage.TypeOPT
		})
		b, _ = out.Pack()
	}
	return b
}

// errorResponse answers a query that does not parse, from its header alone.
func errorResponse(query []byte, rcode dnsmessage.RCode) []byte {
	b := make([]byte, 12)
	copy(b, query[:2])          // ID
	b[2] = 0x80 | query[2]&0x79 // QR, opcode and RD as asked
	b[3] = 0x80 | byte(rcode)   // RA
	return b
}

// forward sends a query for any other name to the upstream resolvers, and
// their answer back unchanged.
func (s *Server) forward(ctx context.Context, q *dnsmessage.Message, query []byte, overTCP bool) []byte {
	if len(s.upstream) == 0 {
		return s.pack(q, reply(q, dnsmessage.RCodeRefused), overTCP)
	}
	for _, up := range s.upstream {
		res, err := exchange(ctx, up, query, overTCP)
		if err == nil {
			return res
		}
		s.log.Debug("Upstream resolver failed", "upstream", up, "err", err)
	}
	return s.pack(q, reply(q, dnsmessage.RCodeServerFailure), overTCP)
}

// exchange sends one query to one resolver.
func exchange(ctx context.Context, server netip.AddrPort, query []byte, overTCP bool) ([]byte, error) {
	network := "udp"
	if overTCP {
		network = "tcp"
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, server.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if overTCP {
		if _, err := conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(query))), query...)); err != nil {
			return nil, err
		}
		var l [2]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return nil, err
		}
		res := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(conn, res); err != nil {
			return nil, err
		}
		return res, nil
	}

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		// A stray datagram with another ID is not the answer.
		if n >= 2 && buf[0] == query[0] && buf[1] == query[1] {
			return slices.Clone(buf[:n]), nil
		}
	}
}

// ResolvConf reads the name servers in a resolv.conf, leaving out the
// gateway's own: a pod whose resolver is the gateway lists only that.
func ResolvConf(path string, exclude []netip.AddrPort, prefix netip.Prefix) ([]netip.AddrPort, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []netip.AddrPort
	for line := range strings.Lines(string(b)) {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		ip, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		ap := netip.AddrPortFrom(ip.Unmap(), 53)
		if prefix.Contains(ap.Addr()) || slices.Contains(exclude, ap) {
			continue
		}
		out = append(out, ap)
	}
	return out, nil
}
