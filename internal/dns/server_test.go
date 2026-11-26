package dns

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davefinster/multits/internal/addr"
	"golang.org/x/net/dns/dnsmessage"
)

// fakeTailnet is a tailnet's resolver as a table.
type fakeTailnet struct {
	id    uint8
	zones []string
	// records are by name, then type.
	records map[string]map[dnsmessage.Type][]dnsmessage.ResourceBody
	local   []netip.Addr
	fail    bool

	// The server asks for A and AAAA at once.
	mu    sync.Mutex
	asked []string
}

func (f *fakeTailnet) ID() uint8                  { return f.id }
func (f *fakeTailnet) Zones() []string            { return f.zones }
func (f *fakeTailnet) IsLocal(ip netip.Addr) bool { return slices.Contains(f.local, ip) }

func (f *fakeTailnet) Query(_ context.Context, name string, qtype dnsmessage.Type) ([]byte, error) {
	f.mu.Lock()
	f.asked = append(f.asked, name+" "+qtype.String())
	f.mu.Unlock()
	if f.fail {
		return nil, errors.New("unreachable")
	}
	n := dnsmessage.MustNewName(name + ".")
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{Response: true, Authoritative: true},
		Questions: []dnsmessage.Question{{Name: n, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	types, ok := f.records[name]
	if !ok {
		msg.Header.RCode = dnsmessage.RCodeNameError
	}
	for _, body := range types[qtype] {
		msg.Answers = append(msg.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: n, Type: qtype, Class: dnsmessage.ClassINET, TTL: 600},
			Body:   body,
		})
	}
	return msg.Pack()
}

func a4(s string) *dnsmessage.AResource {
	return &dnsmessage.AResource{A: netip.MustParseAddr(s).As4()}
}

func a6(s string) *dnsmessage.AAAAResource {
	return &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(s).As16()}
}

func ptr(s string) *dnsmessage.PTRResource {
	return &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(s)}
}

// world is two tailnets that both have a peer at 100.64.0.2.
func world(t *testing.T) (*Server, *fakeTailnet, *fakeTailnet) {
	t.Helper()
	scheme, err := addr.NewScheme(netip.MustParsePrefix("fdcc:79e6::/32"))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint8{1, 2} {
		if err := scheme.AddTailnet(id); err != nil {
			t.Fatal(err)
		}
	}
	home := &fakeTailnet{
		id:    1,
		zones: []string{"home.ts.net", "corp.example"},
		local: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		records: map[string]map[dnsmessage.Type][]dnsmessage.ResourceBody{
			"nas.home.ts.net": {
				dnsmessage.TypeA:    {a4("100.64.0.2")},
				dnsmessage.TypeAAAA: {a6("fd7a:115c:a1e0:ab12:4843:cd96:6240:2")},
			},
			"gw.home.ts.net":             {dnsmessage.TypeA: {a4("100.64.0.1")}},
			"v4only.home.ts.net":         {dnsmessage.TypeA: {a4("100.64.0.9")}},
			"elsewhere.home.ts.net":      {dnsmessage.TypeAAAA: {a6("2001:db8::1")}},
			"wiki.corp.example":          {dnsmessage.TypeA: {a4("10.1.2.3")}},
			"2.0.64.100.in-addr.arpa":    {dnsmessage.TypePTR: {ptr("nas.home.ts.net.")}},
			"_http._tcp.nas.home.ts.net": {dnsmessage.TypeSRV: {&dnsmessage.SRVResource{Priority: 1, Weight: 1, Port: 80, Target: dnsmessage.MustNewName("nas.home.ts.net.")}}},
		},
	}
	work := &fakeTailnet{
		id:    2,
		zones: []string{"work.ts.net", "eng.corp.example"},
		records: map[string]map[dnsmessage.Type][]dnsmessage.ResourceBody{
			"nas.work.ts.net":        {dnsmessage.TypeA: {a4("100.64.0.2")}},
			"build.eng.corp.example": {dnsmessage.TypeA: {a4("100.64.0.7")}},
		},
	}
	s := New(scheme, []Tailnet{work, home}, nil, slog.New(slog.DiscardHandler))
	return s, home, work
}

func query(t *testing.T, s *Server, name string, qtype dnsmessage.Type, edns bool) *dnsmessage.Message {
	t.Helper()
	q := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0xbeef, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: qtype, Class: dnsmessage.ClassINET}},
	}
	if edns {
		var opt dnsmessage.Resource
		opt.Header.Name = dnsmessage.MustNewName(".")
		_ = opt.Header.SetEDNS0(1232, dnsmessage.RCodeSuccess, false)
		opt.Body = &dnsmessage.OPTResource{}
		q.Additionals = []dnsmessage.Resource{opt}
	}
	b, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	res := s.Handle(context.Background(), b, false)
	var m dnsmessage.Message
	if err := m.Unpack(res); err != nil {
		t.Fatalf("%s %s: unpacking the answer: %v", name, qtype, err)
	}
	if m.Header.ID != 0xbeef || !m.Header.Response {
		t.Fatalf("%s %s: header %+v", name, qtype, m.Header)
	}
	return &m
}

func addresses(m *dnsmessage.Message) []string {
	var out []string
	for _, rr := range m.Answers {
		switch body := rr.Body.(type) {
		case *dnsmessage.AAAAResource:
			out = append(out, netip.AddrFrom16(body.AAAA).String())
		case *dnsmessage.AResource:
			out = append(out, "A "+netip.AddrFrom4(body.A).String())
		}
	}
	return out
}

func TestAAAAIsPseudo(t *testing.T) {
	s, _, _ := world(t)
	for _, tc := range []struct {
		name string
		want []string
	}{
		// IPv4 first, then IPv6; both on the tailnet's peer side.
		{"nas.home.ts.net.", []string{"fdcc:79e6:100::6440:2", "fdcc:79e6:101:ab12:4843:cd96:6240:2"}},
		// The same address on another tailnet is another pseudo address.
		{"nas.work.ts.net.", []string{"fdcc:79e6:200::6440:2"}},
		// The gateway's own name is on its own side, which the host keeps.
		{"gw.home.ts.net.", []string{"fdcc:79e6:110::6440:1"}},
		// A split-DNS domain, IPv4 outside Tailscale's range.
		{"wiki.corp.example.", []string{"fdcc:79e6:100::a01:203"}},
		// The longer zone wins: eng.corp.example is work's, inside home's
		// corp.example.
		{"build.eng.corp.example.", []string{"fdcc:79e6:200::6440:7"}},
		// IPv6 in no space has no pseudo address, so the name has none.
		{"elsewhere.home.ts.net.", nil},
		// Case does not matter.
		{"NAS.Home.TS.net.", []string{"fdcc:79e6:100::6440:2", "fdcc:79e6:101:ab12:4843:cd96:6240:2"}},
	} {
		m := query(t, s, tc.name, dnsmessage.TypeAAAA, false)
		if m.Header.RCode != dnsmessage.RCodeSuccess {
			t.Errorf("%s: %v", tc.name, m.Header.RCode)
			continue
		}
		if got := addresses(m); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
		for _, rr := range m.Answers {
			if rr.Header.TTL != 600 {
				t.Errorf("%s: TTL %d, want the tailnet's", tc.name, rr.Header.TTL)
			}
		}
	}
}

func TestANeverLeaksATailnetAddress(t *testing.T) {
	s, _, _ := world(t)
	m := query(t, s, "nas.home.ts.net.", dnsmessage.TypeA, false)
	if m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Errorf("A: %v %v, want an empty answer", m.Header.RCode, addresses(m))
	}
}

func TestNoSuchName(t *testing.T) {
	s, _, _ := world(t)
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeAAAA, dnsmessage.TypeA, dnsmessage.Type(65)} {
		if m := query(t, s, "nope.home.ts.net.", qtype, false); m.Header.RCode != dnsmessage.RCodeNameError {
			t.Errorf("%v: %v, want NXDOMAIN", qtype, m.Header.RCode)
		}
	}
	// A type the tailnet's resolver does not take, for a name that exists.
	if m := query(t, s, "nas.home.ts.net.", dnsmessage.Type(65), false); m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Errorf("HTTPS: %v %v", m.Header.RCode, m.Answers)
	}
}

func TestTailnetFailureIsServerFailure(t *testing.T) {
	s, home, _ := world(t)
	home.fail = true
	if m := query(t, s, "nas.home.ts.net.", dnsmessage.TypeAAAA, false); m.Header.RCode != dnsmessage.RCodeServerFailure {
		t.Errorf("%v", m.Header.RCode)
	}
}

func TestReverse(t *testing.T) {
	s, home, _ := world(t)
	m := query(t, s, "2.0.0.0.0.4.4.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.6.e.9.7.c.c.d.f.ip6.arpa.", dnsmessage.TypePTR, false)
	if m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Fatalf("%v %v", m.Header.RCode, m.Answers)
	}
	if got := m.Answers[0].Body.(*dnsmessage.PTRResource).PTR.String(); got != "nas.home.ts.net." {
		t.Errorf("PTR %s", got)
	}
	if !strings.HasPrefix(m.Answers[0].Header.Name.String(), "2.0.0.0.0.4.4.6.") {
		t.Errorf("owner %s", m.Answers[0].Header.Name)
	}
	if !slices.Contains(home.asked, "2.0.64.100.in-addr.arpa TypePTR") {
		t.Errorf("asked %v", home.asked)
	}

	// Tailnet 9 does not exist.
	if m := query(t, s, "2.0.0.0.0.4.4.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.9.0.6.e.9.7.c.c.d.f.ip6.arpa.", dnsmessage.TypePTR, false); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Errorf("unknown tailnet: %v", m.Header.RCode)
	}
}

func TestSRVTargetsGetPseudoAddresses(t *testing.T) {
	s, _, _ := world(t)
	m := query(t, s, "_http._tcp.nas.home.ts.net.", dnsmessage.TypeSRV, false)
	if m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Fatalf("%v %v", m.Header.RCode, m.Answers)
	}
	if srv := m.Answers[0].Body.(*dnsmessage.SRVResource); srv.Port != 80 || srv.Target.String() != "nas.home.ts.net." {
		t.Errorf("SRV %+v", srv)
	}
}

func TestOtherNamesGoUpstream(t *testing.T) {
	s, home, work := world(t)

	// No upstream: refused.
	if m := query(t, s, "example.com.", dnsmessage.TypeA, false); m.Header.RCode != dnsmessage.RCodeRefused {
		t.Errorf("no upstream: %v", m.Header.RCode)
	}

	upstream := fakeUpstream(t)
	s.upstream = []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1"), upstream}
	m := query(t, s, "example.com.", dnsmessage.TypeA, true)
	if m.Header.RCode != dnsmessage.RCodeSuccess || !slices.Equal(addresses(m), []string{"A 192.0.2.1"}) {
		t.Errorf("forwarded: %v %v", m.Header.RCode, addresses(m))
	}
	// A suffix that is only a suffix of a zone's label is not in it.
	if m := query(t, s, "xhome.ts.net.", dnsmessage.TypeA, false); !slices.Equal(addresses(m), []string{"A 192.0.2.1"}) {
		t.Errorf("xhome.ts.net went to a tailnet: %v", addresses(m))
	}
	if len(home.asked)+len(work.asked) != 0 {
		t.Errorf("the tailnets were asked %v %v", home.asked, work.asked)
	}
}

// fakeUpstream answers A 192.0.2.1 for every name.
func fakeUpstream(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			res := dnsmessage.Message{Header: dnsmessage.Header{ID: q.Header.ID, Response: true}, Questions: q.Questions}
			res.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   a4("192.0.2.1"),
			}}
			b, _ := res.Pack()
			_, _ = pc.WriteTo(b, from)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func TestTruncatesForUDP(t *testing.T) {
	s, home, _ := world(t)
	var many []dnsmessage.ResourceBody
	for i := range 60 {
		many = append(many, a4(netip.AddrFrom4([4]byte{100, 64, 1, byte(i)}).String()))
	}
	home.records["many.home.ts.net"] = map[dnsmessage.Type][]dnsmessage.ResourceBody{dnsmessage.TypeA: many}

	m := query(t, s, "many.home.ts.net.", dnsmessage.TypeAAAA, false)
	if !m.Header.Truncated || len(m.Answers) != 0 {
		t.Errorf("60 AAAA records in 512 bytes: truncated %v, %d answers", m.Header.Truncated, len(m.Answers))
	}
}

// Go's own resolver, which is what Traefik uses, against the server over
// UDP and TCP.
func TestGoResolver(t *testing.T) {
	s, _, _ := world(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close(); _ = ln.Close() })
	go func() { _ = s.ServeUDP(pc) }()
	go func() { _ = s.ServeTCP(ln) }()

	for _, network := range []string{"udp", "tcp"} {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, pc.LocalAddr().String())
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := r.LookupNetIP(ctx, "ip", "nas.work.ts.net")
		cancel()
		if err != nil || len(ips) != 1 || ips[0].String() != "fdcc:79e6:200::6440:2" {
			t.Errorf("%s: %v %v", network, ips, err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		_, err = r.LookupNetIP(ctx, "ip", "nope.home.ts.net")
		cancel()
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
			t.Errorf("%s: a name that does not exist: %v", network, err)
		}

		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		names, err := r.LookupAddr(ctx, "fdcc:79e6:100::6440:2")
		cancel()
		if err != nil || !slices.Equal(names, []string{"nas.home.ts.net."}) {
			t.Errorf("%s: reverse: %v %v", network, names, err)
		}
	}
}

func TestMalformedQueries(t *testing.T) {
	s, _, _ := world(t)
	if res := s.Handle(context.Background(), []byte{1, 2, 3}, false); res != nil {
		t.Errorf("a runt was answered: %x", res)
	}
	garbage := append([]byte{0xbe, 0xef, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}, 0xff, 0xff)
	res := s.Handle(context.Background(), garbage, false)
	if len(res) != 12 || res[0] != 0xbe || res[1] != 0xef || res[3]&0x0f != byte(dnsmessage.RCodeFormatError) {
		t.Errorf("garbage: %x", res)
	}
}

func TestResolvConf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	conf := "search svc.cluster.local\nnameserver fdcc:79e6::53\nnameserver 10.152.183.10\nnameserver fe80::1%eth0\noptions ndots:5\n"
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ResolvConf(path, nil, netip.MustParsePrefix("fdcc:79e6::/32"))
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.AddrPort{netip.MustParseAddrPort("10.152.183.10:53"), netip.MustParseAddrPort("[fe80::1%eth0]:53")}
	if !slices.Equal(got, want) {
		t.Errorf("%v, want %v", got, want)
	}
}
