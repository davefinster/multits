package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/davefinster/multits/internal/config"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

// The gateway's resolver, as Go's own resolver uses it from the host: each
// tailnet's names resolve to pseudo addresses on that tailnet, including the
// same name on two of them; an extra record outside the MagicDNS suffix is
// its tailnet's too; a pseudo address resolves back to its name; anything
// else goes upstream untouched. And a name, once resolved, is dialed.
func TestE2EDNS(t *testing.T) {
	requireScratchNetns(t)
	upstream := fakeUpstream(t)
	w := newWorld(t, func(f *config.File) {
		f.DNS.Upstream = []string{upstream.String()}
	})

	resolver := hostResolver(w.g)
	lookup := func(name string) ([]string, error) {
		ctx, cancel := context.WithTimeout(w.ctx, 5*time.Second)
		defer cancel()
		ips, err := resolver.LookupNetIP(ctx, "ip", name)
		var out []string
		for _, ip := range ips {
			out = append(out, ip.String())
		}
		return out, err
	}

	for name, want := range map[string][]string{
		// a grants magicdns-aaaa: both of the peer's addresses.
		"client-a.a.ts.net": {"fdcc:79e6:100::6440:2", "fdcc:79e6:101:ab12:4843:cd96:6240:2"},
		// b does not, so its MagicDNS gives the IPv4 address alone.
		"client-b.b.ts.net": {"fdcc:79e6:200::6440:2"},
		// The gateway's own name is on its own side.
		"gw.a.ts.net": {"fdcc:79e6:110::6440:1", "fdcc:79e6:111:ab12:4843:cd96:6240:1"},
		"gw.b.ts.net": {"fdcc:79e6:210::6440:1"},
		// a's extra record.
		"nas.corp.example": {"fdcc:79e6:100::6440:63"},
		// Not a tailnet's: upstream, unchanged.
		"example.test": {"192.0.2.1"},
	} {
		eventually(t, name, func() error {
			got, err := lookup(name)
			if err != nil {
				return err
			}
			if !slices.Equal(got, want) {
				return fmt.Errorf("%v, want %v", got, want)
			}
			t.Logf("%s: %v", name, got)
			return nil
		})
	}

	_, err := lookup("nope.a.ts.net")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Errorf("a name no tailnet has: %v", err)
	}

	for pseudo, want := range map[string]string{
		"fdcc:79e6:100::6440:2": "client-a.a.ts.net.",
		"fdcc:79e6:200::6440:2": "client-b.b.ts.net.",
	} {
		ctx, cancel := context.WithTimeout(w.ctx, 5*time.Second)
		names, err := resolver.LookupAddr(ctx, pseudo)
		cancel()
		if err != nil || !slices.Equal(names, []string{want}) {
			t.Errorf("reverse %s: %v %v, want %s", pseudo, names, err, want)
		}
	}

	// By name, from the host, to each tailnet's client.
	for _, c := range []struct {
		name string
		ln   interface {
			Listen(string, string) (net.Listener, error)
		}
	}{{"client-a.a.ts.net", w.clientA}, {"client-b.b.ts.net", w.clientB}} {
		ln, err := c.ln.Listen("tcp", ":9000")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(rw, "this is %s", c.name)
		})}
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(func() { _ = srv.Close() })

		hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: (&net.Dialer{Resolver: resolver}).DialContext}}
		eventually(t, c.name, func() error {
			resp, err := hc.Get("http://" + c.name + ":9000/")
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			if string(b) != "this is "+c.name {
				return fmt.Errorf("got %q", b)
			}
			return nil
		})
		hc.CloseIdleConnections()
	}

	if zones := w.g.Status().Tailnets[0].Zones; !slices.Equal(zones, []string{"a.ts.net", "nas.corp.example"}) {
		t.Errorf("a's zones: %v", zones)
	}
}

// hostResolver is Go's resolver pointed at the gateway's, over the host's
// own network.
func hostResolver(g *Gateway) *net.Resolver {
	server := g.cfg.DNS.Listen[0].String()
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, server)
	}}
}

// fakeUpstream answers A 192.0.2.1 for every name, over UDP on the host.
func fakeUpstream(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "[::1]:0")
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
			if q.Unpack(buf[:n]) != nil || len(q.Questions) != 1 {
				continue
			}
			res := dnsmessage.Message{Header: dnsmessage.Header{ID: q.Header.ID, Response: true, RecursionAvailable: true}, Questions: q.Questions}
			if q.Questions[0].Type == dnsmessage.TypeA {
				res.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
					Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}},
				}}
			}
			b, _ := res.Pack()
			_, _ = pc.WriteTo(b, from)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

// useResolvConf makes /etc/resolv.conf say content, for processes the test
// starts, by mounting over it. It needs a mount namespace of the test's
// own, so that nothing outside sees the change: make test-netns makes one.
func useResolvConf(t *testing.T, content string) {
	t.Helper()
	self, err1 := os.Readlink("/proc/self/ns/mnt")
	init, err2 := os.Readlink("/proc/1/ns/mnt")
	if err1 != nil || err2 != nil || self == init {
		t.Skip("needs a mount namespace of its own to replace /etc/resolv.conf: make test-netns")
	}
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(path, "/etc/resolv.conf", "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("mounting over /etc/resolv.conf: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount("/etc/resolv.conf", 0) })
}
