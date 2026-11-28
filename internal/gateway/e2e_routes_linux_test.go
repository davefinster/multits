package gateway

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/davefinster/multits/internal/config"
	"golang.org/x/net/ipv6"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

// A route the gateway advertises arrives at the host as the gateway's own
// addresses, IPv4 and IPv6 alike, through the AnyIP route: an application on
// the wildcard address accepts for every address in it, with none assigned.
// Withdrawing takes the routes back out while the node stays joined. And an
// ICMP echo crosses to the host's own stack and back.
func TestE2ERoutes(t *testing.T) {
	routed4 := netip.MustParsePrefix("10.99.0.0/24")
	routed6 := netip.MustParsePrefix("2001:db8:feed:6ce8:d2b1:13c8:a553:acfc/128")
	w := newWorld(t, func(f *config.File) {
		a := f.Tailnets["a"]
		a.Routes = []string{routed4.String(), routed6.String()}
		a.IPv6Spaces = map[int]string{2: routed6.String()}
	})

	// Nothing in the tailnet's policy approves the routes, so its admin
	// does: the gateway advertises them and no more.
	node, _ := w.g.Node("a")
	gw := device(w.ctx, t, w.tailnetA, "gw")
	if !slices.Equal(gw.AdvertisedRoutes, []netip.Prefix{routed4, routed6}) || len(gw.ApprovedRoutes) != 0 {
		t.Fatalf("the gateway advertises %v, with %v approved", gw.AdvertisedRoutes, gw.ApprovedRoutes)
	}
	if err := w.tailnetA.ApproveRoutes(w.ctx, gw.ID, []netip.Prefix{routed4, routed6}); err != nil {
		t.Fatal(err)
	}

	lc := w.clientA.LocalClient()
	if _, err := lc.EditPrefs(w.ctx, &ipn.MaskedPrefs{RouteAllSet: true, Prefs: ipn.Prefs{RouteAll: true}}); err != nil {
		t.Fatal(err)
	}

	app := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(rw, "%s -> %s", r.RemoteAddr, r.Context().Value(http.LocalAddrContextKey))
	})}
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Serve(ln) }()
	t.Cleanup(func() { _ = app.Close() })

	for target, want := range map[string]string{
		"10.99.0.7:8080":   "-> [fdcc:79e6:110::a63:7]:8080",
		"10.99.0.200:8080": "-> [fdcc:79e6:110::a63:c8]:8080",
		"[2001:db8:feed:6ce8:d2b1:13c8:a553:acfc]:8080": "-> [fdcc:79e6:112:6ce8:d2b1:13c8:a553:acfc]:8080",
	} {
		eventually(t, target, func() error {
			body, _, err := get(w.clientA, "http://"+target+"/")
			if err != nil {
				return err
			}
			if !strings.HasSuffix(body, want) {
				return fmt.Errorf("got %q, want *%s", body, want)
			}
			t.Logf("%s: %s", target, body)
			return nil
		})
	}

	// The echo must cross the gateway, not be answered by tsnet's own
	// stack: its counters move by the request and the reply.
	before := w.g.counts[1].snapshot(inbound).Packets
	// A UDP server that answers from the address it was reached on, with
	// IPV6_PKTINFO, as quic-go does: the kernel accepts that source only if
	// the address is assigned, which for a host route the gateway does.
	pktinfo, err := net.ListenPacket("udp6", "[::]:8054")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pktinfo.Close() })
	pc := ipv6.NewPacketConn(pktinfo)
	if err := pc.SetControlMessage(ipv6.FlagDst, true); err != nil {
		t.Fatal(err)
	}
	go func() {
		b := make([]byte, 1500)
		for {
			n, cm, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			var reply *ipv6.ControlMessage
			if cm != nil {
				reply = &ipv6.ControlMessage{Src: cm.Dst}
			}
			if _, err := pc.WriteTo(b[:n], reply, from); err != nil {
				t.Logf("replying from %v: %v", cm.Dst, err)
			}
		}
	}()
	eventually(t, "UDP from the routed address", func() error {
		conn, err := w.clientA.Dial(w.ctx, "udp", "["+routed6.Addr().String()+"]:8054")
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte("pktinfo")); err != nil {
			return err
		}
		b := make([]byte, 64)
		n, err := conn.Read(b)
		if err != nil {
			return err
		}
		if string(b[:n]) != "pktinfo" {
			return fmt.Errorf("got %q", b[:n])
		}
		return nil
	})

	eventually(t, "ping", func() error {
		res, err := lc.Ping(w.ctx, w.gwA[0], tailcfg.PingICMP)
		if err != nil {
			return err
		}
		if res.Err != "" {
			return fmt.Errorf("%s", res.Err)
		}
		t.Logf("ICMP echo to %s answered by the host in %.2fms", w.gwA[0], res.LatencySeconds*1000)
		return nil
	})
	if after := w.g.counts[1].snapshot(inbound).Packets; after == before {
		t.Errorf("the echo never reached the host: %d packets in before and after", before)
	}

	w.g.Withdraw(w.ctx)
	eventually(t, "withdrawn", func() error {
		if routes := device(w.ctx, t, w.tailnetA, "gw").AdvertisedRoutes; len(routes) > 0 {
			return fmt.Errorf("still advertised: %v", routes)
		}
		return nil
	})
	if state := node.State(); state != "Running" {
		t.Errorf("withdrawing left the node %s", state)
	}
}
