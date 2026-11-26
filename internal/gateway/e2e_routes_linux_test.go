package gateway

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/davefinster/multits/internal/config"
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

	// The test control plane approves nothing by itself.
	node, _ := w.g.Node("a")
	st, err := node.Status(w.ctx)
	if err != nil {
		t.Fatal(err)
	}
	w.controlA.SetSubnetRoutes(st.Self.PublicKey, []netip.Prefix{routed4, routed6})

	lc, err := w.clientA.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
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
		for _, n := range w.controlA.AllNodes() {
			if n.Hostinfo.Hostname() == "gw" {
				if routes := n.Hostinfo.RoutableIPs().AsSlice(); len(routes) > 0 {
					return fmt.Errorf("still advertised: %v", routes)
				}
				return nil
			}
		}
		return fmt.Errorf("the gateway is not on the tailnet")
	})
	if state := node.State(); state != "Running" {
		t.Errorf("withdrawing left the node %s", state)
	}
}
