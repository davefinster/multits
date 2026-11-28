package gateway

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/davefinster/multits/internal/config"
	"github.com/davefinster/tstest/control"
)

// A Tailscale Service the gateway hosts arrives at the host as the gateway's
// own addresses, like a route: an application on the wildcard address
// answers for the Service's virtual IPs, and the Service's name resolves to
// them on the gateway's own side. The tailnet's policy is what makes the
// gateway its host, and withdrawing stops the gateway offering it while the
// node stays joined.
func TestE2EServices(t *testing.T) {
	const service = "svc:web"
	vip4, vip6 := netip.MustParseAddr("100.64.0.50"), netip.MustParseAddr("fd7a:115c:a1e0:ab12:4843:cd96:6240:50")

	// The tailnet defines the Service, and its policy lets the gateway's
	// tag host it, before the gateway joins and offers to.
	w := newTailnets(t)
	if _, err := w.tailnetA.Tailnet().CreateService(control.Service{Name: service, Ports: []string{"tcp:8080"}, Addrs: []netip.Addr{vip4, vip6}}); err != nil {
		t.Fatal(err)
	}
	w.tailnetA.Tailnet().MustSetPolicy(`{
		"tagOwners": {"tag:gateway": []},
		"autoApprovers": {"services": {"svc:web": ["tag:gateway"]}},
		"grants": [
			{"src": ["*"], "dst": ["*"], "ip": ["*"]},
			{"src": ["*"], "dst": ["svc:web"], "ip": ["tcp:8080"]},
		],
		"nodeAttrs": [{"target": ["*"], "attr": ["magicdns-aaaa"]}],
	}`)
	w.start(t, func(f *config.File) {
		a := f.Tailnets["a"]
		a.Services = []string{service}
		// Only a tagged node may host a Service, and the gateway asks for
		// the tag its key gives it.
		a.AdvertiseTags = []string{gatewayTag}
	})

	// The control plane asks the gateway what it hosts, and approves it.
	gw := device(w.ctx, t, w.tailnetA, "gw")
	hosted := func(want int) error {
		ctx, cancel := context.WithTimeout(w.ctx, 30*time.Second)
		defer cancel()
		return w.control.WaitFor(ctx, func(sn *control.Snapshot) bool {
			n := sn.Node(gw.NodeKey)
			return n != nil && len(n.HostedServices) == want
		})
	}
	if err := hosted(1); err != nil {
		t.Fatalf("the gateway never became the Service's host: %v", err)
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

	// The Service's addresses are the gateway's own on the host: 0x32 is 50.
	for target, want := range map[string]string{
		netip.AddrPortFrom(vip4, 8080).String(): "[fdcc:79e6:100::6440:2]:* -> [fdcc:79e6:110::6440:32]:8080",
		netip.AddrPortFrom(vip6, 8080).String(): "[fdcc:79e6:101:ab12:4843:cd96:6240:2]:* -> [fdcc:79e6:111:ab12:4843:cd96:6240:50]:8080",
	} {
		from, to, _ := strings.Cut(want, ":* -> ")
		eventually(t, target, func() error {
			body, _, err := get(w.clientA, "http://"+target+"/")
			if err != nil {
				return err
			}
			if !strings.HasPrefix(body, from+":") || !strings.HasSuffix(body, " -> "+to) {
				return fmt.Errorf("the application saw %q, want %s", body, want)
			}
			t.Logf("%s: %s", target, body)
			return nil
		})
	}

	// The gateway reports the Service with its addresses as the host has
	// them.
	st := w.g.Status().Tailnets[0]
	var mapped []string
	for _, m := range st.Services[service] {
		mapped = append(mapped, m.Pseudo.String())
	}
	if want := []string{"fdcc:79e6:110::6440:32", "fdcc:79e6:111:ab12:4843:cd96:6240:50"}; !slices.Equal(mapped, want) {
		t.Errorf("status has the Service at %v, want %v", mapped, want)
	}

	// Its name is the tailnet's, and resolves to the gateway's own side, so
	// the application reaches a Service it hosts without leaving the host.
	resolver := hostResolver(w.g)
	eventually(t, "the Service's name", func() error {
		ctx, cancel := context.WithTimeout(w.ctx, 5*time.Second)
		defer cancel()
		ips, err := resolver.LookupNetIP(ctx, "ip", "web.a.ts.net")
		if err != nil {
			return err
		}
		var got []string
		for _, ip := range ips {
			got = append(got, ip.String())
		}
		if want := []string{"fdcc:79e6:110::6440:32", "fdcc:79e6:111:ab12:4843:cd96:6240:50"}; !slices.Equal(got, want) {
			return fmt.Errorf("%v, want %v", got, want)
		}
		return nil
	})

	w.g.Withdraw(w.ctx)
	if err := hosted(0); err != nil {
		t.Errorf("withdrawing left the gateway hosting the Service: %v", err)
	}
	if node, _ := w.g.Node("a"); node.State() != "Running" {
		t.Errorf("withdrawing left the node %s", node.State())
	}
}
