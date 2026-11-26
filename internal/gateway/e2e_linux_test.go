package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/davefinster/multits/internal/config"
	"github.com/vishvananda/netlink"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// requireScratchNetns skips unless the test runs as root in a network
// namespace of its own, which it changes: a TUN device, routes, addresses.
// Run it with `make test-netns`, which does that with unshare.
func requireScratchNetns(t *testing.T) {
	t.Helper()
	if os.Getenv("MULTITS_NETNS") != "1" || os.Geteuid() != 0 {
		t.Skip("needs root in a scratch network namespace: make test-netns")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	// A fresh namespace has only its loopback. Anything else means this is
	// someone's real network, which the test must not touch.
	if len(ifaces) != 1 || ifaces[0].Name != "lo" {
		t.Fatalf("refusing to run: this network namespace has %v, not just lo", ifaces)
	}
	// A fresh namespace's loopback is down, and the test's own servers
	// listen on it before the gateway brings it up.
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
}

// startControl runs a control plane in the test: one tailnet.
func startControl(t *testing.T, domain string, configure ...func(*testcontrol.Server)) *testcontrol.Server {
	t.Helper()
	control := &testcontrol.Server{
		DERPMap:        integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1"),
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: domain,
		Logf:           logger.Discard,
	}
	for _, c := range configure {
		c(control)
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	return control
}

// client is a node on a tailnet with tsnet's own stack, nothing to do with
// the host.
func client(ctx context.Context, t *testing.T, controlURL, name string) *tsnet.Server {
	t.Helper()
	s := &tsnet.Server{
		Dir:        t.TempDir(),
		ControlURL: controlURL,
		Hostname:   name,
		Ephemeral:  true,
		Store:      new(mem.Store),
		Logf:       logger.Discard,
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.Up(ctx); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return s
}

func ipv4(s *tsnet.Server) netip.Addr   { v4, _ := s.TailscaleIPs(); return v4 }
func ipv6Of(s *tsnet.Server) netip.Addr { _, v6 := s.TailscaleIPs(); return v6 }

// The whole path on real nodes and a real kernel. Two tailnets, each with a
// client at the same IPv4 and IPv6 address, reach one application that
// listens on the host's wildcard address like any other; it tells them
// apart by their pseudo addresses, and its replies and its own dials go back
// to the right one.
func TestE2E(t *testing.T) {
	w := newWorld(t)
	ctx, g, clientA, clientB, gwA, gwB := w.ctx, w.g, w.clientA, w.clientB, w.gwA, w.gwB

	// The application: a plain server on the host's wildcard address.
	big := bytes.Repeat([]byte("0123456789abcdef"), 4<<20/16)
	app := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/big":
				_, _ = w.Write(big)
			case "/upload":
				h := sha256.New()
				n, _ := io.Copy(h, r.Body)
				fmt.Fprintf(w, "%d %x", n, h.Sum(nil))
			default:
				local := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
				fmt.Fprintf(w, "%s -> %s", r.RemoteAddr, local)
			}
		}),
	}
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Serve(ln) }()
	t.Cleanup(func() { _ = app.Close() })

	udp, err := net.ListenPacket("udp", ":8053")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(append([]byte(from.String()+" said "), b[:n]...), from)
		}
	}()

	t.Run("each tailnet reaches the application from its own address", func(t *testing.T) {
		for _, tc := range []struct {
			client *tsnet.Server
			gw     netip.Addr
			from   string
			to     string
		}{
			{clientA, gwA[0], "[fdcc:79e6:100::6440:2]", "[fdcc:79e6:110::6440:1]:8080"},
			{clientB, gwB[0], "[fdcc:79e6:200::6440:2]", "[fdcc:79e6:210::6440:1]:8080"},
			{clientA, gwA[1], "[fdcc:79e6:101:ab12:4843:cd96:6240:2]", "[fdcc:79e6:111:ab12:4843:cd96:6240:1]:8080"},
			{clientB, gwB[1], "[fdcc:79e6:201:ab12:4843:cd96:6240:2]", "[fdcc:79e6:211:ab12:4843:cd96:6240:1]:8080"},
		} {
			url := "http://" + netip.AddrPortFrom(tc.gw, 8080).String() + "/"
			eventually(t, url, func() error {
				body, _, err := get(tc.client, url)
				if err != nil {
					return err
				}
				if !strings.HasPrefix(body, tc.from+":") || !strings.HasSuffix(body, " -> "+tc.to) {
					return fmt.Errorf("the application saw %q, want %s:* -> %s", body, tc.from, tc.to)
				}
				t.Logf("%s: %s", url, body)
				return nil
			})
		}
	})

	t.Run("the application dials each tailnet's peer by its pseudo address", func(t *testing.T) {
		for _, tc := range []struct {
			client *tsnet.Server
			name   string
			pseudo string
			gw     netip.Addr
		}{
			{clientA, "client-a", "[fdcc:79e6:100::6440:2]:9000", gwA[0]},
			{clientB, "client-b", "[fdcc:79e6:200::6440:2]:9000", gwB[0]},
			{clientA, "client-a", "[fdcc:79e6:101:ab12:4843:cd96:6240:2]:9000", gwA[1]},
		} {
			ln, err := tc.client.Listen("tcp", ":9000")
			if err != nil {
				t.Fatal(err)
			}
			srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "%s saw %s", tc.name, r.RemoteAddr)
			})}
			go func() { _ = srv.Serve(ln) }()

			hc := &http.Client{Timeout: 20 * time.Second}
			eventually(t, tc.pseudo, func() error {
				resp, err := hc.Get("http://" + tc.pseudo + "/")
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				if want := tc.name + " saw " + tc.gw.String(); !strings.HasPrefix(string(b), want) && !strings.HasPrefix(string(b), tc.name+" saw ["+tc.gw.String()+"]") {
					return fmt.Errorf("got %q, want %s:*", b, want)
				}
				t.Logf("%s: %s", tc.pseudo, b)
				return nil
			})
			hc.CloseIdleConnections()
			_ = srv.Close()
		}
	})

	t.Run("UDP", func(t *testing.T) {
		eventually(t, "udp", func() error {
			conn, err := clientA.Dial(ctx, "udp", netip.AddrPortFrom(gwA[0], 8053).String())
			if err != nil {
				return err
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write([]byte("ping")); err != nil {
				return err
			}
			b := make([]byte, 256)
			n, err := conn.Read(b)
			if err != nil {
				return err
			}
			if got := string(b[:n]); !strings.HasPrefix(got, "[fdcc:79e6:100::6440:2]:") || !strings.HasSuffix(got, " said ping") {
				return fmt.Errorf("got %q", got)
			}
			t.Logf("udp: %s", b[:n])
			return nil
		})
	})

	t.Run("bulk both ways", func(t *testing.T) {
		start := time.Now()
		body, _, err := get(clientA, "http://"+netip.AddrPortFrom(gwA[0], 8080).String()+"/big")
		if err != nil {
			t.Fatal(err)
		}
		if body != string(big) {
			t.Fatalf("downloaded %d bytes that differ from the %d served", len(body), len(big))
		}
		t.Logf("downloaded %d MiB over IPv4 in %v", len(big)>>20, time.Since(start).Round(time.Millisecond))

		start = time.Now()
		hc := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{DialContext: clientB.Dial}}
		defer hc.CloseIdleConnections()
		resp, err := hc.Post("http://"+netip.AddrPortFrom(gwB[1], 8080).String()+"/upload", "application/octet-stream", bytes.NewReader(big))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if want := fmt.Sprintf("%d %x", len(big), sha256.Sum256(big)); string(b) != want {
			t.Fatalf("upload: %q, want %q", b, want)
		}
		t.Logf("uploaded %d MiB over IPv6 in %v", len(big)>>20, time.Since(start).Round(time.Millisecond))
	})

	t.Run("whois", func(t *testing.T) {
		h := g.Handler()
		for pseudo, want := range map[string]string{"fdcc:79e6:100::6440:2": "client-a", "fdcc:79e6:200::6440:2": "client-b"} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("GET", "/whois?addr="+pseudo, nil))
			var who WhoIs
			if err := json.Unmarshal(rec.Body.Bytes(), &who); err != nil || who.WhoIs == nil || who.WhoIs.Node == nil {
				t.Fatalf("%s: %d %s", pseudo, rec.Code, rec.Body)
			}
			if !strings.HasPrefix(who.WhoIs.Node.Name, want+".") {
				t.Errorf("%s is %s, want %s", pseudo, who.WhoIs.Node.Name, want)
			}
		}
	})

	t.Run("a tailnet that is not configured is unreachable at once", func(t *testing.T) {
		start := time.Now()
		_, err := net.DialTimeout("tcp", "[fdcc:79e6:900::6440:2]:80", 10*time.Second)
		if err == nil {
			t.Fatal("dialed a tailnet that does not exist")
		}
		if time.Since(start) > 2*time.Second {
			t.Errorf("took %v to fail: %v", time.Since(start), err)
		}
		t.Logf("refused in %v: %v", time.Since(start).Round(time.Millisecond), err)
	})

	st := g.Status()
	for _, ts := range st.Tailnets {
		t.Logf("%s: in %+v out %+v", ts.Name, ts.Inbound, ts.Outbound)
	}
	t.Logf("unrouted: %+v", st.Unrouted)
}

// world is two tailnets with the gateway on both and a client on each, at
// the same addresses.
type world struct {
	ctx                context.Context
	g                  *Gateway
	controlA, controlB *testcontrol.Server
	clientA, clientB   *tsnet.Server
	gwA, gwB           []netip.Addr
}

// newWorld starts it, with whatever changes to the gateway's configuration
// the test needs.
func newWorld(t *testing.T, configure ...func(*config.File)) *world {
	t.Helper()
	requireScratchNetns(t)
	netns.SetEnabled(false)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)

	// Tailnet a has an extra record outside its MagicDNS suffix, which its
	// resolver answers for and b's knows nothing of; and it grants
	// magicdns-aaaa, without which MagicDNS gives a dual-stack peer's IPv4
	// address only, as b's does.
	controlA := startControl(t, "a.ts.net", func(c *testcontrol.Server) {
		c.DNSConfig.ExtraRecords = []tailcfg.DNSRecord{{Name: "nas.corp.example", Type: "A", Value: "100.64.0.99"}}
		c.DefaultNodeCapabilities = &tailcfg.NodeCapMap{
			nodecap.HTTPS:            []tailcfg.RawMessage{},
			nodecap.MagicDNSPeerAAAA: []tailcfg.RawMessage{},
		}
	})
	controlB := startControl(t, "b.ts.net")

	f := &config.File{}
	f.API.Listen = "off"
	f.Shutdown.DrainDelay = "0s"
	f.Tailnets = map[string]*config.Tailnet{
		"a": {ID: 1, StateDir: t.TempDir(), ControlURL: controlA.HTTPTestServer.URL, Hostname: "gw", Ephemeral: true},
		"b": {ID: 2, StateDir: t.TempDir(), ControlURL: controlB.HTTPTestServer.URL, Hostname: "gw", Ephemeral: true},
	}
	for _, c := range configure {
		c(f)
	}
	cfg, err := f.Resolve()
	if err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	g, err := New(cfg, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = g.Run(runCtx); close(done) }()
	t.Cleanup(func() { stop(); <-done })

	// The gateway joins first in both tailnets, so it and the clients get
	// the same addresses in each.
	w := &world{ctx: ctx, g: g, controlA: controlA, controlB: controlB}
	w.gwA, w.gwB = waitRunning(ctx, t, g, "a"), waitRunning(ctx, t, g, "b")
	t.Logf("gateway: a %v, b %v", w.gwA, w.gwB)

	w.clientA, w.clientB = client(ctx, t, controlA.HTTPTestServer.URL, "client-a"), client(ctx, t, controlB.HTTPTestServer.URL, "client-b")
	if ipv4(w.clientA) != ipv4(w.clientB) || ipv6Of(w.clientA) != ipv6Of(w.clientB) {
		t.Fatalf("the clients' addresses differ (%v %v / %v %v); the test wants them to collide", ipv4(w.clientA), ipv6Of(w.clientA), ipv4(w.clientB), ipv6Of(w.clientB))
	}
	t.Logf("both clients are %v and %v", ipv4(w.clientA), ipv6Of(w.clientA))
	return w
}

// eventually retries f until it succeeds or 45 seconds pass.
func eventually(t *testing.T, name string, f func() error) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for {
		start := time.Now()
		err := f()
		if err == nil {
			return
		}
		if testing.Verbose() {
			t.Logf("%s: not yet after %v: %v", name, time.Since(start).Round(time.Millisecond), err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %v", name, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// get fetches a URL from a tailnet client.
func get(c *tsnet.Server, url string) (string, int, error) {
	hc := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: c.Dial}}
	defer hc.CloseIdleConnections()
	resp, err := hc.Get(url)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode, err
}

// waitRunning waits for a gateway node to run and have its addresses on the
// host, returning them, IPv4 first.
func waitRunning(ctx context.Context, t *testing.T, g *Gateway, name string) []netip.Addr {
	t.Helper()
	node, _ := g.Node(name)
	for {
		if a := node.Addresses(); node.State() == "Running" && len(a.Self) == 2 {
			// The addresses reach the host device just after they are seen.
			time.Sleep(200 * time.Millisecond)
			return a.Self
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s never came up: %s", name, node.State())
		case <-time.After(100 * time.Millisecond):
		}
	}
}
