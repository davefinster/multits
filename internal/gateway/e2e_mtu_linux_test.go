package gateway

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/davefinster/multits/internal/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// device.mtu: tailnet sizes the device and its routes to exactly what the
// tailnet carries, per family. A datagram sent with don't-fragment that fits
// crosses whole, one byte more is refused by the host's own kernel, and TCP
// still moves bulk at the tailnet's segment size, with nothing fragmented.
func TestE2EFitTailnet(t *testing.T) {
	w := newWorld(t, func(f *config.File) { f.Device.MTU = "tailnet" })

	link, err := netlink.LinkByName("multits0")
	if err != nil {
		t.Fatal(err)
	}
	if got := link.Attrs().MTU; got != 1300 {
		t.Errorf("device MTU %d, want 1300", got)
	}
	routes, err := netlink.RouteList(link, netlink.FAMILY_V6)
	if err != nil {
		t.Fatal(err)
	}
	for prefix, want := range map[string]int{"fdcc:79e6:100::/48": 1300, "fdcc:79e6:100::/44": 1280} {
		found := false
		for _, r := range routes {
			if r.Dst != nil && r.Dst.String() == prefix {
				found = true
				if r.MTU != want {
					t.Errorf("route %s MTU %d, want %d", prefix, r.MTU, want)
				}
			}
		}
		if !found {
			t.Errorf("no route %s", prefix)
		}
	}

	// The application sends to client a, with don't-fragment as quic-go
	// does: 1300 bytes of IPv6 is the most, 1252 of UDP payload.
	ln, err := w.clientA.ListenPacket("udp", netip.AddrPortFrom(ipv4(w.clientA), 9100).String())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan int, 4)
	go func() {
		b := make([]byte, 2048)
		for {
			n, _, err := ln.ReadFrom(b)
			if err != nil {
				return
			}
			got <- n
		}
	}()
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
		})
		return errors.Join(err, serr)
	}}
	pc, err := lc.ListenPacket(w.ctx, "udp", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	to := &net.UDPAddr{IP: net.ParseIP("fdcc:79e6:100::6440:2"), Port: 9100}

	eventually(t, "a datagram that fits", func() error {
		if _, err := pc.WriteTo(make([]byte, 1252), to); err != nil {
			return err
		}
		select {
		case n := <-got:
			if n != 1252 {
				return fmt.Errorf("received %d bytes", n)
			}
			return nil
		case <-time.After(2 * time.Second):
			return errors.New("not received")
		}
	})
	if _, err := pc.WriteTo(make([]byte, 1253), to); !errors.Is(err, unix.EMSGSIZE) {
		t.Errorf("one byte over: %v, want EMSGSIZE from the host's kernel", err)
	}

	// TCP: 1 MiB from the application to the client, by its pseudo address.
	tl, err := w.clientA.Listen("tcp", ":9101")
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	big := bytes.Repeat([]byte("fit-the-tailnet!"), 1<<16)
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprint(rw, n)
	})}
	go func() { _ = srv.Serve(tl) }()
	defer srv.Close()
	eventually(t, "bulk TCP", func() error {
		resp, err := http.Post("http://[fdcc:79e6:100::6440:2]:9101/", "application/octet-stream", bytes.NewReader(big))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if string(b) != fmt.Sprint(len(big)) {
			return fmt.Errorf("server read %s bytes", b)
		}
		return nil
	})

	if f := w.g.Status().Tailnets[0].Outbound.Fragmented; f != 0 {
		t.Errorf("%d of the host's packets were fragmented", f)
	}
}
