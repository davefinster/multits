package gateway

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/davefinster/multits/internal/addr"
	"github.com/davefinster/multits/internal/tailnet"
	"github.com/davefinster/multits/internal/xlat"
	"github.com/tailscale/wireguard-go/tun"
)

// udp6 is a UDP datagram in IPv6, with size bytes of payload.
func udp6(src, dst string, sport, dport uint16, size int) []byte {
	pkt := make([]byte, 48+size)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:], uint16(8+size))
	pkt[6], pkt[7] = 17, 64
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(pkt[8:], s[:])
	copy(pkt[24:], d[:])
	binary.BigEndian.PutUint16(pkt[40:], sport)
	binary.BigEndian.PutUint16(pkt[42:], dport)
	binary.BigEndian.PutUint16(pkt[44:], uint16(8+size))
	return pkt
}

// A flow's packets share a number whatever they carry, and its ports are
// part of it only where there are ports to read.
func TestFlowOf(t *testing.T) {
	a := udp6("fdcc:79e6:100::6440:2", "fdcc:79e6:110::6440:1", 40000, 443, 10)
	if flowOf(a) != flowOf(udp6("fdcc:79e6:100::6440:2", "fdcc:79e6:110::6440:1", 40000, 443, 900)) {
		t.Error("one flow's packets differ")
	}

	// Flows that differ in one thing spread: over a few hundred of them,
	// every one of four queues gets some.
	for name, flow := range map[string]func(i int) []byte{
		"port": func(i int) []byte {
			return udp6("fdcc:79e6:100::6440:2", "fdcc:79e6:110::6440:1", uint16(40000+i), 443, 10)
		},
		"peer": func(i int) []byte {
			return udp6(netip.AddrFrom16([16]byte{0xfd, 0xcc, 0x79, 0xe6, 1, 0, 14: byte(i >> 8), 15: byte(i)}).String(), "fdcc:79e6:110::6440:1", 40000, 443, 10)
		},
		"tailnet": func(i int) []byte {
			return udp6(netip.AddrFrom16([16]byte{0xfd, 0xcc, 0x79, 0xe6, byte(1 + i%255), 0, 12: 100, 13: 64, 15: 2}).String(), "fdcc:79e6:110::6440:1", 40000, 443, 10)
		},
	} {
		var queues [4]int
		for i := range 400 {
			queues[flowOf(flow(i))%4]++
		}
		for q, n := range queues {
			if n < 40 {
				t.Errorf("flows that differ by %s: queue %d got %d of 400: %v", name, q, n, queues)
			}
		}
	}

	// A fragment has no ports where a datagram's are: what is there is
	// not part of the flow.
	frag := udp6("fdcc:79e6:100::6440:2", "fdcc:79e6:110::6440:1", 1, 2, 10)
	frag[6] = 44
	other := udp6("fdcc:79e6:100::6440:2", "fdcc:79e6:110::6440:1", 3, 4, 10)
	other[6] = 44
	if flowOf(frag) != flowOf(other) {
		t.Error("a fragment's flow depends on bytes that are not ports")
	}
	if flowOf(a[:39]) != 0 {
		t.Error("a truncated header has a flow")
	}
}

// Buffers come in the size of what they hold: a read's own slab, or the
// smallest class that fits a copy of a small one.
func TestBuffers(t *testing.T) {
	f := newBuffers(128, 1328)
	slab := f.slab()
	if len(slab.Slab) != f.slabSize || len(slab.Packets) != 128 || slab.Done == nil {
		t.Errorf("a slab of %d bytes and %d packets", len(slab.Slab), len(slab.Packets))
	}
	if f.slabSize < 65536+2*tun.ReadPacketSpacing {
		t.Errorf("a slab of %d bytes does not hold an offloaded segment", f.slabSize)
	}
	// One that comes back is as good as new, however it was left.
	slab.Packets = slab.Packets[:3]
	slab.Done(slab)
	if again := f.slab(); len(again.Packets) != 128 {
		t.Errorf("a slab came back with room for %d packets", len(again.Packets))
	}

	for size, want := range map[int]int{1: 2 << 10, 2 << 10: 2 << 10, 2<<10 + 1: 4 << 10, 9000: 16 << 10, handoffMin - 1: 32 << 10, handoffMin: 32 << 10} {
		b := f.compactFor(size)
		if len(b.Slab) != want || len(b.Packets) != 0 || b.Done == nil {
			t.Errorf("a copy of %d bytes got a buffer of %d, want %d", size, len(b.Slab), want)
		}
		b.Packets = append(b.Packets, tun.ReadPacket{Size: size})
		b.Done(b)
		if again := f.compactFor(size); len(again.Slab) != want || len(again.Packets) != 0 {
			t.Errorf("a buffer for %d bytes came back as %d bytes holding %d packets", size, len(again.Slab), len(again.Packets))
		}
	}
	// Past every class, a buffer of its own, which the pools never see.
	if b := f.compactFor(handoffMin + 1); len(b.Slab) != handoffMin+1 || b.Done != nil {
		t.Errorf("an oversized copy got %d bytes", len(b.Slab))
	}
}

// testGateway is a gateway with tailnet 1 configured and its node not yet
// joined, so that everything sent to it is refused, and with what it writes
// to the host kept.
func testGateway(t *testing.T) (*Gateway, *[][]byte) {
	t.Helper()
	scheme, err := addr.NewScheme(netip.MustParsePrefix("fdcc:79e6::/32"))
	if err != nil {
		t.Fatal(err)
	}
	if err := scheme.AddTailnet(1); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	g := &Gateway{scheme: scheme, xlat: xlat.New(scheme, 1280), log: log, bufs: newBuffers(128, 1328)}
	g.counts[1] = &counters{}
	g.byID[1] = tailnet.New(tailnet.Config{Name: "a", ID: 1}, nil, g.toTailnet(1, g.counts[1]), nil, log)
	var written [][]byte
	g.writeTo = func(_ int, bufs [][]byte, offset int) (int, error) {
		for _, b := range bufs {
			written = append(written, append([]byte(nil), b[offset:]...))
		}
		return len(bufs), nil
	}
	return g, &written
}

// readOf is a read of the host's device holding these packets.
func readOf(g *Gateway, pkts ...[]byte) *tailnet.Batch {
	b := g.bufs.slab()
	b.Packets = b.Packets[:0]
	off := tun.ReadPacketSpacing
	for _, p := range pkts {
		copy(b.Slab[off:], p)
		b.Packets = append(b.Packets, tun.ReadPacket{Offset: off, Size: len(p)})
		off += len(p) + tun.ReadPacketSpacing
	}
	return b
}

// A read a node refuses stays the reader's, whichever way it was sent, and
// every packet in it is counted.
func TestForwardRefused(t *testing.T) {
	g, _ := testGateway(t)
	scratch := make([]byte, hostOffset+1328)
	pkt := udp6("fdcc:79e6:110::6440:1", "fdcc:79e6:100::6440:2", 1, 2, 1200)

	small := readOf(g, pkt, pkt)
	if g.forward(0, small, scratch) {
		t.Error("a small read's slab was given away")
	}
	var large [][]byte
	for range handoffMin/len(pkt) + 1 {
		large = append(large, pkt)
	}
	if g.forward(0, readOf(g, large...), scratch) {
		t.Error("a refused read's slab was given away")
	}
	if got := g.counts[1].snapshot(outbound).Dropped["queue-full"]; got != uint64(2+len(large)) {
		t.Errorf("%d packets counted as refused, want %d", got, 2+len(large))
	}
}

// Packets for no tailnet are answered or dropped where they are read, one by
// one, also when they share a read with ones that have a tailnet.
func TestForwardUnrouted(t *testing.T) {
	g, written := testGateway(t)
	scratch := make([]byte, hostOffset+1328)

	g.forward(0, readOf(g,
		udp6("fdcc:79e6:110::6440:1", "fdcc:79e6:900::6440:2", 1, 2, 10), // no such tailnet
		udp6("fdcc:79e6:110::6440:1", "fdcc:79e6:100::6440:2", 1, 2, 10), // tailnet 1
		udp6("fdcc:79e6:110::6440:1", "2001:db8::1", 1, 2, 10),           // outside the prefix
		[]byte{0x45, 0, 0, 20}, // not IPv6
	), scratch)

	if len(*written) != 1 {
		t.Fatalf("%d packets written to the host, want the one error", len(*written))
	}
	if e := (*written)[0]; e[6] != 58 || e[40] != 1 || e[41] != 0 {
		t.Errorf("the host was sent next header %d, type %d code %d; want ICMPv6 no route", e[6], e[40], e[41])
	}
	dropped := g.unrouted.snapshot(outbound).Dropped
	for _, reason := range []string{"no-tailnet", "outside-prefix", "not-ipv6"} {
		if dropped[reason] != 1 {
			t.Errorf("%s counted %d times: %v", reason, dropped[reason], dropped)
		}
	}
	if got := g.counts[1].snapshot(outbound).Dropped["queue-full"]; got != 1 {
		t.Errorf("tailnet 1's packet counted as refused %d times", got)
	}
}

// What a node reads is translated then, and a packet the host must be told
// about is answered from there.
func TestToTailnet(t *testing.T) {
	g, written := testGateway(t)
	translate := g.toTailnet(1, g.counts[1])
	out := make([]byte, 1328)

	n, frags := translate(udp6("fdcc:79e6:110::6440:1", "fdcc:79e6:100::6440:2", 1, 2, 100), out)
	if n != 20+8+100 || frags != nil || out[0] != 0x45 {
		t.Errorf("an IPv4 peer's datagram came to %d bytes, version byte %#x", n, out[0])
	}
	// Larger than the tailnet carries: fragments, each counted.
	n, frags = translate(udp6("fdcc:79e6:110::6440:1", "fdcc:79e6:100::6440:2", 1, 2, 1280), out)
	if n != 0 || len(frags) != 2 {
		t.Errorf("a 1280-byte datagram came to %d bytes and %d fragments", n, len(frags))
	}
	c := g.counts[1].snapshot(outbound)
	if c.Packets != 3 || c.Fragmented != 1 {
		t.Errorf("%d packets and %d fragmented, want 3 and 1", c.Packets, c.Fragmented)
	}

	// From an address that is not the gateway's on that tailnet.
	n, frags = translate(udp6("fd37::1", "fdcc:79e6:100::6440:2", 1, 2, 10), out)
	if n != 0 || frags != nil || len(*written) != 1 {
		t.Fatalf("a bad source came to %d bytes, with %d packets to the host", n, len(*written))
	}
	if e := (*written)[0]; e[40] != 1 || e[41] != 5 {
		t.Errorf("the host was sent type %d code %d, want policy failure", e[40], e[41])
	}
	if got := g.unrouted.snapshot(outbound).Dropped["bad-source"]; got != 1 {
		t.Errorf("bad-source counted %d times", got)
	}
}
