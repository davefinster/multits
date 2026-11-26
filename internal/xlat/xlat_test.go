package xlat

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/davefinster/multits/internal/addr"
)

// naiveSum is a deliberately plain one's complement sum, independent of the
// one under test, so a mistake in the incremental arithmetic cannot hide
// behind the same mistake in the check.
func naiveSum(chunks ...[]byte) uint16 {
	var acc uint64
	for _, b := range chunks {
		for i := 0; i < len(b); i += 2 {
			hi := uint64(b[i]) << 8
			lo := uint64(0)
			if i+1 < len(b) {
				lo = uint64(b[i+1])
			}
			acc += hi | lo
		}
	}
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	return uint16(acc)
}

func be16(v int) []byte { return binary.BigEndian.AppendUint16(nil, uint16(v)) }
func be32(v int) []byte { return binary.BigEndian.AppendUint32(nil, uint32(v)) }

// pseudo4 and pseudo6b are the pseudo-headers, as bytes.
func pseudo4(src, dst []byte, proto uint8, length int) []byte {
	b := append(append([]byte{}, src...), dst...)
	return append(append(b, 0, proto), be16(length)...)
}

func pseudo6b(src, dst []byte, next uint8, length int) []byte {
	b := append(append([]byte{}, src...), dst...)
	return append(append(b, be32(length)...), 0, 0, 0, next)
}

// valid4 checks an IPv4 packet's header checksum and its transport's.
func valid4(t *testing.T, pkt []byte) {
	t.Helper()
	ihl := int(pkt[0]&0xf) * 4
	if naiveSum(pkt[:ihl]) != 0xffff {
		t.Errorf("IPv4 header checksum is wrong")
	}
	proto := pkt[9]
	l4 := pkt[ihl:binary.BigEndian.Uint16(pkt[2:])]
	switch proto {
	case protoTCP, protoUDP:
		if proto == protoUDP && binary.BigEndian.Uint16(l4[6:]) == 0 {
			return
		}
		if naiveSum(pseudo4(pkt[12:16], pkt[16:20], proto, len(l4)), l4) != 0xffff {
			t.Errorf("IPv4 %d checksum is wrong", proto)
		}
	case protoICMP:
		if naiveSum(l4) != 0xffff {
			t.Errorf("ICMPv4 checksum is wrong")
		}
	}
}

// valid6 checks an unfragmented IPv6 packet's transport checksum.
func valid6(t *testing.T, pkt []byte) {
	t.Helper()
	next := pkt[6]
	l4 := pkt[ipv6HeaderLen:]
	switch next {
	case protoTCP, protoUDP, protoICMPv6:
		if naiveSum(pseudo6b(pkt[8:24], pkt[24:40], next, len(l4)), l4) != 0xffff {
			t.Errorf("IPv6 %d checksum is wrong", next)
		}
		if next == protoUDP && binary.BigEndian.Uint16(l4[6:]) == 0 {
			t.Errorf("IPv6 UDP checksum is zero")
		}
	default:
		t.Errorf("unexpected next header %d", next)
	}
}

func tcpSegment(sport, dport int, payload string) []byte {
	b := append(be16(sport), be16(dport)...)
	b = append(b, 0, 0, 0, 1, 0, 0, 0, 0) // seq, ack
	b = append(b, 0x50, 0x02, 0xff, 0xff) // 20 bytes, SYN, window
	b = append(b, 0, 0, 0, 0)             // checksum, urgent
	return append(b, payload...)
}

func udpDatagram(sport, dport int, payload string) []byte {
	b := append(be16(sport), be16(dport)...)
	b = append(b, be16(8+len(payload))...)
	b = append(b, 0, 0)
	return append(b, payload...)
}

func echo(typ uint8, id, seq int, payload string) []byte {
	b := []byte{typ, 0, 0, 0}
	b = append(b, be16(id)...)
	b = append(b, be16(seq)...)
	return append(b, payload...)
}

// setL4Checksum computes the transport checksum of a segment for a
// pseudo-header (nil for ICMPv4).
func setL4Checksum(proto uint8, l4, pseudo []byte) {
	off := map[uint8]int{protoTCP: 16, protoUDP: 6, protoICMP: 2, protoICMPv6: 2}[proto]
	l4[off], l4[off+1] = 0, 0
	c := ^naiveSum(pseudo, l4)
	if proto == protoUDP && c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(l4[off:], c)
}

func ip4(s string) []byte { a := netip.MustParseAddr(s).As4(); return a[:] }
func ip6(s string) []byte { a := netip.MustParseAddr(s).As16(); return a[:] }

// packet4 is an IPv4 packet with correct checksums. frag is the flags and
// offset word.
func packet4(src, dst string, proto uint8, frag int, l4 []byte, checksummed bool) []byte {
	s, d := ip4(src), ip4(dst)
	l4 = append([]byte{}, l4...)
	if checksummed {
		var pseudo []byte
		if proto != protoICMP {
			pseudo = pseudo4(s, d, proto, len(l4))
		}
		setL4Checksum(proto, l4, pseudo)
	}
	h := []byte{0x45, 0x10}
	h = append(h, be16(20+len(l4))...)
	h = append(h, 0x12, 0x34)
	h = append(h, be16(frag)...)
	h = append(h, 63, proto, 0, 0)
	h = append(append(h, s...), d...)
	binary.BigEndian.PutUint16(h[10:], ^naiveSum(h))
	return append(h, l4...)
}

// packet6 is an IPv6 packet with a correct transport checksum.
func packet6(src, dst string, next uint8, l4 []byte) []byte {
	s, d := ip6(src), ip6(dst)
	l4 = append([]byte{}, l4...)
	setL4Checksum(next, l4, pseudo6b(s, d, next, len(l4)))
	h := []byte{0x60, 0, 0, 0}
	h = append(h, be16(len(l4))...)
	h = append(h, next, 64)
	h = append(append(h, s...), d...)
	return append(h, l4...)
}

func newTestTranslator(t *testing.T) *Translator {
	t.Helper()
	s, err := addr.NewScheme(netip.MustParsePrefix("fdcc:79e6::/32"))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint8{1, 2} {
		if err := s.AddTailnet(id); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetSpace(1, 2, netip.MustParsePrefix("2001:db8:feed:6ce8:d2b1:13c8:a553:acfc/128")); err != nil {
		t.Fatal(err)
	}
	return New(s, 1280)
}

func toHost(t *testing.T, x *Translator, tailnet uint8, pkt []byte) Result {
	t.Helper()
	return x.ToHost(tailnet, pkt, make([]byte, len(pkt)+Growth))
}

func toTailnet(t *testing.T, x *Translator, pkt []byte) Result {
	t.Helper()
	return x.ToTailnet(pkt, make([]byte, max(len(pkt), minIPv6MTU)))
}

func addrAt(b []byte) string  { return netip.AddrFrom16([16]byte(b)).String() }
func addr4At(b []byte) string { return netip.AddrFrom4([4]byte(b)).String() }

func TestTCPRoundTrip(t *testing.T) {
	x := newTestTranslator(t)
	syn := packet4("100.64.0.2", "100.64.0.1", protoTCP, 0x4000, tcpSegment(40000, 443, "hello"), true)

	res := toHost(t, x, 1, syn)
	if res.Verdict != Forward {
		t.Fatalf("ToHost: %v %v", res.Verdict, res.Reason)
	}
	v6 := res.Packet
	if got := addrAt(v6[8:24]); got != "fdcc:79e6:100::6440:2" {
		t.Errorf("source %s", got)
	}
	if got := addrAt(v6[24:40]); got != "fdcc:79e6:110::6440:1" {
		t.Errorf("destination %s", got)
	}
	if v6[6] != protoTCP || v6[7] != 63 || trafficClass(v6) != 0x10 {
		t.Errorf("header: next %d hop %d tc %#x", v6[6], v6[7], trafficClass(v6))
	}
	if len(v6) != len(syn)+20 {
		t.Errorf("length %d, want %d", len(v6), len(syn)+20)
	}
	valid6(t, v6)

	// The host answers from the address it was reached on.
	reply := packet6("fdcc:79e6:110::6440:1", "fdcc:79e6:100::6440:2", protoTCP, tcpSegment(443, 40000, "world"))
	res = toTailnet(t, x, reply)
	if res.Verdict != Forward || res.Tailnet != 1 {
		t.Fatalf("ToTailnet: %v %v tailnet %d", res.Verdict, res.Reason, res.Tailnet)
	}
	v4 := res.Packet
	if src, dst := addr4At(v4[12:16]), addr4At(v4[16:20]); src != "100.64.0.1" || dst != "100.64.0.2" {
		t.Errorf("addresses %s -> %s", src, dst)
	}
	if v4[8] != 64 || v4[9] != protoTCP {
		t.Errorf("ttl %d proto %d", v4[8], v4[9])
	}
	// Small enough to be fragmented by an IPv4 path, so no DF, and an
	// identification to reassemble by.
	if frag := binary.BigEndian.Uint16(v4[6:]); frag != 0 || binary.BigEndian.Uint16(v4[4:]) == 0 {
		t.Errorf("frag %#x id %d", frag, binary.BigEndian.Uint16(v4[4:]))
	}
	valid4(t, v4)
	got, want := append([]byte{}, v4[20:]...), append([]byte{}, reply[40:]...)
	clear(got[16:18])
	clear(want[16:18])
	if !bytes.Equal(got, want) {
		t.Errorf("segment changed beyond its checksum")
	}
}

// The same packet from two tailnets reaches the host from two addresses, and
// each answer goes back to the tailnet it came from.
func TestOverlappingTailnets(t *testing.T) {
	x := newTestTranslator(t)
	pkt := packet4("100.64.0.2", "100.64.0.1", protoUDP, 0, udpDatagram(5353, 53, "q"), true)

	a := toHost(t, x, 1, pkt)
	b := toHost(t, x, 2, pkt)
	if addrAt(a.Packet[8:24]) == addrAt(b.Packet[8:24]) {
		t.Fatalf("both tailnets reach the host from %s", addrAt(a.Packet[8:24]))
	}

	for _, tailnet := range []uint8{1, 2} {
		src, _ := x.scheme.Encode(tailnet, addr.Local, netip.MustParseAddr("100.64.0.1"))
		dst, _ := x.scheme.Encode(tailnet, addr.Remote, netip.MustParseAddr("100.64.0.2"))
		res := toTailnet(t, x, packet6(src.String(), dst.String(), protoUDP, udpDatagram(53, 5353, "a")))
		if res.Verdict != Forward || res.Tailnet != tailnet {
			t.Errorf("answer on tailnet %d went to %d (%v)", tailnet, res.Tailnet, res.Reason)
		}
	}
}

func TestUDPWithoutChecksumGetsOne(t *testing.T) {
	x := newTestTranslator(t)
	pkt := packet4("100.64.0.2", "100.64.0.1", protoUDP, 0, udpDatagram(1, 2, "no checksum"), false)
	res := toHost(t, x, 1, pkt)
	if res.Verdict != Forward {
		t.Fatalf("%v %v", res.Verdict, res.Reason)
	}
	valid6(t, res.Packet)

	// Without the rest of the datagram, none can be computed.
	frag := packet4("100.64.0.2", "100.64.0.1", protoUDP, 0x2000, udpDatagram(1, 2, "no checksum"), false)
	if res := toHost(t, x, 1, frag); res.Verdict != Drop || res.Reason != NoChecksum {
		t.Errorf("fragment: %v %v", res.Verdict, res.Reason)
	}
}

func TestEcho(t *testing.T) {
	x := newTestTranslator(t)
	req := packet4("100.64.0.2", "100.64.0.1", protoICMP, 0, echo(icmp4EchoRequest, 7, 1, "ping"), true)
	res := toHost(t, x, 1, req)
	if res.Verdict != Forward {
		t.Fatalf("%v %v", res.Verdict, res.Reason)
	}
	if res.Packet[6] != protoICMPv6 || res.Packet[40] != icmp6EchoRequest {
		t.Errorf("next %d type %d", res.Packet[6], res.Packet[40])
	}
	valid6(t, res.Packet)

	reply := packet6("fdcc:79e6:110::6440:1", "fdcc:79e6:100::6440:2", protoICMPv6, echo(icmp6EchoReply, 7, 1, "ping"))
	res = toTailnet(t, x, reply)
	if res.Verdict != Forward {
		t.Fatalf("%v %v", res.Verdict, res.Reason)
	}
	if res.Packet[9] != protoICMP || res.Packet[20] != icmp4EchoReply {
		t.Errorf("proto %d type %d", res.Packet[9], res.Packet[20])
	}
	valid4(t, res.Packet)
}

// An error from the tailnet about a packet the host sent reaches the host
// quoting that packet as the host sent it, so its socket can match it.
func TestICMPv4ErrorQuotesTheHostsPacket(t *testing.T) {
	x := newTestTranslator(t)
	sent := packet4("100.64.0.1", "100.64.0.2", protoUDP, 0, udpDatagram(5000, 53, "query"), true)
	icmp := append([]byte{icmp4DstUnreach, 3, 0, 0, 0, 0, 0, 0}, sent...)
	pkt := packet4("100.64.0.2", "100.64.0.1", protoICMP, 0, icmp, true)

	res := toHost(t, x, 1, pkt)
	if res.Verdict != Forward {
		t.Fatalf("%v %v", res.Verdict, res.Reason)
	}
	v6 := res.Packet
	valid6(t, v6)
	if v6[40] != icmp6DstUnreach || v6[41] != 4 {
		t.Errorf("type %d code %d, want port unreachable", v6[40], v6[41])
	}
	inner := v6[48:]
	if src, dst := addrAt(inner[8:24]), addrAt(inner[24:40]); src != "fdcc:79e6:110::6440:1" || dst != "fdcc:79e6:100::6440:2" {
		t.Errorf("quoted %s -> %s", src, dst)
	}
	valid6(t, inner)
}

func TestFragmentationNeededBecomesPacketTooBig(t *testing.T) {
	x := newTestTranslator(t)
	sent := packet4("100.64.0.1", "100.64.0.2", protoTCP, 0x4000, tcpSegment(1, 2, "big"), true)
	for _, tc := range []struct{ mtu4, want int }{{1400, 1420}, {1000, 1280}, {0, 1280}} {
		icmp := append([]byte{icmp4DstUnreach, 4, 0, 0, 0, 0}, be16(tc.mtu4)...)
		pkt := packet4("100.64.0.9", "100.64.0.1", protoICMP, 0, append(icmp, sent...), true)
		res := toHost(t, x, 1, pkt)
		if res.Verdict != Forward || res.Packet[40] != icmp6PacketTooBig {
			t.Fatalf("mtu %d: %v %v", tc.mtu4, res.Verdict, res.Reason)
		}
		if got := int(binary.BigEndian.Uint32(res.Packet[44:])); got != tc.want {
			t.Errorf("mtu %d: Packet Too Big says %d, want %d", tc.mtu4, got, tc.want)
		}
		valid6(t, res.Packet)
	}
}

// The host refusing a peer's packet reaches the peer as IPv4, quoting what
// the peer sent with the peer's own addresses.
func TestICMPv6ErrorFromTheHost(t *testing.T) {
	x := newTestTranslator(t)
	// What the peer's packet looked like to the host.
	theirs := packet6("fdcc:79e6:100::6440:2", "fdcc:79e6:110::6440:1", protoUDP, udpDatagram(5000, 9, "knock"))
	icmp := append([]byte{icmp6DstUnreach, 4, 0, 0, 0, 0, 0, 0}, theirs...)
	pkt := packet6("fdcc:79e6:110::6440:1", "fdcc:79e6:100::6440:2", protoICMPv6, icmp)

	res := toTailnet(t, x, pkt)
	if res.Verdict != Forward || res.Tailnet != 1 {
		t.Fatalf("%v %v", res.Verdict, res.Reason)
	}
	v4 := res.Packet
	valid4(t, v4)
	if v4[20] != icmp4DstUnreach || v4[21] != 3 {
		t.Errorf("type %d code %d, want port unreachable", v4[20], v4[21])
	}
	inner := v4[28:]
	if src, dst := addr4At(inner[12:16]), addr4At(inner[16:20]); src != "100.64.0.2" || dst != "100.64.0.1" {
		t.Errorf("quoted %s -> %s", src, dst)
	}
	valid4(t, inner)
}

func TestIPv6OnTheTailnet(t *testing.T) {
	x := newTestTranslator(t)
	peer, self := "fd7a:115c:a1e0:ab12:4843:cd96:6240:2", "fd7a:115c:a1e0:ab12:4843:cd96:6240:1"
	pkt := packet6(peer, self, protoTCP, tcpSegment(40000, 443, "v6"))

	res := toHost(t, x, 1, pkt)
	if res.Verdict != Forward {
		t.Fatalf("%v %v", res.Verdict, res.Reason)
	}
	if src, dst := addrAt(res.Packet[8:24]), addrAt(res.Packet[24:40]); src != "fdcc:79e6:101:ab12:4843:cd96:6240:2" || dst != "fdcc:79e6:111:ab12:4843:cd96:6240:1" {
		t.Errorf("addresses %s -> %s", src, dst)
	}
	valid6(t, res.Packet)

	reply := packet6("fdcc:79e6:111:ab12:4843:cd96:6240:1", "fdcc:79e6:101:ab12:4843:cd96:6240:2", protoTCP, tcpSegment(443, 40000, "v6"))
	res = toTailnet(t, x, reply)
	if res.Verdict != Forward {
		t.Fatalf("%v %v", res.Verdict, res.Reason)
	}
	if src, dst := addrAt(res.Packet[8:24]), addrAt(res.Packet[24:40]); src != self || dst != peer {
		t.Errorf("addresses %s -> %s", src, dst)
	}
	valid6(t, res.Packet)
}

// A peer reaching an address the gateway routes, outside Tailscale's range,
// is in the space configured for it.
func TestConfiguredSpace(t *testing.T) {
	x := newTestTranslator(t)
	pkt := packet6("fd7a:115c:a1e0::2", "2001:db8:feed:6ce8:d2b1:13c8:a553:acfc", protoTCP, tcpSegment(1, 443, ""))
	res := toHost(t, x, 1, pkt)
	if res.Verdict != Forward {
		t.Fatalf("%v %v", res.Verdict, res.Reason)
	}
	if dst := addrAt(res.Packet[24:40]); dst != "fdcc:79e6:112:6ce8:d2b1:13c8:a553:acfc" {
		t.Errorf("destination %s", dst)
	}
	valid6(t, res.Packet)

	// Tailnet 2 has no such space.
	if res := toHost(t, x, 2, pkt); res.Verdict != Drop || res.Reason != Unencodable {
		t.Errorf("tailnet 2: %v %v", res.Verdict, res.Reason)
	}
}

func TestFragments(t *testing.T) {
	x := newTestTranslator(t)
	// A UDP datagram in two fragments: 8 bytes of header and 16 of payload,
	// then 8 more.
	whole := udpDatagram(5000, 6000, "0123456789abcdefTAILTAIL")
	setL4Checksum(protoUDP, whole, pseudo4(ip4("100.64.0.2"), ip4("100.64.0.1"), protoUDP, len(whole)))
	first := packet4("100.64.0.2", "100.64.0.1", protoUDP, 0x2000, whole[:24], false)
	second := packet4("100.64.0.2", "100.64.0.1", protoUDP, 3, whole[24:], false)

	r1, r2 := toHost(t, x, 1, first), toHost(t, x, 1, second)
	if r1.Verdict != Forward || r2.Verdict != Forward {
		t.Fatalf("%v %v / %v %v", r1.Verdict, r1.Reason, r2.Verdict, r2.Reason)
	}
	for i, p := range [][]byte{r1.Packet, r2.Packet} {
		if p[6] != protoFragment || p[40] != protoUDP || binary.BigEndian.Uint32(p[44:]) != 0x1234 {
			t.Errorf("fragment %d: next %d inner %d id %#x", i, p[6], p[40], binary.BigEndian.Uint32(p[44:]))
		}
	}
	if fo := binary.BigEndian.Uint16(r1.Packet[42:]); fo != 1 {
		t.Errorf("first fragment offset word %#x", fo)
	}
	if fo := binary.BigEndian.Uint16(r2.Packet[42:]); fo != 3<<3 {
		t.Errorf("second fragment offset word %#x", fo)
	}

	// Reassembled, the datagram's checksum holds for its IPv6 addresses.
	reassembled := append(append([]byte{}, r1.Packet[48:]...), r2.Packet[48:]...)
	if naiveSum(pseudo6b(r1.Packet[8:24], r1.Packet[24:40], protoUDP, len(reassembled)), reassembled) != 0xffff {
		t.Errorf("reassembled checksum is wrong")
	}

	// And back: the IPv6 fragments become IPv4 ones.
	back := func(frag []byte) []byte {
		out := append([]byte{}, frag...)
		copy(out[8:24], frag[24:40])
		copy(out[24:40], frag[8:24])
		return out
	}
	b1, b2 := toTailnet(t, x, back(r1.Packet)), toTailnet(t, x, back(r2.Packet))
	if b1.Verdict != Forward || b2.Verdict != Forward {
		t.Fatalf("back: %v %v / %v %v", b1.Verdict, b1.Reason, b2.Verdict, b2.Reason)
	}
	if fo := binary.BigEndian.Uint16(b1.Packet[6:]); fo != 0x2000 {
		t.Errorf("first fragment back: %#x", fo)
	}
	if fo := binary.BigEndian.Uint16(b2.Packet[6:]); fo != 3 {
		t.Errorf("second fragment back: %#x", fo)
	}
	if binary.BigEndian.Uint16(b1.Packet[4:]) != 0x1234 {
		t.Errorf("identification lost")
	}
}

func TestDontFragmentFollowsSize(t *testing.T) {
	x := newTestTranslator(t)
	big := packet6("fdcc:79e6:110::6440:1", "fdcc:79e6:100::6440:2", protoUDP, udpDatagram(1, 2, string(make([]byte, 1250))))
	res := toTailnet(t, x, big)
	if res.Verdict != Forward {
		t.Fatalf("%v %v", res.Verdict, res.Reason)
	}
	if frag := binary.BigEndian.Uint16(res.Packet[6:]); frag != 0x4000 {
		t.Errorf("a %d-byte packet has flags %#x, want DF", len(res.Packet), frag)
	}
}

func TestTooBigForTheTailnet(t *testing.T) {
	x := newTestTranslator(t)
	// 1300 bytes of IPv6 is 1280 of IPv4: the most a 1280 tailnet takes.
	fits := packet6("fdcc:79e6:110::6440:1", "fdcc:79e6:100::6440:2", protoUDP, udpDatagram(1, 2, string(make([]byte, 1300-48))))
	if res := toTailnet(t, x, fits); res.Verdict != Forward || len(res.Packet) != 1280 {
		t.Fatalf("1300 bytes: %v %v %d", res.Verdict, res.Reason, len(res.Packet))
	}

	over := packet6("fdcc:79e6:110::6440:1", "fdcc:79e6:100::6440:2", protoUDP, udpDatagram(1, 2, string(make([]byte, 1301-48))))
	res := toTailnet(t, x, over)
	if res.Verdict != Reply || res.Reason != TooBig {
		t.Fatalf("1301 bytes: %v %v", res.Verdict, res.Reason)
	}
	if res.Packet[40] != icmp6PacketTooBig || binary.BigEndian.Uint32(res.Packet[44:]) != 1300 {
		t.Errorf("type %d mtu %d", res.Packet[40], binary.BigEndian.Uint32(res.Packet[44:]))
	}
	if dst := addrAt(res.Packet[24:40]); dst != "fdcc:79e6:110::6440:1" {
		t.Errorf("sent to %s", dst)
	}
	if len(res.Packet) > minIPv6MTU {
		t.Errorf("error is %d bytes", len(res.Packet))
	}
	valid6(t, res.Packet)

	v6 := packet6("fdcc:79e6:111::1", "fdcc:79e6:101::2", protoUDP, udpDatagram(1, 2, string(make([]byte, 1281-48))))
	if res := toTailnet(t, x, v6); res.Verdict != Reply || binary.BigEndian.Uint32(res.Packet[44:]) != 1280 {
		t.Errorf("IPv6 1281 bytes: %v %v", res.Verdict, res.Reason)
	}
}

func TestRefusedFromTheHost(t *testing.T) {
	x := newTestTranslator(t)
	udp := udpDatagram(1, 2, "x")
	for _, tc := range []struct {
		name     string
		src, dst string
		verdict  Verdict
		reason   Reason
		code     uint8
	}{
		{"outside the prefix", "fdcc:79e6:110::6440:1", "2001:db8::1", Drop, OutsidePrefix, 0},
		{"multicast", "fe80::1", "ff02::2", Drop, Multicast, 0},
		{"unknown tailnet", "fdcc:79e6:110::6440:1", "fdcc:79e6:900::6440:2", Reply, NoTailnet, icmp6NoRoute},
		{"a local destination", "fdcc:79e6:110::6440:1", "fdcc:79e6:110::6440:2", Drop, NotRemote, 0},
		{"another tailnet's source", "fdcc:79e6:210::6440:1", "fdcc:79e6:100::6440:2", Reply, BadSource, icmp6PolicyFail},
		{"a remote source", "fdcc:79e6:100::6440:1", "fdcc:79e6:100::6440:2", Reply, BadSource, icmp6PolicyFail},
		{"a source outside the prefix", "fd37::1", "fdcc:79e6:100::6440:2", Reply, BadSource, icmp6PolicyFail},
		{"IPv6 to an IPv4 peer", "fdcc:79e6:111::1", "fdcc:79e6:100::6440:2", Reply, FamilyMismatch, icmp6PolicyFail},
	} {
		res := toTailnet(t, x, packet6(tc.src, tc.dst, protoUDP, udp))
		if res.Verdict != tc.verdict || res.Reason != tc.reason {
			t.Errorf("%s: %v %v, want %v %v", tc.name, res.Verdict, res.Reason, tc.verdict, tc.reason)
			continue
		}
		if res.Verdict == Reply {
			if res.Packet[40] != icmp6DstUnreach || res.Packet[41] != tc.code {
				t.Errorf("%s: type %d code %d", tc.name, res.Packet[40], res.Packet[41])
			}
			if src := addrAt(res.Packet[8:24]); src != "fdcc:79e6::1" {
				t.Errorf("%s: error from %s", tc.name, src)
			}
			valid6(t, res.Packet)
		}
	}

	// No error about an error.
	theirs := packet6("fdcc:79e6:100::6440:2", "fdcc:79e6:110::6440:1", protoUDP, udp)
	icmp := append([]byte{icmp6DstUnreach, 4, 0, 0, 0, 0, 0, 0}, theirs...)
	if res := toTailnet(t, x, packet6("fdcc:79e6:110::6440:1", "fdcc:79e6:900::6440:2", protoICMPv6, icmp)); res.Verdict != Drop {
		t.Errorf("an error about an error: %v %v", res.Verdict, res.Reason)
	}

	if res := toTailnet(t, x, packet4("100.64.0.1", "100.64.0.2", protoUDP, 0, udp, true)); res.Verdict != Drop || res.Reason != NotIPv6 {
		t.Errorf("IPv4 from the host: %v %v", res.Verdict, res.Reason)
	}
}

func TestNeighbourDiscoveryDoesNotCross(t *testing.T) {
	x := newTestTranslator(t)
	ns := []byte{135, 0, 0, 0, 0, 0, 0, 0}
	pkt := packet6("fd7a:115c:a1e0::2", "fd7a:115c:a1e0::1", protoICMPv6, append(ns, ip6("fd7a:115c:a1e0::1")...))
	if res := toHost(t, x, 1, pkt); res.Verdict != Drop || res.Reason != UnsupportedICMP {
		t.Errorf("%v %v", res.Verdict, res.Reason)
	}
}

func TestMalformedDoesNotPanic(t *testing.T) {
	x := newTestTranslator(t)
	seeds := [][]byte{
		packet4("100.64.0.2", "100.64.0.1", protoTCP, 0, tcpSegment(1, 2, "abc"), true),
		packet4("100.64.0.2", "100.64.0.1", protoICMP, 0, append([]byte{3, 3, 0, 0, 0, 0, 0, 0}, packet4("100.64.0.1", "100.64.0.2", protoUDP, 0, udpDatagram(1, 2, "q"), true)...), true),
		packet6("fdcc:79e6:110::6440:1", "fdcc:79e6:100::6440:2", protoUDP, udpDatagram(1, 2, "abc")),
		packet6("fdcc:79e6:110::6440:1", "fdcc:79e6:100::6440:2", protoICMPv6, append([]byte{1, 4, 0, 0, 0, 0, 0, 0}, packet6("fdcc:79e6:100::6440:2", "fdcc:79e6:110::6440:1", protoUDP, udpDatagram(1, 2, "q"))...)),
	}
	for _, seed := range seeds {
		for cut := range len(seed) {
			b := append([]byte{}, seed[:cut]...)
			x.ToHost(1, b, make([]byte, len(b)+Growth))
			x.ToTailnet(b, make([]byte, max(len(b), minIPv6MTU)))
		}
		for i := range seed {
			b := append([]byte{}, seed...)
			b[i] ^= 0xff
			x.ToHost(1, b, make([]byte, len(b)+Growth))
			x.ToTailnet(b, make([]byte, max(len(b), minIPv6MTU)))
		}
	}
}

func FuzzTranslate(f *testing.F) {
	f.Add(packet4("100.64.0.2", "100.64.0.1", protoTCP, 0, tcpSegment(1, 2, "abc"), true))
	f.Add(packet6("fdcc:79e6:110::6440:1", "fdcc:79e6:100::6440:2", protoUDP, udpDatagram(1, 2, "abc")))
	f.Fuzz(func(t *testing.T, b []byte) {
		x := newTestTranslator(t)
		x.ToHost(1, b, make([]byte, len(b)+Growth))
		x.ToTailnet(b, make([]byte, max(len(b), minIPv6MTU)))
	})
}

func BenchmarkTCPToHost(b *testing.B) {
	s, _ := addr.NewScheme(netip.MustParsePrefix("fdcc:79e6::/32"))
	_ = s.AddTailnet(1)
	x := New(s, 1280)
	pkt := packet4("100.64.0.2", "100.64.0.1", protoTCP, 0x4000, tcpSegment(40000, 443, string(make([]byte, 1200))), true)
	out := make([]byte, len(pkt)+Growth)
	b.SetBytes(int64(len(pkt)))
	for b.Loop() {
		if res := x.ToHost(1, pkt, out); res.Verdict != Forward {
			b.Fatal(res.Reason)
		}
	}
}

func BenchmarkTCPToTailnet(b *testing.B) {
	s, _ := addr.NewScheme(netip.MustParsePrefix("fdcc:79e6::/32"))
	_ = s.AddTailnet(1)
	x := New(s, 1280)
	pkt := packet6("fdcc:79e6:110::6440:1", "fdcc:79e6:100::6440:2", protoTCP, tcpSegment(443, 40000, string(make([]byte, 1200))))
	out := make([]byte, len(pkt))
	b.SetBytes(int64(len(pkt)))
	for b.Loop() {
		if res := x.ToTailnet(pkt, out); res.Verdict != Forward {
			b.Fatal(res.Reason)
		}
	}
}
