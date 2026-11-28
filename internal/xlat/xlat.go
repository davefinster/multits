// Package xlat translates packets between the tailnets and the host.
//
// From a tailnet, a packet is IPv4 or IPv6 on that tailnet's addresses. It
// leaves for the host as IPv6 on pseudo addresses (package addr): its source
// becomes the peer's pseudo address, its destination the gateway's. IPv4 is
// translated to IPv6 as stateless IP/ICMP translation does it (RFC 7915);
// IPv6 keeps its header and has its addresses rewritten. Transport checksums
// follow the addresses, ICMP becomes ICMPv6, and the packet an ICMP error
// quotes is translated with it, so that errors still reach the socket they
// are about.
//
// From the host, a packet is IPv6 on pseudo addresses. Its destination says
// which tailnet it is for, which peer on it, and whether that peer is IPv4;
// its source must be one of the gateway's own addresses on that same tailnet,
// in the same family. It leaves for the tailnet translated back.
//
// Nothing here holds state about flows. Each packet is translated on its
// addresses alone, which is what makes a reply find its way back without the
// gateway having seen the request.
package xlat

import (
	"encoding/binary"
	"errors"
	"sync/atomic"

	"github.com/davefinster/multits/internal/addr"
)

const (
	protoHopByHop = 0
	protoICMP     = 1
	protoTCP      = 6
	protoUDP      = 17
	protoRouting  = 43
	protoFragment = 44
	protoICMPv6   = 58
	protoDstOpts  = 60
)

const (
	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
	fragHeaderLen = 8
	icmpHeaderLen = 8

	// minIPv6MTU is the smallest MTU IPv6 allows. An ICMPv6 error is cut
	// to fit in it (RFC 4443, section 2.4).
	minIPv6MTU = 1280
	// maxICMPv4Error bounds an ICMPv4 error (RFC 1812, section 4.3.2.3).
	maxICMPv4Error = 576
	// maxUnfragmented4 is the largest IPv4 packet translated from IPv6 that
	// is sent without DF. IPv6 hosts never send less than 1280 bytes on an
	// error's say-so, so a smaller IPv4 path has to fragment for them
	// (RFC 7915, section 5.1).
	maxUnfragmented4 = minIPv6MTU - 20
)

// Growth is the most a packet grows in translation: IPv4 to IPv6 adds 20
// bytes of header and maybe a fragment header, and an ICMP error does the
// same again for the packet it quotes. An output buffer this much larger than
// its input always suffices, as does one of minIPv6MTU bytes for an ICMPv6
// error the translator replies with.
const Growth = 2 * (ipv6HeaderLen - ipv4HeaderLen + fragHeaderLen)

// Verdict is what to do with a translated packet.
type Verdict uint8

const (
	// Drop the packet.
	Drop Verdict = iota
	// Forward the output on: to the host from ToHost, to Result.Tailnet from
	// ToTailnet.
	Forward
	// Reply to the host with the output, an ICMPv6 error about the packet,
	// which is not sent on. Only ToTailnet replies.
	Reply
)

// Reason says why a packet was dropped or answered with an error.
type Reason uint8

const (
	OK Reason = iota
	// Malformed is a packet whose headers do not parse.
	Malformed
	// NotIPv6 is a packet from the host that is not IPv6.
	NotIPv6
	// Multicast is a packet to a multicast address: from the host, its own
	// neighbour discovery and listener chatter.
	Multicast
	// OutsidePrefix is a packet from the host to an address outside the
	// gateway's prefix.
	OutsidePrefix
	// NoTailnet is a packet from the host to an address in the prefix that
	// is on no configured tailnet.
	NoTailnet
	// NotRemote is a packet from the host to one of the gateway's own
	// addresses, which the host's routes should have kept for itself.
	NotRemote
	// BadSource is a packet from the host whose source is not the gateway's
	// own address on the destination's tailnet.
	BadSource
	// FamilyMismatch is a packet from the host from an IPv4 address to an
	// IPv6 one, or the reverse.
	FamilyMismatch
	// Unencodable is a packet from a tailnet with an IPv6 address in no
	// space of that tailnet.
	Unencodable
	// UnsupportedICMP is an ICMP message with no translation.
	UnsupportedICMP
	// FragmentedICMP is a fragment of an ICMP message, whose checksum cannot
	// be recomputed without the rest of it.
	FragmentedICMP
	// NoChecksum is a fragment of IPv4 UDP without a checksum, which IPv6
	// requires and which cannot be computed from part of a datagram.
	NoChecksum
	// TooBig is a packet from the host too large for the tailnet once
	// translated, answered with a Packet Too Big.
	TooBig
	// SourceRouted is an IPv6 packet with a routing header still to follow.
	SourceRouted
	// NumReasons is the number of reasons, for sizing counters.
	NumReasons
)

var reasonNames = [NumReasons]string{
	OK:              "ok",
	Malformed:       "malformed",
	NotIPv6:         "not-ipv6",
	Multicast:       "multicast",
	OutsidePrefix:   "outside-prefix",
	NoTailnet:       "no-tailnet",
	NotRemote:       "not-remote",
	BadSource:       "bad-source",
	FamilyMismatch:  "family-mismatch",
	Unencodable:     "unencodable",
	UnsupportedICMP: "unsupported-icmp",
	FragmentedICMP:  "fragmented-icmp",
	NoChecksum:      "no-checksum",
	TooBig:          "too-big",
	SourceRouted:    "source-routed",
}

func (r Reason) String() string {
	if r < NumReasons {
		return reasonNames[r]
	}
	return "unknown"
}

// Result is the outcome of translating one packet.
type Result struct {
	Verdict Verdict
	Reason  Reason
	// Tailnet is the tailnet a packet from the host is for.
	Tailnet uint8
	// Packet is the output: the start of the buffer the caller passed.
	Packet []byte
	// Fragments, when set, replace Packet: a packet from the host too large
	// for the tailnet, in fragments that fit, each its own allocation and
	// sent in order.
	Fragments [][]byte
}

func drop(r Reason) Result { return Result{Verdict: Drop, Reason: r} }

// Translator translates packets. It is safe for concurrent use.
type Translator struct {
	scheme     *addr.Scheme
	tailnetMTU int
	gateway    [16]byte
	ipID       atomic.Uint32
}

// New returns a translator for the scheme. tailnetMTU is the largest packet
// a tailnet carries; a packet from the host that would be larger is answered
// with a Packet Too Big rather than sent.
func New(scheme *addr.Scheme, tailnetMTU int) *Translator {
	x := &Translator{scheme: scheme, tailnetMTU: tailnetMTU}
	x.gateway = scheme.Gateway().As16()
	return x
}

// ToHost translates a packet that arrived from a tailnet. out must be at
// least Growth bytes longer than pkt.
func (x *Translator) ToHost(tailnet uint8, pkt, out []byte) Result {
	if len(pkt) == 0 {
		return drop(Malformed)
	}
	switch pkt[0] >> 4 {
	case 4:
		return x.fromTailnet4(tailnet, pkt, out)
	case 6:
		return x.fromTailnet6(tailnet, pkt, out)
	default:
		return drop(Malformed)
	}
}

// Tailnet reports which configured tailnet a packet from the host is
// addressed to, from its destination's prefix and tailnet number alone. It is
// for deciding where a packet is translated, before translating it: false is
// a packet for no tailnet, and ToTailnet says what to do about it. True is
// not yet a packet ToTailnet forwards.
func (x *Translator) Tailnet(pkt []byte) (uint8, bool) {
	if len(pkt) < ipv6HeaderLen || pkt[0]>>4 != 6 {
		return 0, false
	}
	return x.scheme.TailnetOf(pkt[24:40])
}

// ToTailnet translates a packet the host sent towards a tailnet. out must be
// at least as long as pkt, and at least minIPv6MTU bytes for a Reply.
func (x *Translator) ToTailnet(pkt, out []byte) Result {
	if len(pkt) < ipv6HeaderLen || pkt[0]>>4 != 6 {
		return drop(NotIPv6)
	}
	pkt, ok := trim6(pkt)
	if !ok {
		return drop(Malformed)
	}
	if pkt[24] == 0xff {
		return drop(Multicast)
	}

	var dstIP, srcIP [16]byte
	dm, dn, err := x.scheme.DecodeTo(dstIP[:], pkt[24:40])
	switch {
	case errors.Is(err, addr.ErrOutsidePrefix):
		return drop(OutsidePrefix)
	case err != nil:
		return x.unreachable(pkt, out, icmp6NoRoute, NoTailnet)
	case dm.Side != addr.Remote:
		return drop(NotRemote)
	}

	sm, sn, err := x.scheme.DecodeTo(srcIP[:], pkt[8:24])
	if err != nil || sm.Side != addr.Local || sm.Tailnet != dm.Tailnet {
		return x.unreachable(pkt, out, icmp6PolicyFail, BadSource)
	}
	if (sn == 4) != (dn == 4) {
		return x.unreachable(pkt, out, icmp6PolicyFail, FamilyMismatch)
	}

	var res Result
	if dn == 4 {
		res = x.toTailnet4(pkt, srcIP[:4], dstIP[:4], out)
	} else {
		res = x.toTailnet6(dm.Tailnet, pkt, srcIP[:], dstIP[:], out)
	}
	if res.Verdict == Forward {
		res.Tailnet = dm.Tailnet
	}
	return res
}

// ipv4 is a parsed IPv4 header.
type ipv4 struct {
	ihl    int
	total  int
	tos    uint8
	id     uint16
	more   bool
	offset uint16 // in 8-byte units
	ttl    uint8
	proto  uint8
	src    []byte
	dst    []byte
}

func (h *ipv4) fragmented() bool { return h.more || h.offset != 0 }

// parse4 parses an IPv4 header. A quoted packet, one inside an ICMP error,
// may be cut short of the length its header states.
func parse4(pkt []byte, quoted bool) (ipv4, bool) {
	if len(pkt) < ipv4HeaderLen || pkt[0]>>4 != 4 {
		return ipv4{}, false
	}
	h := ipv4{
		ihl:   int(pkt[0]&0x0f) * 4,
		total: int(binary.BigEndian.Uint16(pkt[2:])),
		tos:   pkt[1],
		id:    binary.BigEndian.Uint16(pkt[4:]),
		ttl:   pkt[8],
		proto: pkt[9],
		src:   pkt[12:16],
		dst:   pkt[16:20],
	}
	frag := binary.BigEndian.Uint16(pkt[6:])
	h.more = frag&0x2000 != 0
	h.offset = frag & 0x1fff
	if h.ihl < ipv4HeaderLen || h.ihl > len(pkt) || h.total < h.ihl {
		return ipv4{}, false
	}
	if h.total > len(pkt) && !quoted {
		return ipv4{}, false
	}
	return h, true
}

// trim6 cuts an IPv6 packet to the length its header states.
func trim6(pkt []byte) ([]byte, bool) {
	n := ipv6HeaderLen + int(binary.BigEndian.Uint16(pkt[4:]))
	if n > len(pkt) {
		return nil, false
	}
	return pkt[:n], true
}

func isMulticast4(ip []byte) bool {
	return ip[0]&0xf0 == 0xe0 || (ip[0] == 0xff && ip[1] == 0xff && ip[2] == 0xff && ip[3] == 0xff)
}

func trafficClass(pkt []byte) uint8 { return pkt[0]<<4 | pkt[1]>>4 }

func writeIPv6Header(b []byte, tc uint8, payloadLen int, next, hop uint8, src, dst []byte) {
	b[0] = 0x60 | tc>>4
	b[1] = tc << 4
	b[2], b[3] = 0, 0
	binary.BigEndian.PutUint16(b[4:], uint16(payloadLen))
	b[6] = next
	b[7] = hop
	copy(b[8:24], src[:16])
	copy(b[24:40], dst[:16])
}

// writeIPv4Header writes a 20-byte IPv4 header, checksum included.
func writeIPv4Header(b []byte, tos uint8, total int, id, frag uint16, ttl, proto uint8, src, dst []byte) {
	b[0] = 0x45
	b[1] = tos
	binary.BigEndian.PutUint16(b[2:], uint16(total))
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], frag)
	b[8] = ttl
	b[9] = proto
	b[10], b[11] = 0, 0
	copy(b[12:16], src[:4])
	copy(b[16:20], dst[:4])
	binary.BigEndian.PutUint16(b[10:], checksum(b[:ipv4HeaderLen], 0))
}

// nextID is an identification for an IPv4 packet translated from one that
// had none, so that a router that fragments it can be reassembled after.
func (x *Translator) nextID() uint16 { return uint16(x.ipID.Add(1)) }

// ext6 is where an IPv6 packet's extension headers end.
type ext6 struct {
	proto  uint8  // the upper-layer protocol
	upper  int    // its offset
	frag   bool   // a fragment header was present
	offset uint16 // the fragment offset, in 8-byte units
	more   bool
	id     uint32
}

// walk6 walks an IPv6 packet's extension headers to its upper layer.
func walk6(pkt []byte) (ext6, Reason) {
	var e ext6
	next := pkt[6]
	off := ipv6HeaderLen
	for range 8 {
		switch next {
		case protoHopByHop, protoDstOpts, protoRouting:
			if off+8 > len(pkt) {
				return e, Malformed
			}
			// A packet still on its way through a source route is not ours
			// to deliver.
			if next == protoRouting && pkt[off+3] != 0 {
				return e, SourceRouted
			}
			next, off = pkt[off], off+(int(pkt[off+1])+1)*8
		case protoFragment:
			if off+fragHeaderLen > len(pkt) {
				return e, Malformed
			}
			fo := binary.BigEndian.Uint16(pkt[off+2:])
			e.frag, e.offset, e.more = true, fo>>3, fo&1 != 0
			e.id = binary.BigEndian.Uint32(pkt[off+4:])
			next, off = pkt[off], off+fragHeaderLen
		default:
			if off > len(pkt) {
				return e, Malformed
			}
			e.proto, e.upper = next, off
			return e, OK
		}
	}
	return e, Malformed
}

// adjustTransport updates the transport checksum in l4 for a pseudo-header
// whose addresses summed to from and now sum to to. It reports false when the
// header is too short to hold its checksum, which a quoted packet may be and
// is excused.
func adjustTransport(proto uint8, l4 []byte, from, to uint16, quoted bool) bool {
	switch proto {
	case protoTCP:
		if len(l4) < 18 {
			return quoted
		}
		binary.BigEndian.PutUint16(l4[16:], adjust(binary.BigEndian.Uint16(l4[16:]), from, to))
	case protoUDP:
		if len(l4) < 8 {
			return quoted
		}
		// Zero is IPv4's "no checksum", which has nothing to adjust.
		if c := binary.BigEndian.Uint16(l4[6:]); c != 0 {
			c = adjust(c, from, to)
			if c == 0 {
				c = 0xffff
			}
			binary.BigEndian.PutUint16(l4[6:], c)
		}
	}
	return true
}

// fromTailnet4 translates IPv4 from a tailnet to IPv6 for the host.
func (x *Translator) fromTailnet4(tailnet uint8, pkt, out []byte) Result {
	h, ok := parse4(pkt, false)
	if !ok {
		return drop(Malformed)
	}
	if isMulticast4(h.dst) {
		return drop(Multicast)
	}
	payload := pkt[h.ihl:h.total]

	var src6, dst6 [16]byte
	x.scheme.Encode4(src6[:], tailnet, addr.Remote, h.src)
	x.scheme.Encode4(dst6[:], tailnet, addr.Local, h.dst)

	if h.proto == protoICMP {
		if h.fragmented() {
			return drop(FragmentedICMP)
		}
		return x.icmp4to6(tailnet, &h, src6[:], dst6[:], payload, out)
	}

	n, reason := write4to6(&h, src6[:], dst6[:], payload, len(payload), out, false)
	if reason != OK {
		return drop(reason)
	}
	if h.proto == protoTCP && h.offset == 0 {
		// What the peer offers is what the host will send it, and the host's
		// MTU is larger than the tailnet's.
		hdr := ipv6HeaderLen
		if h.fragmented() {
			hdr += fragHeaderLen
		}
		clampMSS(out[hdr:n], uint16(x.tailnetMTU-ipv4HeaderLen-20))
	}
	return Result{Verdict: Forward, Packet: out[:n]}
}

// write4to6 writes into out the IPv6 translation of the IPv4 packet h with
// the given payload, on new addresses, and returns its length. statedLen is
// the payload length h's header states, which for a quoted packet can be
// more than it carries. A quoted packet is left with what checksum it can be
// given; nothing checks one.
func write4to6(h *ipv4, src6, dst6, payload []byte, statedLen int, out []byte, quoted bool) (int, Reason) {
	next := h.proto
	if next == protoICMP {
		next = protoICMPv6
	}
	hdr := ipv6HeaderLen
	if h.fragmented() {
		hdr += fragHeaderLen
	}
	n := hdr + len(payload)
	if len(out) < n {
		return 0, TooBig
	}

	plen := statedLen + hdr - ipv6HeaderLen
	if h.fragmented() {
		writeIPv6Header(out, h.tos, plen, protoFragment, h.ttl, src6, dst6)
		frag := out[ipv6HeaderLen:hdr]
		frag[0], frag[1] = next, 0
		fo := h.offset << 3
		if h.more {
			fo |= 1
		}
		binary.BigEndian.PutUint16(frag[2:], fo)
		binary.BigEndian.PutUint32(frag[4:], uint32(h.id))
	} else {
		writeIPv6Header(out, h.tos, plen, next, h.ttl, src6, dst6)
	}

	l4 := out[hdr:n]
	copy(l4, payload)
	if h.offset != 0 {
		// A later fragment carries no transport header.
		return n, OK
	}

	switch h.proto {
	case protoICMP:
		// Only a quoted packet gets here: ICMP proper is translated on its
		// own. Its type is all that matters to whoever matches it.
		if len(l4) > 0 {
			switch l4[0] {
			case icmp4EchoRequest:
				l4[0] = icmp6EchoRequest
			case icmp4EchoReply:
				l4[0] = icmp6EchoReply
			}
		}
	case protoUDP:
		if len(l4) >= 8 && binary.BigEndian.Uint16(l4[6:]) == 0 && !quoted {
			// IPv6 requires the checksum IPv4 let the sender leave out, and
			// it can only be computed over the whole datagram.
			if h.fragmented() {
				return 0, NoChecksum
			}
			c := checksum(l4, pseudo6(src6, dst6, len(l4), protoUDP))
			if c == 0 {
				c = 0xffff
			}
			binary.BigEndian.PutUint16(l4[6:], c)
			return n, OK
		}
		fallthrough
	default:
		if !adjustTransport(h.proto, l4, addrSum(h.src, h.dst), addrSum(src6, dst6), quoted) {
			return 0, Malformed
		}
	}
	return n, OK
}

// fromTailnet6 moves IPv6 from a tailnet onto pseudo addresses for the host.
func (x *Translator) fromTailnet6(tailnet uint8, pkt, out []byte) Result {
	if len(pkt) < ipv6HeaderLen {
		return drop(Malformed)
	}
	pkt, ok := trim6(pkt)
	if !ok {
		return drop(Malformed)
	}
	if pkt[24] == 0xff {
		return drop(Multicast)
	}
	if len(out) < len(pkt) {
		return drop(TooBig)
	}

	b := out[:len(pkt)]
	copy(b, pkt)
	if !x.scheme.Encode6(b[8:24], tailnet, addr.Remote, pkt[8:24]) ||
		!x.scheme.Encode6(b[24:40], tailnet, addr.Local, pkt[24:40]) {
		return drop(Unencodable)
	}

	// The packet an error quotes is one the host sent: from the gateway's
	// side of the tailnet to a peer.
	quote := func(inner []byte) bool {
		return x.scheme.Encode6(inner[8:24], tailnet, addr.Local, inner[8:24]) &&
			x.scheme.Encode6(inner[24:40], tailnet, addr.Remote, inner[24:40])
	}
	if reason := fixup6(b, pkt[8:24], pkt[24:40], quote); reason != OK {
		return drop(reason)
	}
	clampMSS6(b, x.tailnetMTU)
	return Result{Verdict: Forward, Packet: b}
}

// toTailnet6 moves IPv6 from the host back onto a tailnet's addresses.
func (x *Translator) toTailnet6(tailnet uint8, pkt, src, dst, out []byte) Result {
	// Too large for the tailnet, the packet is fragmented, as the host would
	// have done itself had its MTU been the tailnet's: see fragment6. Only
	// one with extension headers, which would need splitting into the part
	// every fragment repeats and the part they share, is refused instead.
	if len(pkt) > x.tailnetMTU && pkt[6] != protoTCP && pkt[6] != protoUDP && pkt[6] != protoICMPv6 {
		return x.tooBig(pkt, out, x.tailnetMTU)
	}

	b := out[:len(pkt)]
	copy(b, pkt)
	copy(b[8:24], src)
	copy(b[24:40], dst)

	// The packet an error quotes is one a peer sent: from a peer's pseudo
	// address to one of the gateway's, both on this tailnet.
	quote := func(inner []byte) bool {
		var s, d [16]byte
		sm, sn, err := x.scheme.DecodeTo(s[:], inner[8:24])
		if err != nil || sn != 16 || sm.Side != addr.Remote || sm.Tailnet != tailnet {
			return false
		}
		dm, dn, err := x.scheme.DecodeTo(d[:], inner[24:40])
		if err != nil || dn != 16 || dm.Side != addr.Local || dm.Tailnet != tailnet {
			return false
		}
		copy(inner[8:24], s[:])
		copy(inner[24:40], d[:])
		return true
	}
	if reason := fixup6(b, pkt[8:24], pkt[24:40], quote); reason != OK {
		return drop(reason)
	}
	clampMSS6(b, x.tailnetMTU)
	if len(b) > x.tailnetMTU {
		return x.fragment6(b)
	}
	return Result{Verdict: Forward, Packet: b}
}

// fixup6 repairs an IPv6 packet whose addresses were rewritten from oldSrc
// and oldDst: its transport checksum, and for an ICMPv6 error, the addresses
// of the packet it quotes, which quote rewrites.
func fixup6(b, oldSrc, oldDst []byte, quote func(inner []byte) bool) Reason {
	e, reason := walk6(b)
	if reason != OK {
		return reason
	}
	if e.offset != 0 {
		return OK
	}
	l4 := b[e.upper:]
	from, to := addrSum(oldSrc, oldDst), addrSum(b[8:24], b[24:40])

	switch e.proto {
	case protoTCP, protoUDP:
		if !adjustTransport(e.proto, l4, from, to, false) {
			return Malformed
		}
	case protoICMPv6:
		if e.frag {
			return FragmentedICMP
		}
		if len(l4) < icmpHeaderLen {
			return Malformed
		}
		switch l4[0] {
		case icmp6EchoRequest, icmp6EchoReply:
			binary.BigEndian.PutUint16(l4[2:], adjust(binary.BigEndian.Uint16(l4[2:]), from, to))
		case icmp6DstUnreach, icmp6PacketTooBig, icmp6TimeExceeded, icmp6ParamProblem:
			inner := l4[icmpHeaderLen:]
			if len(inner) < ipv6HeaderLen || inner[0]>>4 != 6 {
				return Malformed
			}
			innerSrc, innerDst := [16]byte(inner[8:24]), [16]byte(inner[24:40])
			if !quote(inner) {
				return Unencodable
			}
			if ie, r := walk6(inner); r == OK && ie.offset == 0 {
				adjustTransport(ie.proto, inner[ie.upper:], addrSum(innerSrc[:], innerDst[:]), addrSum(inner[8:24], inner[24:40]), true)
			}
			// The quote is covered by the ICMPv6 checksum too, so it is
			// computed again rather than adjusted twice.
			binary.BigEndian.PutUint16(l4[2:], 0)
			binary.BigEndian.PutUint16(l4[2:], checksum(l4, pseudo6(b[8:24], b[24:40], len(l4), protoICMPv6)))
		default:
			// Neighbour discovery, listener reports and the like are
			// link-local business that has no meaning across the gateway.
			return UnsupportedICMP
		}
	}
	return OK
}

// toTailnet4 translates IPv6 from the host to IPv4 for a tailnet.
func (x *Translator) toTailnet4(pkt, src4, dst4, out []byte) Result {
	e, reason := walk6(pkt)
	if reason != OK {
		return drop(reason)
	}
	upper := pkt[e.upper:]
	total := ipv4HeaderLen + len(upper)

	if e.proto == protoICMPv6 {
		if e.frag {
			return drop(FragmentedICMP)
		}
		return x.fit4(x.icmp6to4(pkt, src4, dst4, upper, out))
	}

	id, frag := x.fragFields(&e, total)
	writeIPv4Header(out, trafficClass(pkt), total, id, frag, pkt[7], e.proto, src4, dst4)
	l4 := out[ipv4HeaderLen:total]
	copy(l4, upper)
	if e.offset == 0 && !adjustTransport(e.proto, l4, addrSum(pkt[8:24], pkt[24:40]), addrSum(src4, dst4), false) {
		return drop(Malformed)
	}
	if e.offset == 0 && e.proto == protoTCP {
		clampMSS(l4, uint16(x.tailnetMTU-ipv4HeaderLen-20))
	}
	return x.fit4(Result{Verdict: Forward, Packet: out[:total]})
}

// fit4 fragments an IPv4 packet for the tailnet that is too large for it.
func (x *Translator) fit4(res Result) Result {
	if res.Verdict != Forward || len(res.Packet) <= x.tailnetMTU {
		return res
	}
	return x.fragment4(res.Packet)
}

// fragFields is the identification and the flags and offset of an IPv4
// packet translated from IPv6.
func (x *Translator) fragFields(e *ext6, total int) (id, frag uint16) {
	if e.frag {
		frag = e.offset
		if e.more {
			frag |= 0x2000
		}
		return uint16(e.id), frag
	}
	if total > maxUnfragmented4 {
		return 0, 0x4000 // DF
	}
	return x.nextID(), 0
}
