package xlat

import (
	"encoding/binary"

	"github.com/davefinster/multits/internal/addr"
)

const (
	icmp4EchoReply      = 0
	icmp4DstUnreach     = 3
	icmp4EchoRequest    = 8
	icmp4TimeExceeded   = 11
	icmp6DstUnreach     = 1
	icmp6PacketTooBig   = 2
	icmp6TimeExceeded   = 3
	icmp6ParamProblem   = 4
	icmp6EchoRequest    = 128
	icmp6EchoReply      = 129
	icmp6NoRoute        = 0
	icmp6PolicyFail     = 5
	icmp6UnrecognizedNH = 1
)

// mapError4to6 is the ICMPv6 type, code and second word of an ICMPv4 error
// (RFC 7915, section 4.2).
func mapError4to6(msg []byte) (typ, code uint8, word uint32, ok bool) {
	switch msg[0] {
	case icmp4DstUnreach:
		switch msg[1] {
		case 0, 1, 5, 6, 7, 8, 11, 12:
			return icmp6DstUnreach, 0, 0, true
		case 2: // protocol unreachable: a parameter problem, at the next header
			return icmp6ParamProblem, icmp6UnrecognizedNH, 6, true
		case 3:
			return icmp6DstUnreach, 4, 0, true
		case 4: // fragmentation needed
			// IPv6 carries 20 bytes more of header, and an IPv6 host never
			// goes below 1280 however small the IPv4 path is: below that,
			// its packets go out without DF and IPv4 fragments them.
			mtu := uint32(binary.BigEndian.Uint16(msg[6:])) + ipv6HeaderLen - ipv4HeaderLen
			return icmp6PacketTooBig, 0, max(mtu, minIPv6MTU), true
		case 9, 10, 13, 15:
			return icmp6DstUnreach, 1, 0, true
		}
	case icmp4TimeExceeded:
		if msg[1] <= 1 {
			return icmp6TimeExceeded, msg[1], 0, true
		}
	}
	return 0, 0, 0, false
}

// mapError6to4 is the ICMPv4 type, code and second word of an ICMPv6 error
// (RFC 7915, section 5.2).
func mapError6to4(msg []byte) (typ, code uint8, word uint32, ok bool) {
	switch msg[0] {
	case icmp6DstUnreach:
		switch msg[1] {
		case 0, 2, 3:
			return icmp4DstUnreach, 1, 0, true
		case 1, 5, 6:
			return icmp4DstUnreach, 10, 0, true
		case 4:
			return icmp4DstUnreach, 3, 0, true
		}
	case icmp6PacketTooBig:
		mtu := int64(binary.BigEndian.Uint32(msg[4:])) - (ipv6HeaderLen - ipv4HeaderLen)
		return icmp4DstUnreach, 4, uint32(min(max(mtu, 68), 0xffff)), true
	case icmp6TimeExceeded:
		if msg[1] <= 1 {
			return icmp4TimeExceeded, msg[1], 0, true
		}
	case icmp6ParamProblem:
		if msg[1] == icmp6UnrecognizedNH {
			return icmp4DstUnreach, 2, 0, true
		}
	}
	return 0, 0, 0, false
}

// icmp4to6 translates an ICMPv4 message from a tailnet to ICMPv6.
func (x *Translator) icmp4to6(tailnet uint8, h *ipv4, src6, dst6, msg, out []byte) Result {
	if len(msg) < icmpHeaderLen {
		return drop(Malformed)
	}
	body := out[ipv6HeaderLen:]
	var n int

	switch msg[0] {
	case icmp4EchoRequest, icmp4EchoReply:
		if len(body) < len(msg) {
			return drop(TooBig)
		}
		n = copy(body, msg)
		body[0], body[1] = icmp6EchoRequest, 0
		if msg[0] == icmp4EchoReply {
			body[0] = icmp6EchoReply
		}

	default:
		typ, code, word, ok := mapError4to6(msg)
		if !ok {
			return drop(UnsupportedICMP)
		}
		inner, ok := parse4(msg[icmpHeaderLen:], true)
		if !ok {
			return drop(Malformed)
		}
		quoted := msg[icmpHeaderLen:]
		payload := quoted[inner.ihl:min(inner.total, len(quoted))]

		// The quoted packet is one the host sent: from the gateway's side of
		// the tailnet to a peer.
		var isrc, idst [16]byte
		x.scheme.Encode4(isrc[:], tailnet, addr.Local, inner.src)
		x.scheme.Encode4(idst[:], tailnet, addr.Remote, inner.dst)

		m, reason := write4to6(&inner, isrc[:], idst[:], payload, inner.total-inner.ihl, body[icmpHeaderLen:], true)
		if reason != OK {
			return drop(reason)
		}
		n = icmpHeaderLen + min(m, minIPv6MTU-ipv6HeaderLen-icmpHeaderLen)
		body[0], body[1] = typ, code
		binary.BigEndian.PutUint32(body[4:], word)
	}

	writeIPv6Header(out, h.tos, n, protoICMPv6, h.ttl, src6, dst6)
	binary.BigEndian.PutUint16(body[2:], 0)
	binary.BigEndian.PutUint16(body[2:], checksum(body[:n], pseudo6(src6, dst6, n, protoICMPv6)))
	return Result{Verdict: Forward, Packet: out[:ipv6HeaderLen+n]}
}

// icmp6to4 translates an ICMPv6 message from the host to ICMPv4.
func (x *Translator) icmp6to4(pkt, src4, dst4, msg, out []byte) Result {
	if len(msg) < icmpHeaderLen {
		return drop(Malformed)
	}
	body := out[ipv4HeaderLen:]
	var n int

	switch msg[0] {
	case icmp6EchoRequest, icmp6EchoReply:
		n = copy(body, msg)
		body[0], body[1] = icmp4EchoRequest, 0
		if msg[0] == icmp6EchoReply {
			body[0] = icmp4EchoReply
		}

	case icmp6DstUnreach, icmp6PacketTooBig, icmp6TimeExceeded, icmp6ParamProblem:
		typ, code, word, ok := mapError6to4(msg)
		if !ok {
			return drop(UnsupportedICMP)
		}
		m, reason := x.quote6to4(msg[icmpHeaderLen:], body[icmpHeaderLen:])
		if reason != OK {
			return drop(reason)
		}
		n = icmpHeaderLen + min(m, maxICMPv4Error-ipv4HeaderLen-icmpHeaderLen)
		body[0], body[1] = typ, code
		binary.BigEndian.PutUint32(body[4:], word)

	default:
		return drop(UnsupportedICMP)
	}

	binary.BigEndian.PutUint16(body[2:], 0)
	binary.BigEndian.PutUint16(body[2:], checksum(body[:n], 0))

	total := ipv4HeaderLen + n
	writeIPv4Header(out, trafficClass(pkt), total, x.nextID(), 0, pkt[7], protoICMP, src4, dst4)
	return Result{Verdict: Forward, Packet: out[:total]}
}

// quote6to4 translates the IPv6 packet an ICMPv6 error from the host quotes,
// which is one a peer sent: from a peer's pseudo address to the gateway's.
func (x *Translator) quote6to4(quoted, out []byte) (int, Reason) {
	if len(quoted) < ipv6HeaderLen || quoted[0]>>4 != 6 {
		return 0, Malformed
	}
	var s, d [16]byte
	sm, sn, err := x.scheme.DecodeTo(s[:], quoted[8:24])
	if err != nil || sn != 4 || sm.Side != addr.Remote {
		return 0, Unencodable
	}
	dm, dn, err := x.scheme.DecodeTo(d[:], quoted[24:40])
	if err != nil || dn != 4 || dm.Side != addr.Local || dm.Tailnet != sm.Tailnet {
		return 0, Unencodable
	}

	e, reason := walk6(quoted)
	if reason != OK {
		return 0, reason
	}
	upper := quoted[e.upper:]
	stated := ipv6HeaderLen + int(binary.BigEndian.Uint16(quoted[4:])) - e.upper
	if len(out) < ipv4HeaderLen+len(upper) {
		return 0, TooBig
	}

	proto := e.proto
	if proto == protoICMPv6 {
		proto = protoICMP
	}
	var id, frag uint16
	if e.frag {
		id, frag = uint16(e.id), e.offset
		if e.more {
			frag |= 0x2000
		}
	}
	writeIPv4Header(out, trafficClass(quoted), ipv4HeaderLen+stated, id, frag, quoted[7], proto, s[:4], d[:4])

	l4 := out[ipv4HeaderLen : ipv4HeaderLen+len(upper)]
	copy(l4, upper)
	if e.offset == 0 {
		if e.proto == protoICMPv6 && len(l4) > 0 {
			switch l4[0] {
			case icmp6EchoRequest:
				l4[0] = icmp4EchoRequest
			case icmp6EchoReply:
				l4[0] = icmp4EchoReply
			}
		} else {
			adjustTransport(e.proto, l4, addrSum(quoted[8:24], quoted[24:40]), addrSum(s[:4], d[:4]), true)
		}
	}
	return ipv4HeaderLen + len(upper), OK
}

// unreachable answers a packet from the host with a Destination Unreachable.
func (x *Translator) unreachable(pkt, out []byte, code uint8, reason Reason) Result {
	return x.icmp6Error(pkt, out, icmp6DstUnreach, code, 0, reason)
}

// tooBig answers a packet from the host with a Packet Too Big.
func (x *Translator) tooBig(pkt, out []byte, mtu int) Result {
	return x.icmp6Error(pkt, out, icmp6PacketTooBig, 0, uint32(mtu), TooBig)
}

// icmp6Error builds an ICMPv6 error about pkt, from the gateway's own
// address, for the host. It is never sent about an ICMPv6 error, nor to an
// address that cannot be answered (RFC 4443, section 2.4).
func (x *Translator) icmp6Error(pkt, out []byte, typ, code uint8, word uint32, reason Reason) Result {
	if isICMP6Error(pkt) || isUnspecified(pkt[8:24]) {
		return drop(reason)
	}
	if len(out) < minIPv6MTU {
		return drop(reason)
	}

	quote := min(len(pkt), minIPv6MTU-ipv6HeaderLen-icmpHeaderLen)
	n := icmpHeaderLen + quote
	writeIPv6Header(out, 0, n, protoICMPv6, 64, x.gateway[:], pkt[8:24])
	body := out[ipv6HeaderLen : ipv6HeaderLen+n]
	body[0], body[1] = typ, code
	binary.BigEndian.PutUint16(body[2:], 0)
	binary.BigEndian.PutUint32(body[4:], word)
	copy(body[icmpHeaderLen:], pkt[:quote])
	binary.BigEndian.PutUint16(body[2:], checksum(body, pseudo6(x.gateway[:], pkt[8:24], n, protoICMPv6)))
	return Result{Verdict: Reply, Reason: reason, Packet: out[:ipv6HeaderLen+n]}
}

// isICMP6Error reports whether pkt is an ICMPv6 error, or cannot be told
// apart from one.
func isICMP6Error(pkt []byte) bool {
	e, reason := walk6(pkt)
	if reason != OK {
		return true
	}
	if e.proto != protoICMPv6 {
		return false
	}
	if e.offset != 0 || e.upper >= len(pkt) {
		return true
	}
	return pkt[e.upper] < 128
}

func isUnspecified(ip []byte) bool {
	for _, b := range ip[:16] {
		if b != 0 {
			return false
		}
	}
	return true
}
