package xlat

import "encoding/binary"

// A packet from the host can be larger than the tailnet carries, because the
// host's MTU is larger than the tailnet's on purpose. quic-go, which Traefik
// serves HTTP/3 with, sends its first packets with 1280 bytes of UDP
// payload and the don't-fragment bit, and on a 1280-byte interface the
// kernel refuses every one of them: there is no room for the IP and UDP
// headers. So the host's MTU leaves room (hostnet), and the packets that
// would not fit the tailnet are fragmented here, which the peer's stack
// reassembles like any other. TCP never needs it: its MSS is clamped to
// what the tailnet carries in both directions (clampMSS), so only UDP and
// ICMP larger than the tailnet's MTU are fragmented.
//
// For IPv6 this is what the host would have done itself, as the source of
// the packet, had its MTU been the tailnet's. For IPv4 it is what a router
// does with a packet without DF; the DF bit the translation sets on large
// packets says what the tailnet beyond may do, and the fragments are sized
// so that it need do nothing.

// fragment4 splits an IPv4 packet with a 20-byte header into fragments that
// fit the tailnet. A packet that is already a fragment keeps its
// identification and offset, and its last piece keeps its more-fragments
// bit.
func (x *Translator) fragment4(pkt []byte) Result {
	h, ok := parse4(pkt, false)
	if !ok || h.ihl != ipv4HeaderLen {
		return drop(Malformed)
	}
	data := pkt[ipv4HeaderLen:h.total]
	maxData := (x.tailnetMTU - ipv4HeaderLen) &^ 7
	id := h.id
	if !h.fragmented() {
		id = x.nextID()
	}

	frags := make([][]byte, 0, (len(data)+maxData-1)/maxData)
	for off := 0; off < len(data); off += maxData {
		end := min(off+maxData, len(data))
		frag := h.offset + uint16(off/8)
		if end < len(data) || h.more {
			frag |= 0x2000
		}
		f := make([]byte, ipv4HeaderLen+end-off)
		writeIPv4Header(f, h.tos, len(f), id, frag, h.ttl, h.proto, h.src, h.dst)
		copy(f[ipv4HeaderLen:], data[off:end])
		frags = append(frags, f)
	}
	return Result{Verdict: Forward, Fragments: frags}
}

// fragment6 splits an IPv6 packet with no extension headers into fragments
// that fit the tailnet.
func (x *Translator) fragment6(pkt []byte) Result {
	next := pkt[6]
	data := pkt[ipv6HeaderLen:]
	maxData := (x.tailnetMTU - ipv6HeaderLen - fragHeaderLen) &^ 7
	id := x.ipID.Add(1)

	frags := make([][]byte, 0, (len(data)+maxData-1)/maxData)
	for off := 0; off < len(data); off += maxData {
		end := min(off+maxData, len(data))
		f := make([]byte, ipv6HeaderLen+fragHeaderLen+end-off)
		copy(f[:ipv6HeaderLen], pkt[:ipv6HeaderLen])
		binary.BigEndian.PutUint16(f[4:], uint16(fragHeaderLen+end-off))
		f[6] = protoFragment
		fh := f[ipv6HeaderLen:]
		fh[0], fh[1] = next, 0
		fo := uint16(off/8) << 3
		if end < len(data) {
			fo |= 1
		}
		binary.BigEndian.PutUint16(fh[2:], fo)
		binary.BigEndian.PutUint32(fh[4:], id)
		copy(f[ipv6HeaderLen+fragHeaderLen:], data[off:end])
		frags = append(frags, f)
	}
	return Result{Verdict: Forward, Fragments: frags}
}

// clampMSS lowers the maximum segment size a TCP SYN offers to max, so that
// neither end ever sends a segment the tailnet cannot carry. The host's
// interface is larger than the tailnet's, and a peer behind a subnet router
// can offer what its own LAN carries; without the clamp, both would be
// fragmented here, every full segment of every connection.
func clampMSS(tcp []byte, max uint16) {
	if len(tcp) < 20 || tcp[13]&0x02 == 0 {
		return
	}
	end := int(tcp[12]>>4) * 4
	if end > len(tcp) {
		return
	}
	for o := 20; o < end; {
		switch kind := tcp[o]; kind {
		case 0:
			return
		case 1:
			o++
			continue
		}
		if o+1 >= end || tcp[o+1] < 2 || o+int(tcp[o+1]) > end {
			return
		}
		if tcp[o] == 2 && tcp[o+1] == 4 {
			v := o + 2
			if binary.BigEndian.Uint16(tcp[v:]) <= max {
				return
			}
			// The words of the segment the value lies across, which an odd
			// offset makes two.
			lo, hi := v&^1, (v+3)&^1
			before := fold(sum(0, tcp[lo:hi]))
			binary.BigEndian.PutUint16(tcp[v:], max)
			after := fold(sum(0, tcp[lo:hi]))
			binary.BigEndian.PutUint16(tcp[16:], adjust(binary.BigEndian.Uint16(tcp[16:]), before, after))
			return
		}
		o += int(tcp[o+1])
	}
}

// clampMSS6 clamps the MSS of a TCP SYN in an IPv6 packet.
func clampMSS6(pkt []byte, mtu int) {
	e, reason := walk6(pkt)
	if reason == OK && e.proto == protoTCP && e.offset == 0 {
		clampMSS(pkt[e.upper:], uint16(mtu-ipv6HeaderLen-20))
	}
}
