package xlat

import (
	"bytes"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	gv4 "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	gv6 "gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// The fragments the translator makes of a datagram too large for the tailnet
// reassemble in gVisor, the stack a tsnet peer terminates them in, into the
// datagram the host sent, IPv4 and IPv6 alike.
//
// This is the IPv6 half's only end-to-end check. tailscale.com v1.104.7's
// netstack drops the first fragment of IPv6 TCP and UDP before gVisor sees
// it: wgengine/netstack/gro.RXChecksumOffload checks a transport checksum
// from the fragment header on, because packet.Parsed reports a first
// fragment's protocol as its transport's, and only its IPv4 branch knows to
// skip fragments. A tsnet peer, the end-to-end test's clients, never
// receives such a datagram; a kernel-mode node does.
func TestFragmentsReassembleInGVisor(t *testing.T) {
	for _, tc := range []struct {
		name, src, dst string
		self           tcpip.Address
		proto          tcpip.NetworkProtocolNumber
	}{
		{"v4", "fdcc:79e6:110::6440:1", "fdcc:79e6:100::6440:2", tcpip.AddrFrom4([4]byte{100, 64, 0, 2}), gv4.ProtocolNumber},
		{"v6", "fdcc:79e6:111::1", "fdcc:79e6:101::2", tcpip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 15: 2}), gv6.ProtocolNumber},
	} {
		x := newTestTranslator(t)
		payload := bytes.Repeat([]byte{'q'}, 1280)
		res := toTailnet(t, x, packet6(tc.src, tc.dst, protoUDP, udpDatagram(443, 50000, string(payload))))
		if len(res.Fragments) != 2 {
			t.Fatalf("%s: %d fragments", tc.name, len(res.Fragments))
		}

		s := stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{gv4.NewProtocol, gv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
		})
		link := channel.New(16, 1280, "")
		if err := s.CreateNIC(1, link); err != nil {
			t.Fatal(err)
		}
		if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: tc.proto, AddressWithPrefix: tc.self.WithPrefix()}, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
		var wq waiter.Queue
		ep, err := s.NewEndpoint(udp.ProtocolNumber, tc.proto, &wq)
		if err != nil {
			t.Fatal(err)
		}
		if err := ep.Bind(tcpip.FullAddress{Addr: tc.self, Port: 50000}); err != nil {
			t.Fatal(err)
		}
		for _, f := range res.Fragments {
			link.InjectInbound(tc.proto, stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte{}, f...))}))
		}
		var out bytes.Buffer
		var rerr tcpip.Error
		for range 50 {
			if _, rerr = ep.Read(&out, tcpip.ReadOptions{}); rerr == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if rerr != nil || !bytes.Equal(out.Bytes(), payload) {
			st := s.Stats()
			t.Errorf("%s: read %d bytes (%v); IP received %d, malformed fragments %d, UDP checksum errors %d",
				tc.name, out.Len(), rerr, st.IP.PacketsReceived.Value(), st.IP.MalformedFragmentsReceived.Value(), st.UDP.ChecksumErrors.Value())
		}
		ep.Close()
		s.Close()
	}
}
