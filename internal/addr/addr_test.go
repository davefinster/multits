package addr

import (
	"errors"
	"net/netip"
	"testing"
)

func testScheme(t *testing.T) *Scheme {
	t.Helper()
	s, err := NewScheme(netip.MustParsePrefix("fdcc:79e6::/32"))
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
	if err := s.SetSpace(1, 3, netip.MustParsePrefix("2001:db8:1:2::/64")); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEncodeIsReadable(t *testing.T) {
	s := testScheme(t)
	for _, tc := range []struct {
		tailnet uint8
		side    Side
		ip      string
		want    string
	}{
		{1, Remote, "100.64.0.5", "fdcc:79e6:100::6440:5"},
		{1, Local, "100.64.0.1", "fdcc:79e6:110::6440:1"},
		{2, Remote, "100.64.0.5", "fdcc:79e6:200::6440:5"},
		{1, Remote, "fd7a:115c:a1e0:ab12:4843:cd96:6240:5", "fdcc:79e6:101:ab12:4843:cd96:6240:5"},
		{1, Local, "fd7a:115c:a1e0::1", "fdcc:79e6:111::1"},
		{1, Local, "2001:db8:feed:6ce8:d2b1:13c8:a553:acfc", "fdcc:79e6:112:6ce8:d2b1:13c8:a553:acfc"},
		{1, Remote, "2001:db8:1:2::42", "fdcc:79e6:103:2::42"},
		{1, Remote, "::ffff:10.1.2.3", "fdcc:79e6:100::a01:203"},
	} {
		got, err := s.Encode(tc.tailnet, tc.side, netip.MustParseAddr(tc.ip))
		if err != nil {
			t.Errorf("Encode(%d, %s, %s): %v", tc.tailnet, tc.side, tc.ip, err)
			continue
		}
		if got.String() != tc.want {
			t.Errorf("Encode(%d, %s, %s) = %s, want %s", tc.tailnet, tc.side, tc.ip, got, tc.want)
		}

		back, err := s.Decode(got)
		if err != nil {
			t.Errorf("Decode(%s): %v", got, err)
			continue
		}
		if want := netip.MustParseAddr(tc.ip).Unmap(); back.IP != want || back.Tailnet != tc.tailnet || back.Side != tc.side {
			t.Errorf("Decode(%s) = %v, want tailnet %d %s %s", got, back, tc.tailnet, tc.side, want)
		}
	}
}

// The same IPv4 address on two tailnets, and on both sides of one, is four
// different pseudo addresses.
func TestOverlappingIPv4IsDistinct(t *testing.T) {
	s := testScheme(t)
	ip := netip.MustParseAddr("100.64.0.2")
	seen := map[netip.Addr]bool{}
	for _, tailnet := range []uint8{1, 2} {
		for _, side := range []Side{Remote, Local} {
			a, err := s.Encode(tailnet, side, ip)
			if err != nil {
				t.Fatal(err)
			}
			if seen[a] {
				t.Fatalf("%s is produced twice", a)
			}
			seen[a] = true
		}
	}
}

func TestEncodeRefusesAnUnconfiguredIPv6(t *testing.T) {
	s := testScheme(t)
	for _, ip := range []string{"2001:db8:1:3::1", "2001:db8:feed:6ce8:d2b1:13c8:a553:acfd", "fe80::1"} {
		if a, err := s.Encode(1, Remote, netip.MustParseAddr(ip)); err == nil {
			t.Errorf("Encode(%s) = %s, want an error", ip, a)
		}
	}
	// Spaces are per tailnet.
	if a, err := s.Encode(2, Remote, netip.MustParseAddr("2001:db8:1:2::42")); err == nil {
		t.Errorf("Encode on tailnet 2 of tailnet 1's space = %s, want an error", a)
	}
}

func TestDecodeRefuses(t *testing.T) {
	s := testScheme(t)
	for _, tc := range []struct {
		addr string
		want error
	}{
		{"fdcc:79e7:100::1", ErrOutsidePrefix},
		{"100.64.0.1", ErrOutsidePrefix},
		{"fdcc:79e6::1", ErrGateway},
		{"fdcc:79e6:300::1", ErrUnknown},
		{"fdcc:79e6:120::1", ErrMalformed},   // side 2
		{"fdcc:79e6:100:1::1", ErrMalformed}, // IPv4 space with a nonzero pad
		{"fdcc:79e6:104::1", ErrMalformed},   // space 4 is not configured
		{"fdcc:79e6:103:3::1", ErrMalformed}, // outside space 3's /64
		{"fdcc:79e6:112:6ce8:d2b1:13c8:a553:acfd", ErrMalformed},
	} {
		a, err := s.Decode(netip.MustParseAddr(tc.addr))
		if !errors.Is(err, tc.want) {
			t.Errorf("Decode(%s) = %v, %v; want %v", tc.addr, a, err, tc.want)
		}
	}
}

func TestPrefixes(t *testing.T) {
	s := testScheme(t)
	for _, tc := range []struct {
		got  netip.Prefix
		want string
	}{
		{s.TailnetPrefix(1), "fdcc:79e6:100::/40"},
		{s.SidePrefix(1, Local), "fdcc:79e6:110::/44"},
		{s.SidePrefix(2, Remote), "fdcc:79e6:200::/44"},
		{s.SpacePrefix(1, Remote, SpaceTailscale), "fdcc:79e6:101::/48"},
		{s.SpacePrefix(1, Local, SpaceIPv4), "fdcc:79e6:110::/48"},
	} {
		if tc.got.String() != tc.want {
			t.Errorf("got %s, want %s", tc.got, tc.want)
		}
	}

	local, _ := s.Encode(1, Local, netip.MustParseAddr("100.64.0.1"))
	remote, _ := s.Encode(1, Remote, netip.MustParseAddr("100.64.0.1"))
	if !s.SidePrefix(1, Local).Contains(local) || s.SidePrefix(1, Local).Contains(remote) {
		t.Errorf("the local /44 does not separate %s from %s", local, remote)
	}
	if got := s.Gateway().String(); got != "fdcc:79e6::1" {
		t.Errorf("Gateway() = %s", got)
	}
}

func TestSchemeValidation(t *testing.T) {
	for _, p := range []string{"fdcc:79e6::/48", "fdcc:79e6:1::/32", "2001:db8::/32", "fd7a:115c::/32"} {
		if _, err := NewScheme(netip.MustParsePrefix(p)); err == nil {
			t.Errorf("NewScheme(%s) accepted", p)
		}
	}

	s := testScheme(t)
	if err := s.AddTailnet(0); err == nil {
		t.Error("tailnet 0 accepted")
	}
	if err := s.AddTailnet(1); err == nil {
		t.Error("tailnet 1 accepted twice")
	}
	for _, tc := range []struct {
		space  Space
		prefix string
	}{
		{1, "2001:db8:9::/64"},       // not a configurable space
		{16, "2001:db8:9::/64"},      // nor is this
		{4, "2001:db8::/32"},         // too short
		{4, "fd7a:115c:a1e0:1::/64"}, // Tailscale's
		{4, "fdcc:79e6:1234::/48"},   // the gateway's
		{4, "2001:db8:1:2:3::/80"},   // overlaps space 3
		{2, "2001:db8:7::/64"},       // space 2 is taken
		{4, "2001:db8:1:2:3::1/64"},  // host bits
		{4, "10.0.0.0/8"},            // not IPv6
	} {
		if err := s.SetSpace(1, tc.space, netip.MustParsePrefix(tc.prefix)); err == nil {
			t.Errorf("SetSpace(1, %d, %s) accepted", tc.space, tc.prefix)
		}
	}
}

func TestEncodeInPlace(t *testing.T) {
	s := testScheme(t)
	ip := netip.MustParseAddr("fd7a:115c:a1e0:ab12:4843:cd96:6240:5").As16()
	if !s.Encode6(ip[:], 1, Remote, ip[:]) {
		t.Fatal("Encode6 failed")
	}
	if got := netip.AddrFrom16(ip).String(); got != "fdcc:79e6:101:ab12:4843:cd96:6240:5" {
		t.Fatalf("in place: %s", got)
	}
	_, n, err := s.DecodeTo(ip[:], ip[:])
	if err != nil || n != 16 {
		t.Fatalf("DecodeTo: %d %v", n, err)
	}
	if got := netip.AddrFrom16(ip).String(); got != "fd7a:115c:a1e0:ab12:4843:cd96:6240:5" {
		t.Fatalf("in place back: %s", got)
	}
}

func BenchmarkEncodeDecode4(b *testing.B) {
	s, _ := NewScheme(netip.MustParsePrefix("fdcc:79e6::/32"))
	_ = s.AddTailnet(1)
	ip := []byte{100, 64, 0, 5}
	var buf, out [16]byte
	for b.Loop() {
		s.Encode4(buf[:], 1, Remote, ip)
		if _, _, err := s.DecodeTo(out[:], buf[:]); err != nil {
			b.Fatal(err)
		}
	}
}
