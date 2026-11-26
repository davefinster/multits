// Package addr is the pseudo-IPv6 addressing scheme. Every address on every
// tailnet the gateway joins is given one IPv6 address that also says which
// tailnet it is on and which side of the gateway it is. The mapping holds no
// state: encoding and decoding are pure functions of the address and the
// configuration, so a packet's addresses alone say where it goes.
//
// That is the point of it. A tailnet's IPv4 addresses are unique only within
// that tailnet, and two tailnets routinely hand out the same ones. An
// application behind the gateway sees every peer as a distinct IPv6 address
// and answers it as it would any other; the gateway decodes the reply's
// destination to find the tailnet and the address on it.
//
// # Layout
//
// Most significant bit first:
//
//	bits   0-31  prefix   the gateway's /32, from the configuration
//	bits  32-39  tailnet  1-255, from the configuration; 0 is the gateway's own
//	bits  40-43  side     0 a peer on the tailnet, 1 the gateway's own address there
//	bits  44-47  space    which kind of address the payload holds
//	bits  48-127 payload  80 bits
//
// Spaces:
//
//	0     IPv4. The payload is 48 zero bits and the address.
//	1     Tailscale's IPv6 range, fd7a:115c:a1e0::/48. The payload is the
//	      address's low 80 bits, which is everything that varies in it.
//	2-15  An IPv6 prefix of /48 or longer configured for the tailnet: the
//	      payload is the address's low 80 bits. These are for subnet routes
//	      outside Tailscale's range.
//
// Read as hex, the third group is the tailnet, the side and the space, and the
// rest is the address. With the prefix fdcc:79e6::/32, tailnet 1:
//
//	fdcc:79e6:100::6440:5                      peer 100.64.0.5
//	fdcc:79e6:110::6440:1                      this gateway's 100.64.0.1
//	fdcc:79e6:101:ab12:4843:cd96:6240:5        peer fd7a:115c:a1e0:ab12:4843:cd96:6240:5
//
// So a tailnet is a /40, a side of it a /44, and a space of a side a /48.
package addr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// PrefixBits is the length of the gateway's prefix.
const PrefixBits = 32

// Side says whether an address belongs to the gateway or to a peer.
type Side uint8

const (
	// Remote is a peer: anything on a tailnet that is not the gateway.
	Remote Side = 0
	// Local is one of the gateway's own addresses on a tailnet: its node
	// addresses, the virtual IPs of Services it hosts, and the addresses in
	// routes it advertises.
	Local Side = 1
)

func (s Side) String() string {
	switch s {
	case Remote:
		return "remote"
	case Local:
		return "local"
	default:
		return fmt.Sprintf("side(%d)", uint8(s))
	}
}

// Space says which kind of address a pseudo address carries.
type Space uint8

const (
	// SpaceIPv4 holds any IPv4 address.
	SpaceIPv4 Space = 0
	// SpaceTailscale holds an address in Tailscale's IPv6 range.
	SpaceTailscale Space = 1
	// FirstConfigured is the first space available for a configured prefix.
	FirstConfigured Space = 2
	// LastConfigured is the last.
	LastConfigured Space = 15
)

// MinSpaceBits is the shortest IPv6 prefix a configured space may hold: what
// is left of it after 80 bits of payload.
const MinSpaceBits = 128 - 80

// TailscaleULA is Tailscale's IPv6 range, which is space 1.
var TailscaleULA = netip.MustParsePrefix("fd7a:115c:a1e0::/48")

var uniqueLocal = netip.MustParsePrefix("fc00::/7")

// Errors returned by Parse and Decode.
var (
	ErrOutsidePrefix = errors.New("not in the gateway's prefix")
	ErrGateway       = errors.New("is the gateway's own address, not a tailnet's")
	ErrUnknown       = errors.New("names a tailnet that is not configured")
	ErrMalformed     = errors.New("is not a valid pseudo address")
)

// Meta is what a pseudo address says besides the address it carries.
type Meta struct {
	Tailnet uint8
	Side    Side
	Space   Space
}

// Addr is a decoded pseudo address.
type Addr struct {
	Meta
	// IP is the address on the tailnet.
	IP netip.Addr
}

func (a Addr) String() string {
	return fmt.Sprintf("tailnet %d %s %s", a.Tailnet, a.Side, a.IP)
}

// space is one configured IPv6 space.
type space struct {
	prefix netip.Prefix
	// head is the prefix's first six bytes, which the payload does not carry.
	head [6]byte
}

// Scheme holds the configuration that the encoding depends on: the prefix,
// which tailnets exist, and the IPv6 spaces configured for each.
//
// It is built once and then only read, so it is safe to share.
type Scheme struct {
	prefix   netip.Prefix
	head     [4]byte
	tailnets [256]bool
	spaces   [256][LastConfigured + 1]space
}

// NewScheme starts a scheme on the given prefix, which must be a /32 inside
// the unique local range, fc00::/7. A prefix that is not unique local could
// be someone's real network, and the gateway would capture their traffic.
func NewScheme(prefix netip.Prefix) (*Scheme, error) {
	if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return nil, fmt.Errorf("prefix %s is not IPv6", prefix)
	}
	if prefix.Bits() != PrefixBits {
		return nil, fmt.Errorf("prefix %s must be a /%d", prefix, PrefixBits)
	}
	if prefix.Masked() != prefix {
		return nil, fmt.Errorf("prefix %s has bits set past its length, did you mean %s?", prefix, prefix.Masked())
	}
	if !uniqueLocal.Contains(prefix.Addr()) {
		return nil, fmt.Errorf("prefix %s is not in the unique local range %s", prefix, uniqueLocal)
	}
	if prefix.Overlaps(TailscaleULA) {
		return nil, fmt.Errorf("prefix %s overlaps Tailscale's own range %s", prefix, TailscaleULA)
	}

	s := &Scheme{prefix: prefix}
	b := prefix.Addr().As16()
	copy(s.head[:], b[:4])
	return s, nil
}

// AddTailnet makes a tailnet number valid.
func (s *Scheme) AddTailnet(tailnet uint8) error {
	if tailnet == 0 {
		return errors.New("tailnet 0 is reserved for the gateway itself")
	}
	if s.tailnets[tailnet] {
		return fmt.Errorf("tailnet %d is configured twice", tailnet)
	}
	s.tailnets[tailnet] = true
	return nil
}

// HasTailnet reports whether the tailnet number is configured.
func (s *Scheme) HasTailnet(tailnet uint8) bool { return s.tailnets[tailnet] }

// SetSpace configures an IPv6 prefix as one of a tailnet's spaces.
func (s *Scheme) SetSpace(tailnet uint8, sp Space, prefix netip.Prefix) error {
	if !s.tailnets[tailnet] {
		return fmt.Errorf("tailnet %d is not configured", tailnet)
	}
	if sp < FirstConfigured || sp > LastConfigured {
		return fmt.Errorf("space %d: configured spaces are %d to %d", sp, FirstConfigured, LastConfigured)
	}
	if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return fmt.Errorf("space %d: %s is not an IPv6 prefix", sp, prefix)
	}
	if prefix.Bits() < MinSpaceBits {
		return fmt.Errorf("space %d: %s is shorter than /%d, and only 80 bits of an address fit", sp, prefix, MinSpaceBits)
	}
	if prefix.Masked() != prefix {
		return fmt.Errorf("space %d: %s has bits set past its length, did you mean %s?", sp, prefix, prefix.Masked())
	}
	if prefix.Overlaps(TailscaleULA) {
		return fmt.Errorf("space %d: %s is inside Tailscale's range, which is space %d already", sp, prefix, SpaceTailscale)
	}
	if prefix.Overlaps(s.prefix) {
		return fmt.Errorf("space %d: %s overlaps the gateway's prefix %s", sp, prefix, s.prefix)
	}
	if s.spaces[tailnet][sp].prefix.IsValid() {
		return fmt.Errorf("space %d of tailnet %d is configured twice", sp, tailnet)
	}
	for other := FirstConfigured; other <= LastConfigured; other++ {
		if p := s.spaces[tailnet][other].prefix; p.IsValid() && p.Overlaps(prefix) {
			return fmt.Errorf("space %d: %s overlaps space %d, %s", sp, prefix, other, p)
		}
	}

	b := prefix.Addr().As16()
	entry := space{prefix: prefix}
	copy(entry.head[:], b[:6])
	s.spaces[tailnet][sp] = entry
	return nil
}

// Spaces returns a tailnet's configured spaces.
func (s *Scheme) Spaces(tailnet uint8) map[Space]netip.Prefix {
	out := map[Space]netip.Prefix{}
	for sp := FirstConfigured; sp <= LastConfigured; sp++ {
		if p := s.spaces[tailnet][sp].prefix; p.IsValid() {
			out[sp] = p
		}
	}
	return out
}

// Prefix returns the gateway's prefix.
func (s *Scheme) Prefix() netip.Prefix { return s.prefix }

// Gateway returns the gateway's own address: the one it sends ICMP errors
// from. It is in tailnet 0, which no tailnet can be.
func (s *Scheme) Gateway() netip.Addr {
	var b [16]byte
	copy(b[:], s.head[:])
	b[15] = 1
	return netip.AddrFrom16(b)
}

// Resolver returns the address the gateway's resolver listens on unless
// configured otherwise, also in tailnet 0: the gateway's prefix and ::53.
func (s *Scheme) Resolver() netip.Addr {
	var b [16]byte
	copy(b[:], s.head[:])
	b[15] = 0x53
	return netip.AddrFrom16(b)
}

// TailnetPrefix returns the /40 that holds every address of a tailnet.
func (s *Scheme) TailnetPrefix(tailnet uint8) netip.Prefix {
	return s.block(tailnet, 0, 0, 40)
}

// SidePrefix returns the /44 that holds one side of a tailnet.
func (s *Scheme) SidePrefix(tailnet uint8, side Side) netip.Prefix {
	return s.block(tailnet, side, 0, 44)
}

// SpacePrefix returns the /48 that holds one space of one side of a tailnet.
func (s *Scheme) SpacePrefix(tailnet uint8, side Side, sp Space) netip.Prefix {
	return s.block(tailnet, side, sp, 48)
}

func (s *Scheme) block(tailnet uint8, side Side, sp Space, bits int) netip.Prefix {
	var b [16]byte
	copy(b[:], s.head[:])
	b[4] = tailnet
	b[5] = byte(side)<<4 | byte(sp)
	return netip.PrefixFrom(netip.AddrFrom16(b), bits).Masked()
}

// Encode returns the pseudo address of ip on a tailnet. It fails for an IPv6
// address in no space of that tailnet.
func (s *Scheme) Encode(tailnet uint8, side Side, ip netip.Addr) (netip.Addr, error) {
	var b [16]byte
	ip = ip.Unmap()
	if ip.Is4() {
		a := ip.As4()
		s.Encode4(b[:], tailnet, side, a[:])
		return netip.AddrFrom16(b), nil
	}
	if !ip.IsValid() {
		return netip.Addr{}, errors.New("invalid address")
	}
	a := ip.As16()
	if !s.Encode6(b[:], tailnet, side, a[:]) {
		return netip.Addr{}, fmt.Errorf("%s is in no address space of tailnet %d: IPv6 outside %s needs a configured space", ip, tailnet, TailscaleULA)
	}
	return netip.AddrFrom16(b), nil
}

// Encode4 writes into dst, 16 bytes, the pseudo address of the IPv4 address
// in ip, 4 bytes.
func (s *Scheme) Encode4(dst []byte, tailnet uint8, side Side, ip []byte) {
	_ = dst[15]
	copy(dst[:4], s.head[:])
	dst[4] = tailnet
	dst[5] = byte(side)<<4 | byte(SpaceIPv4)
	clear(dst[6:12])
	copy(dst[12:16], ip[:4])
}

// Encode6 writes into dst, 16 bytes, the pseudo address of the IPv6 address
// in ip, 16 bytes, and reports whether it could. dst and ip may be the same.
func (s *Scheme) Encode6(dst []byte, tailnet uint8, side Side, ip []byte) bool {
	_, _ = dst[15], ip[15]

	sp, ok := s.space6(tailnet, ip)
	if !ok {
		return false
	}

	// The payload before the head: when dst is ip, writing the head first
	// would lose nothing the payload needs, but the space is already known
	// and this order is correct whichever way the two alias.
	copy(dst[6:16], ip[6:16])
	copy(dst[:4], s.head[:])
	dst[4] = tailnet
	dst[5] = byte(side)<<4 | byte(sp)
	return true
}

var tsHead = func() (h [6]byte) {
	b := TailscaleULA.Addr().As16()
	copy(h[:], b[:6])
	return h
}()

// space6 finds the space an IPv6 address is in.
func (s *Scheme) space6(tailnet uint8, ip []byte) (Space, bool) {
	if [6]byte(ip[:6]) == tsHead {
		return SpaceTailscale, true
	}
	for sp := FirstConfigured; sp <= LastConfigured; sp++ {
		entry := &s.spaces[tailnet][sp]
		if entry.prefix.IsValid() && [6]byte(ip[:6]) == entry.head && entry.prefix.Contains(netip.AddrFrom16([16]byte(ip[:16]))) {
			return sp, true
		}
	}
	return 0, false
}

// Decode returns what a pseudo address says.
func (s *Scheme) Decode(a netip.Addr) (Addr, error) {
	if !a.Is6() || a.Is4In6() {
		return Addr{}, ErrOutsidePrefix
	}
	b := a.As16()
	var out [16]byte
	meta, n, err := s.DecodeTo(out[:], b[:])
	if err != nil {
		return Addr{}, err
	}
	if n == 4 {
		return Addr{Meta: meta, IP: netip.AddrFrom4([4]byte(out[:4]))}, nil
	}
	return Addr{Meta: meta, IP: netip.AddrFrom16(out)}, nil
}

// DecodeTo decodes the pseudo address in a, 16 bytes, writing the address it
// carries into out, which needs 16 bytes, and returning its length: 4 for
// IPv4, 16 for IPv6. out and a may be the same.
func (s *Scheme) DecodeTo(out, a []byte) (Meta, int, error) {
	_, _ = out[15], a[15]

	if [4]byte(a[:4]) != s.head {
		return Meta{}, 0, ErrOutsidePrefix
	}
	meta := Meta{Tailnet: a[4], Side: Side(a[5] >> 4), Space: Space(a[5] & 0x0f)}
	if meta.Tailnet == 0 {
		return meta, 0, ErrGateway
	}
	if !s.tailnets[meta.Tailnet] {
		return meta, 0, ErrUnknown
	}
	if meta.Side != Remote && meta.Side != Local {
		return meta, 0, ErrMalformed
	}

	switch meta.Space {
	case SpaceIPv4:
		if binary.BigEndian.Uint64(a[4:12])&0x0000ffffffffffff != 0 {
			return meta, 0, ErrMalformed
		}
		copy(out[:4], a[12:16])
		return meta, 4, nil

	case SpaceTailscale:
		copy(out[6:16], a[6:16])
		copy(out[:6], tsHead[:])
		return meta, 16, nil

	default:
		entry := &s.spaces[meta.Tailnet][meta.Space]
		if !entry.prefix.IsValid() {
			return meta, 0, ErrMalformed
		}
		var ip [16]byte
		copy(ip[:6], entry.head[:])
		copy(ip[6:], a[6:16])
		// A space longer than /48 fixes some of the payload's bits too, and
		// an address that disagrees with them is in no space at all.
		if !entry.prefix.Contains(netip.AddrFrom16(ip)) {
			return meta, 0, ErrMalformed
		}
		copy(out[:16], ip[:])
		return meta, 16, nil
	}
}
