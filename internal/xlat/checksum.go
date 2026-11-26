package xlat

import "encoding/binary"

// sum adds b, as big-endian 16-bit words, to a one's complement accumulator.
// An odd final byte is padded with zero, as every Internet checksum is.
func sum(acc uint32, b []byte) uint32 {
	for len(b) >= 8 {
		acc += uint32(binary.BigEndian.Uint16(b)) + uint32(binary.BigEndian.Uint16(b[2:])) +
			uint32(binary.BigEndian.Uint16(b[4:])) + uint32(binary.BigEndian.Uint16(b[6:]))
		b = b[8:]
		// Fold now and then so a jumbo payload cannot overflow.
		if acc > 0x7fffffff {
			acc = acc>>16 + acc&0xffff
		}
	}
	for len(b) >= 2 {
		acc += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		acc += uint32(b[0]) << 8
	}
	return acc
}

// fold reduces an accumulator to 16 bits.
func fold(acc uint32) uint16 {
	for acc > 0xffff {
		acc = acc>>16 + acc&0xffff
	}
	return uint16(acc)
}

// checksum is the Internet checksum of b, starting from initial, which is
// where a pseudo-header's sum goes.
func checksum(b []byte, initial uint32) uint16 {
	return ^fold(sum(initial, b))
}

// adjust updates a checksum for a change in the data it covers, given the
// folded sums of the old and the new data (RFC 1624, equation 3). It is how
// a transport checksum follows its pseudo-header's addresses without the
// payload being read again.
func adjust(csum, oldSum, newSum uint16) uint16 {
	return ^fold(uint32(^csum) + uint32(^oldSum) + uint32(newSum))
}

// pseudo6 is the sum of an IPv6 pseudo-header (RFC 8200, section 8.1).
func pseudo6(src, dst []byte, length int, next uint8) uint32 {
	acc := sum(sum(0, src[:16]), dst[:16])
	return acc + uint32(length>>16) + uint32(length&0xffff) + uint32(next)
}

// addrSum is the folded sum of a packet's two addresses, which is all of its
// pseudo-header that translation changes: the length and the protocol sum
// the same in IPv4 and IPv6.
func addrSum(src, dst []byte) uint16 {
	return fold(sum(sum(0, src), dst))
}
