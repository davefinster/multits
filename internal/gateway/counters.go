package gateway

import (
	"sync/atomic"

	"github.com/davefinster/multits/internal/xlat"
)

// direction is which way a packet crossed.
type direction int

const (
	// inbound is from a tailnet to the host.
	inbound direction = iota
	// outbound is from the host to a tailnet.
	outbound
)

// counters are one tailnet's packet counts.
type counters struct {
	packets [2]atomic.Uint64
	bytes   [2]atomic.Uint64
	// drops are by reason; the last slot is a packet translated but not
	// sent, because the node was not up or not keeping up.
	drops [2][xlat.NumReasons + 1]atomic.Uint64
}

func (c *counters) pass(d direction, n int) {
	c.packets[d].Add(1)
	c.bytes[d].Add(uint64(n))
}

func (c *counters) drop(d direction, r xlat.Reason) { c.drops[d][r].Add(1) }

// Counts is a snapshot of counters.
type Counts struct {
	Packets uint64            `json:"packets"`
	Bytes   uint64            `json:"bytes"`
	Dropped map[string]uint64 `json:"dropped,omitempty"`
}

func (c *counters) snapshot(d direction) Counts {
	out := Counts{Packets: c.packets[d].Load(), Bytes: c.bytes[d].Load()}
	for r := range c.drops[d] {
		n := c.drops[d][r].Load()
		if n == 0 {
			continue
		}
		if out.Dropped == nil {
			out.Dropped = map[string]uint64{}
		}
		name := "queue-full"
		if xlat.Reason(r) < xlat.NumReasons {
			name = xlat.Reason(r).String()
		}
		out.Dropped[name] = n
	}
	return out
}
