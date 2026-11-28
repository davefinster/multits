package tailnet

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
)

// batchOf lays packets out end to end, as a read of the host's device leaves
// them once they are copied out of it.
func batchOf(done func(*Batch), pkts ...[]byte) *Batch {
	b := &Batch{Done: done}
	for _, p := range pkts {
		b.Packets = append(b.Packets, tun.ReadPacket{Offset: len(b.Slab), Size: len(p)})
		b.Slab = append(b.Slab, p...)
	}
	return b
}

// packet is n bytes that say which packet they are.
func packet(tag byte, n int) []byte { return bytes.Repeat([]byte{tag}, n) }

// same is a translation that changes nothing.
func same(pkt, out []byte) (int, [][]byte) { return copy(out, pkt), nil }

// read reads once, with room for count packets, and returns what it read.
func read(t *testing.T, d *device, slab []byte, count int) [][]byte {
	t.Helper()
	packets := make([]tun.ReadPacket, count)
	n, err := d.Read(slab, packets)
	if err != nil {
		t.Fatal(err)
	}
	var got [][]byte
	end := 0
	for _, p := range packets[:n] {
		if p.Offset < end+tun.ReadPacketSpacing {
			t.Errorf("a packet at %d, less than the spacing after the last one's end at %d", p.Offset, end)
		}
		end = p.Offset + p.Size
		got = append(got, bytes.Clone(slab[p.Offset:end]))
	}
	if end+tun.ReadPacketSpacing > len(slab) {
		t.Errorf("the last packet ends at %d of %d, without the spacing after it", end, len(slab))
	}
	return got
}

func tags(pkts [][]byte) string {
	var s []byte
	for _, p := range pkts {
		s = append(s, p[0])
	}
	return string(s)
}

// A whole batch is one read, each packet translated into the node's slab,
// and the batch goes back to its owner once its last packet is read.
func TestReadTranslatesABatch(t *testing.T) {
	done := 0
	upper := func(pkt, out []byte) (int, [][]byte) { return copy(out, bytes.ToUpper(pkt)), nil }
	d := newDevice(nil, upper)
	if !d.send(batchOf(func(*Batch) { done++ }, packet('a', 100), packet('b', 1300), packet('c', 40))) {
		t.Fatal("the batch was refused")
	}

	got := read(t, d, make([]byte, 1<<16), 8)
	if len(got) != 3 || !bytes.Equal(got[0], packet('A', 100)) || !bytes.Equal(got[1], packet('B', 1300)) || !bytes.Equal(got[2], packet('C', 40)) {
		t.Errorf("read %q", tags(got))
	}
	if done != 1 {
		t.Errorf("the batch was handed back %d times", done)
	}
}

// A read takes what it has room for, by packets and by bytes, and the next
// one carries on from there, into the batches behind.
func TestReadResumes(t *testing.T) {
	done := 0
	d := newDevice(nil, same)
	d.send(batchOf(func(*Batch) { done++ }, packet('a', 100), packet('b', 100), packet('c', 100)))
	d.send(batchOf(func(*Batch) { done++ }, packet('d', 100), packet('e', 100)))

	slab := make([]byte, 1<<16)
	if got := tags(read(t, d, slab, 2)); got != "ab" || done != 0 {
		t.Errorf("first read %q, %d batches back", got, done)
	}
	if got := tags(read(t, d, slab, 2)); got != "cd" || done != 1 {
		t.Errorf("second read %q, %d batches back", got, done)
	}
	if got := tags(read(t, d, slab, 2)); got != "e" || done != 2 {
		t.Errorf("third read %q, %d batches back", got, done)
	}

	// A slab with room to translate one packet, and no more.
	d.send(batchOf(nil, packet('f', 100), packet('g', 100)))
	one := make([]byte, tun.ReadPacketSpacing+MTU+tun.ReadPacketSpacing)
	if got := tags(read(t, d, one, 8)); got != "f" {
		t.Errorf("a slab for one read %q", got)
	}
	if got := tags(read(t, d, one, 8)); got != "g" {
		t.Errorf("and then %q", got)
	}
}

// A packet too large for the tailnet arrives as fragments, which are read in
// order ahead of what follows, across reads if need be.
func TestReadFragments(t *testing.T) {
	split := func(pkt, out []byte) (int, [][]byte) {
		if pkt[0] == 'b' {
			return 0, [][]byte{packet('1', 60), packet('2', 60), packet('3', 20)}
		}
		return copy(out, pkt), nil
	}
	d := newDevice(nil, split)
	d.send(batchOf(nil, packet('a', 100), packet('b', 140), packet('c', 100)))

	slab := make([]byte, 1<<16)
	if got := tags(read(t, d, slab, 3)); got != "a12" {
		t.Errorf("first read %q", got)
	}
	if got := tags(read(t, d, slab, 3)); got != "3c" {
		t.Errorf("second read %q", got)
	}
}

// A packet the translation drops, or answers, is not read, and neither is
// one larger than the node reads at all; what follows them is.
func TestReadSkips(t *testing.T) {
	drop := func(pkt, out []byte) (int, [][]byte) {
		if pkt[0] == 'x' {
			return 0, nil
		}
		return copy(out, pkt), nil
	}
	d := newDevice(nil, drop)
	d.send(batchOf(nil, packet('x', 100), packet('a', 100), packet('x', 100)))
	d.send(batchOf(nil, packet('x', 100)))
	d.send(batchOf(nil, packet('L', 4000), packet('b', 100)))

	// Room to translate one ordinary packet, but not the large one.
	slab := make([]byte, tun.ReadPacketSpacing+MTU+tun.ReadPacketSpacing)
	if got := tags(read(t, d, slab, 8)); got != "a" {
		t.Errorf("first read %q", got)
	}
	if got := tags(read(t, d, slab, 8)); got != "b" {
		t.Errorf("second read %q", got)
	}
}

// The queue is bounded by packets. A batch that does not fit is refused, and
// is still its sender's: it is not handed back, and nothing of it is read.
func TestSendIsBounded(t *testing.T) {
	d := newDevice(nil, same)
	done := 0
	back := func(*Batch) { done++ }

	sent := 0
	for d.send(batchOf(back, packet('a', 10), packet('a', 10), packet('a', 10))) {
		sent += 3
		if sent > queueDepth {
			t.Fatalf("%d packets queued, past the bound of %d", sent, queueDepth)
		}
	}
	if sent != queueDepth/3*3 {
		t.Errorf("%d packets queued, want %d", sent, queueDepth/3*3)
	}
	if d.send(&Batch{}) {
		t.Error("an empty batch was taken")
	}

	// Reading makes room again, and reads exactly what was taken.
	slab := make([]byte, 1<<20)
	read := 0
	for read < sent {
		packets := make([]tun.ReadPacket, 128)
		n, err := d.Read(slab, packets)
		if err != nil {
			t.Fatal(err)
		}
		read += n
	}
	if read != sent || done != sent/3 {
		t.Errorf("read %d of %d packets, %d of %d batches back", read, sent, done, sent/3)
	}
	if !d.send(batchOf(back, packet('b', 10))) {
		t.Error("a drained queue refused a batch")
	}
}

// Closing ends a read that is waiting, and the device takes nothing more.
func TestClose(t *testing.T) {
	d := newDevice(nil, same)
	errc := make(chan error, 1)
	go func() {
		_, err := d.Read(make([]byte, 1<<16), make([]tun.ReadPacket, 8))
		errc <- err
	}()
	time.Sleep(10 * time.Millisecond)
	_ = d.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, os.ErrClosed) {
			t.Errorf("the waiting read returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting read never returned")
	}
	if d.send(batchOf(nil, packet('a', 10))) {
		t.Error("a closed device took a batch")
	}
}
