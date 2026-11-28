package gateway

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/davefinster/multits/internal/config"
	"github.com/davefinster/tstest"
)

// device.queues gives the device that many queues, each with its own reader.
// The gateway writes every flow to the queue the flow maps to, and the
// kernel sends the host's side of a flow to the queue it was last written
// to, so flows from the tailnets spread over the readers. Written to one
// queue, they would all be read from it. Nothing is lost or reordered beyond
// what TCP mends on the way: every flow gets back exactly what it sent.
func TestE2EQueues(t *testing.T) {
	const queues, flows = 4, 16
	w := newWorld(t, func(f *config.File) { f.Device.Queues = queues })

	// The application sends back what it is sent.
	ln, err := net.Listen("tcp6", "[::]:9200")
	if err != nil {
		t.Fatal(err)
	}
	app := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_, _ = w.Write(body)
		}),
	}
	go func() { _ = app.Serve(ln) }()
	defer app.Close()

	// Reach the application once from each tailnet before the flows start.
	for _, c := range []*tstest.Node{w.clientA, w.clientB} {
		eventually(t, "the application", func() error {
			_, _, err := get(c, "http://"+net.JoinHostPort(w.gwA[0].String(), "9200")+"/")
			return err
		})
	}

	// Each flow is a connection of its own, half from each tailnet, sending
	// and receiving enough for the kernel to hand over whole segments.
	sent := make([]byte, 512<<10)
	if _, err := rand.Read(sent); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, flows)
	for i := range flows {
		c := w.clientA
		if i%2 == 1 {
			c = w.clientB
		}
		wg.Go(func() {
			hc := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{DialContext: c.Dial}}
			defer hc.CloseIdleConnections()
			resp, err := hc.Post("http://"+net.JoinHostPort(w.gwA[0].String(), "9200")+"/", "application/octet-stream", bytes.NewReader(sent))
			if err != nil {
				errs <- fmt.Errorf("flow %d: %w", i, err)
				return
			}
			defer resp.Body.Close()
			got, err := io.ReadAll(resp.Body)
			if err != nil || !bytes.Equal(got, sent) {
				errs <- fmt.Errorf("flow %d: got %d bytes back of %d, equal %v: %v", i, len(got), len(sent), bytes.Equal(got, sent), err)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	st := w.g.Status()
	if len(st.Queues) != queues {
		t.Fatalf("status has %d queues, want %d", len(st.Queues), queues)
	}
	var total, most uint64
	for _, n := range st.Queues {
		total += n
		most = max(most, n)
	}
	t.Logf("packets read from each queue: %v", st.Queues)
	// Written to one queue, all but a handful of packets are read from it.
	// Sixteen equal flows spread over four queues leave one queue with nine
	// tenths of the packets less than once in ten million runs.
	if most*10 > total*9 {
		t.Errorf("one queue read %d of %d packets: %v", most, total, st.Queues)
	}
}
