package gateway

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// An unmodified Traefik as the application: it has no idea there is a
// tailnet. A client on tailnet a reaches it through the gateway, and it
// proxies to a backend on tailnet b by that backend's pseudo address. Its
// allow list tells the tailnets apart by prefix, and its access log and the
// X-Forwarded-For it sends name the client by its pseudo address.
//
// MULTITS_TRAEFIK names the binary: make test-netns ARGS='...' does not set
// it, so run it as
//
//	make test-netns TRAEFIK=/path/to/traefik
func TestE2ETraefik(t *testing.T) {
	bin := os.Getenv("MULTITS_TRAEFIK")
	if bin == "" {
		t.Skip("MULTITS_TRAEFIK names no traefik binary")
	}
	w := newWorld(t)
	// Traefik resolves its backends' names as any Go program does, through
	// /etc/resolv.conf: here, the gateway.
	useResolvConf(t, "nameserver "+w.g.cfg.DNS.Listen[0].Addr().String()+"\n")

	// The backend: on tailnet b, at the address client a also has on a.
	ln, err := w.clientB.Listen("tcp", ":9000")
	if err != nil {
		t.Fatal(err)
	}
	backend := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(rw, "backend on b; remote %s; X-Forwarded-For %s", r.RemoteAddr, r.Header.Get("X-Forwarded-For"))
	})}
	go func() { _ = backend.Serve(ln) }()
	t.Cleanup(func() { _ = backend.Close() })

	backendPseudo, err := w.g.Scheme().Encode(2, 0, netip.MustParseAddr("100.64.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	peersA := w.g.Status().Tailnets[0].Peers

	dir := t.TempDir()
	dynamic := fmt.Sprintf(`
http:
  routers:
    open:
      entryPoints: [web]
      rule: PathPrefix(%[1]s/open%[1]s)
      service: backend
    a-only:
      entryPoints: [web]
      rule: PathPrefix(%[1]s/a-only%[1]s)
      middlewares: [tailnet-a]
      service: backend
    by-name:
      entryPoints: [web]
      rule: PathPrefix(%[1]s/by-name%[1]s)
      service: backend-by-name
  middlewares:
    tailnet-a:
      ipAllowList:
        sourceRange: ["%[2]s"]
  services:
    backend:
      loadBalancer:
        servers:
          - url: "http://[%[3]s]:9000"
    backend-by-name:
      loadBalancer:
        servers:
          - url: "http://client-b.b.ts.net:9000"
`, "`", peersA, backendPseudo)
	if err := os.WriteFile(filepath.Join(dir, "dynamic.yaml"), []byte(dynamic), 0o644); err != nil {
		t.Fatal(err)
	}
	accessLog := filepath.Join(dir, "access.json")

	cmd := exec.Command(bin,
		"--entryPoints.web.address=:8080",
		"--providers.file.filename="+filepath.Join(dir, "dynamic.yaml"),
		"--log.level=WARN",
		"--accessLog.filePath="+accessLog,
		"--accessLog.format=json",
		"--accessLog.bufferingSize=0",
	)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	eventually(t, "traefik listening", func() error {
		c, err := net.Dial("tcp", "[::1]:8080")
		if err == nil {
			c.Close()
		}
		return err
	})

	entry := "http://" + netip.AddrPortFrom(w.gwA[0], 8080).String()
	for _, tc := range []struct {
		name   string
		client string
		path   string
		code   int
		xff    string
	}{
		{"a reaches b's backend", "a", "/open", 200, "fdcc:79e6:100::6440:2"},
		{"b reaches its own backend through a", "b", "/open", 200, "fdcc:79e6:200::6440:2"},
		{"a is allowed", "a", "/a-only", 200, "fdcc:79e6:100::6440:2"},
		{"b is not", "b", "/a-only", 403, ""},
		{"a reaches b's backend by its MagicDNS name", "a", "/by-name", 200, "fdcc:79e6:100::6440:2"},
	} {
		c := w.clientA
		if tc.client == "b" {
			c = w.clientB
		}
		url := entry + tc.path
		if tc.client == "b" {
			url = "http://" + netip.AddrPortFrom(w.gwB[0], 8080).String() + tc.path
		}
		eventually(t, tc.name, func() error {
			body, code, err := get(c, url)
			if err != nil {
				return err
			}
			if code != tc.code {
				return fmt.Errorf("status %d, want %d: %s", code, tc.code, body)
			}
			if tc.code == 200 {
				// The backend sees the gateway's address on tailnet b, and
				// the client's pseudo address in the header.
				if !strings.HasPrefix(body, "backend on b; remote 100.64.0.1:") || !strings.HasSuffix(body, "X-Forwarded-For "+tc.xff) {
					return fmt.Errorf("backend said %q", body)
				}
			}
			t.Logf("%s: %d %s", tc.name, code, body)
			return nil
		})
	}

	// Traefik's own record of who it served.
	f, err := os.Open(accessLog)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	seen := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var line struct {
			ClientHost    string `json:"ClientHost"`
			RequestPath   string `json:"RequestPath"`
			OriginStatus  int    `json:"OriginStatus"`
			DownstreamSta int    `json:"DownstreamStatus"`
		}
		if json.Unmarshal(sc.Bytes(), &line) == nil {
			seen[line.ClientHost]++
			t.Logf("access log: %s %s %d", line.ClientHost, line.RequestPath, line.DownstreamSta)
		}
	}
	for _, host := range []string{"fdcc:79e6:100::6440:2", "fdcc:79e6:200::6440:2"} {
		if seen[host] == 0 {
			t.Errorf("the access log never names %s: %v", host, seen)
		}
	}
}
