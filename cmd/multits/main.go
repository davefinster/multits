// Command multits is a gateway onto several tailnets at once for an
// application that knows nothing of them.
//
//	multits run    -config multits.yaml [-v]
//	multits check  -config multits.yaml
//	multits probe  [URL]
//	multits version
//	multits encode -config multits.yaml TAILNET IP [local|remote]
//	multits decode -config multits.yaml ADDRESS
//
// run joins every configured tailnet and serves. check validates the
// configuration and prints the address plan. encode and decode convert
// between an address on a tailnet and its pseudo address, which is what to
// write in the application's own configuration: allow lists, backends.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/davefinster/multits/internal/addr"
	"github.com/davefinster/multits/internal/config"
	"github.com/davefinster/multits/internal/gateway"
)

// version is set at build time: the commit an image was built from.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	if cmd == "version" {
		fmt.Println(version)
		return
	}
	if cmd == "probe" {
		// An exec probe for an image with nothing else in it: the API
		// listens on the loopback, which a kubelet's HTTP probe cannot
		// reach from the node.
		url := "http://" + config.DefaultAPI + "/healthz"
		if len(args) > 0 {
			url = args[0]
		}
		if err := probe(url); err != nil {
			fmt.Fprintln(os.Stderr, "multits probe:", err)
			os.Exit(1)
		}
		return
	}

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	path := fs.String("config", "/etc/multits/multits.yaml", "configuration file")
	verbose := fs.Bool("v", false, "log tsnet's own debug output too")
	_ = fs.Parse(args)

	var err error
	switch cmd {
	case "run":
		err = run(*path, *verbose)
	case "check":
		err = check(*path)
	case "encode":
		err = encode(*path, fs.Args())
	case "decode":
		err = decode(*path, fs.Args())
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "multits:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  multits run    -config FILE [-v]
  multits check  -config FILE
  multits encode -config FILE TAILNET IP [local|remote]
  multits decode -config FILE ADDRESS
  multits probe  [URL]
  multits version`)
	os.Exit(2)
}

func run(path string, verbose bool) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	log.Info("Starting", "version", version)

	g, err := gateway.New(cfg, nil, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return g.Run(ctx)
}

// probe GETs url and fails unless it answers 200.
func probe(url string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s: %s", url, resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func check(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	s := cfg.Scheme
	if cfg.Device.FitTailnet {
		fmt.Printf("prefix   %s\ngateway  %s\ndevice   %s, MTU %d fitted to the tailnets' %d (IPv4 space %d, IPv6 %d)\n",
			s.Prefix(), s.Gateway(), cfg.Device.Name, cfg.TailnetMTU+20, cfg.TailnetMTU, cfg.TailnetMTU+20, cfg.TailnetMTU)
	} else {
		fmt.Printf("prefix   %s\ngateway  %s\ndevice   %s, MTU %d, room for quic-go over the tailnets' %d\n", s.Prefix(), s.Gateway(), cfg.Device.Name, cfg.TailnetMTU+48, cfg.TailnetMTU)
	}
	switch {
	case len(cfg.DNS.Listen) == 0:
		fmt.Printf("dns      off\n\n")
	case cfg.DNS.Upstream != nil:
		fmt.Printf("dns      %v, upstream %v\n\n", cfg.DNS.Listen, cfg.DNS.Upstream)
	default:
		fmt.Printf("dns      %v, upstream from %s\n\n", cfg.DNS.Listen, cfg.DNS.ResolvConf)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TAILNET\tID\tALL\tPEERS\tLOCAL\tSPACES")
	for _, tc := range cfg.Tailnets {
		spaces := s.Spaces(tc.ID)
		keys := make([]int, 0, len(spaces))
		for k := range spaces {
			keys = append(keys, int(k))
		}
		sort.Ints(keys)
		desc := "0 IPv4, 1 " + addr.TailscaleULA.String()
		for _, k := range keys {
			desc += fmt.Sprintf(", %d %s", k, spaces[addr.Space(k)])
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\n", tc.Name, tc.ID, s.TailnetPrefix(tc.ID), s.SidePrefix(tc.ID, addr.Remote), s.SidePrefix(tc.ID, addr.Local), desc)
	}
	return w.Flush()
}

func encode(path string, args []string) error {
	if len(args) < 2 || len(args) > 3 {
		return errors.New("encode TAILNET IP [local|remote]")
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	var id uint8
	for _, tc := range cfg.Tailnets {
		if tc.Name == args[0] || fmt.Sprint(tc.ID) == args[0] {
			id = tc.ID
		}
	}
	if id == 0 {
		return fmt.Errorf("no tailnet %q", args[0])
	}
	ip, err := netip.ParseAddr(args[1])
	if err != nil {
		return err
	}
	side := addr.Remote
	if len(args) == 3 {
		switch args[2] {
		case "remote":
		case "local":
			side = addr.Local
		default:
			return fmt.Errorf("side %q: local or remote", args[2])
		}
	}
	p, err := cfg.Scheme.Encode(id, side, ip)
	if err != nil {
		return err
	}
	fmt.Println(p)
	return nil
}

func decode(path string, args []string) error {
	if len(args) != 1 {
		return errors.New("decode ADDRESS")
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(args[0])
	if err != nil {
		return err
	}
	a, err := cfg.Scheme.Decode(ip)
	if err != nil {
		return fmt.Errorf("%s %w", ip, err)
	}
	name := ""
	for _, tc := range cfg.Tailnets {
		if tc.ID == a.Tailnet {
			name = tc.Name
		}
	}
	fmt.Printf("tailnet %s (%d), %s, space %d: %s\n", name, a.Tailnet, a.Side, a.Space, a.IP)
	return nil
}
