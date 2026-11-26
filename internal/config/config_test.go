package config

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseExample(t *testing.T) {
	cfg, err := Load("../../multits.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scheme.Prefix().String() != DefaultPrefix || cfg.TailnetMTU != 1280 || cfg.Device.Name != "multits0" {
		t.Errorf("defaults: %s %d %s", cfg.Scheme.Prefix(), cfg.TailnetMTU, cfg.Device.Name)
	}
	if cfg.API.Listen != DefaultAPI || cfg.Shutdown.DrainDelay != 10*time.Second {
		t.Errorf("api %q drain %v", cfg.API.Listen, cfg.Shutdown.DrainDelay)
	}
	if len(cfg.Tailnets) != 2 || cfg.Tailnets[0].Name != "home" || cfg.Tailnets[1].Name != "work" {
		t.Fatalf("tailnets: %+v", cfg.Tailnets)
	}
	home := cfg.Tailnets[0]
	if home.Hostname != "edge" || len(home.Routes) != 2 || len(home.Services) != 1 || home.Services[0] != "svc:web" {
		t.Errorf("home: %+v", home)
	}
	if cfg.Tailnets[1].Hostname != "work" {
		t.Errorf("work's hostname defaults to its name, got %q", cfg.Tailnets[1].Hostname)
	}
}

func TestRefused(t *testing.T) {
	for _, tc := range []struct {
		name, yaml, want string
	}{
		{"no tailnets", `prefix: fdcc:79e6::/32`, "no tailnets"},
		{"a global prefix", "prefix: 2001:db8::/32\ntailnets: {a: {id: 1, stateDir: /a}}", "unique local"},
		{"id 0", "tailnets: {a: {id: 0, stateDir: /a}}", "between 1 and 255"},
		{"the same id twice", "tailnets: {a: {id: 1, stateDir: /a}, b: {id: 1, stateDir: /b}}", "twice"},
		{"no stateDir", "tailnets: {a: {id: 1}}", "stateDir is required"},
		{"a shared stateDir", "tailnets: {a: {id: 1, stateDir: /s}, b: {id: 2, stateDir: /s}}", "share stateDir"},
		{"two auth keys", "tailnets: {a: {id: 1, stateDir: /a, authKey: k, authKeyFile: /k}}", "mutually exclusive"},
		{"a client ID without tags", "tailnets: {a: {id: 1, stateDir: /a, clientID: c}}", "requires advertiseTags"},
		{"a Service without tags", "tailnets: {a: {id: 1, stateDir: /a, services: [web]}}", "requires advertiseTags"},
		{"a route with host bits", "tailnets: {a: {id: 1, stateDir: /a, routes: [10.0.0.1/24]}}", "did you mean"},
		{"an IPv6 route in no space", "tailnets: {a: {id: 1, stateDir: /a, routes: ['2001:db8::/64']}}", "needs an ipv6Spaces entry"},
		{"a space too short", "tailnets: {a: {id: 1, stateDir: /a, ipv6Spaces: {2: '2001:db8::/32'}}}", "shorter than /48"},
		{"space 1", "tailnets: {a: {id: 1, stateDir: /a, ipv6Spaces: {1: '2001:db8::/64'}}}", "numbered 2 to 15"},
		{"a misspelled field", "tailnets: {a: {id: 1, stateDir: /a, advertizeTags: [tag:x]}}", "advertizeTags"},
		{"a bad drain delay", "shutdown: {drainDelay: soon}\ntailnets: {a: {id: 1, stateDir: /a}}", "not a duration"},
	} {
		_, err := Parse([]byte(tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error containing %q", tc.name, err, tc.want)
		}
	}
}

func TestIPv6RouteInItsSpace(t *testing.T) {
	cfg, err := Parse([]byte(`
tailnets:
  a:
    id: 1
    stateDir: /a
    routes: ['2001:db8:1:2::/64', 'fd7a:115c:a1e0:b1a::/64']
    ipv6Spaces: {2: '2001:db8:1::/48'}
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Tailnets[0].Routes) != 2 {
		t.Errorf("routes: %v", cfg.Tailnets[0].Routes)
	}
}

func TestAPIOff(t *testing.T) {
	cfg, err := Parse([]byte("api: {listen: \"off\"}\ntailnets: {a: {id: 1, stateDir: /a}}"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.API.Listen != "" {
		t.Errorf("listen %q", cfg.API.Listen)
	}
}

func TestDNS(t *testing.T) {
	cfg, err := Parse([]byte("tailnets: {a: {id: 1, stateDir: /a, dnsDomains: [Corp.Example., lab.internal]}}"))
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(cfg.DNS.Listen); got != "[[fdcc:79e6::53]:53]" {
		t.Errorf("default listen %s", got)
	}
	if cfg.DNS.Upstream != nil || cfg.DNS.ResolvConf != DefaultResolvConf {
		t.Errorf("default upstream %v from %s", cfg.DNS.Upstream, cfg.DNS.ResolvConf)
	}
	if got := cfg.Tailnets[0].DNSDomains; !slices.Equal(got, []string{"corp.example", "lab.internal"}) {
		t.Errorf("dnsDomains %v", got)
	}

	cfg, err = Parse([]byte("dns: {listen: ['127.0.0.1', '[fdcc:79e6::5353]:5353'], upstream: ['10.152.183.10', '[2001:db8::53]:5300']}\ntailnets: {a: {id: 1, stateDir: /a}}"))
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(cfg.DNS.Listen, cfg.DNS.Upstream); got != "[127.0.0.1:53 [fdcc:79e6::5353]:5353] [10.152.183.10:53 [2001:db8::53]:5300]" {
		t.Errorf("explicit: %s", got)
	}

	cfg, err = Parse([]byte("dns: {disabled: true}\ntailnets: {a: {id: 1, stateDir: /a}}"))
	if err != nil || len(cfg.DNS.Listen) != 0 {
		t.Errorf("disabled: %v %v", cfg.DNS.Listen, err)
	}

	for _, tc := range []struct{ yaml, want string }{
		{"dns: {listen: ['[fdcc:79e6:100::53]:53']}", "only fdcc:79e6::/40"},
		{"dns: {upstream: ['fdcc:79e6::53']}", "is the gateway itself"},
		{"dns: {listen: ['127.0.0.1:53'], upstream: ['127.0.0.1']}", "is the gateway itself"},
		{"dns: {upstream: [resolver.example]}", "dns.upstream"},
		{"tailnets: {a: {id: 1, stateDir: /a, dnsDomains: ['bad name']}}", "not a domain"},
	} {
		y := tc.yaml
		if !strings.Contains(y, "tailnets") {
			y += "\ntailnets: {a: {id: 1, stateDir: /a}}"
		}
		if _, err := Parse([]byte(y)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.yaml, err, tc.want)
		}
	}
}
