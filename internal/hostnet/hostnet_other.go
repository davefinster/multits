//go:build !linux

package hostnet

import (
	"errors"
	"log/slog"
	"net/netip"

	"github.com/davefinster/multits/internal/addr"
	"github.com/tailscale/wireguard-go/tun"
)

// Options configure the device.
type Options struct {
	Name       string
	TailnetMTU int
	Queues     int
}

// Interface is unavailable off Linux.
type Interface struct{}

// Open fails: the gateway's host side is Linux's TUN and routing.
func Open(*addr.Scheme, []uint8, Options, *slog.Logger) (*Interface, error) {
	return nil, errors.New("the host device needs Linux")
}

func (*Interface) SetLocal(uint8, []netip.Addr, []netip.Addr) error { return nil }
func (*Interface) AddGatewayAddress(netip.Addr) error               { return nil }
func (*Interface) Device() tun.Device                               { return nil }
func (*Interface) Name() string                                     { return "" }
func (*Interface) Close() error                                     { return nil }
