package gateway

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/netip"
	"strings"

	"github.com/davefinster/multits/internal/addr"
)

// The headers GET /identify answers with. They say who made a request, by
// its tailnet's own account, for an application to pass to the backend
// behind it: what `tailscale serve` tells its backend, for a proxy that
// serves several tailnets and that its backends see as just one peer.
//
// Multits-Tags and the Multits-User-* headers are exclusive: a tagged node
// has no user behind it, so it carries its tags and nothing else.
const (
	// HeaderTailnet is the tailnet's name in the gateway's configuration.
	HeaderTailnet = "Multits-Tailnet"
	// HeaderAddress is the client's address on that tailnet.
	HeaderAddress = "Multits-Address"
	// HeaderNode is the client node's MagicDNS name, with no trailing dot.
	// Its domain is the tailnet's, which is what tells two tailnets' tags
	// apart: tag:ci on one is not tag:ci on another.
	HeaderNode = "Multits-Node"
	// HeaderTags are a tagged node's ACL tags, comma-separated.
	HeaderTags = "Multits-Tags"
	// HeaderUserLogin is the login name of the user who owns the node.
	HeaderUserLogin = "Multits-User-Login"
	// HeaderUserName is that user's display name. It and the login are
	// RFC 2047 encoded when they are not ASCII, as tailscale serve does.
	HeaderUserName = "Multits-User-Name"
)

// IdentityHeaders are all the headers /identify sets, for an application
// that removes them from what its clients send.
var IdentityHeaders = []string{HeaderTailnet, HeaderAddress, HeaderNode, HeaderTags, HeaderUserLogin, HeaderUserName}

// handleIdentify is an authentication server for Traefik's forwardAuth. The
// client's pseudo address arrives as the last entry of X-Forwarded-For,
// where forwardAuth puts the address of the connection it is asking about;
// with trustForwardHeader false, it is the only entry. The answer is 200
// with the identity headers, which authResponseHeadersRegex ^Multits- copies
// onto the request after deleting any the client sent, or 403 for a client
// that is not a peer on a tailnet, which Traefik returns to the client.
//
// The header is believed because the API listens on the loopback, for the
// application beside the gateway; anything that can reach it can already
// ask /whois about any address.
func (g *Gateway) handleIdentify(w http.ResponseWriter, r *http.Request) {
	client, err := forwardedClient(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a, err := g.scheme.Decode(client)
	if err == nil && a.Side != addr.Remote {
		err = errors.New("it is the gateway's own address")
	}
	if err != nil {
		writeError(w, http.StatusForbidden, fmt.Errorf("the client %s is not a peer on a tailnet: %w", client, err))
		return
	}
	node := g.byID[a.Tailnet]
	name := node.Config().Name
	who, err := node.WhoIs(r.Context(), netip.AddrPortFrom(a.IP, 0))
	if err == nil && (who == nil || who.Node == nil) {
		err = errors.New("no node")
	}
	if err != nil {
		writeError(w, http.StatusForbidden, fmt.Errorf("the client %s is unknown to %s: %w", a.IP, name, err))
		return
	}
	tagged := len(who.Node.Tags) > 0
	if !tagged && (who.UserProfile == nil || who.UserProfile.LoginName == "") {
		writeError(w, http.StatusForbidden, fmt.Errorf("the client %s on %s has neither tags nor a user", a.IP, name))
		return
	}

	h := w.Header()
	h.Set(HeaderTailnet, name)
	h.Set(HeaderAddress, a.IP.String())
	h.Set(HeaderNode, strings.TrimSuffix(who.Node.Name, "."))
	if tagged {
		h.Set(HeaderTags, strings.Join(who.Node.Tags, ","))
	} else {
		h.Set(HeaderUserLogin, mime.QEncoding.Encode("utf-8", who.UserProfile.LoginName))
		if n := who.UserProfile.DisplayName; n != "" {
			h.Set(HeaderUserName, mime.QEncoding.Encode("utf-8", n))
		}
	}
	writeJSON(w, http.StatusOK, WhoIs{Tailnet: name, ID: a.Tailnet, IP: a.IP, WhoIs: who})
}

// forwardedClient is the last address in X-Forwarded-For: the one the proxy
// asking appended itself.
func forwardedClient(r *http.Request) (netip.Addr, error) {
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return netip.Addr{}, errors.New("no X-Forwarded-For: /identify is for a proxy's forward authentication, which sends the client's address in it")
	}
	last := values[len(values)-1]
	if i := strings.LastIndexByte(last, ','); i >= 0 {
		last = last[i+1:]
	}
	a, err := netip.ParseAddr(strings.TrimSpace(last))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("X-Forwarded-For: %w", err)
	}
	return a.Unmap(), nil
}
