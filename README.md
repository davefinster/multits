# multits

A sidecar that puts an unmodified application on several tailnets at once.

The traefik-tsnet fork embeds a tsnet node per tailnet inside Traefik. This
is the other way round: the nodes live in a separate process, and the
application sees nothing of Tailscale at all. Every peer on every tailnet
arrives at the application as an ordinary IPv6 connection from an ordinary
IPv6 address. The application answers it the way it answers anything else,
and the gateway takes the answer back to the right tailnet. The gateway is
also the application's resolver, so a tailnet's names resolve to those
addresses too.

A tailnet's IPv4 addresses are unique only within that tailnet, and two
tailnets routinely hand out the same ones. Its IPv6 addresses aren't
reliably unique across tailnets either: Tailscale's original allocation
derives them from the IPv4 address, and the in-process test control plane
hands identical ones to two tailnets. So the gateway gives every address on
every tailnet a **pseudo IPv6 address** that also encodes which tailnet the
address is on. The mapping is deterministic and stateless: a packet's
addresses alone say where it goes. The gateway keeps no table of flows, and
two replicas with the same configuration map everything the same way.

```
 tailnet home ── WireGuard ── tsnet "home" ─┐
 tailnet work ── WireGuard ── tsnet "work" ─┼─ translator ─ multits0 (TUN) ─ kernel ─ app on [::]:443
 tailnet lab  ── WireGuard ── tsnet "lab"  ─┘                └──────── the application's network namespace ────────┘
```

## Pseudo addresses

Most significant bit first:

| bits   | field   | |
| ------ | ------- | --- |
| 0–31   | prefix  | the gateway's /32, unique local; default `fdcc:79e6::/32` |
| 32–39  | tailnet | 1–255, from the configuration; 0 is the gateway itself |
| 40–43  | side    | 0 a peer on the tailnet, 1 the gateway's own address there |
| 44–47  | space   | 0 IPv4, 1 Tailscale's `fd7a:115c:a1e0::/48`, 2–15 configured IPv6 prefixes |
| 48–127 | payload | 80 bits: the address |

The 80-bit payload holds everything that varies in a Tailscale IPv6
address, so both families convert both ways without loss. Read as hex, the
third group is tailnet, side and space, and the rest is the address. With
tailnet `home` as 1:

| on tailnet home | pseudo address |
| --- | --- |
| peer `100.64.0.5` | `fdcc:79e6:100::6440:5` |
| this gateway, `100.64.0.1` | `fdcc:79e6:110::6440:1` |
| peer `fd7a:115c:a1e0:ab12:4843:cd96:6240:5` | `fdcc:79e6:101:ab12:4843:cd96:6240:5` |
| advertised route address `198.51.100.10` | `fdcc:79e6:110::c633:640a` |
| advertised route `2001:db8:feed:…:acfc`, in space 2 | `fdcc:79e6:112:6ce8:d2b1:13c8:a553:acfc` |

A tailnet is a /40, each side of it a /44, and each space of a side a /48.
An IP allow list for "every peer on home" is `fdcc:79e6:100::/44`.

`multits check` prints the plan for a configuration, and `multits encode` /
`multits decode` convert single addresses.

IPv4 always encodes. IPv6 encodes when it is in Tailscale's range or in an
`ipv6Spaces` prefix configured for that tailnet; these exist for subnet
routes outside Tailscale's range. Anything else is dropped and counted as
`unencodable`. That only happens with IPv6 from behind a subnet router that
doesn't SNAT.

## Getting packets in and out

Nothing intercepts the application's packets: no netfilter, no eBPF, no
proxying. The gateway creates a TUN device in the application's network
namespace and installs ordinary routes, so the application's own sockets do
the rest:

| route | why |
| --- | --- |
| `local fdcc:79e6:T1::/44 dev lo table local` per tailnet | AnyIP. Every gateway address on the tailnet is the host's own, so a socket on `[::]` accepts connections to any of them with nothing assigned. This covers node addresses, Service VIPs and every address in an advertised route. |
| `fdcc:79e6:T00::/48 dev multits0 src <node's IPv4 pseudo>` | IPv4 peers. The application's replies and its own dials go into the device. |
| `fdcc:79e6:T00::/44 dev multits0 src <node's IPv6 pseudo>` | every other space of the peer side |
| `fdcc:79e6::/32 dev multits0` | everything else in the prefix, so a tailnet that isn't configured is answered with an ICMPv6 error (`network is unreachable`) instead of leaking out the default route |

The node's own addresses and its Services' VIPs are also assigned to the
device as /128s, for applications that bind one, and they become the routes'
preferred sources.

**MTU.** The device and its routes have the tailnet's MTU plus 48: 1328 for
Tailscale's 1280. That's room for an IPv6 packet carrying 1280 bytes of UDP,
which is what quic-go, and so Traefik's HTTP/3, sends its first packets
with, and with don't-fragment set. On an interface of the tailnet's own
1280, the kernel refuses every one of them. A packet from the host that the
tailnet can't carry whole is fragmented by the gateway, and the peer
reassembles it. TCP never needs that: the gateway clamps the MSS of every
SYN, in both directions, to what the tailnet carries (1240 for an IPv4 peer,
1220 for IPv6), even for a peer behind a subnet router that offers its
LAN's. The end-to-end tests check both: 4 MiB of TCP each way with nothing
fragmented, and a 1280-byte datagram sent with don't-fragment arriving
whole.

On the tailnet side, each node is a `tsnet.Server` given an in-memory
`tun.Device`. With one, tsnet hands the device every packet for the node's
addresses, its TUN-mode Service VIPs and its advertised routes. It keeps
only what one of its own sockets is waiting for (the PeerAPI). What the
device produces goes out over WireGuard as though an operating system had
sent it.

## Translation

- **IPv4 on a tailnet ↔ IPv6 on the host**: stateless IP/ICMP translation
  as RFC 7915 describes it. That covers the header, fragments (to and from
  IPv6 fragment headers), transport checksums (adjusted, not recomputed, per
  RFC 1624), and IPv4 UDP without a checksum (computed, since IPv6 requires
  one). Echo maps to ICMPv6 echo, and errors map to their ICMPv6 equivalents
  with the quoted packet translated too, so a port unreachable or a
  fragmentation needed still reaches the socket it's about. DF is set above
  1260 bytes, and an identification is generated below that.
- **IPv6 on a tailnet ↔ IPv6 on the host**: addresses rewritten, checksums
  adjusted, ICMPv6 errors' quoted packets rewritten. Neighbour discovery and
  MLD don't cross.
- **Refused from the host**: a source that isn't the gateway's own address
  on the destination's tailnet, or is in the wrong family, gets ICMPv6
  destination unreachable code 5 (connect fails with `EACCES`). An unknown
  tailnet gets code 0. A packet too big for the tailnet is fragmented (see
  MTU above), except an IPv6 one with extension headers, which gets Packet
  Too Big.

Translation costs about 40 ns per packet (`go test -bench . ./internal/xlat`).

## Names

The gateway is also the application's resolver, on the prefix's `::53`
(`[fdcc:79e6::53]:53`, UDP and TCP) unless `dns.listen` says otherwise.
Point the application's resolv.conf at it and it resolves tailnet names as
well as everything it did before:

- **A name in one of a tailnet's zones is asked of that tailnet's own
  resolver**, MagicDNS, through its node. A tailnet's zones are its
  MagicDNS suffix, its split-DNS domains, the names of its extra records
  (all three read from the node, and kept current) and any `dnsDomains`
  configured for it. When two tailnets claim a name, the longer zone wins,
  then the lower tailnet number.
- **The answer comes back on pseudo addresses.** Every A and AAAA record
  becomes an AAAA record of that address's pseudo address on that tailnet,
  IPv4-derived first, with the TTL MagicDNS gave. The gateway's own names
  and Service VIPs it hosts come back on its local side, so the
  application talks to itself without going round the tailnet. A query for
  A gets an empty answer, because a tailnet's IPv4 addresses aren't
  reachable from the host as themselves. NXDOMAIN, CNAMEs, and SRV, TXT
  and MX records pass through.
- **A pseudo address resolves back** to the name its tailnet gives the
  address (PTR in `ip6.arpa`).
- **Every other name goes to `dns.upstream` unchanged.** By default that's
  the name servers in `/etc/resolv.conf` other than the gateway's own. In
  a pod whose resolver is the gateway, that leaves none, so name the
  cluster's resolver explicitly.

| query | answer |
| --- | --- |
| `nas.tail1234.ts.net AAAA`, on tailnet 1 | `fdcc:79e6:100::6440:5` (and `fdcc:79e6:101:…` with `magicdns-aaaa`) |
| `nas.tail1234.ts.net A` | no records |
| `edge.tail1234.ts.net AAAA`, the gateway itself | `fdcc:79e6:110::6440:1` |
| `5.0.4.4.6.0…6.e.9.7.c.c.d.f.ip6.arpa PTR` | `nas.tail1234.ts.net.` |
| `kubernetes.default.svc.cluster.local A` | the upstream's answer |

On its default address, the resolver is out of the tailnets' reach. Peers
only ever address pseudo addresses on their tailnets' own blocks, never the
gateway's. A wildcard `dns.listen` would change that: every tailnet's peers
could resolve and forward through it.

MagicDNS gives a dual-stack peer's IPv6 address only when the tailnet
grants the `magicdns-aaaa` node attribute. Without it, a name resolves to
the IPv4-derived pseudo address alone. The gateway answers what the
tailnet's resolver says and nothing more.

## Running it

Requirements:

- Linux.
- `CAP_NET_ADMIN` in the application's network namespace.
- `/dev/net/tun`. The gateway creates the node if it's missing, which needs
  `CAP_MKNOD`.
- The application must listen on IPv6. Traefik's `address: ":443"` does;
  one bound to `0.0.0.0` won't see anything.

```sh
make build
multits check -config multits.yaml
multits run   -config multits.yaml
```

[`multits.example.yaml`](multits.example.yaml) documents every setting. Per
tailnet, the options follow traefik-tsnet's `tailnets` options: `stateDir`,
`authKey`/`authKeyFile`, `clientID`/`idTokenFile`, `controlURL`,
`ephemeral`, `advertiseTags`, `routes`, `services` (hosted in TUN mode),
`acceptRoutes`, and `id` and `ipv6Spaces` for the addressing. **A tailnet's
`id`, a space's number and the prefix are part of every pseudo address.**
Treat them like a network plan: never renumber or reuse them.

### Image

`ghcr.io/davefinster/multits` is built by
[`.github/workflows/image.yml`](.github/workflows/image.yml) for linux/amd64.
It builds on every push to main, tagged `latest` and `sha-<short commit>`,
and on a `v*` tag, tagged with the version. Pin deployments to a `sha-` tag.
Pull requests build without pushing. `go vet` and the unit tests run inside
the build, so an image that fails them is never pushed.

The image is distroless static: the binary and CA certificates. It runs as
root, which the gateway needs for `CAP_NET_ADMIN`, for making
`/dev/net/tun`, and for port 53. Its default command is `run -config
/etc/multits/multits.yaml`. `multits version` prints the commit it was built
from. `multits probe [URL]` GETs the local API, `/healthz` by default, and
fails unless it answers 200. It's an exec probe for an image with nothing
else in it, since the API listens on the loopback, where a kubelet's HTTP
probe can't reach.

The GHCR package took the repository's visibility when first published:
public, so a cluster pulls it with no `imagePullSecret`. To build without
the workflow:

```sh
docker buildx build --builder fleet --platform linux/amd64 --push -t ghcr.io/davefinster/multits:dev .
```

### As a Kubernetes sidecar

Containers in a pod share a network namespace, so the gateway's device and
routes are the application's.

```yaml
spec:
  # The gateway is the pod's resolver: tailnet names and everything else.
  dnsPolicy: None
  dnsConfig:
    nameservers: ["fdcc:79e6::53"]
    searches: [tail1234.ts.net, default.svc.cluster.local, svc.cluster.local, cluster.local]
    options: [{name: ndots, value: "5"}]
  initContainers:
    - name: multits            # a native sidecar: starts first, stops last
      image: ghcr.io/davefinster/multits:sha-…   # pin a build
      restartPolicy: Always
      args: [run, -config, /etc/multits/multits.yaml]   # with dns.upstream: [<cluster DNS>]
      securityContext:
        capabilities: {add: [NET_ADMIN]}
      # The app starts once the tailnets are joined and the resolver is up.
      startupProbe:
        httpGet: {host: 127.0.0.1, port: 9099, path: /healthz}
        periodSeconds: 1
        failureThreshold: 120
      volumeMounts:
        - {name: multits-config, mountPath: /etc/multits}
        - {name: multits-state, mountPath: /var/lib/multits}
  containers:
    - name: traefik
      image: traefik:v3.8
      args: [--entryPoints.websecure.address=:443, …]
      lifecycle:
        # A native sidecar gets SIGTERM only once the app has exited: too
        # late to move peers to another replica while the app drains. So
        # the app's own preStop withdraws the gateway's routes and Services
        # first. The gateway stays joined, and the app keeps answering what
        # still arrives.
        preStop:
          exec:
            command: [wget, -q, -O-, --post-data=, http://127.0.0.1:9099/withdraw]
```

The pod's resolv.conf is the gateway's own too. tsnet's lookups of the
control plane go through the gateway's resolver, to the upstream, which is
why the resolver starts before the nodes join.

`/withdraw` takes POST only, which is why the hook is an `exec` rather than
an `httpGet`. Traefik's image has busybox `wget`.

### With Traefik

An unmodified Traefik needs nothing tailnet-specific. Peers appear as
`ClientHost` in its access log and in `X-Forwarded-For`. A backend on a
tailnet is a URL with its MagicDNS name, which Traefik resolves through the
gateway like any other, or with a pseudo address. An allow list tells
tailnets apart by prefix:

```yaml
http:
  middlewares:
    home-only:
      ipAllowList:
        sourceRange: ["fdcc:79e6:100::/44"]     # every peer on tailnet 1
  services:
    nas:
      loadBalancer:
        servers:
          - url: "http://nas.tail5678.ts.net:8080"       # on tailnet 2, by name
          - url: "http://[fdcc:79e6:200::6440:7]:8080"   # or 100.64.0.7 on tailnet 2
```

## Local API

On `127.0.0.1:9099` by default (`api.listen`):

| | |
| --- | --- |
| `GET /status` | every tailnet: state, addresses with their pseudo addresses, routes, spaces, DNS zones, packet counts and drops by reason; the resolver's addresses and upstream |
| `GET /healthz` | 200 when every node is `Running`, 503 otherwise |
| `GET /whois?addr=A` | who is behind a peer's pseudo address (Tailscale's WhoIs, on the right tailnet); `[A]:port` works too |
| `GET /decode?addr=A`, `GET /encode?tailnet=T&ip=I&side=local\|remote` | the scheme |
| `POST /withdraw` | stop publishing routes and Services while staying joined |

`/whois` answers for every tailnet, so keep the API on the loopback.

## Tests

```sh
make test                                       # unit tests, no privileges
make test-netns                                 # end to end, root in scratch net and mount namespaces
make traefik                                    # fetch Traefik v3.8.0, checksum-verified
make test-netns TRAEFIK=dist/traefik-v3.8.0-arm64/traefik   # plus Traefik as the application
```

The end-to-end tests run two in-process control planes as two tailnets. In
each, the gateway and a client get identical IPv4 and IPv6 addresses. The
application is a plain kernel-socket server in the namespace (or Traefik).
The tests check that each tailnet reaches the app from a distinct pseudo
address, that the app's dials and replies reach the right tailnet, UDP, bulk
TCP both ways, advertised IPv4 and IPv6 routes arriving through AnyIP, ICMP
echo answered by the host kernel, whois, withdraw, and an unconfigured
tailnet failing fast.

For names, Go's resolver checks each tailnet's names, with and without
`magicdns-aaaa`, plus the gateway's own names, an extra record outside the
suffix, reverse lookups, NXDOMAIN, upstream passthrough, and dialling by
name. Traefik, last run as the upstream v3.8.0 release, reaches a backend on
the other tailnet by its MagicDNS name: the test mounts a resolv.conf naming
the gateway over `/etc/resolv.conf`, in the test's own mount namespace.

The tests refuse to run in a network namespace that has any interface but
`lo`, or to replace resolv.conf outside a mount namespace of their own.

## Limits and next steps

- **Names are only what the tailnet's resolver knows.** A single-label
  name needs a search domain: the gateway doesn't guess which tailnet
  `nas` is on. The gateway doesn't cache.
- **UDP from a wildcard socket replies from the node's address.** That's the
  kernel's source selection, through the routes' preferred source. A UDP
  service on a Service VIP or a routed address should bind that address, or
  use `IPV6_PKTINFO`, which quic-go does.
- **Exposure.** Everything listening on the wildcard address in the namespace
  is reachable from every tailnet, as far as its ACLs allow. That's the same
  as running tailscaled in the pod.
- **IPv6 outside Tailscale's range** needs an `ipv6Spaces` entry. Unencodable
  addresses are dropped and counted.
- **Fragmented IPv6 doesn't reach a netstack peer.** Through tailscale.com
  v1.104.7, a node on Tailscale's userspace netstack (tsnet, or tailscaled
  with `--tun=userspace-networking`) drops the first fragment of IPv6 TCP
  and UDP. `wgengine/netstack/gro.RXChecksumOffload` checks the transport
  checksum from the fragment header on, because its IPv6 branch doesn't
  skip fragments the way its IPv4 branch does. Kernel-mode nodes and IPv4
  are unaffected. The only fragments the gateway sends are UDP and ICMP
  larger than 1280 bytes, such as quic-go's first packets. So HTTP/3 to
  such a peer works over IPv4 and not IPv6 until that's fixed upstream.
  `TestFragmentsReassembleInGVisor` checks the fragments against gVisor
  itself.
- The host-to-tailnet path allocates per packet, and one device queue is the
  default. Neither has been profiled under load.
