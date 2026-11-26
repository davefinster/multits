# syntax=docker/dockerfile:1
# multits: one gateway onto several tailnets for an unmodified application.
# See README.md.
#
# Build: docker buildx build --builder fleet --platform linux/amd64 --push -t ghcr.io/davefinster/multits .
# Run:   as a sidecar sharing the application's network namespace, with
#        CAP_NET_ADMIN, the configuration at /etc/multits/multits.yaml and
#        each tailnet's stateDir on a volume:
#          docker run --cap-add NET_ADMIN -v ./multits.yaml:/etc/multits/multits.yaml \
#            -v multits:/var/lib/multits ghcr.io/davefinster/multits

# ---- the gateway -----------------------------------------------------------
# The build stage runs on the build machine's own architecture and
# cross-compiles: the gateway is pure Go, so an arm64 machine builds the
# amd64 image with no emulation. The toolchain must be at least go.mod's go
# directive, which tailscale.com sets.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS TARGETARCH
ENV CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# The unit tests are the build gate. The end-to-end tests need root in
# network and mount namespaces of their own, and skip themselves here.
RUN go vet ./... && go test ./...
ARG VERSION=dev
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/multits ./cmd/multits

# ---- runtime ---------------------------------------------------------------
# distroless static: CA certificates for the control plane, and nothing
# else. It runs as root, which the gateway needs: CAP_NET_ADMIN for its TUN
# device, its routes and addresses, CAP_MKNOD to make /dev/net/tun where a
# runtime left it out, and port 53 for the resolver.
FROM gcr.io/distroless/static

LABEL org.opencontainers.image.title="multits" \
      org.opencontainers.image.description="A sidecar that puts an unmodified application on several tailnets at once, on stateless pseudo-IPv6 addresses" \
      org.opencontainers.image.source="https://github.com/davefinster/multits"

COPY --from=build /out/multits /usr/local/bin/multits
ENTRYPOINT ["/usr/local/bin/multits"]
CMD ["run", "-config", "/etc/multits/multits.yaml"]
