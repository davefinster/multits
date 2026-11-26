BIN ?= dist/multits
TEST_BIN ?= $(or $(TMPDIR),/tmp)/multits-gateway.test

.PHONY: build test test-netns lint traefik

# The Traefik release the end-to-end tests run as the application, checked
# against the release's published SHA-256.
TRAEFIK_VERSION := v3.8.0
TRAEFIK_SHA256_arm64 := 3c85f6f40ef10eddcdcce6f5416b2ba9a818ddcd900b1f9e4955b7bbb744a9fc
TRAEFIK_SHA256_amd64 := 266f4b02a3c9d16880c6d913053c6358df8163e296b6f0899ed4544d0a742bd6
GOARCH := $(shell go env GOARCH)
TRAEFIK_DIR := dist/traefik-$(TRAEFIK_VERSION)-$(GOARCH)

VERSION ?= $(shell git rev-parse HEAD 2>/dev/null || echo dev)

build:
	CGO_ENABLED=0 go build -ldflags="-X main.version=$(VERSION)" -o $(BIN) ./cmd/multits

test:
	go test ./...

# The end-to-end tests need root and change the network and /etc/resolv.conf:
# they run in network and mount namespaces of their own, which unshare makes
# and discards.
test-netns:
	go test -c -o $(TEST_BIN) ./internal/gateway
	sudo env MULTITS_NETNS=1 MULTITS_TRAEFIK=$(TRAEFIK) unshare --net --mount $(TEST_BIN) -test.run 'E2E' -test.v $(ARGS)

lint:
	go vet ./...
	gofmt -l .

# make traefik, then make test-netns TRAEFIK=dist/traefik-v3.8.0-$(GOARCH)/traefik
traefik: $(TRAEFIK_DIR)/traefik

$(TRAEFIK_DIR)/traefik:
	mkdir -p $(TRAEFIK_DIR)
	curl -fsSL -o $(TRAEFIK_DIR)/traefik.tar.gz https://github.com/traefik/traefik/releases/download/$(TRAEFIK_VERSION)/traefik_$(TRAEFIK_VERSION)_linux_$(GOARCH).tar.gz
	echo "$(TRAEFIK_SHA256_$(GOARCH))  $(TRAEFIK_DIR)/traefik.tar.gz" | sha256sum -c -
	tar -xzf $(TRAEFIK_DIR)/traefik.tar.gz -C $(TRAEFIK_DIR) traefik
	rm $(TRAEFIK_DIR)/traefik.tar.gz
