.PHONY: build test test-root lint format clean release bench

CARGO = cargo
TARGET = target/release

# Version from git describe, fallback to Cargo.toml version
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")

build:
	$(CARGO) build --release

test:
	$(CARGO) test --workspace

# Root-required tests (raw sockets) — requires sudo or CAP_NET_RAW
test-root:
	$(CARGO) test --workspace --features root-tests

lint:
	$(CARGO) clippy --workspace -- -D warnings
	$(CARGO) clippy --workspace --all-features -- -D warnings

format:
	$(CARGO) fmt --check

fmt:
	$(CARGO) fmt

clean:
	$(CARGO) clean
	rm -rf $(TARGET)

release: build
	@echo "Release binaries in $(TARGET)/"
	@ls -lh $(TARGET)/rs-udp-sender $(TARGET)/rs-udp-packet-generator $(TARGET)/rs-udp-snmp-trap-generator

bench:
	$(CARGO) bench --workspace

# Development
dev:
	$(CARGO) watch -x check -x test

# Install locally
install: build
	install -m 755 $(TARGET)/rs-udp-sender /usr/local/bin/rs-udp-sender
	install -m 755 $(TARGET)/rs-udp-packet-generator /usr/local/bin/rs-udp-packet-generator
	install -m 755 $(TARGET)/rs-udp-snmp-trap-generator /usr/local/bin/rs-udp-snmp-trap-generator

docker:
	docker build -t rs-udp-sender:$(VERSION) .
