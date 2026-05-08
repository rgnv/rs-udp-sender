.PHONY: help build test test-root lint format fmt clean release bench coverage dev install docker

CARGO = cargo
TARGET = target/release

# Version from git describe, fallback to Cargo.toml version
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")

help:
	@echo "Available targets:"
	@echo "  help        Show this help"
	@echo "  build       Build all binaries (release)"
	@echo "  test        Run workspace tests"
	@echo "  test-root   Run root-required tests (feature: root-tests)"
	@echo "  lint        Run clippy with warnings denied"
	@echo "  format      Check formatting"
	@echo "  fmt         Apply formatting"
	@echo "  clean       Clean build artifacts"
	@echo "  release     Build and list release binaries"
	@echo "  bench       Run workspace benchmarks"
	@echo "  coverage    Generate HTML coverage report (cargo-tarpaulin)"
	@echo "  dev         Watch and run check+test"
	@echo "  install     Install binaries to /usr/local/bin"
	@echo "  docker      Build Docker image"

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

# Coverage (requires cargo-tarpaulin)
coverage:
	cargo tarpaulin --workspace --out Html --output-dir coverage
	@echo "Coverage report generated: coverage/tarpaulin-report.html"

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
