# syntax=docker/dockerfile:1.7
#
# Multi-stage build for rs-udp-sender. Pinned base images for reproducibility
# and supply-chain hygiene (trivy DS-0001).
#
# Build:
#   docker build --build-arg VERSION=0.0.1 -t rs-udp-sender:0.0.1 .
# Run (raw sockets require CAP_NET_RAW):
#   docker run --rm -i --cap-add=NET_RAW rs-udp-sender:0.0.1

FROM rust:1.94-alpine3.20 AS planner
RUN cargo install cargo-chef --locked
WORKDIR /app
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM rust:1.94-alpine3.20 AS cacher
RUN apk add --no-cache musl-dev
RUN cargo install cargo-chef --locked
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

FROM rust:1.94-alpine3.20 AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
ARG VERSION=dev
COPY --from=cacher /app/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo
COPY . .
RUN cargo build --release --bin rs-udp-sender && \
    strip target/release/rs-udp-sender

# Pinned runtime base (trivy DS-0001 fix).
FROM alpine:3.20
ARG VERSION=dev
RUN addgroup -S udp && adduser -S udp -G udp
COPY --from=builder /app/target/release/rs-udp-sender /usr/local/bin/rs-udp-sender
ENV RS_UDP_SENDER_VERSION=${VERSION}
LABEL org.opencontainers.image.version=${VERSION} \
      org.opencontainers.image.source="https://github.com/rgnv/rs-udp-sender" \
      org.opencontainers.image.title="rs-udp-sender" \
      org.opencontainers.image.description="High-throughput UDP packet sender with per-packet IP/port spoofing (Rust)" \
      org.opencontainers.image.licenses="Apache-2.0"
USER udp
# Liveness probe (trivy DS-0026 fix). The binary supports `--version`; exit 0
# means the binary is intact and runnable inside the container.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["rs-udp-sender", "--version"]
ENTRYPOINT ["rs-udp-sender"]
