FROM rust:1.94-alpine AS planner
RUN cargo install cargo-chef --locked
WORKDIR /app
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM rust:1.94-alpine AS cacher
RUN apk add --no-cache musl-dev
RUN cargo install cargo-chef --locked
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

FROM rust:1.94-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY --from=cacher /app/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo
COPY . .
RUN cargo build --release --bin rs-udp-sender && \
    strip target/release/rs-udp-sender

FROM alpine:latest
RUN addgroup -S udp && adduser -S udp -G udp
COPY --from=builder /app/target/release/rs-udp-sender /usr/local/bin/rs-udp-sender
USER udp
ENTRYPOINT ["rs-udp-sender"]
