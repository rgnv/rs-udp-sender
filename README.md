# rs-udp-sender — Fast UDP Packet Sender (Rust)

Rust workspace for high-throughput UDP packet generation and raw-socket sending with per-packet source/destination control.

This project is the Rust equivalent of [Cribl's Go `udp-sender`](https://github.com/criblio/udp-sender) and keeps the same wire protocol, feature set, and operational model.

## Features

- Dynamic IP spoofing per packet (source + destination IP)
- Dynamic port spoofing per packet (source + destination port)
- IPv4 and IPv6 support
- Raw socket sender (manual IP/UDP header construction)
- Configurable MTU (`576..=9000`, default `1500`)
- Binary streaming protocol over stdin/stdout
- SNMP trap generation support (v1, v2c, v3)
- Structured ND-JSON logging
- Docker-friendly runtime (`--cap-add=NET_RAW`)

## Binaries

This workspace builds three binaries:

- `rs-udp-sender`
- `rs-udp-packet-generator`
- `rs-udp-snmp-trap-generator`

## Requirements

- Rust toolchain (workspace currently targets edition 2024)
- Linux/macOS for raw socket use (Windows raw-socket path is not supported here)
- Root privileges or Linux `CAP_NET_RAW`

## Installation

### cargo install

Install from local workspace:

```bash
cargo install --path crates/udp-sender --bin rs-udp-sender
cargo install --path crates/packet-generator --bin rs-udp-packet-generator
cargo install --path crates/snmp-trap-generator --bin rs-udp-snmp-trap-generator
```

Or install from git (example):

```bash
cargo install --git https://github.com/rgnv/rs-udp-sender --bin rs-udp-sender
cargo install --git https://github.com/rgnv/rs-udp-sender --bin rs-udp-packet-generator
cargo install --git https://github.com/rgnv/rs-udp-sender --bin rs-udp-snmp-trap-generator
```

### Make install

```bash
make build
sudo make install
```

This installs binaries to `/usr/local/bin`.

### Docker

```bash
docker build -t rs-udp-sender:latest .

# Generator + sender pipeline in container
rs-udp-packet-generator --count 10 --dest-ip 192.168.1.100 --dest-port 514 | \
  docker run --rm -i --cap-add=NET_RAW rs-udp-sender:latest rs-udp-sender
```

Important: raw sockets require `--cap-add=NET_RAW`.

## Usage

### 1) Send generated packets

```bash
rs-udp-packet-generator --count 100 --dest-ip 192.168.1.100 --dest-port 514 | \
  sudo rs-udp-sender
```

### 2) IPv6 stream

```bash
rs-udp-packet-generator --ipv6 --base-ip 2001:db8::1 --dest-ip 2001:db8::100 --dest-port 8080 --count 50 | \
  sudo rs-udp-sender
```

### 3) Custom MTU

```bash
rs-udp-packet-generator --count 100 --dest-ip 192.168.1.100 --dest-port 514 | \
  sudo rs-udp-sender --mtu 9000
```

### 4) SNMP v2c traps

```bash
rs-udp-snmp-trap-generator --version 2c --count 100 --dest-ip 192.168.1.100 --dest-port 162 | \
  sudo rs-udp-sender
```

### 5) SNMP v3 traps (basic support)

```bash
rs-udp-snmp-trap-generator --version 3 --count 10 --dest-ip 192.168.1.100 --dest-port 162 \
  --security-name myuser --auth-proto SHA --auth-pass "myauthpass123456" \
  --priv-proto AES --priv-pass "myprivpass123456" | \
  sudo rs-udp-sender
```

Note: v3 auth/priv key derivation is not fully implemented yet; auth/priv combinations currently return `KeyInitFailed`.

## CLI Reference

### rs-udp-sender

```text
Usage: rs-udp-sender [OPTIONS]

Options:
  -h, --help        Show help
  -V, --version     Print version and exit
  -v, --verbose     Enable debug logs
  -m, --mtu <bytes> Maximum Transmission Unit (default: 1500, range: 576-9000)
```

### rs-udp-packet-generator

```text
Usage: rs-udp-packet-generator [OPTIONS]

Options:
  --base-ip <ip>        Base source IP, incremented per packet (default: 10.0.0.1)
  --base-port <port>    Base source port (default: 5000)
  --count <n>           Packet count (default: 10)
  --dest-ip <ip>        Destination IP (default: 192.168.1.100)
  --dest-port <port>    Destination port (default: 514)
  --ipv6                Generate IPv6 packets
  --message <text>      Message template (default: "Test packet")
  -h, --help            Show help
```

### rs-udp-snmp-trap-generator

```text
Usage: rs-udp-snmp-trap-generator [OPTIONS]

Options:
  --count <n>                Number of traps (default: 10)
  --version <1|2c|3>         SNMP version (default: 2c)
  --community <string>       Community string for v1/v2c (default: public)
  --base-ip <ip>             Base source IP (default: 10.0.0.1)
  --base-port <port>         Base source port (default: 161)
  --dest-ip <ip>             Destination IP (default: 192.168.1.100)
  --dest-port <port>         Destination port (default: 162)
  --trap-oid <oid>           Trap OID (default: 1.3.6.1.6.3.1.1.5.1)
  --enterprise <oid>         Enterprise OID for v1 (default: 1.3.6.1.4.1.99999)
  --security-name <user>     SNMPv3 username
  --auth-proto <proto>       SNMPv3 auth protocol
  --auth-pass <pass>         SNMPv3 auth passphrase
  --priv-proto <proto>       SNMPv3 privacy protocol
  --priv-pass <pass>         SNMPv3 privacy passphrase
  --ipv6                     Generate IPv6 packets
  --message <text>           Message in sysDescr varbind
  -h, --help                 Show help
```

## Performance

Benchmarks run on 10M packets (1400B payload each, ~13GB total payload).

### Generator Throughput (Linux, single thread)
| Generator | Time | Throughput | Memory |
|-----------|------|-----------|--------|
| Go packet-generator | 20.09s | ~650 MB/s | 9.4 MB |
| Rust packet-generator | 3.58s | ~3.64 GB/s | 2.5 MB |

The Rust generator is **5.6x faster** and uses **3.7x less memory**.

### Sender Pipeline (generate + parse + build + raw socket send)
Both senders are bottlenecked by raw socket throughput, not CPU. 
The Rust sender has lower base overhead (~1.2 MB vs ~3.5 MB binary size).
Pipeline throughput for both is dominated by generator speed.

## Protocol and Design Docs

- [DESIGN.md](./DESIGN.md)
- [PROTOCOL.md](./PROTOCOL.md)
- [SNMP.md](./SNMP.md)

## Makefile Reference

| Target | Description |
|--------|-------------|
| `make build` | Build all workspace binaries (release) |
| `make test` | Run workspace tests |
| `make test-root` | Run root-required tests (`root-tests` feature) |
| `make lint` | Run clippy with warnings denied |
| `make format` | Check formatting |
| `make fmt` | Apply formatting |
| `make clean` | Clean build artifacts |
| `make release` | Build and list release binaries |
| `make bench` | Run benchmarks |
| `make install` | Install binaries to `/usr/local/bin` |
| `make docker` | Build Docker image |

## Security Notes

- Raw socket capabilities are powerful; use in controlled environments.
- Prefer Linux `CAP_NET_RAW` over running as full root where possible.
- IP spoofing can violate policy/law in some environments; use only with authorization.
