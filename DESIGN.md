# rs-udp-sender Design

## Overview

`rs-udp-sender` is a Cargo workspace with three crates:

1. `crates/udp-sender` (core library + sender binary)
2. `crates/packet-generator` (binary protocol packet generator)
3. `crates/snmp-trap-generator` (SNMP trap payload generator)

The core design goal matches the Go implementation: each packet can carry its own source/destination IP and ports, enabling fully dynamic spoofed traffic patterns.

## Workspace Architecture

```text
/root/rs-udp-sender
├── Cargo.toml                     # Workspace definition
├── Makefile                       # Build/test/lint/install helpers
└── crates/
    ├── udp-sender/
    │   ├── Cargo.toml
    │   └── src/
    │       ├── lib.rs
    │       ├── main.rs
    │       ├── constants.rs
    │       ├── logger.rs
    │       ├── protocol.rs
    │       ├── packet.rs
    │       ├── sender.rs
    │       └── snmp.rs
    ├── packet-generator/
    │   ├── Cargo.toml
    │   └── src/main.rs
    └── snmp-trap-generator/
        ├── Cargo.toml
        └── src/main.rs
```

## Data Flow

```text
rs-udp-packet-generator / rs-udp-snmp-trap-generator
    -> stdout (binary protocol stream)
    -> rs-udp-sender stdin
    -> ProtocolStream parser
    -> PacketBuilder (IP+UDP headers/checksums)
    -> UDPSender raw socket send
```

## Crate: udp-sender

### Purpose

Provides reusable primitives for parsing the binary stream, constructing IPv4/IPv6 UDP packets, structured logging, SNMP trap encoding helpers, and raw-socket transmission.

### Public exports (`src/lib.rs`)

- `pub mod constants`
- `pub mod logger`
- `pub mod packet`
- `pub mod protocol`
- `pub mod sender`
- `pub mod snmp`
- Re-exports: `Logger`, `PacketBuilder`, `ProtocolStream`, `UDPSender`, and constants.

### Module design

#### `constants.rs`
Responsibilities:
- Protocol constants (magic bytes, flags)
- MTU bounds and header sizes
- SNMP OID constants
- Logging level enum

Key public API:
- `MAGIC_BYTES`, `FLAG_IPV6`
- `DEFAULT_MTU`, `MIN_MTU`, `MAX_MTU`
- `IPV4_HEADER_SIZE`, `IPV6_HEADER_SIZE`, `UDP_HEADER_SIZE`
- `LogLevel`

#### `logger.rs`
Responsibilities:
- ND-JSON structured logging to stdout
- log-level filtering
- flattened top-level fields

Key public API:
- `Logger::new(min_level: LogLevel) -> Logger`
- `Logger::log(...)`
- Convenience methods: `debug`, `info`, `warn`, `error`, `fatal`

#### `protocol.rs`
Responsibilities:
- Parse the binary frame stream from any `Read`
- Validate magic, flags, address widths, and payload lengths
- Enforce MTU limits at parse stage
- Emit periodic progress logs

Key types/APIs:
- `Packet` (parsed frame)
- `ProtocolError`
- `ProtocolStream<'a, R: Read>` iterator
- `ProtocolStream::new(reader, has_ipv6, mtu, logger)`

Design note: `ProtocolStream` iterator replaces Go's `processInputStream` loop and makes packet parsing composable with Rust iterator ergonomics.

#### `packet.rs`
Responsibilities:
- Build full raw IPv4/IPv6 packets from parsed protocol packets
- Construct IP and UDP headers
- Compute checksums (IPv4 header + UDP pseudo-header checks)
- Enforce MTU before build

Key public API:
- `PacketBuilder::new(mtu)`
- `PacketBuilder::build_packet(&Packet) -> Result<Vec<u8>, PacketError>`
- `PacketError::MTUExceeded`

#### `sender.rs`
Responsibilities:
- Manage raw sockets (IPv4 required, IPv6 optional)
- Send already-built packet bytes with destination socket addressing
- Close and clean up descriptors

Key public API:
- `trait PacketSender`
  - `send(&mut self, packet, dest_ip, dest_port, src_ip, src_port)`
  - `close(&mut self)`
- `struct UDPSender`
  - `UDPSender::new()`
  - `UDPSender::has_ipv6()`

Design note: Rust `PacketSender` trait is the equivalent abstraction replacing the Go `PacketSender` interface.

#### `snmp.rs`
Responsibilities:
- Build SNMP trap PDUs (v1/v2c/v3) as payload bytes
- Represent varbinds and SNMP value types
- Validate configuration and return typed errors

Key public API:
- Config structs:
  - `SNMPV1TrapConfig`
  - `SNMPV2cTrapConfig`
  - `SNMPV3TrapConfig`
- Enums:
  - `SNMPType`, `SNMPValue`
  - `AuthProtocol`, `PrivProtocol`
- Functions:
  - `build_snmpv1_trap_pdu(...)`
  - `build_snmpv2c_trap_pdu(...)`
  - `build_snmpv3_trap_pdu(...)`

## Crate: packet-generator

### Purpose

CLI generator that writes protocol frames to stdout for `rs-udp-sender`.

Responsibilities:
- Parse CLI arguments (base/destination IPs and ports, count, message, IPv6 mode)
- Increment source IP/port per packet
- Encode each packet as binary protocol frame:
  - magic
  - flags
  - source/destination addresses
  - source/destination ports
  - payload length
  - payload bytes

Output is streaming-friendly and can be piped directly into `rs-udp-sender`.

## Crate: snmp-trap-generator

### Purpose

CLI generator that creates SNMP trap PDUs and wraps them in the same binary protocol frames.

Responsibilities:
- Parse SNMP configuration flags (version/community/security/auth/priv)
- Build version-specific SNMP payloads via `udp_sender::snmp`
- Increment source identity (IP/port) across generated traps
- Emit binary stream compatible with `rs-udp-sender`

## Error Handling Strategy

- Parsing errors are typed (`ProtocolError`) and include field context.
- Packet-build validation errors are typed (`PacketError`).
- Raw socket and send path errors are typed (`SenderError`).
- SNMP construction errors are typed (`SnmpError`).
- CLI binaries log and continue where safe (e.g., dropped oversized packets), otherwise return non-zero on fatal setup/runtime errors.

## Testing Strategy

- Unit tests in each module verify:
  - protocol parsing and corruption handling
  - golden packet bytes and checksum correctness
  - SNMP encoding behavior and validation
  - sender behavior in root-gated tests
- Root-only/raw-socket tests are gated with ignore/feature patterns and run via `make test-root`.

## Extensibility

The architecture keeps clear seams:

- `PacketSender` trait allows alternate transports or mock senders.
- `ProtocolStream` isolates wire parsing from send logic.
- `PacketBuilder` isolates packet construction/checksum logic.
- SNMP logic is payload-only and independent from raw socket sender.

This enables adding new generators, protocol extensions, or sender backends without rewriting the full pipeline.
