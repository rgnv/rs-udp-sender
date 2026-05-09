# AGENTS.md — udp-sender core library

**Parent:** [Root AGENTS.md](../../AGENTS.md)

## OVERVIEW
Core crate: binary protocol parser, raw socket sender, SNMP trap builder. Library (`lib.rs`) + binary (`main.rs`).

## WHERE TO LOOK
| Module | File | Lines | Purpose |
|--------|------|-------|---------|
| `constants` | constants.rs | 88 | Magic bytes, MTU limits, SNMP OIDs, header sizes |
| `logger` | logger.rs | 231 | ND-JSON logging (custom, not tracing) |
| `protocol` | protocol.rs | 956 | Binary protocol stream parser + Iterator impl |
| `packet` | packet.rs | 612 | IP/UDP header builder, RFC 1071 checksums |
| `sender` | sender.rs | 369 | Raw socket sender (nix), `PacketSender` trait |
| `snmp` | snmp.rs | 1275 | SNMP v1/v2c/v3 trap PDU construction (rasn-snmp), full USM (auth+priv+INFORM) |
| `main` | main.rs | 340 | CLI entry point (clap derive) |

## CONVENTIONS
- Logger takes `(&str, &[(&str, &str)])` — string key only, no structured values
- `ProtocolStream::new()` takes `&Logger` — injected, not global
- Packet sizes computed as `ip_header + 8 (UDP) + payload.len()`
- MTU exceeded → logged + skipped, NOT fatal

## ANTI-PATTERNS
- Do NOT use `#[tokio::main]` or any async in this crate
- Do NOT add new pub exports to `lib.rs` without updating the root AGENTS.md WHERE TO LOOK table
- Do NOT change `Packet` struct fields without updating golden test vectors
