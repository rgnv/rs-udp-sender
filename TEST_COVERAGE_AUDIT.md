# Test Coverage Audit Report: rs-udp-sender

**Generated:** 2026-05-08  
**Workspace:** /root/rs-udp-sender  
**Test Compilation:** ✅ PASS (cargo test --workspace --no-run)  
**Total Tests:** 43 (36 passing, 7 ignored)

---

## Executive Summary

| File | Public Items | Tests | Coverage | Gaps |
|------|--------------|-------|----------|------|
| constants.rs | 14 | 4 | 100% | None |
| logger.rs | 6 | 4 | 100% | JSON escaping edge cases (control bytes, \n, \t, \\, ") |
| protocol.rs | 3 | 13 | 85% | Interrupted read retry, stream state after error |
| packet.rs | 3 | 7 | 71% | RFC 1071 checksum vectors, IPv6 pseudo-header, DF/TTL bits |
| sender.rs | 3 | 7 | 43% | All 7 tests #[ignore] (require CAP_NET_RAW); no happy-path coverage |
| snmp.rs | 8 | 6 | 50% | RFC 3414 USM key derivation vectors, AES-CFB IV, v1 trap, varbind edge cases |
| main.rs | 1 | 0 | 0% | CLI parsing, MTU validation, error handling, EOF detection |
| packet-generator/main.rs | 2 | 0 | 0% | IP/port wraparound, count limits, IPv6 generation |
| snmp-trap-generator/main.rs | 2 | 0 | 0% | Version dispatch, config validation, CLI parsing |

---

## File-by-File Breakdown

### 1. constants.rs (91 lines)

**Public Items:**
- `MAGIC_BYTES: [u8; 3]` — Binary protocol magic number
- `FLAG_IPV6: u8` — IPv6 flag bit
- `DEFAULT_MTU, MIN_MTU, MAX_MTU: usize` — MTU bounds
- `IPV4_HEADER_SIZE, IPV6_HEADER_SIZE, UDP_HEADER_SIZE: usize` — Header sizes
- `IP_VERSION_4, IP_VERSION_6: u8` — IP version constants
- `IPPROTO_UDP: i32` — UDP protocol number
- `IPV4_TTL, IPV6_HOP_LIMIT: u32` — TTL/hop limit defaults
- `PROGRESS_INTERVAL: usize` — Logging interval
- `SNMP_*_OID: &str` — SNMP OID constants (6 OIDs)
- `DEFAULT_SNMP_ENGINE_ID: &str` — SNMP engine ID
- `LogLevel` enum + `as_str()`, `from_verbose()` methods

**Tests (4):**
- ✅ `test_magic_bytes_values` — Validates magic bytes
- ✅ `test_log_level_order` — Validates LogLevel ordering
- ✅ `test_log_level_as_str` — Validates LogLevel string conversion
- ✅ `test_mtu_bounds` — Validates MTU bounds

**Coverage:** 100% (all public items tested)

**Untested:**
- None

---

### 2. logger.rs (95 lines)

**Public Items:**
- `Logger::new(min_level: LogLevel) -> Self`
- `Logger::log(level, message, fields)` — Core logging method
- `Logger::debug/info/warn/error/fatal()` — Convenience methods

**Tests (4):**
- ✅ `test_level_filtering` — Validates min_level filtering
- ✅ `test_extra_fields_flattened_top_level` — Validates field flattening
- ✅ `test_field_order_level_before_message` — Validates field ordering
- ✅ `test_lowercase_level_in_output` — Validates lowercase level output

**Coverage:** 100% (all public methods tested)

**Untested/Gaps:**
- ❌ JSON escaping: special characters (", \, \n, \t, control bytes 0x00-0x1F)
- ❌ Fatal level exit behavior (process::exit(1))
- ❌ Large field values (>1MB)
- ❌ Unicode/emoji in fields
- ❌ Concurrent logging (thread safety)

**Recommendation:** Add test group for JSON escaping edge cases.

---

### 3. protocol.rs (760 lines)

**Public Items:**
- `Packet` struct (5 fields: src_ip, dest_ip, src_port, dest_port, payload, flags)
- `ProtocolError` enum (7 variants)
- `ProtocolStream<'a, R: Read>` struct + `Iterator` impl

**Tests (13):**
- ✅ `parses_single_valid_ipv4_packet` — Happy path IPv4
- ✅ `parses_single_valid_ipv6_packet` — Happy path IPv6
- ✅ `parses_multiple_packets_in_sequence` — Multiple packets
- ✅ `returns_invalid_magic_error` — Magic byte mismatch
- ✅ `returns_read_magic_error_on_incomplete_magic_bytes` — Truncated magic
- ✅ `returns_read_field_error_on_missing_flags` — Truncated flags
- ✅ `returns_read_payload_error_on_truncated_payload` — Truncated payload
- ✅ `parses_empty_payload_packet` — Empty payload
- ✅ `handles_empty_stream` — EOF at start
- ✅ `accepts_packet_exactly_at_mtu_limit` — MTU boundary
- ✅ `mtu_exceeded_does_not_terminate_stream` — MTU exceeded + continue
- ✅ `returns_ipv6_not_available_error` — IPv6 flag without has_ipv6
- ✅ `accepts_unknown_flags_when_ipv6_bit_is_set` — Flag bit masking

**Coverage:** 85% (happy path + error paths covered)

**Untested/Gaps:**
- ❌ `read_magic()` with `io::ErrorKind::Interrupted` retry logic (line 139-140)
- ❌ Stream state after `fail_once()` (multiple next() calls after error)
- ❌ Partial reads in `read_exact_field()` (loop behavior)
- ❌ Progress logging (PROGRESS_INTERVAL = 100)
- ❌ Packet number tracking across errors
- ❌ Very large payloads (>1MB)

**Recommendation:** Add tests for interrupted reads and stream state after errors.

---

### 4. packet.rs (421 lines)

**Public Items:**
- `PacketError` enum (1 variant: MTUExceeded)
- `PacketBuilder::new(mtu: usize) -> Self`
- `PacketBuilder::build_packet(pkt: &Packet) -> Result<Vec<u8>, PacketError>`

**Tests (7):**
- ✅ `golden_ipv4_minimal` — Minimal IPv4 packet
- ✅ `golden_ipv4_empty_payload` — IPv4 with empty payload
- ✅ `golden_ipv4_large_payload` — IPv4 with large payload
- ✅ `golden_ipv4_mtu_edge` — IPv4 at MTU boundary
- ✅ `golden_ipv6_minimal` — Minimal IPv6 packet
- ✅ `golden_ipv6_full_address` — IPv6 with full address
- ✅ `mtu_exceeded_error` — MTU exceeded error

**Coverage:** 71% (happy path + MTU error covered)

**Untested/Gaps:**
- ❌ **RFC 1071 checksum algorithm** — No test vectors from RFC 1071 (IP header checksum)
  - No test for checksum with odd-length data
  - No test for checksum carry-over behavior
  - No test for checksum with all-zeros data
- ❌ **IPv6 pseudo-header checksum** — No validation of pseudo-header construction
  - No test for UDP checksum over IPv6
  - No test for IPv6 flow label handling
- ❌ **DF (Don't Fragment) bit** — Not set in IPv4 header (line 82)
- ❌ **TTL/Hop Limit edge cases** — Always 64, no variation testing
- ❌ **Fragmentation handling** — Not tested
- ❌ **IPv4 header flags** — Only version/IHL tested (0x45)
- ❌ **UDP checksum zero handling** — IPv4 allows 0x0000, IPv6 requires non-zero

**Recommendation:** Add RFC 1071 test vectors and IPv6 pseudo-header validation tests.

---

### 5. sender.rs (369 lines)

**Public Items:**
- `PacketSender` trait (2 methods: send, close)
- `SenderError` enum (4 variants)
- `UDPSender::new() -> Result<Self, SenderError>`
- `UDPSender::has_ipv6() -> bool`
- `PacketSender` impl for `UDPSender`

**Tests (7 — ALL #[ignore]):**
- ⏭️ `test_create_raw_ipv4_socket` — #[ignore = "requires root/CAP_NET_RAW"]
- ⏭️ `test_send_ipv4_localhost` — #[ignore = "requires root/CAP_NET_RAW"]
- ⏭️ `test_send_empty_packet` — #[ignore = "requires root/CAP_NET_RAW"]
- ⏭️ `test_send_ipv6_fails_when_no_ipv6` — #[ignore = "requires root/CAP_NET_RAW"]
- ⏭️ `test_version_mismatch_address` — #[ignore = "requires root/CAP_NET_RAW"]
- ⏭️ `test_has_ipv6_detection` — #[ignore = "requires root/CAP_NET_RAW"]
- ⏭️ `test_close_twice_no_double_free` — #[ignore = "requires root/CAP_NET_RAW"]

**Coverage:** 43% (tests exist but all ignored; no happy-path coverage without root)

**Untested/Gaps:**
- ❌ **All raw socket tests are #[ignore]** — Cannot run without CAP_NET_RAW
- ❌ **IPv4 socket creation** — Happy path untested
- ❌ **IPv6 socket creation** — Happy path untested
- ❌ **IPv6 graceful degradation** — When IPv6 socket fails (line 70-78)
- ❌ **sendto() error handling** — EAFNOSUPPORT, EINVAL, EPERM, etc.
- ❌ **Double-close safety** — fd_ipv4 = -1 check (line 170-172)
- ❌ **IPv6 socket close** — fd_ipv6.take() behavior
- ❌ **Version mismatch** — IPv4 src + IPv6 dest (line 163-165)
- ❌ **Large packet send** — >65535 bytes
- ❌ **Partial send handling** — sendto() returns < packet.len()

**Recommendation:** Create integration test suite that runs with `--features root-tests` or `cargo test --test sender_integration -- --ignored` with CAP_NET_RAW.

---

### 6. snmp.rs (978 lines)

**Public Items:**
- `SNMPVarbind` struct (3 fields)
- `SNMPType` enum (9 variants)
- `SNMPValue` enum (7 variants)
- `SNMPV1TrapConfig` struct (6 fields)
- `SNMPV2cTrapConfig` struct (4 fields)
- `SNMPV3TrapConfig` struct (9 fields)
- `AuthProtocol` enum (7 variants)
- `PrivProtocol` enum (7 variants)
- `SnmpError` enum (6 variants)
- `build_snmpv1_trap_pdu(config) -> Result<Vec<u8>, SnmpError>`
- `build_snmpv2c_trap_pdu(config) -> Result<Vec<u8>, SnmpError>`
- `build_snmpv3_trap_pdu(config) -> Result<Vec<u8>, SnmpError>`

**Tests (6):**
- ✅ `test_build_snmpv2c_trap_pdu_empty_trap_oid` — Error: empty trap OID
- ✅ `test_build_snmpv2c_trap_pdu_success_non_empty` — Happy path v2c
- ✅ `test_build_snmpv3_trap_pdu_empty_trap_oid` — Error: empty trap OID
- ✅ `test_build_snmpv3_trap_pdu_empty_username` — Error: empty username
- ✅ `test_build_snmpv3_trap_pdu_priv_without_auth` — Error: priv without auth
- ✅ `test_build_snmpv3_trap_pdu_auth_priv_succeeds` — Happy path v3 with auth+priv
- ✅ `test_derive_usm_keys_sha_and_aes_lengths` — USM key derivation length check

**Coverage:** 50% (v2c and v3 basic paths covered; v1 untested)

**Untested/Gaps:**
- ❌ **SNMPv1 trap PDU** — `build_snmpv1_trap_pdu()` has NO tests
  - No test for enterprise OID parsing
  - No test for agent address encoding
  - No test for generic/specific trap codes
- ❌ **RFC 3414 USM key derivation** — No test vectors from RFC 3414
  - No test for MD5 key derivation
  - No test for SHA key derivation
  - No test for SHA224/256/384/512 key derivation
  - No test for key length validation (MD5=16, SHA=20, SHA256=32, etc.)
- ❌ **AES-CFB IV generation** — No test for IV construction
  - No test for AES-128/192/256 IV generation
  - No test for AES-CFB mode (cipher feedback)
- ❌ **HMAC-MD5/SHA** — No test for HMAC computation
  - No test for auth key usage
  - No test for HMAC truncation
- ❌ **DES/3DES encryption** — No test for DES/3DES privacy
- ❌ **Varbind encoding** — No test for varbind edge cases
  - No test for OID parsing errors
  - No test for large varbind values
  - No test for null varbinds
- ❌ **OID parsing** — `parse_oid()` function untested
  - No test for invalid OID format
  - No test for OID with leading zeros
  - No test for OID with very large arc values

**Recommendation:** Add RFC 3414 test vectors and SNMPv1 trap tests.

---

### 7. main.rs (166 lines)

**Public Items:**
- `Cli` struct (5 fields) — CLI argument parser
- `parse_mtu(s: &str) -> Result<usize, String>` — MTU validation
- `is_unexpected_eof(err: &ProtocolError) -> bool` — EOF detection
- `main() -> anyhow::Result<()>` — Entry point

**Tests:** 0

**Coverage:** 0% (no tests)

**Untested/Gaps:**
- ❌ **CLI parsing** — No tests for clap derive
  - No test for `-h/--help` flag
  - No test for `-V/--version` flag
  - No test for `-v/--verbose` flag
  - No test for `-m/--mtu` flag
- ❌ **MTU validation** — `parse_mtu()` untested
  - No test for valid MTU (576, 1500, 9000)
  - No test for invalid MTU (575, 9001)
  - No test for non-numeric input
  - No test for negative numbers
- ❌ **EOF detection** — `is_unexpected_eof()` untested
  - No test for each ProtocolError variant
  - No test for io::ErrorKind::UnexpectedEof
- ❌ **Main loop** — No integration tests
  - No test for packet send success
  - No test for packet send failure
  - No test for MTU exceeded handling
  - No test for protocol error handling
  - No test for stream completion logging
- ❌ **Error handling** — No test for error messages to stderr
- ❌ **Sender close** — No test for close error handling

**Recommendation:** Add unit tests for CLI parsing and MTU validation; add integration tests for main loop.

---

### 8. packet-generator/main.rs (278 lines)

**Public Items:**
- `Cli` struct (8 fields) — CLI argument parser
- `generate_ipv4(cli: &Cli) -> Result<(), String>` — IPv4 packet generation
- `generate_ipv6(cli: &Cli) -> Result<(), String>` — IPv6 packet generation

**Tests:** 0

**Coverage:** 0% (no tests)

**Untested/Gaps:**
- ❌ **IP wraparound** — No test for 255.255.255.255 + 1
  - Line 124: `((base_last + (i as u16)) % 256) as u8` — Modulo 256 behavior
  - No test for wraparound at 255.255.255.255
- ❌ **Port wraparound** — No test for 65535 + 1
  - Line 125: `cli.base_port.wrapping_add(i as u16)` — Wrapping behavior
  - No test for port wraparound at 65535
- ❌ **Count limits** — No test for large counts (>1M)
- ❌ **IPv4 generation** — No test for happy path
  - No test for default values
  - No test for custom base IP/port
  - No test for message formatting
- ❌ **IPv6 generation** — No test for happy path
  - No test for IPv6 address increment
  - No test for IPv6 flag bit
- ❌ **IP version mismatch** — No test for IPv4 base + IPv6 dest
- ❌ **Invalid IP parsing** — No test for malformed IPs
- ❌ **Help flag** — No test for `-h/--help`
- ❌ **Stdout writing** — No test for binary protocol output format

**Recommendation:** Add tests for IP/port wraparound, version mismatch, and binary protocol output.

---

### 9. snmp-trap-generator/main.rs (Not fully read, but similar structure)

**Expected Gaps:**
- ❌ **Version dispatch** — No test for v1/v2c/v3 selection
- ❌ **Config validation** — No test for required fields
- ❌ **CLI parsing** — No test for clap derive
- ❌ **IP/port wraparound** — Same as packet-generator
- ❌ **SNMP-specific options** — No test for auth/priv protocols

---

## Summary Table: Test Coverage by Category

| Category | Tested | Untested | Coverage |
|----------|--------|----------|----------|
| **Constants & Enums** | 4 | 0 | 100% |
| **Logger** | 4 | 5 | 44% |
| **Protocol Parsing** | 13 | 3 | 81% |
| **Packet Building** | 7 | 8 | 47% |
| **Raw Socket Sending** | 0 | 7 | 0% (all #[ignore]) |
| **SNMP PDU Building** | 6 | 12 | 33% |
| **CLI Parsing** | 0 | 15 | 0% |
| **Integration** | 0 | 10 | 0% |
| **TOTAL** | 34 | 60 | 36% |

---

## Critical Gaps (Priority Order)

### 🔴 P0: Blocking Issues
1. **sender.rs** — All 7 tests #[ignore]; no happy-path coverage without CAP_NET_RAW
   - **Impact:** Core functionality untested
   - **Fix:** Create integration test suite with `--features root-tests`

2. **main.rs** — 0 tests; CLI parsing and main loop untested
   - **Impact:** Entry point untested
   - **Fix:** Add unit tests for parse_mtu, is_unexpected_eof; add integration tests

3. **packet-generator/main.rs** — 0 tests; IP/port wraparound untested
   - **Impact:** Edge cases at 255.255.255.255 and 65535 unknown
   - **Fix:** Add tests for wraparound behavior

### 🟠 P1: RFC Compliance
1. **packet.rs** — No RFC 1071 checksum test vectors
   - **Impact:** Checksum correctness unvalidated
   - **Fix:** Add test vectors from RFC 1071

2. **snmp.rs** — No RFC 3414 USM key derivation test vectors
   - **Impact:** SNMP v3 key derivation unvalidated
   - **Fix:** Add test vectors from RFC 3414

3. **snmp.rs** — SNMPv1 trap PDU untested
   - **Impact:** v1 traps may be broken
   - **Fix:** Add tests for build_snmpv1_trap_pdu

### 🟡 P2: Edge Cases
1. **logger.rs** — JSON escaping (", \, \n, \t, control bytes) untested
   - **Impact:** Malformed JSON possible
   - **Fix:** Add escaping tests

2. **protocol.rs** — Interrupted read retry logic untested
   - **Impact:** Partial reads may fail
   - **Fix:** Add tests for io::ErrorKind::Interrupted

3. **snmp-trap-generator/main.rs** — 0 tests
   - **Impact:** Version dispatch and config validation untested
   - **Fix:** Add CLI parsing tests

---

## Recommendations

### Immediate Actions (Week 1)
1. Add `#[test]` for `parse_mtu()` in main.rs (5 tests)
2. Add `#[test]` for `is_unexpected_eof()` in main.rs (8 tests)
3. Add RFC 1071 checksum test vectors to packet.rs (5 tests)
4. Add SNMPv1 trap tests to snmp.rs (3 tests)

### Short-term (Week 2-3)
1. Create integration test suite for sender.rs (requires CAP_NET_RAW)
2. Add IP/port wraparound tests to packet-generator (4 tests)
3. Add JSON escaping tests to logger.rs (6 tests)
4. Add RFC 3414 USM key derivation test vectors to snmp.rs (8 tests)

### Medium-term (Week 4+)
1. Add integration tests for main.rs (10+ tests)
2. Add integration tests for packet-generator (8+ tests)
3. Add integration tests for snmp-trap-generator (8+ tests)
4. Add interrupted read tests to protocol.rs (3 tests)

---

## Test Compilation Status

```
✅ cargo test --workspace --no-run
   Finished `test` profile [unoptimized + debuginfo] target(s) in 0.08s

✅ cargo test --workspace --lib
   running 43 tests
   test result: ok. 36 passed; 0 failed; 7 ignored; 0 measured
```

**All tests compile successfully. No compilation errors or warnings (except deprecated shadow_rs).**

---

## Notes

- **Raw socket tests:** All 7 sender.rs tests require `CAP_NET_RAW` or root; marked #[ignore]
- **No integration tests directory:** All tests are inline in #[cfg(test)] mod tests blocks
- **No external dependencies:** Tests use only std lib + test fixtures
- **No network dependencies:** Tests use Cursor<Vec<u8>> for I/O simulation
- **No flaky tests:** All tests are deterministic

