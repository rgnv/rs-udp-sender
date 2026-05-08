# SNMP Trap Support

`rs-udp-sender` supports SNMP trap traffic generation and sending (v1, v2c, v3) with full IP/port spoofing via raw sockets.

Like syslog mode, the sender is payload-agnostic. `rs-udp-snmp-trap-generator` builds SNMP PDUs, wraps them in the binary protocol frames, and writes to stdout. `rs-udp-sender` reads frames and sends the payload bytes as UDP datagrams.

## How It Works

1. `rs-udp-snmp-trap-generator` encodes SNMP trap PDUs.
2. It wraps each PDU in the binary protocol frame:
   - magic
   - flags
   - source/destination IPs
   - source/destination ports
   - payload length
   - payload bytes
3. It writes frames to stdout.
4. `rs-udp-sender` parses frames and transmits raw IP+UDP packets.

```text
rs-udp-snmp-trap-generator -> [binary protocol stdout] -> rs-udp-sender -> [raw socket] -> network
```

## Version Support

### SNMPv1

- Supported
- Enterprise OID + classic trap fields
- Requires IPv4 agent address for v1 trap encoding

### SNMPv2c

- Supported
- Community-based trap PDU with standard varbinds (`sysUpTime.0`, `snmpTrapOID.0`)

### SNMPv3

- Basic message/PDU structure supported
- NoAuth/NoPriv works
- Auth/Priv key derivation is not fully implemented
- Auth or priv combinations currently return:
  - `KeyInitFailed("v3 key derivation not yet fully implemented — requires manual AES/DES key gen")`

## Supported SNMPv3 Auth Protocol Enum Values

The Rust implementation exposes these auth protocol variants:

- `NoAuth`
- `MD5`
- `SHA`
- `SHA224`
- `SHA256`
- `SHA384`
- `SHA512`

CLI mapping currently accepts and maps at least:

- `MD5`
- `SHA`
- `SHA256`
- empty value => `NoAuth`

## Supported SNMPv3 Privacy Protocol Enum Values

The Rust implementation exposes these privacy protocol variants:

- `NoPriv`
- `DES`
- `AES`
- `AES192`
- `AES256`
- `AES192C`
- `AES256C`

CLI mapping currently accepts and maps at least:

- `DES`
- `AES`
- empty value => `NoPriv`

## Examples

```bash
# v2c coldStart traps
rs-udp-snmp-trap-generator --version 2c --count 100 \
  --dest-ip 192.168.1.100 --dest-port 162 | sudo rs-udp-sender

# v1 traps with enterprise OID
rs-udp-snmp-trap-generator --version 1 --count 50 \
  --dest-ip 192.168.1.100 --dest-port 162 \
  --enterprise 1.3.6.1.4.1.99999 | sudo rs-udp-sender

# v3 trap generation attempt (auth/priv currently returns KeyInitFailed)
rs-udp-snmp-trap-generator --version 3 --count 10 \
  --dest-ip 192.168.1.100 --dest-port 162 \
  --security-name myuser --auth-proto SHA --auth-pass "myauthpass123456" \
  --priv-proto AES --priv-pass "myprivpass123456" | sudo rs-udp-sender

# spoofed source identities
rs-udp-snmp-trap-generator --version 2c --count 50 \
  --base-ip 10.0.0.1 --base-port 161 \
  --dest-ip 192.168.1.100 --dest-port 162 | sudo rs-udp-sender

# save and replay
rs-udp-snmp-trap-generator --version 2c --count 1000 \
  --dest-ip 192.168.1.100 > snmp-traps.bin
cat snmp-traps.bin | sudo rs-udp-sender

# jumbo MTU path
rs-udp-snmp-trap-generator --version 2c --count 100 \
  --dest-ip 192.168.1.100 | sudo rs-udp-sender --mtu 9000
```

## snmp-trap-generator Flags

```text
Usage: rs-udp-snmp-trap-generator [OPTIONS]

Options:
  --count <n>                Number of traps to generate (default: 10)
  --version <1|2c|3>         SNMP version (default: 2c)
  --community <string>       Community string for v1/v2c (default: public)
  --base-ip <ip>             Base source IP (default: 10.0.0.1)
  --base-port <port>         Base source port (default: 161)
  --dest-ip <ip>             Destination IP (default: 192.168.1.100)
  --dest-port <port>         Destination port (default: 162)
  --trap-oid <oid>           Trap OID (default: 1.3.6.1.6.3.1.1.5.1)
  --enterprise <oid>         Enterprise OID for v1 (default: 1.3.6.1.4.1.99999)
  --security-name <string>   SNMPv3 username
  --auth-proto <string>      SNMPv3 auth protocol
  --auth-pass <string>       SNMPv3 auth passphrase
  --priv-proto <string>      SNMPv3 privacy protocol
  --priv-pass <string>       SNMPv3 privacy passphrase
  --ipv6                     Generate IPv6 packets
  --message <string>         Message in sysDescr varbind
```

## Common Trap OIDs

| OID | Name | Description |
|-----|------|-------------|
| 1.3.6.1.6.3.1.1.5.1 | coldStart | Agent reinitializing, config may change |
| 1.3.6.1.6.3.1.1.5.2 | warmStart | Agent reinitializing, config unchanged |
| 1.3.6.1.6.3.1.1.5.3 | linkDown | Network interface went down |
| 1.3.6.1.6.3.1.1.5.4 | linkUp | Network interface came up |
| 1.3.6.1.6.3.1.1.5.5 | authenticationFailure | SNMP auth failure |

## Dependencies

SNMP encoding is implemented with:

- `rasn`
- `rasn-snmp`
- `rasn-smi`

These handle ASN.1/BER structures and SNMP message models used by the generator.
