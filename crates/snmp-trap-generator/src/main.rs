use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use udp_sender::constants::{
    DEFAULT_SNMP_ENGINE_ID, FLAG_IPV6, MAGIC_BYTES, SNMP_SYS_DESCR_OID, SNMP_SYS_NAME_OID,
};
use udp_sender::snmp::{
    AuthProtocol, PrivProtocol, SNMPType, SNMPV1TrapConfig, SNMPV2cTrapConfig, SNMPV3TrapConfig,
    SNMPValue, SNMPVarbind, build_snmpv1_trap_pdu, build_snmpv2c_trap_pdu, build_snmpv3_trap_pdu,
};

const DEFAULT_TRAP_OID: &str = "1.3.6.1.6.3.1.1.5.1";
const DEFAULT_ENTERPRISE_OID: &str = "1.3.6.1.4.1.99999";

const HELP_TEXT: &str = "Usage of snmp-trap-generator:
  -count int
      Number of traps to generate (default 10)
  -version string
      SNMP version: 1, 2c, 3 (default \"2c\")
  -community string
      Community string (v1/v2c) (default \"public\")
  -base-ip string
      Base source IP (will increment) (default \"10.0.0.1\")
  -base-port int
      Base source port (default 161)
  -dest-ip string
      Destination IP (default \"192.168.1.100\")
  -dest-port int
      Destination port (default 162)
  -trap-oid string
      Trap OID (default \"1.3.6.1.6.3.1.1.5.1\")
  -enterprise string
      Enterprise OID (v1) (default \"1.3.6.1.4.1.99999\")
  -security-name string
      SNMPv3 USM username
  -auth-proto string
      SNMPv3 auth protocol (MD5, SHA, SHA256)
  -auth-pass string
      SNMPv3 auth passphrase
  -priv-proto string
      SNMPv3 privacy protocol (DES, AES)
  -priv-pass string
      SNMPv3 privacy passphrase
  -ipv6 bool
      Generate IPv6 packets
  -message string
      Message in sysDescr varbind (default \"SNMP trap from udp-sender\")

Description:
  Generates SNMP trap packets for consumption by udp-sender.
  Supports SNMPv1, v2c, and v3 trap PDUs.

Examples:
  Generate SNMPv2c traps:
    snmp-trap-generator

  Generate v3 traps with auth:
    snmp-trap-generator -version 3 -security-name myuser -auth-proto SHA -auth-pass secret123
";

#[derive(Parser, Debug)]
#[command(
    name = "snmp-trap-generator",
    disable_help_flag = true,
    disable_version_flag = true
)]
struct Args {
    #[arg(long = "count", default_value_t = 10)]
    count: usize,

    #[arg(long = "version", default_value = "2c")]
    version: String,

    #[arg(long = "community", default_value = "public")]
    community: String,

    #[arg(long = "base-ip", default_value = "10.0.0.1")]
    base_ip: String,

    #[arg(long = "base-port", default_value_t = 161)]
    base_port: u16,

    #[arg(long = "dest-ip", default_value = "192.168.1.100")]
    dest_ip: String,

    #[arg(long = "dest-port", default_value_t = 162)]
    dest_port: u16,

    #[arg(long = "trap-oid", default_value = DEFAULT_TRAP_OID)]
    trap_oid: String,

    #[arg(long = "enterprise", default_value = DEFAULT_ENTERPRISE_OID)]
    enterprise: String,

    #[arg(long = "security-name", default_value = "")]
    security_name: String,

    #[arg(long = "auth-proto", default_value = "")]
    auth_proto: String,

    #[arg(long = "auth-pass", default_value = "")]
    auth_pass: String,

    #[arg(long = "priv-proto", default_value = "")]
    priv_proto: String,

    #[arg(long = "priv-pass", default_value = "")]
    priv_pass: String,

    #[arg(long = "ipv6", default_value_t = false)]
    ipv6: bool,

    #[arg(long = "message", default_value = "SNMP trap from udp-sender")]
    message: String,

    #[arg(long = "is-inform", default_value_t = false)]
    is_inform: bool,
}

fn main() {
    if let Err(err) = run() {
        let _ = writeln!(io::stderr().lock(), "{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.iter().any(|a| a == "-h" || a == "--help") {
        let mut stderr = io::stderr().lock();
        stderr
            .write_all(HELP_TEXT.as_bytes())
            .map_err(|e| format!("failed to write help text: {e}"))?;
        return Ok(());
    }

    let normalized_args = normalize_go_style_flags(raw_args);
    let args = Args::try_parse_from(normalized_args).map_err(|e| e.to_string())?;

    let base_ip_addr = IpAddr::from_str(&args.base_ip)
        .map_err(|_| format!("Invalid base IP: {}", args.base_ip))?;
    let dest_ip_addr = IpAddr::from_str(&args.dest_ip)
        .map_err(|_| format!("Invalid destination IP: {}", args.dest_ip))?;

    let is_ipv6 = base_ip_addr.is_ipv6();
    if args.ipv6 && !is_ipv6 {
        return Err(format!(
            "IPv6 flag set but base IP is IPv4: {}",
            args.base_ip
        ));
    }
    if !args.ipv6 && is_ipv6 {
        return Err(format!(
            "IPv4 mode but base IP is IPv6: {} (use -ipv6 flag)",
            args.base_ip
        ));
    }

    if base_ip_addr.is_ipv6() != dest_ip_addr.is_ipv6() {
        return Err(format!(
            "Source and dest IP versions must match (src: {}, dest: {})",
            args.base_ip, args.dest_ip
        ));
    }

    let version = normalize_version(&args.version)?;
    if version == SNMPVersion::V3 && args.security_name.is_empty() {
        return Err("SNMPv3 requires --security-name".to_string());
    }

    {
        let mut stderr = io::stderr().lock();
        writeln!(
            stderr,
            "Generating {} SNMPv{} traps: {}:{} -> {}:{} (oid: {})",
            args.count,
            args.version,
            args.base_ip,
            args.base_port,
            args.dest_ip,
            args.dest_port,
            args.trap_oid
        )
        .map_err(|e| format!("failed to write status: {e}"))?;
    }

    let mut stdout = io::stdout().lock();
    for i in 0..args.count {
        let src_ip = increment_ip(base_ip_addr, i);
        let src_port = args.base_port.wrapping_add(u16::try_from(i & 0xFFFF).unwrap_or(0));
        let pdu_bytes = build_pdu(&args, version, src_ip, i)
            .map_err(|e| format!("Error encoding SNMP trap {}: {e}", i + 1))?;

        write_frame(
            &mut stdout,
            src_ip,
            src_port,
            dest_ip_addr,
            args.dest_port,
            &pdu_bytes,
            is_ipv6,
        )
        .map_err(|e| format!("failed to write output frame: {e}"))?;

        if (i + 1) % 100 == 0 {
            let mut stderr = io::stderr().lock();
            writeln!(stderr, "Generated {} traps...", i + 1)
                .map_err(|e| format!("failed to write progress: {e}"))?;
        }
    }

    let mut stderr = io::stderr().lock();
    writeln!(stderr, "Complete: generated {} traps", args.count)
        .map_err(|e| format!("failed to write completion: {e}"))?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SNMPVersion {
    V1,
    V2c,
    V3,
}

fn normalize_version(input: &str) -> Result<SNMPVersion, String> {
    match input.to_ascii_lowercase().as_str() {
        "1" | "v1" => Ok(SNMPVersion::V1),
        "2" | "2c" | "v2c" => Ok(SNMPVersion::V2c),
        "3" | "v3" => Ok(SNMPVersion::V3),
        _ => Err(format!("Unsupported SNMP version: {input}")),
    }
}

fn increment_ip(base_ip: IpAddr, i: usize) -> IpAddr {
    match base_ip {
        IpAddr::V4(base) => {
            let mut octets = base.octets();
            octets[3] = octets[3].wrapping_add(i as u8);
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        IpAddr::V6(base) => {
            let mut octets = base.octets();
            octets[15] = octets[15].wrapping_add(i as u8);
            IpAddr::V6(octets.into())
        }
    }
}

fn build_pdu(
    args: &Args,
    version: SNMPVersion,
    src_ip: IpAddr,
    seq: usize,
) -> Result<Vec<u8>, String> {
    let timestamp = now_unix_seconds();
    let varbinds = vec![
        SNMPVarbind {
            oid: SNMP_SYS_DESCR_OID.to_string(),
            asn_type: SNMPType::OctetString,
            value: SNMPValue::Str(format!("{} #{}", args.message, seq + 1)),
        },
        SNMPVarbind {
            oid: SNMP_SYS_NAME_OID.to_string(),
            asn_type: SNMPType::OctetString,
            value: SNMPValue::Str("udp-sender".to_string()),
        },
    ];

    match version {
        SNMPVersion::V1 => {
            let agent_addr = match src_ip {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => {
                    return Err("SNMPv1 trap generation requires IPv4 source address".to_string());
                }
            };

            build_snmpv1_trap_pdu(SNMPV1TrapConfig {
                community: args.community.clone(),
                enterprise_oid: args.enterprise.clone(),
                agent_addr,
                generic_trap: 6,
                specific_trap: (seq + 1) as i32,
                timestamp: Some(timestamp),
                varbinds,
            })
            .map_err(|e| e.to_string())
        }
        SNMPVersion::V2c => build_snmpv2c_trap_pdu(SNMPV2cTrapConfig {
            community: args.community.clone(),
            trap_oid: args.trap_oid.clone(),
            timestamp: Some(timestamp),
            varbinds,
        })
        .map_err(|e| e.to_string()),
        SNMPVersion::V3 => build_snmpv3_trap_pdu(SNMPV3TrapConfig {
            username: args.security_name.clone(),
            engine_id: Some(DEFAULT_SNMP_ENGINE_ID.to_string()),
            auth_protocol: parse_auth_proto(&args.auth_proto)?,
            auth_password: args.auth_pass.clone(),
            priv_protocol: parse_priv_proto(&args.priv_proto)?,
            priv_password: args.priv_pass.clone(),
            engine_boots: 0,
            engine_time: timestamp,
            trap_oid: args.trap_oid.clone(),
            timestamp: Some(timestamp),
            varbinds,
            is_inform: args.is_inform,
        })
        .map_err(|e| e.to_string()),
    }
}

fn parse_auth_proto(proto: &str) -> Result<AuthProtocol, String> {
    match proto.to_ascii_uppercase().as_str() {
        "" | "NOAUTH" | "NONE" => Ok(AuthProtocol::NoAuth),
        "MD5" => Ok(AuthProtocol::MD5),
        "SHA" | "SHA1" => Ok(AuthProtocol::SHA),
        "SHA224" => Ok(AuthProtocol::SHA224),
        "SHA256" => Ok(AuthProtocol::SHA256),
        "SHA384" => Ok(AuthProtocol::SHA384),
        "SHA512" => Ok(AuthProtocol::SHA512),
        other => Err(format!(
            "invalid --auth-proto '{other}': expected one of NoAuth, MD5, SHA, SHA224, SHA256, SHA384, SHA512"
        )),
    }
}

fn parse_priv_proto(proto: &str) -> Result<PrivProtocol, String> {
    match proto.to_ascii_uppercase().as_str() {
        "" | "NOPRIV" | "NONE" => Ok(PrivProtocol::NoPriv),
        "DES" => Ok(PrivProtocol::DES),
        "AES" | "AES128" => Ok(PrivProtocol::AES),
        "AES192" => Ok(PrivProtocol::AES192),
        "AES256" => Ok(PrivProtocol::AES256),
        "AES192C" => Ok(PrivProtocol::AES192C),
        "AES256C" => Ok(PrivProtocol::AES256C),
        other => Err(format!(
            "invalid --priv-proto '{other}': expected one of NoPriv, DES, AES, AES192, AES256, AES192C, AES256C"
        )),
    }
}

fn write_frame(
    out: &mut impl Write,
    src_ip: IpAddr,
    src_port: u16,
    dest_ip: IpAddr,
    dest_port: u16,
    payload: &[u8],
    is_ipv6: bool,
) -> io::Result<()> {
    out.write_all(&MAGIC_BYTES)?;

    let mut flags = 0u8;
    if is_ipv6 {
        flags |= FLAG_IPV6;
    }
    out.write_all(&[flags])?;

    match src_ip {
        IpAddr::V4(ip) => out.write_all(&ip.octets())?,
        IpAddr::V6(ip) => out.write_all(&ip.octets())?,
    }

    match dest_ip {
        IpAddr::V4(ip) => out.write_all(&ip.octets())?,
        IpAddr::V6(ip) => out.write_all(&ip.octets())?,
    }

    out.write_all(&src_port.to_be_bytes())?;
    out.write_all(&dest_port.to_be_bytes())?;
    let payload_len = u16::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("payload length {} exceeds u16::MAX", payload.len()),
        )
    })?;
    out.write_all(&payload_len.to_be_bytes())?;
    out.write_all(payload)?;
    Ok(())
}

fn now_unix_seconds() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

fn normalize_go_style_flags(args: Vec<String>) -> Vec<String> {
    args.into_iter()
        .map(|arg| {
            if arg.starts_with('-')
                && !arg.starts_with("--")
                && arg.len() > 2
                && arg != "-h"
                && arg != "-V"
            {
                format!("--{}", &arg[1..])
            } else {
                arg
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_auth_proto_accepts_known() {
        assert!(matches!(parse_auth_proto("").unwrap(), AuthProtocol::NoAuth));
        assert!(matches!(parse_auth_proto("md5").unwrap(), AuthProtocol::MD5));
        assert!(matches!(parse_auth_proto("SHA1").unwrap(), AuthProtocol::SHA));
        assert!(matches!(parse_auth_proto("sha256").unwrap(), AuthProtocol::SHA256));
        assert!(matches!(parse_auth_proto("SHA512").unwrap(), AuthProtocol::SHA512));
    }

    #[test]
    fn parse_auth_proto_rejects_unknown() {
        let err = parse_auth_proto("bogus").unwrap_err();
        assert!(err.contains("invalid --auth-proto"));
        assert!(err.to_ascii_uppercase().contains("BOGUS"));
    }

    #[test]
    fn parse_priv_proto_accepts_known() {
        assert!(matches!(parse_priv_proto("").unwrap(), PrivProtocol::NoPriv));
        assert!(matches!(parse_priv_proto("des").unwrap(), PrivProtocol::DES));
        assert!(matches!(parse_priv_proto("AES").unwrap(), PrivProtocol::AES));
        assert!(matches!(parse_priv_proto("AES128").unwrap(), PrivProtocol::AES));
        assert!(matches!(parse_priv_proto("aes256").unwrap(), PrivProtocol::AES256));
    }

    #[test]
    fn parse_priv_proto_rejects_unknown() {
        let err = parse_priv_proto("rot13").unwrap_err();
        assert!(err.contains("invalid --priv-proto"));
        assert!(err.to_ascii_uppercase().contains("ROT13"));
    }

    #[test]
    fn parse_auth_proto_covers_all_variants() {
        assert!(matches!(parse_auth_proto("NoAuth").unwrap(), AuthProtocol::NoAuth));
        assert!(matches!(parse_auth_proto("none").unwrap(), AuthProtocol::NoAuth));
        assert!(matches!(parse_auth_proto("MD5").unwrap(), AuthProtocol::MD5));
        assert!(matches!(parse_auth_proto("sha").unwrap(), AuthProtocol::SHA));
        assert!(matches!(parse_auth_proto("SHA224").unwrap(), AuthProtocol::SHA224));
        assert!(matches!(parse_auth_proto("sha384").unwrap(), AuthProtocol::SHA384));
    }

    #[test]
    fn parse_priv_proto_covers_all_variants() {
        assert!(matches!(parse_priv_proto("NoPriv").unwrap(), PrivProtocol::NoPriv));
        assert!(matches!(parse_priv_proto("none").unwrap(), PrivProtocol::NoPriv));
        assert!(matches!(parse_priv_proto("aes192").unwrap(), PrivProtocol::AES192));
        assert!(matches!(parse_priv_proto("AES192C").unwrap(), PrivProtocol::AES192C));
        assert!(matches!(parse_priv_proto("aes256c").unwrap(), PrivProtocol::AES256C));
    }

    #[test]
    fn normalize_version_accepts_canonical_and_aliases() {
        assert!(matches!(normalize_version("1").unwrap(), SNMPVersion::V1));
        assert!(matches!(normalize_version("v1").unwrap(), SNMPVersion::V1));
        assert!(matches!(normalize_version("V1").unwrap(), SNMPVersion::V1));
        assert!(matches!(normalize_version("2").unwrap(), SNMPVersion::V2c));
        assert!(matches!(normalize_version("2c").unwrap(), SNMPVersion::V2c));
        assert!(matches!(normalize_version("V2c").unwrap(), SNMPVersion::V2c));
        assert!(matches!(normalize_version("3").unwrap(), SNMPVersion::V3));
        assert!(matches!(normalize_version("v3").unwrap(), SNMPVersion::V3));
    }

    #[test]
    fn normalize_version_rejects_garbage() {
        let err = normalize_version("foo").unwrap_err();
        assert_eq!(err, "Unsupported SNMP version: foo");
        let err = normalize_version("4").unwrap_err();
        assert_eq!(err, "Unsupported SNMP version: 4");
    }

    // increment_ip mutates the LAST octet only and wraps at 256, matching the
    // Go reference. This guarantees `count > 256 - last_octet` does not panic.
    #[test]
    fn increment_ip_v4_increments_last_octet() {
        let base = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(increment_ip(base, 0), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(increment_ip(base, 5), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)));
        // wrapping_add: 1 + 255 = 0
        assert_eq!(increment_ip(base, 255), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
    }

    #[test]
    fn increment_ip_v6_increments_last_octet() {
        let base: IpAddr = "2001:db8::1".parse().unwrap();
        let inc5 = increment_ip(base, 5);
        let octets = match inc5 {
            IpAddr::V6(v6) => v6.octets(),
            IpAddr::V4(_) => panic!("expected v6"),
        };
        assert_eq!(octets[15], 6);
        // First 15 octets unchanged
        let base_octets = match base {
            IpAddr::V6(v6) => v6.octets(),
            IpAddr::V4(_) => panic!(),
        };
        assert_eq!(&octets[..15], &base_octets[..15]);
    }

    // Full IPv4 frame layout for snmp-trap-generator: must match
    // packet-generator/protocol byte-for-byte (MAGIC+flags+src+dst+ports+len+payload).
    #[test]
    fn write_frame_ipv4_layout_is_exact() {
        let mut out = Vec::new();
        write_frame(
            &mut out,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            161,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            162,
            b"AB",
            false,
        )
        .expect("frame write succeeds");

        assert_eq!(out.len(), 3 + 1 + 4 + 4 + 2 + 2 + 2 + 2);
        assert_eq!(&out[0..3], &MAGIC_BYTES);
        assert_eq!(out[3], 0); // not ipv6
        assert_eq!(&out[4..8], &[10, 0, 0, 1]);
        assert_eq!(&out[8..12], &[192, 168, 1, 100]);
        // src_port=161 → 0x00A1
        assert_eq!(&out[12..14], &[0x00, 0xA1]);
        // dest_port=162 → 0x00A2
        assert_eq!(&out[14..16], &[0x00, 0xA2]);
        // payload_len=2
        assert_eq!(&out[16..18], &[0x00, 0x02]);
        assert_eq!(&out[18..20], b"AB");
    }

    #[test]
    fn write_frame_ipv6_sets_flag_and_uses_16_byte_addrs() {
        let mut out = Vec::new();
        let src: IpAddr = "2001:db8::1".parse().unwrap();
        let dst: IpAddr = "2001:db8::100".parse().unwrap();
        write_frame(&mut out, src, 161, dst, 162, b"x", true).expect("frame write succeeds");

        assert_eq!(out[3], FLAG_IPV6);
        // src + dst = 32 bytes following MAGIC+flags
        assert_eq!(out.len(), 3 + 1 + 16 + 16 + 2 + 2 + 2 + 1);
    }

    #[test]
    fn write_frame_rejects_oversized_payload() {
        let mut out = Vec::new();
        let oversized = vec![0u8; usize::from(u16::MAX) + 1];
        let err = write_frame(
            &mut out,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            1,
            IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            2,
            &oversized,
            false,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("exceeds u16::MAX"));
    }

    // normalize_go_style_flags rewrites Go's single-dash long flags to clap's
    // double-dash form, while preserving short flags (-h, -V) and already-correct
    // double-dash flags. Single-char `-x` flags stay single-dash.
    #[test]
    fn normalize_go_style_flags_rewrites_single_dash_long() {
        let input = vec![
            "snmp-trap-generator".to_string(),
            "-version".to_string(),
            "2c".to_string(),
            "-count".to_string(),
            "5".to_string(),
        ];
        let out = normalize_go_style_flags(input);
        assert_eq!(out[1], "--version");
        assert_eq!(out[2], "2c");
        assert_eq!(out[3], "--count");
        assert_eq!(out[4], "5");
    }

    #[test]
    fn normalize_go_style_flags_preserves_short_and_double() {
        let input = vec![
            "snmp-trap-generator".to_string(),
            "-h".to_string(),
            "-V".to_string(),
            "--version".to_string(),
            "-x".to_string(),
        ];
        let out = normalize_go_style_flags(input);
        assert_eq!(out[1], "-h");
        assert_eq!(out[2], "-V");
        assert_eq!(out[3], "--version");
        // Single-char -x is preserved (len == 2)
        assert_eq!(out[4], "-x");
    }
}
