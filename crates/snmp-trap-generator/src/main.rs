use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use udp_sender::constants::{FLAG_IPV6, MAGIC_BYTES, SNMP_SYS_DESCR_OID, SNMP_SYS_NAME_OID};
use udp_sender::snmp::{
    build_snmpv1_trap_pdu, build_snmpv2c_trap_pdu, build_snmpv3_trap_pdu, AuthProtocol,
    PrivProtocol, SNMPType, SNMPV1TrapConfig, SNMPV2cTrapConfig, SNMPV3TrapConfig, SNMPValue,
    SNMPVarbind,
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
#[command(name = "snmp-trap-generator", disable_help_flag = true, disable_version_flag = true)]
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
        return Err(format!("IPv6 flag set but base IP is IPv4: {}", args.base_ip));
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
        let src_port = args.base_port.wrapping_add(i as u16);
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

#[derive(Clone, Copy, PartialEq, Eq)]
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

fn build_pdu(args: &Args, version: SNMPVersion, src_ip: IpAddr, seq: usize) -> Result<Vec<u8>, String> {
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
            engine_id: Some("udp-sender".to_string()),
            auth_protocol: parse_auth_proto(&args.auth_proto),
            auth_password: args.auth_pass.clone(),
            priv_protocol: parse_priv_proto(&args.priv_proto),
            priv_password: args.priv_pass.clone(),
            engine_boots: 0,
            engine_time: timestamp,
            trap_oid: args.trap_oid.clone(),
            timestamp: Some(timestamp),
            varbinds,
        })
        .map_err(|e| e.to_string()),
    }
}

fn parse_auth_proto(proto: &str) -> AuthProtocol {
    match proto.to_ascii_uppercase().as_str() {
        "MD5" => AuthProtocol::MD5,
        "SHA" => AuthProtocol::SHA,
        "SHA256" => AuthProtocol::SHA256,
        "SHA384" => AuthProtocol::SHA384,
        "SHA512" => AuthProtocol::SHA512,
        "" => AuthProtocol::NoAuth,
        _ => AuthProtocol::NoAuth,
    }
}

fn parse_priv_proto(proto: &str) -> PrivProtocol {
    match proto.to_ascii_uppercase().as_str() {
        "DES" => PrivProtocol::DES,
        "AES" => PrivProtocol::AES,
        "" => PrivProtocol::NoPriv,
        _ => PrivProtocol::NoPriv,
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
    out.write_all(&(payload.len() as u16).to_be_bytes())?;
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
