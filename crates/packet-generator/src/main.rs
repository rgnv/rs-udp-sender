use std::io::{self, Write};
use std::net::IpAddr;
use std::process::ExitCode;

use clap::{ArgAction, Parser};
use udp_sender::constants::{FLAG_IPV6, MAGIC_BYTES};

const HELP_TEXT: &str = r#"Usage of packet-generator:
  -base-ip string
        Base source IP address (will increment) (default \"10.0.0.1\")
  -base-port int
        Base source port number (will increment) (default 5000)
  -count int
        Number of packets to generate (default 10)
  -dest-ip string
        Destination IP address (default \"192.168.1.100\")
  -dest-port int
        Destination port number (default 514)
  -ipv6
        Generate IPv6 packets instead of IPv4
  -message string
        Message template (will append packet number) (default \"Test packet\")

Description:
  Generates binary protocol packets to stdout for consumption by udp-sender.
  Packets include IP headers built by udp-sender, this tool only generates
  the binary protocol format.

Examples:
  Generate 10 test packets:
    packet-generator

  Custom IPs and count:
    packet-generator -base-ip 10.0.0.50 -dest-ip 192.168.1.50 -count 100

  Generate IPv6 packets:
    packet-generator -ipv6
"#;

#[derive(Debug, Parser)]
#[command(name = "packet-generator")]
#[command(disable_help_flag = true)]
struct Cli {
    #[arg(long = "base-ip", default_value = "10.0.0.1")]
    base_ip: String,

    #[arg(long = "base-port", default_value_t = 5000)]
    base_port: u16,

    #[arg(long = "count", default_value_t = 10)]
    count: usize,

    #[arg(long = "dest-ip", default_value = "192.168.1.100")]
    dest_ip: String,

    #[arg(long = "dest-port", default_value_t = 514)]
    dest_port: u16,

    #[arg(long = "ipv6", action = ArgAction::SetTrue)]
    ipv6: bool,

    #[arg(long = "message", default_value = "Test packet")]
    message: String,

    #[arg(short = 'h', long = "help", action = ArgAction::SetTrue)]
    help: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    if cli.help {
        print!("{HELP_TEXT}");
        io::stdout().flush().map_err(|e| e.to_string())?;
        return Ok(());
    }

    if cli.ipv6 {
        generate_ipv6(&cli)
    } else {
        generate_ipv4(&cli)
    }
}

fn generate_ipv4(cli: &Cli) -> Result<(), String> {
    let base_ip = parse_ip(&cli.base_ip)?;
    let dest_ip = parse_ip(&cli.dest_ip)?;

    let base_v4 = match base_ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            return Err(format!(
                "IPv4 mode but base IP is IPv6: {} (use -ipv6 flag)",
                cli.base_ip
            ));
        }
    };

    let dest_v4 = match dest_ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            return Err(format!(
                "Source and destination IP versions must match (source: {}, dest: {})",
                cli.base_ip, cli.dest_ip
            ));
        }
    };

    let base_octets = base_v4.octets();
    let base_last = u16::from(base_octets[3]);
    let mut stdout = io::stdout();

    for i in 0..cli.count {
        let mut src = base_octets;
        src[3] = ((base_last + (i as u16)) % 256) as u8;
        let src_port = cli.base_port.wrapping_add(i as u16);
        let payload = format!("{} {}", cli.message, i).into_bytes();

        write_packet(
            &mut stdout,
            0,
            &src,
            &dest_v4.octets(),
            src_port,
            cli.dest_port,
            &payload,
        )?;
    }

    Ok(())
}

fn generate_ipv6(cli: &Cli) -> Result<(), String> {
    let base_ip = parse_ip(&cli.base_ip)?;
    let dest_ip = parse_ip(&cli.dest_ip)?;

    let base_v6 = match base_ip {
        IpAddr::V6(v6) => v6,
        IpAddr::V4(_) => {
            return Err(format!(
                "IPv6 flag set but base IP is IPv4: {}",
                cli.base_ip
            ));
        }
    };

    let dest_v6 = match dest_ip {
        IpAddr::V6(v6) => v6,
        IpAddr::V4(_) => {
            return Err(format!(
                "Source and destination IP versions must match (source: {}, dest: {})",
                cli.base_ip, cli.dest_ip
            ));
        }
    };

    let base_octets = base_v6.octets();
    let base_last = u16::from(base_octets[15]);
    let mut stdout = io::stdout();

    for i in 0..cli.count {
        let mut src = base_octets;
        src[15] = ((base_last + (i as u16)) % 256) as u8;
        let src_port = cli.base_port.wrapping_add(i as u16);
        let payload = format!("{} {}", cli.message, i).into_bytes();

        write_packet(
            &mut stdout,
            FLAG_IPV6,
            &src,
            &dest_v6.octets(),
            src_port,
            cli.dest_port,
            &payload,
        )?;
    }

    Ok(())
}

fn parse_ip(raw: &str) -> Result<IpAddr, String> {
    raw.parse::<IpAddr>()
        .map_err(|_| format!("Invalid IP address: {raw}"))
}

fn write_packet<W: Write>(
    out: &mut W,
    flags: u8,
    src_ip: &[u8],
    dest_ip: &[u8],
    src_port: u16,
    dest_port: u16,
    payload: &[u8],
) -> Result<(), String> {
    let payload_len = u16::try_from(payload.len()).map_err(|_| "payload too large".to_string())?;

    out.write_all(&MAGIC_BYTES).map_err(|e| e.to_string())?;
    out.write_all(&[flags]).map_err(|e| e.to_string())?;
    out.write_all(src_ip).map_err(|e| e.to_string())?;
    out.write_all(dest_ip).map_err(|e| e.to_string())?;
    out.write_all(&src_port.to_be_bytes())
        .map_err(|e| e.to_string())?;
    out.write_all(&dest_port.to_be_bytes())
        .map_err(|e| e.to_string())?;
    out.write_all(&payload_len.to_be_bytes())
        .map_err(|e| e.to_string())?;
    out.write_all(payload).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn writes_expected_ipv4_frame_prefix() {
        let mut out = Vec::new();
        write_packet(
            &mut out,
            0,
            &Ipv4Addr::new(10, 0, 0, 1).octets(),
            &Ipv4Addr::new(192, 168, 1, 100).octets(),
            5000,
            514,
            b"Test packet 0",
        )
        .expect("packet write succeeds");

        assert_eq!(&out[0..3], &MAGIC_BYTES);
        assert_eq!(out[3], 0);
        assert_eq!(&out[4..8], &[10, 0, 0, 1]);
    }

    #[test]
    fn payload_length_is_big_endian() {
        let mut out = Vec::new();
        write_packet(
            &mut out,
            0,
            &Ipv4Addr::new(1, 1, 1, 1).octets(),
            &Ipv4Addr::new(2, 2, 2, 2).octets(),
            1,
            2,
            b"abc",
        )
        .expect("packet write succeeds");

        let payload_len_offset = 3 + 1 + 4 + 4 + 2 + 2;
        assert_eq!(&out[payload_len_offset..payload_len_offset + 2], &[0, 3]);
    }

    #[test]
    fn ipv6_sets_flag() {
        let mut out = Vec::new();
        write_packet(
            &mut out,
            FLAG_IPV6,
            &Ipv6Addr::LOCALHOST.octets(),
            &Ipv6Addr::LOCALHOST.octets(),
            5000,
            514,
            b"Test packet 0",
        )
        .expect("packet write succeeds");

        assert_eq!(out[3], FLAG_IPV6);
    }

    #[test]
    fn parse_ip_accepts_v4_and_v6() {
        assert_eq!(
            parse_ip("10.0.0.1").unwrap(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(
            parse_ip("::1").unwrap(),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
        assert_eq!(
            parse_ip("2001:db8::1").unwrap(),
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())
        );
    }

    #[test]
    fn parse_ip_rejects_garbage() {
        let err = parse_ip("not.an.ip").unwrap_err();
        assert!(err.starts_with("Invalid IP address:"));
        assert!(err.contains("not.an.ip"));

        let err = parse_ip("").unwrap_err();
        assert!(err.starts_with("Invalid IP address:"));

        let err = parse_ip("999.999.999.999").unwrap_err();
        assert!(err.starts_with("Invalid IP address:"));
    }

    // Verifies the full IPv4 frame byte layout matches the binary protocol exactly:
    // MAGIC(3) + flags(1) + src_ip(4) + dest_ip(4) + src_port(2 BE) + dest_port(2 BE)
    // + payload_len(2 BE) + payload — must remain stable for Go interop.
    #[test]
    fn full_ipv4_frame_layout_is_exact() {
        let mut out = Vec::new();
        write_packet(
            &mut out,
            0,
            &Ipv4Addr::new(10, 0, 0, 1).octets(),
            &Ipv4Addr::new(192, 168, 1, 100).octets(),
            5000,
            514,
            b"hi",
        )
        .expect("packet write succeeds");

        // MAGIC + flags + 4 + 4 + 2 + 2 + 2 + 2 = 20 bytes
        assert_eq!(out.len(), 3 + 1 + 4 + 4 + 2 + 2 + 2 + 2);
        assert_eq!(&out[0..3], &MAGIC_BYTES);
        assert_eq!(out[3], 0);
        assert_eq!(&out[4..8], &[10, 0, 0, 1]);
        assert_eq!(&out[8..12], &[192, 168, 1, 100]);
        // src_port=5000 → 0x1388 BE
        assert_eq!(&out[12..14], &[0x13, 0x88]);
        // dest_port=514 → 0x0202 BE
        assert_eq!(&out[14..16], &[0x02, 0x02]);
        // payload_len=2 → 0x0002 BE
        assert_eq!(&out[16..18], &[0x00, 0x02]);
        assert_eq!(&out[18..20], b"hi");
    }

    // Verifies the full IPv6 frame byte layout: src/dest are 16 bytes each.
    #[test]
    fn full_ipv6_frame_layout_is_exact() {
        let mut out = Vec::new();
        let src = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let dst = "2001:db8::100".parse::<Ipv6Addr>().unwrap();
        write_packet(
            &mut out,
            FLAG_IPV6,
            &src.octets(),
            &dst.octets(),
            8080,
            1234,
            b"x",
        )
        .expect("packet write succeeds");

        // MAGIC + flags + 16 + 16 + 2 + 2 + 2 + 1 = 42 bytes
        assert_eq!(out.len(), 3 + 1 + 16 + 16 + 2 + 2 + 2 + 1);
        assert_eq!(&out[0..3], &MAGIC_BYTES);
        assert_eq!(out[3], FLAG_IPV6);
        assert_eq!(&out[4..20], &src.octets());
        assert_eq!(&out[20..36], &dst.octets());
        // src_port=8080 → 0x1F90
        assert_eq!(&out[36..38], &[0x1F, 0x90]);
        // dest_port=1234 → 0x04D2
        assert_eq!(&out[38..40], &[0x04, 0xD2]);
        // payload_len=1
        assert_eq!(&out[40..42], &[0x00, 0x01]);
    }

    // u16 payload-length cap: anything larger than u16::MAX must be rejected,
    // matching Go reference behaviour.
    #[test]
    fn payload_too_large_is_rejected() {
        let oversized = vec![0u8; usize::from(u16::MAX) + 1];
        let mut out = Vec::new();
        let err = write_packet(
            &mut out,
            0,
            &Ipv4Addr::new(1, 1, 1, 1).octets(),
            &Ipv4Addr::new(2, 2, 2, 2).octets(),
            1,
            2,
            &oversized,
        )
        .unwrap_err();
        assert_eq!(err, "payload too large");
    }
}
