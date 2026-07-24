use std::io;

use clap::{ArgAction, Parser};
use shadow_rs::shadow;

use udp_sender::packet::PacketError;
use udp_sender::protocol::ProtocolError;
use udp_sender::sender::PacketSender;
use udp_sender::{
    DEFAULT_MTU, LogLevel, Logger, MAX_MTU, MIN_MTU, PacketBuilder, ProtocolStream, UDPSender,
};

shadow!(build);

const DESCRIPTION_AND_EXAMPLES: &str = "Description:
  Reads binary protocol packets from stdin and sends them as UDP datagrams.
  Supports IPv4 and IPv6 raw socket sending with full packet control.

Examples:
  Generate and send test packets:
    packet-generator | udp-sender

  Send with custom MTU:
    packet-generator | udp-sender -mtu 9000

  Enable debug logging:
    packet-generator | udp-sender -verbose";

#[derive(Debug, Parser)]
#[command(
    name = "udp-sender",
    bin_name = "udp-sender",
    version = shadow_rs::formatcp!(
        "version {} (commit {}, built {})",
        build::PKG_VERSION,
        build::SHORT_COMMIT,
        build::BUILD_TIME_2822
    ),
    disable_help_flag = true,
    disable_version_flag = true,
    after_help = DESCRIPTION_AND_EXAMPLES,
    help_template = "Usage of udp-sender:
  -h, --help
      Show this help message
  -m, --mtu int
      Maximum Transmission Unit (default 1500)
  -V, --version
      Print version and exit
  -v, --verbose
      Enable verbose logging (debug level)
{after-help}
"
)]
struct Cli {
    #[arg(short = 'h', long = "help", action = ArgAction::Help, help = "Show this help message")]
    _help: Option<bool>,

    #[arg(short = 'V', long = "version", action = ArgAction::Version, help = "Print version and exit")]
    _version: Option<bool>,

    #[arg(short = 'v', long = "verbose", action = ArgAction::SetTrue, help = "Enable verbose logging (debug level)")]
    verbose: bool,

    #[arg(short = 'm', long = "mtu", default_value_t = DEFAULT_MTU, value_parser = parse_mtu, help = "Maximum Transmission Unit")]
    mtu: usize,
}

/// Rewrites Go-style single-dash long flags (`-mtu`, `-verbose`) to clap's
/// double-dash form, matching the Go reference CLI. Single-char flags like
/// `-m`, `-v`, `-h`, `-V` are preserved.
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

fn parse_mtu(s: &str) -> Result<usize, String> {
    let mtu = s.parse::<usize>().map_err(|e| e.to_string())?;
    if (MIN_MTU..=MAX_MTU).contains(&mtu) {
        Ok(mtu)
    } else {
        Err(format!(
            "MTU must be between {MIN_MTU} and {MAX_MTU} bytes (got {mtu})"
        ))
    }
}

fn is_unexpected_eof(err: &ProtocolError) -> bool {
    match err {
        ProtocolError::ReadMagic { source, .. }
        | ProtocolError::ReadField { source, .. }
        | ProtocolError::ReadPayload { source, .. }
        | ProtocolError::ReadError(source) => source.kind() == io::ErrorKind::UnexpectedEof,
        _ => false,
    }
}

fn main() -> anyhow::Result<()> {
    let raw_args: Vec<String> = std::env::args().collect();
    // try_parse_from returns Err for -h/-V (DisplayHelp/DisplayVersion);
    // Error::exit reproduces Cli::parse() behavior: print to stdout and
    // exit 0 for those, print usage to stderr and exit 2 for real errors.
    let cli = match Cli::try_parse_from(normalize_go_style_flags(raw_args)) {
        Ok(cli) => cli,
        Err(err) => err.exit(),
    };

    let logger = Logger::new(if cli.verbose {
        LogLevel::Debug
    } else {
        LogLevel::Info
    });

    let mtu_s = cli.mtu.to_string();
    logger.info("Starting UDP sender", &[("mtu", &mtu_s)]);

    let mut sender = UDPSender::new()?;
    let stream = ProtocolStream::new(std::io::stdin(), sender.has_ipv6(), cli.mtu, &logger);
    let builder = PacketBuilder::new(cli.mtu);

    let mut packets_sent: u64 = 0;
    let mut packets_dropped: u64 = 0;
    let mut bytes_sent: u64 = 0;
    let mut scratch: Vec<u8> = Vec::with_capacity(cli.mtu);

    for item in stream {
        match item {
            Ok(packet) => match builder.build_packet_into(&mut scratch, &packet) {
                Ok(()) => {
                    match sender.send(
                        &scratch,
                        packet.dest_ip,
                        packet.dest_port,
                        packet.src_ip,
                        packet.src_port,
                    ) {
                        Ok(sent_bytes) => {
                            packets_sent += 1;
                            bytes_sent += sent_bytes as u64;
                        }
                        Err(err) => {
                            packets_dropped += 1;
                            let err_s = err.to_string();
                            logger.error("Failed to send packet", &[("error", &err_s)]);
                        }
                    }
                }
                Err(PacketError::MTUExceeded { .. }) => {
                    packets_dropped += 1;
                }
                Err(err) => {
                    packets_dropped += 1;
                    let err_s = err.to_string();
                    logger.error("Failed to build packet", &[("error", &err_s)]);
                }
            },
            // Clean EOF is handled by the stream itself (it returns None);
            // any UnexpectedEof reaching here is a truncated frame mid-packet.
            Err(err) if is_unexpected_eof(&err) => {
                packets_dropped += 1;
                let err_s = err.to_string();
                logger.error("Truncated packet at end of stream", &[("error", &err_s)]);
                break;
            }
            Err(ProtocolError::MTUExceeded { .. }) => {
                packets_dropped += 1;
            }
            Err(err) => {
                packets_dropped += 1;
                let err_s = err.to_string();
                logger.error("Failed to parse packet", &[("error", &err_s)]);
            }
        }
    }

    let packets_sent_s = packets_sent.to_string();
    let packets_dropped_s = packets_dropped.to_string();
    let bytes_sent_s = bytes_sent.to_string();
    logger.info(
        "Stream complete",
        &[
            ("packets_sent", &packets_sent_s),
            ("packets_dropped", &packets_dropped_s),
            ("bytes_sent", &bytes_sent_s),
        ],
    );

    if let Err(err) = sender.close() {
        let err_s = err.to_string();
        logger.error("Error closing sender", &[("error", &err_s)]);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn parse_mtu_accepts_default() {
        assert_eq!(parse_mtu("1500").unwrap(), 1500);
    }

    #[test]
    fn parse_mtu_accepts_min() {
        assert_eq!(parse_mtu("576").unwrap(), MIN_MTU);
    }

    #[test]
    fn parse_mtu_accepts_max() {
        assert_eq!(parse_mtu("9000").unwrap(), MAX_MTU);
    }

    #[test]
    fn parse_mtu_rejects_below_min() {
        let err = parse_mtu("575").unwrap_err();
        assert!(err.contains("MTU must be between"));
        assert!(err.contains("575"));
    }

    #[test]
    fn parse_mtu_rejects_above_max() {
        let err = parse_mtu("9001").unwrap_err();
        assert!(err.contains("MTU must be between"));
        assert!(err.contains("9001"));
    }

    #[test]
    fn parse_mtu_rejects_zero() {
        assert!(parse_mtu("0").is_err());
    }

    #[test]
    fn parse_mtu_rejects_non_numeric() {
        assert!(parse_mtu("abc").is_err());
    }

    #[test]
    fn parse_mtu_rejects_negative() {
        assert!(parse_mtu("-1").is_err());
    }

    #[test]
    fn parse_mtu_rejects_empty() {
        assert!(parse_mtu("").is_err());
    }

    #[test]
    fn is_unexpected_eof_true_for_read_magic_eof() {
        let err = ProtocolError::ReadMagic {
            read: 0,
            source: Error::from(ErrorKind::UnexpectedEof),
        };
        assert!(is_unexpected_eof(&err));
    }

    #[test]
    fn is_unexpected_eof_true_for_read_field_eof() {
        let err = ProtocolError::ReadField {
            field: "src_ip",
            source: Error::from(ErrorKind::UnexpectedEof),
        };
        assert!(is_unexpected_eof(&err));
    }

    #[test]
    fn is_unexpected_eof_true_for_read_payload_eof() {
        let err = ProtocolError::ReadPayload {
            payload_len: 32,
            source: Error::from(ErrorKind::UnexpectedEof),
        };
        assert!(is_unexpected_eof(&err));
    }

    #[test]
    fn is_unexpected_eof_true_for_read_error_eof() {
        let err = ProtocolError::ReadError(Error::from(ErrorKind::UnexpectedEof));
        assert!(is_unexpected_eof(&err));
    }

    #[test]
    fn is_unexpected_eof_false_for_other_io_kind() {
        let err = ProtocolError::ReadError(Error::from(ErrorKind::ConnectionReset));
        assert!(!is_unexpected_eof(&err));
    }

    #[test]
    fn is_unexpected_eof_false_for_invalid_magic() {
        let err = ProtocolError::InvalidMagic {
            got0: 0x00,
            got1: 0x00,
            got2: 0x00,
            exp0: 0xC1,
            exp1: 0x21,
            exp2: 0xB1,
        };
        assert!(!is_unexpected_eof(&err));
    }

    #[test]
    fn is_unexpected_eof_false_for_mtu_exceeded() {
        let err = ProtocolError::MTUExceeded {
            packet_number: 1,
            packet_size: 9029,
            mtu: 1500,
            payload_size: 9001,
            source_ip: "10.0.0.1".parse().unwrap(),
            source_port: 5000,
            dest_ip: "192.168.1.100".parse().unwrap(),
            dest_port: 514,
        };
        assert!(!is_unexpected_eof(&err));
    }

    #[test]
    fn is_unexpected_eof_false_for_ipv6_unavailable() {
        let err = ProtocolError::IPv6NotAvailable;
        assert!(!is_unexpected_eof(&err));
    }

    #[test]
    fn cli_parses_defaults() {
        let cli = Cli::try_parse_from(["udp-sender"]).unwrap();
        assert_eq!(cli.mtu, DEFAULT_MTU);
        assert!(!cli.verbose);
    }

    #[test]
    fn cli_verbose_short_flag() {
        let cli = Cli::try_parse_from(["udp-sender", "-v"]).unwrap();
        assert!(cli.verbose);
    }

    #[test]
    fn cli_verbose_long_flag() {
        let cli = Cli::try_parse_from(["udp-sender", "--verbose"]).unwrap();
        assert!(cli.verbose);
    }

    #[test]
    fn cli_mtu_short_flag() {
        let cli = Cli::try_parse_from(["udp-sender", "-m", "9000"]).unwrap();
        assert_eq!(cli.mtu, 9000);
    }

    #[test]
    fn cli_mtu_long_flag() {
        let cli = Cli::try_parse_from(["udp-sender", "--mtu", "1280"]).unwrap();
        assert_eq!(cli.mtu, 1280);
    }

    #[test]
    fn cli_rejects_invalid_mtu() {
        assert!(Cli::try_parse_from(["udp-sender", "--mtu", "100"]).is_err());
    }

    #[test]
    fn cli_rejects_unknown_flag() {
        assert!(Cli::try_parse_from(["udp-sender", "--bogus"]).is_err());
    }

    #[test]
    fn go_style_single_dash_long_flags_parse() {
        let normalized = normalize_go_style_flags(vec![
            "udp-sender".to_string(),
            "-mtu".to_string(),
            "9000".to_string(),
            "-verbose".to_string(),
        ]);
        let cli = Cli::try_parse_from(normalized).unwrap();
        assert_eq!(cli.mtu, 9000);
        assert!(cli.verbose);
    }

    #[test]
    fn normalize_go_style_flags_preserves_short_flags() {
        let out = normalize_go_style_flags(vec![
            "udp-sender".to_string(),
            "-m".to_string(),
            "1500".to_string(),
            "-v".to_string(),
            "-h".to_string(),
            "-V".to_string(),
            "--mtu".to_string(),
        ]);
        assert_eq!(out[1], "-m");
        assert_eq!(out[3], "-v");
        assert_eq!(out[4], "-h");
        assert_eq!(out[5], "-V");
        assert_eq!(out[6], "--mtu");
    }

    #[test]
    fn cli_version_flag_requests_display_version() {
        let err = Cli::try_parse_from(["udp-sender", "-V"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn cli_help_flag_requests_display_help() {
        let err = Cli::try_parse_from(["udp-sender", "-h"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn go_style_version_flag_requests_display_version() {
        let normalized =
            normalize_go_style_flags(vec!["udp-sender".to_string(), "-version".to_string()]);
        let err = Cli::try_parse_from(normalized).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }
}
