pub const MAGIC_BYTES: [u8; 3] = [0xC1, 0x21, 0xB1];

pub const FLAG_IPV6: u8 = 0x01;

pub const DEFAULT_MTU: usize = 1500;
pub const MIN_MTU: usize = 576;
pub const MAX_MTU: usize = 9000;

pub const IPV4_HEADER_SIZE: usize = 20;
pub const IPV6_HEADER_SIZE: usize = 40;
pub const UDP_HEADER_SIZE: usize = 8;

pub const IP_VERSION_4: u8 = 4;
pub const IP_VERSION_6: u8 = 6;

pub const IPPROTO_UDP: i32 = 17;

pub const IPV4_TTL: u8 = 64;
pub const IPV6_HOP_LIMIT: u32 = 64;

pub const PROGRESS_INTERVAL: usize = 100;

pub const SNMP_TRAP_OID: &str = "1.3.6.1.6.3.1.1.4.1";
pub const SNMP_SYS_UP_TIME_OID: &str = "1.3.6.1.2.1.1.3.0";
pub const SNMP_SYS_DESCR_OID: &str = "1.3.6.1.2.1.1.1.0";
pub const SNMP_SYS_NAME_OID: &str = "1.3.6.1.2.1.1.5.0";
pub const SNMP_SYS_LOCATION_OID: &str = "1.3.6.1.2.1.1.6.0";
pub const SNMP_SYS_CONTACT_OID: &str = "1.3.6.1.2.1.1.4.0";

pub const DEFAULT_SNMP_ENGINE_ID: &str = "800000020109840301";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
    Fatal = 4,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Fatal => "fatal",
        }
    }

    pub fn from_verbose(verbose: bool) -> Self {
        if verbose { Self::Debug } else { Self::Info }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_bytes_values() {
        assert_eq!(MAGIC_BYTES, [0xC1, 0x21, 0xB1]);
    }

    #[test]
    fn test_log_level_order() {
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
        assert!(LogLevel::Error < LogLevel::Fatal);
    }

    #[test]
    fn test_log_level_as_str() {
        assert_eq!(LogLevel::Debug.as_str(), "debug");
        assert_eq!(LogLevel::Info.as_str(), "info");
        assert_eq!(LogLevel::Warn.as_str(), "warn");
        assert_eq!(LogLevel::Error.as_str(), "error");
        assert_eq!(LogLevel::Fatal.as_str(), "fatal");
    }

    #[test]
    fn test_mtu_bounds() {
        assert!(
            MIN_MTU >= 68,
            "min MTU must be at least 68 bytes (IPv4 minimum)"
        );
        assert!(MAX_MTU >= DEFAULT_MTU);
    }
}
