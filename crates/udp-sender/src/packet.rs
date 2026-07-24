use std::net::IpAddr;

use thiserror::Error;

use crate::constants::{DEFAULT_MTU, IPPROTO_UDP, IPV4_TTL, IPV6_HOP_LIMIT};
use crate::protocol::Packet;

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("packet size {size} exceeds MTU limit of {mtu} bytes")]
    MTUExceeded { mtu: usize, size: usize },

    #[error("packet length {size} does not fit in a 16-bit length field")]
    LengthOverflow { size: usize },

    #[error("source and destination IP address families must match")]
    FamilyMismatch,
}

pub struct PacketBuilder {
    mtu: usize,
}

impl PacketBuilder {
    pub fn new(mtu: usize) -> Self {
        Self { mtu }
    }

    pub fn build_packet(&self, pkt: &Packet) -> Result<Vec<u8>, PacketError> {
        let mut out = Vec::new();
        self.build_packet_into(&mut out, pkt)?;
        Ok(out)
    }

    pub fn build_packet_into(&self, out: &mut Vec<u8>, pkt: &Packet) -> Result<(), PacketError> {
        self.validate_mtu(pkt)?;

        out.clear();
        match pkt.src_ip {
            IpAddr::V4(_) => {
                out.reserve(20 + 8 + pkt.payload.len());
                let ip_header = self.build_ipv4_header(pkt)?;
                let udp_header = self.build_udp_header(pkt, false)?;
                out.extend_from_slice(&ip_header);
                out.extend_from_slice(&udp_header);
            }
            IpAddr::V6(_) => {
                out.reserve(40 + 8 + pkt.payload.len());
                let ip_header = self.build_ipv6_header(pkt)?;
                let udp_header = self.build_udp_header(pkt, true)?;
                out.extend_from_slice(&ip_header);
                out.extend_from_slice(&udp_header);
            }
        }
        out.extend_from_slice(&pkt.payload);

        Ok(())
    }

    fn validate_mtu(&self, pkt: &Packet) -> Result<(), PacketError> {
        let ip_header = match pkt.src_ip {
            IpAddr::V4(_) => 20,
            IpAddr::V6(_) => 40,
        };

        let total = ip_header + 8 + pkt.payload.len();
        if total > self.mtu {
            return Err(PacketError::MTUExceeded {
                mtu: self.mtu,
                size: total,
            });
        }

        Ok(())
    }

    fn build_ipv4_header(&self, pkt: &Packet) -> Result<[u8; 20], PacketError> {
        let (IpAddr::V4(src), IpAddr::V4(dest)) = (pkt.src_ip, pkt.dest_ip) else {
            return Err(PacketError::FamilyMismatch);
        };

        let mut header = [0u8; 20];
        header[0] = 0x45;
        header[1] = 0x00;

        let total_len =
            u16::try_from(20 + 8 + pkt.payload.len()).map_err(|_| PacketError::LengthOverflow {
                size: 20 + 8 + pkt.payload.len(),
            })?;
        header[2..4].copy_from_slice(&total_len.to_be_bytes());

        header[4..6].copy_from_slice(&0u16.to_be_bytes());
        header[6..8].copy_from_slice(&0u16.to_be_bytes());

        header[8] = IPV4_TTL;
        header[9] = IPPROTO_UDP;

        header[10] = 0;
        header[11] = 0;

        header[12..16].copy_from_slice(&src.octets());
        header[16..20].copy_from_slice(&dest.octets());

        let checksum = Self::calculate_checksum(&header);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());

        Ok(header)
    }

    fn build_ipv6_header(&self, pkt: &Packet) -> Result<[u8; 40], PacketError> {
        let (IpAddr::V6(src), IpAddr::V6(dest)) = (pkt.src_ip, pkt.dest_ip) else {
            return Err(PacketError::FamilyMismatch);
        };

        let mut header = [0u8; 40];
        header[0..4].copy_from_slice(&0x6000_0000u32.to_be_bytes());

        let payload_len =
            u16::try_from(8 + pkt.payload.len()).map_err(|_| PacketError::LengthOverflow {
                size: 8 + pkt.payload.len(),
            })?;
        header[4..6].copy_from_slice(&payload_len.to_be_bytes());

        header[6] = IPPROTO_UDP;
        header[7] = IPV6_HOP_LIMIT;

        header[8..24].copy_from_slice(&src.octets());
        header[24..40].copy_from_slice(&dest.octets());

        Ok(header)
    }

    fn build_udp_header(&self, pkt: &Packet, is_ipv6: bool) -> Result<[u8; 8], PacketError> {
        let mut header = [0u8; 8];

        header[0..2].copy_from_slice(&pkt.src_port.to_be_bytes());
        header[2..4].copy_from_slice(&pkt.dest_port.to_be_bytes());

        let len =
            u16::try_from(8 + pkt.payload.len()).map_err(|_| PacketError::LengthOverflow {
                size: 8 + pkt.payload.len(),
            })?;
        header[4..6].copy_from_slice(&len.to_be_bytes());

        header[6] = 0;
        header[7] = 0;

        let checksum = self.calculate_udp_checksum(
            &header,
            &pkt.payload,
            pkt.src_ip,
            pkt.dest_ip,
            is_ipv6,
            len,
        );
        // A computed checksum of 0x0000 is transmitted as 0xFFFF: zero means
        // "no checksum" for IPv4 (RFC 768) and is illegal for IPv6 (RFC 8200 §8.1).
        let checksum = if checksum == 0 { 0xFFFF } else { checksum };
        header[6..8].copy_from_slice(&checksum.to_be_bytes());

        Ok(header)
    }

    fn calculate_checksum(data: &[u8]) -> u16 {
        let mut sum = OnesComplementSum::new();
        sum.update(data);
        sum.finish()
    }

    fn calculate_udp_checksum(
        &self,
        udp_header: &[u8; 8],
        payload: &[u8],
        src_ip: IpAddr,
        dest_ip: IpAddr,
        is_ipv6: bool,
        udp_len: u16,
    ) -> u16 {
        let mut sum = OnesComplementSum::new();

        if is_ipv6 {
            let mut pseudo = [0u8; 40];

            if let IpAddr::V6(src) = src_ip {
                pseudo[0..16].copy_from_slice(&src.octets());
            }
            if let IpAddr::V6(dest) = dest_ip {
                pseudo[16..32].copy_from_slice(&dest.octets());
            }

            pseudo[32..36].copy_from_slice(&u32::from(udp_len).to_be_bytes());
            pseudo[39] = IPPROTO_UDP;

            sum.update(&pseudo);
        } else {
            let mut pseudo = [0u8; 12];

            if let IpAddr::V4(src) = src_ip {
                pseudo[0..4].copy_from_slice(&src.octets());
            }
            if let IpAddr::V4(dest) = dest_ip {
                pseudo[4..8].copy_from_slice(&dest.octets());
            }

            pseudo[8] = 0;
            pseudo[9] = IPPROTO_UDP;

            pseudo[10..12].copy_from_slice(&udp_len.to_be_bytes());

            sum.update(&pseudo);
        }

        sum.update(udp_header);
        sum.update(payload);
        sum.finish()
    }
}

/// Incremental RFC 1071 one's-complement sum over consecutive slices,
/// carrying an odd trailing byte across slice boundaries.
struct OnesComplementSum {
    sum: u32,
    pending_hi: Option<u8>,
}

impl OnesComplementSum {
    fn new() -> Self {
        Self {
            sum: 0,
            pending_hi: None,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut data = data;

        if let Some(hi) = self.pending_hi.take() {
            match data.split_first() {
                Some((&lo, rest)) => {
                    self.sum = self
                        .sum
                        .wrapping_add(u32::from(u16::from_be_bytes([hi, lo])));
                    data = rest;
                }
                None => {
                    self.pending_hi = Some(hi);
                    return;
                }
            }
        }

        let (words, tail) = data.as_chunks::<2>();
        for &[a, b] in words {
            self.sum = self.sum.wrapping_add(u32::from(u16::from_be_bytes([a, b])));
        }
        if let Some(&hi) = tail.first() {
            self.pending_hi = Some(hi);
        }
    }

    fn finish(mut self) -> u16 {
        if let Some(hi) = self.pending_hi.take() {
            self.sum = self.sum.wrapping_add(u32::from(hi) << 8);
        }

        let mut sum = self.sum;
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        !sum as u16
    }
}

impl Default for PacketBuilder {
    fn default() -> Self {
        Self::new(DEFAULT_MTU)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::protocol::Packet;

    use super::{OnesComplementSum, PacketBuilder, PacketError};

    const IPV4_MINIMAL_HEX: &str =
        "4500002100000000401166ca0a0000010a00000230390202000d75c468656c6c6f";

    const IPV4_LARGE_PAYLOAD_HEX: &str = concat!(
        "45000594000000004011f0dcc0a80164c0a801c8d4311f9005807caf0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );

    const IPV4_MTU_EDGE_HEX: &str = concat!(
        "450005dc0000000040111ceeac100001ac1000020400232805c875120000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );

    const IPV4_EMPTY_PAYLOAD_HEX: &str = "4500001c00000000401168c00101010108080808000000350008ed97";

    const IPV6_MINIMAL_HEX: &str = "60000000000d114020010db800000000000000000000000120010db800000000000000000000000230390202000d2e5268656c6c6f";

    const IPV6_FULL_ADDRESS_HEX: &str = "60000000000c1140fe80000000000000aabbccfffeddeeffff0200000000000000000000000000018000076c000c2d7274657374";

    fn build_packet(
        payload: Vec<u8>,
        src_ip: IpAddr,
        src_port: u16,
        dest_ip: IpAddr,
        dest_port: u16,
        mtu: usize,
    ) -> Vec<u8> {
        let pkt = Packet {
            src_ip,
            dest_ip,
            src_port,
            dest_port,
            payload,
            flags: 0,
        };

        PacketBuilder::new(mtu)
            .build_packet(&pkt)
            .expect("packet build should succeed")
    }

    #[test]
    fn golden_ipv4_minimal() {
        let out = build_packet(
            b"hello".to_vec(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            514,
            1500,
        );

        assert_eq!(hex::encode(out), IPV4_MINIMAL_HEX);
    }

    #[test]
    fn golden_ipv4_large_payload() {
        let out = build_packet(
            vec![0u8; 1400],
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            54321,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
            8080,
            1500,
        );

        assert_eq!(hex::encode(out), IPV4_LARGE_PAYLOAD_HEX);
    }

    #[test]
    fn golden_ipv4_mtu_edge() {
        let out = build_packet(
            vec![0u8; 1472],
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            1024,
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2)),
            9000,
            1500,
        );

        assert_eq!(hex::encode(out), IPV4_MTU_EDGE_HEX);
    }

    #[test]
    fn golden_ipv4_empty_payload() {
        let out = build_packet(
            vec![],
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            0,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            1500,
        );

        assert_eq!(hex::encode(out), IPV4_EMPTY_PAYLOAD_HEX);
    }

    #[test]
    fn golden_ipv6_minimal() {
        let out = build_packet(
            b"hello".to_vec(),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
            12345,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2)),
            514,
            1500,
        );

        assert_eq!(hex::encode(out), IPV6_MINIMAL_HEX);
    }

    #[test]
    fn golden_ipv6_full_address() {
        let out = build_packet(
            b"test".to_vec(),
            IpAddr::V6(Ipv6Addr::new(
                0xfe80, 0, 0, 0, 0xaabb, 0xccff, 0xfedd, 0xeeff,
            )),
            32768,
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
            1900,
            1500,
        );

        assert_eq!(hex::encode(out), IPV6_FULL_ADDRESS_HEX);
    }

    #[test]
    fn mtu_exceeded_error() {
        let pkt = Packet {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 1,
            dest_port: 2,
            payload: vec![0u8; 1401],
            flags: 0,
        };

        let err = PacketBuilder::new(1428)
            .build_packet(&pkt)
            .expect_err("should exceed mtu");
        match err {
            PacketError::MTUExceeded { mtu, size } => {
                assert_eq!(mtu, 1428);
                assert_eq!(size, 1429);
            }
            other => panic!("expected MTUExceeded, got {other:?}"),
        }
    }

    #[test]
    fn mtu_exceeded_ipv6_uses_40_byte_header() {
        let pkt = Packet {
            src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dest_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            src_port: 1,
            dest_port: 2,
            payload: vec![0u8; 1453],
            flags: 0,
        };

        let err = PacketBuilder::new(1500)
            .build_packet(&pkt)
            .expect_err("ipv6 should exceed 1500 mtu at payload 1453 (40+8+1453=1501)");
        match err {
            PacketError::MTUExceeded { mtu, size } => {
                assert_eq!(mtu, 1500);
                assert_eq!(size, 40 + 8 + 1453);
            }
            other => panic!("expected MTUExceeded, got {other:?}"),
        }
    }

    #[test]
    fn mtu_boundary_exact_fit_succeeds_ipv4() {
        let pkt = Packet {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 1,
            dest_port: 2,
            payload: vec![0u8; 1472],
            flags: 0,
        };

        let out = PacketBuilder::new(1500)
            .build_packet(&pkt)
            .expect("exact mtu fit should succeed");
        assert_eq!(out.len(), 1500);
    }

    #[test]
    fn mtu_boundary_exact_fit_succeeds_ipv6() {
        let pkt = Packet {
            src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dest_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            src_port: 1,
            dest_port: 2,
            payload: vec![0u8; 1452],
            flags: 0,
        };

        let out = PacketBuilder::new(1500)
            .build_packet(&pkt)
            .expect("exact ipv6 mtu fit should succeed");
        assert_eq!(out.len(), 1500);
    }

    #[test]
    fn packet_error_display_format() {
        let err = PacketError::MTUExceeded {
            mtu: 1500,
            size: 1600,
        };
        assert_eq!(
            format!("{err}"),
            "packet size 1600 exceeds MTU limit of 1500 bytes"
        );
    }

    #[test]
    fn default_builder_uses_default_mtu() {
        let builder = PacketBuilder::default();
        let pkt = Packet {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 1,
            dest_port: 2,
            payload: vec![0u8; 1473],
            flags: 0,
        };
        let err = builder
            .build_packet(&pkt)
            .expect_err("default mtu (1500) should reject 20+8+1473=1501");
        match err {
            PacketError::MTUExceeded { mtu, .. } => assert_eq!(mtu, 1500),
            other => panic!("expected MTUExceeded, got {other:?}"),
        }
    }

    #[test]
    fn ipv4_header_field_layout() {
        let pkt = Packet {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 12345,
            dest_port: 514,
            payload: b"hello".to_vec(),
            flags: 0,
        };
        let out = PacketBuilder::new(1500).build_packet(&pkt).unwrap();
        assert_eq!(out[0], 0x45, "version=4, IHL=5");
        assert_eq!(out[1], 0x00, "DSCP/ECN=0");
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 33, "total length");
        assert_eq!(out[8], 64, "TTL=64");
        assert_eq!(out[9], 17, "protocol=UDP");
        assert_eq!(&out[12..16], &[10, 0, 0, 1], "src ip");
        assert_eq!(&out[16..20], &[10, 0, 0, 2], "dest ip");
    }

    #[test]
    fn ipv6_header_field_layout() {
        let pkt = Packet {
            src_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
            dest_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2)),
            src_port: 12345,
            dest_port: 514,
            payload: b"hello".to_vec(),
            flags: 0,
        };
        let out = PacketBuilder::new(1500).build_packet(&pkt).unwrap();
        assert_eq!(out[0], 0x60, "version=6");
        assert_eq!(out[6], 17, "next header=UDP");
        assert_eq!(out[7], 64, "hop limit=64");
        assert_eq!(u16::from_be_bytes([out[4], out[5]]), 13, "payload length");
    }

    #[test]
    fn udp_header_ports_big_endian() {
        let pkt = Packet {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 0xABCD,
            dest_port: 0x1234,
            payload: b"x".to_vec(),
            flags: 0,
        };
        let out = PacketBuilder::new(1500).build_packet(&pkt).unwrap();
        assert_eq!(&out[20..22], &[0xAB, 0xCD], "src port BE");
        assert_eq!(&out[22..24], &[0x12, 0x34], "dest port BE");
    }

    #[test]
    fn udp_header_extreme_ports() {
        let pkt = Packet {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 0,
            dest_port: 0xFFFF,
            payload: b"x".to_vec(),
            flags: 0,
        };
        let out = PacketBuilder::new(1500).build_packet(&pkt).unwrap();
        assert_eq!(&out[20..22], &[0x00, 0x00]);
        assert_eq!(&out[22..24], &[0xFF, 0xFF]);
    }

    #[test]
    fn ipv4_checksum_is_valid_rfc1071() {
        let pkt = Packet {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 12345,
            dest_port: 514,
            payload: b"hello".to_vec(),
            flags: 0,
        };
        let out = PacketBuilder::new(1500).build_packet(&pkt).unwrap();
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < 20 {
            sum = sum.wrapping_add(u16::from_be_bytes([out[i], out[i + 1]]) as u32);
            i += 2;
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum, 0xffff, "IPv4 checksum verification per RFC 1071");
    }

    #[test]
    fn ipv6_no_ip_header_checksum() {
        let pkt = Packet {
            src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dest_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            src_port: 1,
            dest_port: 2,
            payload: b"x".to_vec(),
            flags: 0,
        };
        let out = PacketBuilder::new(1500).build_packet(&pkt).unwrap();
        assert_eq!(out.len(), 40 + 8 + 1, "ipv6 has no header checksum field");
    }

    #[test]
    fn mismatched_ip_families_error() {
        let pkt = Packet {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dest_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            src_port: 1,
            dest_port: 2,
            payload: b"x".to_vec(),
            flags: 0,
        };
        let err = PacketBuilder::new(1500)
            .build_packet(&pkt)
            .expect_err("v4 src / v6 dest must fail");
        assert!(matches!(err, PacketError::FamilyMismatch));

        let pkt = Packet {
            src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dest_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 1,
            dest_port: 2,
            payload: b"x".to_vec(),
            flags: 0,
        };
        let err = PacketBuilder::new(1500)
            .build_packet(&pkt)
            .expect_err("v6 src / v4 dest must fail");
        assert!(matches!(err, PacketError::FamilyMismatch));
    }

    #[test]
    fn length_overflow_error_for_oversized_payload() {
        // MTU is user-controlled; a huge MTU must not silently truncate lengths.
        let pkt = Packet {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 1,
            dest_port: 2,
            payload: vec![0u8; 70_000],
            flags: 0,
        };
        let err = PacketBuilder::new(100_000)
            .build_packet(&pkt)
            .expect_err("payload > u16 capacity must fail");
        assert!(matches!(err, PacketError::LengthOverflow { .. }));
    }

    #[test]
    fn build_packet_into_matches_build_packet_and_reuses_buffer() {
        let pkt = Packet {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 12345,
            dest_port: 514,
            payload: b"hello".to_vec(),
            flags: 0,
        };
        let builder = PacketBuilder::new(1500);
        let expected = builder.build_packet(&pkt).unwrap();

        let mut scratch = Vec::with_capacity(1500);
        builder.build_packet_into(&mut scratch, &pkt).unwrap();
        assert_eq!(scratch, expected);

        // Reuse clears stale content and reproduces identical bytes.
        builder.build_packet_into(&mut scratch, &pkt).unwrap();
        assert_eq!(scratch, expected);
    }

    #[test]
    fn udp_total_length_overflow_is_rejected() {
        // 8 + 65527 = 65535 fits the UDP length field, but the IPv4 total
        // length (20 + 65535) does not fit u16 and must error, not truncate.
        let pkt = Packet {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 1,
            dest_port: 2,
            payload: vec![0u8; 65527],
            flags: 0,
        };
        let err = PacketBuilder::new(70_000).build_packet(&pkt);
        assert!(matches!(err, Err(PacketError::LengthOverflow { .. })));
    }

    #[test]
    fn incremental_sum_matches_concatenated_reference() {
        // Odd-length first slice forces a carry across the boundary.
        let a = [0x45u8, 0x00, 0x00];
        let b = [0x21u8, 0x00, 0x00, 0x00, 0x40, 0x11];
        let c = [0x66u8];

        let mut inc = OnesComplementSum::new();
        inc.update(&a);
        inc.update(&b);
        inc.update(&c);
        let incremental = inc.finish();

        let mut concat = Vec::new();
        concat.extend_from_slice(&a);
        concat.extend_from_slice(&b);
        concat.extend_from_slice(&c);
        let reference = PacketBuilder::calculate_checksum(&concat);

        assert_eq!(incremental, reference);
    }
}
