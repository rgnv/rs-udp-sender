use std::net::IpAddr;

use thiserror::Error;

use crate::constants::DEFAULT_MTU;
use crate::protocol::Packet;

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("packet size {size} exceeds MTU limit of {mtu} bytes")]
    MTUExceeded { mtu: usize, size: usize },
}

pub struct PacketBuilder {
    mtu: usize,
}

impl PacketBuilder {
    pub fn new(mtu: usize) -> Self {
        Self { mtu }
    }

    pub fn build_packet(&self, pkt: &Packet) -> Result<Vec<u8>, PacketError> {
        self.validate_mtu(pkt)?;

        match pkt.src_ip {
            IpAddr::V4(_) => self.build_ipv4_packet(pkt),
            IpAddr::V6(_) => self.build_ipv6_packet(pkt),
        }
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

    fn build_ipv4_packet(&self, pkt: &Packet) -> Result<Vec<u8>, PacketError> {
        let ip_header = self.build_ipv4_header(pkt);
        let udp_header = self.build_udp_header(pkt, false);

        let mut packet = Vec::with_capacity(ip_header.len() + udp_header.len() + pkt.payload.len());
        packet.extend_from_slice(&ip_header);
        packet.extend_from_slice(&udp_header);
        packet.extend_from_slice(&pkt.payload);

        Ok(packet)
    }

    fn build_ipv6_packet(&self, pkt: &Packet) -> Result<Vec<u8>, PacketError> {
        let ip_header = self.build_ipv6_header(pkt);
        let udp_header = self.build_udp_header(pkt, true);

        let mut packet = Vec::with_capacity(ip_header.len() + udp_header.len() + pkt.payload.len());
        packet.extend_from_slice(&ip_header);
        packet.extend_from_slice(&udp_header);
        packet.extend_from_slice(&pkt.payload);

        Ok(packet)
    }

    fn build_ipv4_header(&self, pkt: &Packet) -> [u8; 20] {
        let mut header = [0u8; 20];
        header[0] = 0x45;
        header[1] = 0x00;

        let total_len = (20 + 8 + pkt.payload.len()) as u16;
        header[2..4].copy_from_slice(&total_len.to_be_bytes());

        header[4..6].copy_from_slice(&0u16.to_be_bytes());
        header[6..8].copy_from_slice(&0u16.to_be_bytes());

        header[8] = 64;
        header[9] = 17;

        header[10] = 0;
        header[11] = 0;

        if let IpAddr::V4(src) = pkt.src_ip {
            header[12..16].copy_from_slice(&src.octets());
        }

        if let IpAddr::V4(dest) = pkt.dest_ip {
            header[16..20].copy_from_slice(&dest.octets());
        }

        let checksum = Self::calculate_checksum(&header);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());

        header
    }

    fn build_ipv6_header(&self, pkt: &Packet) -> [u8; 40] {
        let mut header = [0u8; 40];
        header[0..4].copy_from_slice(&0x6000_0000u32.to_be_bytes());

        let payload_len = (8 + pkt.payload.len()) as u16;
        header[4..6].copy_from_slice(&payload_len.to_be_bytes());

        header[6] = 17;
        header[7] = 64;

        if let IpAddr::V6(src) = pkt.src_ip {
            header[8..24].copy_from_slice(&src.octets());
        }

        if let IpAddr::V6(dest) = pkt.dest_ip {
            header[24..40].copy_from_slice(&dest.octets());
        }

        header
    }

    fn build_udp_header(&self, pkt: &Packet, is_ipv6: bool) -> [u8; 8] {
        let mut header = [0u8; 8];

        header[0..2].copy_from_slice(&pkt.src_port.to_be_bytes());
        header[2..4].copy_from_slice(&pkt.dest_port.to_be_bytes());

        let len = (8 + pkt.payload.len()) as u16;
        header[4..6].copy_from_slice(&len.to_be_bytes());

        header[6] = 0;
        header[7] = 0;

        let checksum =
            self.calculate_udp_checksum(&header, &pkt.payload, pkt.src_ip, pkt.dest_ip, is_ipv6);
        header[6..8].copy_from_slice(&checksum.to_be_bytes());

        header
    }

    fn calculate_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        let mut i = 0;
        while i + 1 < data.len() {
            let word = u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            sum = sum.wrapping_add(word);
            i += 2;
        }

        if data.len() % 2 == 1 {
            sum = sum.wrapping_add((data[data.len() - 1] as u32) << 8);
        }

        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        !sum as u16
    }

    fn calculate_udp_checksum(
        &self,
        udp_header: &[u8; 8],
        payload: &[u8],
        src_ip: IpAddr,
        dest_ip: IpAddr,
        is_ipv6: bool,
    ) -> u16 {
        let mut pseudo_header = if is_ipv6 {
            let mut pseudo = [0u8; 40];

            if let IpAddr::V6(src) = src_ip {
                pseudo[0..16].copy_from_slice(&src.octets());
            }
            if let IpAddr::V6(dest) = dest_ip {
                pseudo[16..32].copy_from_slice(&dest.octets());
            }

            let udp_len = (udp_header.len() + payload.len()) as u32;
            pseudo[32..36].copy_from_slice(&udp_len.to_be_bytes());
            pseudo[39] = 17;

            pseudo.to_vec()
        } else {
            let mut pseudo = [0u8; 12];

            if let IpAddr::V4(src) = src_ip {
                pseudo[0..4].copy_from_slice(&src.octets());
            }
            if let IpAddr::V4(dest) = dest_ip {
                pseudo[4..8].copy_from_slice(&dest.octets());
            }

            pseudo[8] = 0;
            pseudo[9] = 17;

            let udp_len = (udp_header.len() + payload.len()) as u16;
            pseudo[10..12].copy_from_slice(&udp_len.to_be_bytes());

            pseudo.to_vec()
        };

        pseudo_header.extend_from_slice(udp_header);
        pseudo_header.extend_from_slice(payload);

        Self::calculate_checksum(&pseudo_header)
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

    use super::{PacketBuilder, PacketError};

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
}
