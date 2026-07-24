use std::io::{self, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

use crate::constants::{
    FLAG_IPV6, IPV4_HEADER_SIZE, IPV6_HEADER_SIZE, LogLevel, MAGIC_BYTES, PROGRESS_INTERVAL,
    UDP_HEADER_SIZE,
};
use crate::logger::Logger;

#[derive(Debug)]
pub struct Packet {
    pub src_ip: IpAddr,
    pub dest_ip: IpAddr,
    pub src_port: u16,
    pub dest_port: u16,
    pub payload: Vec<u8>,
    pub flags: u8,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error(
        "invalid magic number: got [0x{got0:02X} 0x{got1:02X} 0x{got2:02X}], expected [0x{exp0:02X} 0x{exp1:02X} 0x{exp2:02X}] - stream may be misaligned"
    )]
    InvalidMagic {
        got0: u8,
        got1: u8,
        got2: u8,
        exp0: u8,
        exp1: u8,
        exp2: u8,
    },

    #[error("IPv6 packet received but IPv6 is not available")]
    IPv6NotAvailable,

    #[error("packet size {packet_size} exceeds MTU limit of {mtu} bytes")]
    MTUExceeded {
        packet_number: u64,
        packet_size: usize,
        mtu: usize,
        payload_size: usize,
        source_ip: IpAddr,
        source_port: u16,
        dest_ip: IpAddr,
        dest_port: u16,
    },

    #[error("reading magic bytes: {source} (read {read} bytes)")]
    ReadMagic { read: usize, source: io::Error },

    #[error("reading {field}: {source}")]
    ReadField {
        field: &'static str,
        source: io::Error,
    },

    #[error("reading payload ({payload_len} bytes): {source}")]
    ReadPayload {
        payload_len: usize,
        source: io::Error,
    },

    #[error(transparent)]
    ReadError(#[from] io::Error),
}

pub struct ProtocolStream<'a, R: Read> {
    reader: BufReader<R>,
    has_ipv6: bool,
    mtu: usize,
    logger: &'a Logger,
    packets_sent: u64,
    packets_dropped: u64,
    bytes_sent: u64,
    terminated: bool,
}

enum MagicRead {
    Complete([u8; 3]),
    EndOfStream,
}

impl<'a, R: Read> ProtocolStream<'a, R> {
    pub fn new(reader: R, has_ipv6: bool, mtu: usize, logger: &'a Logger) -> Self {
        Self {
            reader: BufReader::with_capacity(64 * 1024, reader),
            has_ipv6,
            mtu,
            logger,
            packets_sent: 0,
            packets_dropped: 0,
            bytes_sent: 0,
            terminated: false,
        }
    }

    fn read_magic(&mut self) -> Result<MagicRead, ProtocolError> {
        let mut magic = [0u8; 3];
        let mut read = 0usize;

        while read < magic.len() {
            match self.reader.read(&mut magic[read..]) {
                Ok(0) => {
                    if read == 0 {
                        return Ok(MagicRead::EndOfStream);
                    }

                    return Err(ProtocolError::ReadMagic {
                        read,
                        source: io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "failed to fill whole buffer",
                        ),
                    });
                }
                Ok(n) => {
                    read += n;
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(err) => {
                    return Err(ProtocolError::ReadMagic { read, source: err });
                }
            }
        }

        Ok(MagicRead::Complete(magic))
    }

    fn read_exact_field(
        &mut self,
        buf: &mut [u8],
        field: &'static str,
    ) -> Result<(), ProtocolError> {
        self.reader
            .read_exact(buf)
            .map_err(|source| ProtocolError::ReadField { field, source })
    }

    fn read_u16_be(&mut self, field: &'static str) -> Result<u16, ProtocolError> {
        let mut bytes = [0u8; 2];
        self.read_exact_field(&mut bytes, field)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn fail_once<T>(&mut self, err: ProtocolError) -> Option<Result<T, ProtocolError>> {
        self.terminated = true;
        Some(Err(err))
    }
}

impl<'a, R: Read> Iterator for ProtocolStream<'a, R> {
    type Item = Result<Packet, ProtocolError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.terminated {
            return None;
        }

        let magic = match self.read_magic() {
            Ok(MagicRead::EndOfStream) => {
                self.terminated = true;
                return None;
            }
            Ok(MagicRead::Complete(magic)) => magic,
            Err(err) => return self.fail_once(err),
        };

        if magic != MAGIC_BYTES {
            return self.fail_once(ProtocolError::InvalidMagic {
                got0: magic[0],
                got1: magic[1],
                got2: magic[2],
                exp0: MAGIC_BYTES[0],
                exp1: MAGIC_BYTES[1],
                exp2: MAGIC_BYTES[2],
            });
        }

        let mut flags_buf = [0u8; 1];
        if let Err(err) = self.read_exact_field(&mut flags_buf, "flags byte") {
            return self.fail_once(err);
        }
        let flags = flags_buf[0];
        let is_ipv6 = (flags & FLAG_IPV6) != 0;

        if is_ipv6 && !self.has_ipv6 {
            return self.fail_once(ProtocolError::IPv6NotAvailable);
        }

        let (src_ip, dest_ip) = if is_ipv6 {
            let mut src = [0u8; 16];
            if let Err(err) = self.read_exact_field(&mut src, "IPv6 source address") {
                return self.fail_once(err);
            }

            let mut dest = [0u8; 16];
            if let Err(err) = self.read_exact_field(&mut dest, "IPv6 destination address") {
                return self.fail_once(err);
            }

            (
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dest)),
            )
        } else {
            let mut src = [0u8; 4];
            if let Err(err) = self.read_exact_field(&mut src, "IPv4 source address") {
                return self.fail_once(err);
            }

            let mut dest = [0u8; 4];
            if let Err(err) = self.read_exact_field(&mut dest, "IPv4 destination address") {
                return self.fail_once(err);
            }

            (
                IpAddr::V4(Ipv4Addr::from(src)),
                IpAddr::V4(Ipv4Addr::from(dest)),
            )
        };

        let src_port = match self.read_u16_be("source port") {
            Ok(v) => v,
            Err(err) => return self.fail_once(err),
        };

        let dest_port = match self.read_u16_be("destination port") {
            Ok(v) => v,
            Err(err) => return self.fail_once(err),
        };

        let payload_len = match self.read_u16_be("payload length") {
            Ok(v) => v as usize,
            Err(err) => return self.fail_once(err),
        };

        let mut payload = vec![0u8; payload_len];
        if payload_len > 0
            && let Err(source) = self.reader.read_exact(&mut payload)
        {
            return self.fail_once(ProtocolError::ReadPayload {
                payload_len,
                source,
            });
        }

        let ip_header_size = if is_ipv6 {
            IPV6_HEADER_SIZE
        } else {
            IPV4_HEADER_SIZE
        };
        let packet_size = ip_header_size + UDP_HEADER_SIZE + payload.len();
        if packet_size > self.mtu {
            let packet_number = self.packets_sent + self.packets_dropped + 1;
            let payload_size = payload.len();
            let source_ip = src_ip;
            let source_port = src_port;
            let err_text = format!(
                "packet size {} exceeds MTU limit of {} bytes",
                packet_size, self.mtu
            );

            let packet_number_s = packet_number.to_string();
            let payload_size_s = payload_size.to_string();
            let source_ip_s = source_ip.to_string();
            let source_port_s = source_port.to_string();
            let dest_ip_s = dest_ip.to_string();
            let dest_port_s = dest_port.to_string();

            self.logger.error(
                "Packet dropped due to MTU limit",
                &[
                    ("packet_number", &packet_number_s),
                    ("payload_size", &payload_size_s),
                    ("source_ip", &source_ip_s),
                    ("source_port", &source_port_s),
                    ("dest_ip", &dest_ip_s),
                    ("dest_port", &dest_port_s),
                    ("error", &err_text),
                ],
            );
            self.packets_dropped += 1;

            return Some(Err(ProtocolError::MTUExceeded {
                packet_number,
                packet_size,
                mtu: self.mtu,
                payload_size,
                source_ip,
                source_port,
                dest_ip,
                dest_port,
            }));
        }

        self.packets_sent += 1;
        self.bytes_sent += payload.len() as u64;

        if (self.packets_sent as usize).is_multiple_of(PROGRESS_INTERVAL)
            && self.logger.would_log(LogLevel::Debug)
        {
            let packets_sent = self.packets_sent.to_string();
            let bytes_sent = self.bytes_sent.to_string();

            self.logger.debug(
                "Progress update",
                &[("packets_sent", &packets_sent), ("bytes_sent", &bytes_sent)],
            );
        }

        Some(Ok(Packet {
            src_ip,
            dest_ip,
            src_port,
            dest_port,
            payload,
            flags,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;
    use crate::logger::Logger;
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn test_logger() -> Logger {
        Logger::new(LogLevel::Info)
    }

    fn encode_packet(
        src_ip: IpAddr,
        dest_ip: IpAddr,
        src_port: u16,
        dest_port: u16,
        payload: &[u8],
        flags: u8,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC_BYTES);
        buf.push(flags);
        match src_ip {
            IpAddr::V4(ip) => buf.extend_from_slice(&ip.octets()),
            IpAddr::V6(ip) => buf.extend_from_slice(&ip.octets()),
        }
        match dest_ip {
            IpAddr::V4(ip) => buf.extend_from_slice(&ip.octets()),
            IpAddr::V6(ip) => buf.extend_from_slice(&ip.octets()),
        }
        buf.extend_from_slice(&src_port.to_be_bytes());
        buf.extend_from_slice(&dest_port.to_be_bytes());
        let payload_len = payload.len() as u16;
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn parses_single_valid_ipv4_packet() {
        let src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dest_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let payload = b"hello";
        let data = encode_packet(src_ip, dest_ip, 12345, 514, payload, 0);

        let logger = test_logger();
        let mut stream = ProtocolStream::new(Cursor::new(data), true, 1500, &logger);

        let packet = stream
            .next()
            .expect("expected one packet")
            .expect("expected valid packet");
        assert_eq!(packet.src_ip, src_ip);
        assert_eq!(packet.dest_ip, dest_ip);
        assert_eq!(packet.src_port, 12345);
        assert_eq!(packet.dest_port, 514);
        assert_eq!(packet.payload, payload);
        assert_eq!(packet.flags, 0);

        assert!(stream.next().is_none());
    }

    #[test]
    fn parses_single_valid_ipv6_packet() {
        let src_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let dest_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
        let payload = b"ipv6";
        let data = encode_packet(src_ip, dest_ip, 54321, 80, payload, FLAG_IPV6);

        let logger = test_logger();
        let mut stream = ProtocolStream::new(Cursor::new(data), true, 1500, &logger);

        let packet = stream
            .next()
            .expect("expected one packet")
            .expect("expected valid packet");
        assert_eq!(packet.src_ip, src_ip);
        assert_eq!(packet.dest_ip, dest_ip);
        assert_eq!(packet.src_port, 54321);
        assert_eq!(packet.dest_port, 80);
        assert_eq!(packet.payload, payload);
        assert_eq!(packet.flags, FLAG_IPV6);

        assert!(stream.next().is_none());
    }

    #[test]
    fn parses_multiple_packets_in_sequence() {
        let p1 = encode_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1000,
            2000,
            b"packet1",
            0,
        );
        let p2 = encode_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
            3000,
            4000,
            b"packet2",
            0,
        );
        let p3 = encode_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)),
            5000,
            6000,
            b"packet3",
            0,
        );

        let mut data = Vec::new();
        data.extend_from_slice(&p1);
        data.extend_from_slice(&p2);
        data.extend_from_slice(&p3);

        let logger = test_logger();
        let mut stream = ProtocolStream::new(Cursor::new(data), true, 1500, &logger);

        let pkt1 = stream.next().expect("pkt1 missing").expect("pkt1 invalid");
        assert_eq!(pkt1.payload, b"packet1");

        let pkt2 = stream.next().expect("pkt2 missing").expect("pkt2 invalid");
        assert_eq!(pkt2.payload, b"packet2");

        let pkt3 = stream.next().expect("pkt3 missing").expect("pkt3 invalid");
        assert_eq!(pkt3.payload, b"packet3");

        assert!(stream.next().is_none());
    }

    #[test]
    fn returns_invalid_magic_error() {
        let mut data = encode_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            12345,
            514,
            b"hello",
            0,
        );
        data[0] = 0xDE;
        data[1] = 0xAD;
        data[2] = 0xBE;

        let logger = test_logger();
        let mut stream = ProtocolStream::new(Cursor::new(data), true, 1500, &logger);

        match stream.next() {
            Some(Err(ProtocolError::InvalidMagic {
                got0,
                got1,
                got2,
                exp0,
                exp1,
                exp2,
            })) => {
                assert_eq!((got0, got1, got2), (0xDE, 0xAD, 0xBE));
                assert_eq!(
                    (exp0, exp1, exp2),
                    (MAGIC_BYTES[0], MAGIC_BYTES[1], MAGIC_BYTES[2])
                );
            }
            other => panic!("expected InvalidMagic error, got {other:?}"),
        }

        assert!(stream.next().is_none());
    }

    #[test]
    fn returns_ipv6_not_available_error() {
        let data = encode_packet(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            54321,
            80,
            b"ipv6",
            FLAG_IPV6,
        );

        let logger = test_logger();
        let mut stream = ProtocolStream::new(Cursor::new(data), false, 1500, &logger);

        match stream.next() {
            Some(Err(ProtocolError::IPv6NotAvailable)) => {}
            other => panic!("expected IPv6NotAvailable error, got {other:?}"),
        }

        assert!(stream.next().is_none());
    }

    #[test]
    fn mtu_exceeded_does_not_terminate_stream() {
        let big_payload = vec![b'X'; 80]; // IPv4 packet size = 20 + 8 + 80 = 108 (> 100)
        let big_packet = encode_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            12345,
            54321,
            &big_payload,
            0,
        );

        let small_packet = encode_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4)),
            12346,
            54322,
            b"ok",
            0,
        );

        let mut data = Vec::new();
        data.extend_from_slice(&big_packet);
        data.extend_from_slice(&small_packet);

        let logger = test_logger();
        let mut stream = ProtocolStream::new(Cursor::new(data), true, 100, &logger);

        match stream.next() {
            Some(Err(ProtocolError::MTUExceeded {
                packet_number,
                packet_size,
                mtu,
                payload_size,
                source_ip,
                source_port,
                dest_ip,
                dest_port,
            })) => {
                assert_eq!(packet_number, 1);
                assert_eq!(packet_size, IPV4_HEADER_SIZE + UDP_HEADER_SIZE + 80);
                assert_eq!(mtu, 100);
                assert_eq!(payload_size, 80);
                assert_eq!(source_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
                assert_eq!(source_port, 12345);
                assert_eq!(dest_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
                assert_eq!(dest_port, 54321);
            }
            other => panic!("expected MTUExceeded error, got {other:?}"),
        }

        let ok_packet = stream
            .next()
            .expect("expected second packet")
            .expect("expected valid second packet");
        assert_eq!(ok_packet.payload, b"ok");
        assert_eq!(ok_packet.src_port, 12346);
        assert_eq!(ok_packet.dest_port, 54322);

        assert!(stream.next().is_none());
    }

    #[test]
    fn parses_empty_payload_packet() {
        let data = encode_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            1234,
            5678,
            b"",
            0,
        );

        let logger = test_logger();
        let mut stream = ProtocolStream::new(Cursor::new(data), true, 1500, &logger);

        let packet = stream
            .next()
            .expect("expected one packet")
            .expect("expected valid packet");
        assert!(packet.payload.is_empty());
        assert!(stream.next().is_none());
    }

    #[test]
    fn accepts_packet_exactly_at_mtu_limit() {
        let payload = vec![0xAB; 32]; // 20 + 8 + 32 = 60
        let mtu = IPV4_HEADER_SIZE + UDP_HEADER_SIZE + payload.len();

        let data = encode_packet(
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2)),
            1111,
            2222,
            &payload,
            0,
        );

        let logger = test_logger();
        let mut stream = ProtocolStream::new(Cursor::new(data), true, mtu, &logger);

        let packet = stream
            .next()
            .expect("expected packet")
            .expect("packet should be accepted at MTU limit");
        assert_eq!(packet.payload, payload);
        assert!(stream.next().is_none());
    }

    #[test]
    fn preserves_binary_payload_bytes() {
        let payload = [0x00, 0xFF, 0x80, 0x01];
        let data = encode_packet(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            9000,
            9001,
            &payload,
            0,
        );

        let logger = test_logger();
        let mut stream = ProtocolStream::new(Cursor::new(data), true, 1500, &logger);

        let packet = stream
            .next()
            .expect("expected packet")
            .expect("expected valid packet");
        assert_eq!(packet.payload, payload);
        assert!(stream.next().is_none());
    }

    #[test]
    fn accepts_unknown_flags_when_ipv6_bit_is_set() {
        let flags = FLAG_IPV6 | 0x80;
        let data = encode_packet(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            54321,
            80,
            b"ipv6 unknown flags",
            flags,
        );

        let logger = test_logger();
        let mut stream = ProtocolStream::new(Cursor::new(data), true, 1500, &logger);

        let packet = stream
            .next()
            .expect("expected packet")
            .expect("expected valid packet");
        assert_eq!(packet.flags, flags);
        assert!(matches!(packet.src_ip, IpAddr::V6(_)));
        assert!(matches!(packet.dest_ip, IpAddr::V6(_)));
    }

    #[test]
    fn handles_empty_stream() {
        let logger = test_logger();
        let mut stream = ProtocolStream::new(Cursor::new(Vec::<u8>::new()), true, 1500, &logger);
        assert!(stream.next().is_none());
    }

    #[test]
    fn returns_read_magic_error_on_incomplete_magic_bytes() {
        let logger = test_logger();
        let mut stream = ProtocolStream::new(
            Cursor::new(vec![MAGIC_BYTES[0], MAGIC_BYTES[1]]),
            true,
            1500,
            &logger,
        );

        match stream.next() {
            Some(Err(ProtocolError::ReadMagic { read, source })) => {
                assert_eq!(read, 2);
                assert_eq!(source.kind(), io::ErrorKind::UnexpectedEof);
            }
            other => panic!("expected ReadMagic error, got {other:?}"),
        }
    }

    #[test]
    fn returns_read_field_error_on_missing_flags() {
        let logger = test_logger();
        let mut stream =
            ProtocolStream::new(Cursor::new(MAGIC_BYTES.to_vec()), true, 1500, &logger);

        match stream.next() {
            Some(Err(ProtocolError::ReadField { field, source })) => {
                assert_eq!(field, "flags byte");
                assert_eq!(source.kind(), io::ErrorKind::UnexpectedEof);
            }
            other => panic!("expected ReadField(flags byte) error, got {other:?}"),
        }
    }

    #[test]
    fn returns_read_payload_error_on_truncated_payload() {
        let mut data = encode_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            12345,
            8080,
            &[0u8; 100],
            0,
        );
        data.truncate(data.len() - 10);

        let logger = test_logger();
        let mut stream = ProtocolStream::new(Cursor::new(data), true, 1500, &logger);

        match stream.next() {
            Some(Err(ProtocolError::ReadPayload {
                payload_len,
                source,
            })) => {
                assert_eq!(payload_len, 100);
                assert_eq!(source.kind(), io::ErrorKind::UnexpectedEof);
            }
            other => panic!("expected ReadPayload error, got {other:?}"),
        }
    }

    /// A `Read` adapter that returns `ErrorKind::Interrupted` for the first
    /// `interrupt_count` calls and then delegates to an inner cursor. Used to
    /// exercise the retry loop in `read_magic`.
    struct InterruptingReader {
        inner: Cursor<Vec<u8>>,
        interrupts_left: usize,
    }

    impl InterruptingReader {
        fn new(data: Vec<u8>, interrupts: usize) -> Self {
            Self {
                inner: Cursor::new(data),
                interrupts_left: interrupts,
            }
        }
    }

    impl io::Read for InterruptingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.interrupts_left > 0 {
                self.interrupts_left -= 1;
                return Err(io::Error::new(io::ErrorKind::Interrupted, "interrupted"));
            }
            self.inner.read(buf)
        }
    }

    /// A `Read` adapter that surfaces a custom non-Interrupted error on the
    /// first call. Used to verify `read_magic` propagates real I/O errors.
    struct FailingMagicReader {
        called: bool,
    }

    impl io::Read for FailingMagicReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            if !self.called {
                self.called = true;
                return Err(io::Error::new(io::ErrorKind::ConnectionReset, "boom"));
            }
            Ok(0)
        }
    }

    /// A `Read` adapter that always returns one byte at a time from an inner
    /// buffer. Forces `read_magic` to accumulate across multiple Ok(n>0) calls.
    struct OneByteAtATimeReader {
        inner: Cursor<Vec<u8>>,
    }

    impl io::Read for OneByteAtATimeReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let mut tiny = [0u8; 1];
            match self.inner.read(&mut tiny)? {
                0 => Ok(0),
                _ => {
                    buf[0] = tiny[0];
                    Ok(1)
                }
            }
        }
    }

    #[test]
    fn read_magic_retries_through_interrupted_errors() {
        let data = encode_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1111,
            2222,
            b"hello",
            0,
        );
        let reader = InterruptingReader::new(data, 5);
        let logger = test_logger();
        let mut stream = ProtocolStream::new(reader, true, 1500, &logger);

        let packet = stream
            .next()
            .expect("expected a packet")
            .expect("packet parse should succeed despite interrupts");
        assert_eq!(packet.payload, b"hello");
        assert_eq!(packet.src_port, 1111);
        assert_eq!(packet.dest_port, 2222);
    }

    #[test]
    fn read_magic_propagates_non_interrupted_error() {
        let logger = test_logger();
        let mut stream =
            ProtocolStream::new(FailingMagicReader { called: false }, true, 1500, &logger);

        match stream.next() {
            Some(Err(ProtocolError::ReadMagic { read, source })) => {
                assert_eq!(read, 0);
                assert_eq!(source.kind(), io::ErrorKind::ConnectionReset);
            }
            other => panic!("expected ReadMagic(ConnectionReset) error, got {other:?}"),
        }
    }

    #[test]
    fn read_magic_accumulates_partial_reads() {
        let data = encode_packet(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            5000,
            6000,
            b"abc",
            0,
        );
        let reader = OneByteAtATimeReader {
            inner: Cursor::new(data),
        };
        let logger = test_logger();
        let mut stream = ProtocolStream::new(reader, true, 1500, &logger);

        let packet = stream
            .next()
            .expect("expected a packet")
            .expect("packet parse should succeed across one-byte reads");
        assert_eq!(packet.payload, b"abc");
    }

    #[test]
    fn stream_continues_after_mtu_exceeded_with_subsequent_valid_packet() {
        let mut data = encode_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            5555,
            6666,
            &[0xAAu8; 1500],
            0,
        );
        data.extend(encode_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4)),
            7777,
            8888,
            b"ok",
            0,
        ));

        let logger = test_logger();
        let mut stream = ProtocolStream::new(Cursor::new(data), true, 1500, &logger);

        match stream.next() {
            Some(Err(ProtocolError::MTUExceeded { .. })) => {}
            other => panic!("expected MTUExceeded, got {other:?}"),
        }

        let recovered = stream
            .next()
            .expect("expected a second packet")
            .expect("second packet should parse cleanly");
        assert_eq!(recovered.payload, b"ok");
        assert_eq!(recovered.src_port, 7777);
    }

    #[test]
    fn invalid_magic_terminates_stream_permanently() {
        let mut data = vec![0xDE, 0xAD, 0xBE];
        data.extend_from_slice(&[0u8; 32]);
        let logger = test_logger();
        let mut stream = ProtocolStream::new(Cursor::new(data), true, 1500, &logger);

        match stream.next() {
            Some(Err(ProtocolError::InvalidMagic { .. })) => {}
            other => panic!("expected InvalidMagic, got {other:?}"),
        }
        // Subsequent calls must yield None (terminated flag set).
        assert!(stream.next().is_none(), "stream should be terminated");
        assert!(stream.next().is_none(), "stream should remain terminated");
    }

    #[test]
    fn end_of_stream_after_completed_packet_yields_none() {
        let data = encode_packet(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
            53,
            53,
            b"dns",
            0,
        );
        let logger = test_logger();
        let mut stream = ProtocolStream::new(Cursor::new(data), true, 1500, &logger);

        let pkt = stream.next().expect("first").expect("ok");
        assert_eq!(pkt.payload, b"dns");
        assert!(stream.next().is_none());
        assert!(stream.next().is_none());
    }
}
