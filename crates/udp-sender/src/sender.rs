use std::net::{IpAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};

use nix::libc;
use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType, socket};
use nix::unistd::close;
use thiserror::Error;

pub trait PacketSender {
    fn send(
        &mut self,
        packet: &[u8],
        dest_ip: IpAddr,
        dest_port: u16,
        src_ip: IpAddr,
        src_port: u16,
    ) -> Result<usize, SenderError>;

    fn close(&mut self) -> Result<(), SenderError>;
}

#[derive(Error, Debug)]
pub enum SenderError {
    #[error("Failed to create IPv4 raw socket: {0}")]
    IPv4Socket(#[source] nix::Error),

    #[error("Failed to create IPv6 raw socket: {0}")]
    IPv6Socket(#[source] nix::Error),

    #[error("Send failed: {0}")]
    SendError(#[source] nix::Error),

    #[error("Close failed: {0}")]
    CloseError(#[source] nix::Error),
}

pub struct UDPSender {
    fd_ipv4: RawFd,
    fd_ipv6: Option<RawFd>,
    has_ipv6: bool,
}

impl UDPSender {
    pub fn new() -> Result<Self, SenderError> {
        let fd_ipv4_owned = socket(
            AddressFamily::Inet,
            SockType::Raw,
            SockFlag::empty(),
            Some(SockProtocol::Raw),
        )
        .map_err(SenderError::IPv4Socket)?;

        let enable_hdrincl: libc::c_int = 1;
        let setopt_result = unsafe {
            libc::setsockopt(
                fd_ipv4_owned.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                (&enable_hdrincl as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if setopt_result != 0 {
            let err = nix::errno::Errno::last();
            return Err(SenderError::IPv4Socket(err));
        }

        let fd_ipv4 = fd_ipv4_owned.into_raw_fd();

        let (fd_ipv6, has_ipv6) = match socket(
            AddressFamily::Inet6,
            SockType::Raw,
            SockFlag::empty(),
            Some(SockProtocol::Raw),
        ) {
            Ok(fd) => {
                let fd = fd.into_raw_fd();
                if enable_ipv6_hdrincl(fd) {
                    (Some(fd), true)
                } else {
                    // IPv6 header inclusion is required for source spoofing;
                    // degrade gracefully to IPv4-only if we cannot enable it.
                    let _ = close(fd);
                    (None, false)
                }
            }
            Err(_) => (None, false),
        };

        Ok(Self {
            fd_ipv4,
            fd_ipv6,
            has_ipv6,
        })
    }

    pub fn has_ipv6(&self) -> bool {
        self.has_ipv6
    }
}

/// Enable IPV6_HDRINCL so the kernel accepts our fully-formed IPv6 header
/// instead of prepending its own. `libc::IPV6_HDRINCL` is only exposed on
/// Linux targets; on other platforms the option is not available and we keep
/// the socket as-is.
#[cfg(target_os = "linux")]
fn enable_ipv6_hdrincl(fd: RawFd) -> bool {
    let enable_hdrincl: libc::c_int = 1;
    let setopt_result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_HDRINCL,
            (&enable_hdrincl as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    setopt_result == 0
}

#[cfg(not(target_os = "linux"))]
fn enable_ipv6_hdrincl(_fd: RawFd) -> bool {
    true
}

impl PacketSender for UDPSender {
    fn send(
        &mut self,
        packet: &[u8],
        dest_ip: IpAddr,
        dest_port: u16,
        src_ip: IpAddr,
        _src_port: u16,
    ) -> Result<usize, SenderError> {
        match (src_ip, dest_ip) {
            (IpAddr::V4(src_v4), IpAddr::V4(dest_v4)) => {
                let _ = src_v4;
                let socket_addr = SocketAddrV4::new(dest_v4, dest_port);
                let sockaddr = libc::sockaddr_in {
                    #[cfg(any(
                        target_os = "macos",
                        target_os = "ios",
                        target_os = "freebsd",
                        target_os = "openbsd",
                        target_os = "netbsd",
                        target_os = "dragonfly"
                    ))]
                    sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: socket_addr.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(socket_addr.ip().octets()),
                    },
                    sin_zero: [0; 8],
                };

                let sent = unsafe {
                    libc::sendto(
                        self.fd_ipv4,
                        packet.as_ptr().cast(),
                        packet.len(),
                        0,
                        (&sockaddr as *const libc::sockaddr_in).cast(),
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                };

                if sent < 0 {
                    Err(SenderError::SendError(nix::errno::Errno::last()))
                } else {
                    Ok(sent as usize)
                }
            }
            (IpAddr::V6(_), IpAddr::V6(dest_v6)) => {
                let fd = self.fd_ipv6.ok_or_else(|| {
                    SenderError::SendError(nix::Error::from(nix::errno::Errno::EAFNOSUPPORT))
                })?;
                let socket_addr = SocketAddrV6::new(dest_v6, 0, 0, 0);
                let sockaddr = libc::sockaddr_in6 {
                    #[cfg(any(
                        target_os = "macos",
                        target_os = "ios",
                        target_os = "freebsd",
                        target_os = "openbsd",
                        target_os = "netbsd",
                        target_os = "dragonfly"
                    ))]
                    sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: socket_addr.port().to_be(),
                    sin6_flowinfo: socket_addr.flowinfo(),
                    sin6_addr: libc::in6_addr {
                        s6_addr: socket_addr.ip().octets(),
                    },
                    sin6_scope_id: socket_addr.scope_id(),
                };

                let sent = unsafe {
                    libc::sendto(
                        fd,
                        packet.as_ptr().cast(),
                        packet.len(),
                        0,
                        (&sockaddr as *const libc::sockaddr_in6).cast(),
                        std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    )
                };

                if sent < 0 {
                    Err(SenderError::SendError(nix::errno::Errno::last()))
                } else {
                    Ok(sent as usize)
                }
            }
            _ => Err(SenderError::SendError(nix::Error::from(
                nix::errno::Errno::EINVAL,
            ))),
        }
    }

    fn close(&mut self) -> Result<(), SenderError> {
        let err4 = if self.fd_ipv4 >= 0 {
            let fd = self.fd_ipv4;
            self.fd_ipv4 = -1;
            close(fd).err()
        } else {
            None
        };

        let err6 = if let Some(fd) = self.fd_ipv6.take() {
            close(fd).err()
        } else {
            None
        };

        self.has_ipv6 = self.fd_ipv6.is_some();

        if let Some(err) = err4 {
            return Err(SenderError::CloseError(err));
        }

        if let Some(err) = err6 {
            return Err(SenderError::CloseError(err));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PacketBuilder;
    use crate::protocol::Packet;
    use std::net::Ipv4Addr;

    fn build_test_packet(payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::new(1500);
        let packet = Packet {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 12345,
            dest_port: 54321,
            payload: payload.to_vec(),
            flags: 0,
        };
        builder.build_packet(&packet).expect("build packet")
    }

    #[test]
    #[ignore = "requires root/CAP_NET_RAW"]
    fn test_create_raw_ipv4_socket() {
        let mut sender = UDPSender::new().expect("IPv4 raw socket must succeed as root");
        assert!(sender.fd_ipv4 >= 0);
        sender.close().expect("close must succeed");
    }

    #[test]
    #[ignore = "requires root/CAP_NET_RAW"]
    fn test_has_ipv6_detection() {
        let mut sender = UDPSender::new().expect("create sender");
        let has_v6 = sender.has_ipv6();
        assert!(sender.fd_ipv4 >= 0);
        assert_eq!(sender.fd_ipv6.is_some(), has_v6);
        sender.close().expect("close must succeed");
    }

    #[test]
    #[ignore = "requires root/CAP_NET_RAW"]
    fn test_send_ipv4_localhost() {
        let mut sender = UDPSender::new().expect("create sender");
        let payload = b"hello";
        let packet = build_test_packet(payload);

        let result = sender.send(
            &packet,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            54321,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            12345,
        );

        // sendto() returns the number of bytes sent (IP+UDP+payload)
        match result {
            Ok(sent) => assert!(sent > 0, "send must return positive byte count"),
            Err(SenderError::SendError(e)) => {
                // ENETUNREACH is acceptable on systems without lo interface config
                if e != nix::errno::Errno::ENETUNREACH {
                    panic!("unexpected send error: {}", e);
                }
            }
            Err(e) => panic!("unexpected error: {}", e),
        }

        sender.close().expect("close must succeed");
    }

    #[test]
    #[ignore = "requires root/CAP_NET_RAW"]
    fn test_send_ipv6_fails_when_no_ipv6() {
        let sender = UDPSender::new().expect("create sender");
        let mut sender = sender;
        let has_v6 = sender.has_ipv6();

        if has_v6 {
            let payload = b"test6";
            let packet = build_test_packet(payload);

            let result = sender.send(
                &packet,
                IpAddr::V6("::1".parse().unwrap()),
                54321,
                IpAddr::V6("::1".parse().unwrap()),
                12345,
            );

            match result {
                Ok(_) | Err(SenderError::SendError(_)) => {}
                Err(e) => panic!("unexpected error: {e}"),
            }
        } else {
            let payload = b"test6";
            let packet = build_test_packet(payload);

            let result = sender.send(
                &packet,
                IpAddr::V6("::1".parse().unwrap()),
                54321,
                IpAddr::V6("::1".parse().unwrap()),
                12345,
            );

            match result {
                Err(SenderError::SendError(nix::errno::Errno::EAFNOSUPPORT)) => {}
                other => panic!("expected EAFNOSUPPORT, got: {other:?}"),
            }
        }

        sender.close().expect("close must succeed");
    }

    #[test]
    #[ignore = "requires root/CAP_NET_RAW"]
    fn test_close_twice_no_double_free() {
        let mut sender = UDPSender::new().expect("create sender");
        sender.close().expect("first close must succeed");
        // Second close should not panic (fd set to -1/taken)
        let result = sender.close();
        match result {
            Ok(()) => {}                          // close of -1/fd returns silently via nix's close
            Err(SenderError::CloseError(_)) => {} // also acceptable
            Err(e) => panic!("unexpected error on second close: {e}"),
        }
    }

    #[test]
    #[ignore = "requires root/CAP_NET_RAW"]
    fn test_send_empty_packet() {
        let mut sender = UDPSender::new().expect("create sender");
        // Headers-only packet (no payload) — still valid as IP+UDP frame
        let empty = build_test_packet(b"");

        let result = sender.send(
            &empty,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            0,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            0,
        );

        match result {
            Ok(sent) => assert!(sent > 0),
            Err(SenderError::SendError(nix::errno::Errno::ENETUNREACH)) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }

        sender.close().expect("close must succeed");
    }

    #[test]
    #[ignore = "requires root/CAP_NET_RAW"]
    fn test_version_mismatch_address() {
        let mut sender = UDPSender::new().expect("create sender");
        let packet = build_test_packet(b"test");

        let result = sender.send(
            &packet,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            0,
            IpAddr::V6("::1".parse().unwrap()),
            0,
        );

        match result {
            Err(SenderError::SendError(nix::errno::Errno::EINVAL)) => {}
            other => panic!("expected EINVAL for v4/v6 mismatch, got: {other:?}"),
        }

        sender.close().expect("close must succeed");
    }
}
