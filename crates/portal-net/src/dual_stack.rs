//! Dual-stack listener helpers + IPv6 canonicalization (R12 / R12-canon).
//!
//! Single-owner module per R7. `portal-relay` (Phase 5) imports
//! `canonicalize_ip` for its policy-side ACL lookup; `bind_dual_stack_udp` and
//! `bind_dual_stack_tcp` are the canonical socket constructors used by both
//! the QUIC backhaul (`quic::endpoint`) and the relay-side TCP/UDP forwarders.
//!
//! ## Default behavior (R12)
//!
//! - `v4_only = false` (default): bind an IPv6 socket with `IPV6_V6ONLY=false`
//!   so the kernel accepts both IPv4 and IPv6 traffic on a single endpoint.
//! - `v4_only = true`: bind an IPv4-only socket on `0.0.0.0` (or the supplied
//!   IPv4 address). Used by deployments that explicitly disable v6.
//!
//! ## Canonicalization
//!
//! IPv4-mapped IPv6 addresses (`::ffff:0:0/96`) are unwrapped to their 32-bit
//! IPv4 form so policy lookups in `portal-relay` see a stable representation
//! regardless of whether the connection arrived on an `IPV6_V6ONLY=false`
//! dual-stack listener or a v4-only listener.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::error::NetError;

/// Canonicalize an IP address for policy lookup.
///
/// IPv4-mapped IPv6 addresses (`::ffff:0:0/96`) are unwrapped to their 32-bit
/// IPv4 form. Other addresses are returned unchanged. Single-owner helper per
/// R12-canon — `portal-relay` (Phase 5) imports this for its policy-side ACL
/// lookup.
#[must_use]
pub const fn canonicalize_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Canonicalize a [`SocketAddr`] by applying [`canonicalize_ip`] to its IP.
///
/// The port is preserved. The returned address is `V4` whenever the input was
/// an IPv4-mapped IPv6, even when the input arrived as `V6`.
#[must_use]
pub const fn canonicalize_socket(addr: SocketAddr) -> SocketAddr {
    let port = addr.port();
    match canonicalize_ip(addr.ip()) {
        IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
        IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0)),
    }
}

/// Bind a UDP socket suitable for handing to `quinn::Endpoint::new`.
///
/// By default (R12) the socket accepts both IPv4 and IPv6 traffic via
/// `IPV6_V6ONLY = false`. Pass `v4_only = true` to bind a v4-only socket on
/// `0.0.0.0` (or the supplied IPv4 address).
///
/// # Errors
///
/// Returns [`NetError::Io`] on bind failure (port in use, permission denied,
/// invalid address family combination). Returns [`NetError::BindFailed`] when
/// the requested combination cannot be expressed (e.g., `v4_only=true` with a
/// non-wildcard IPv6 address).
pub fn bind_dual_stack_udp(
    addr: IpAddr,
    port: u16,
    v4_only: bool,
) -> Result<std::net::UdpSocket, NetError> {
    let (socket, sock_addr) = build_dual_stack_socket(addr, port, v4_only, Type::DGRAM)?;
    socket.bind(&sock_addr)?;
    let std_socket: std::net::UdpSocket = socket_into_udp(socket);
    Ok(std_socket)
}

/// Bind a TCP listener with the same dual-stack semantics as
/// [`bind_dual_stack_udp`]. Returns a tokio `TcpListener` (the default listener
/// type for the relay's TCP port forwarder, U7).
///
/// # Errors
///
/// Same as [`bind_dual_stack_udp`].
pub async fn bind_dual_stack_tcp(
    addr: IpAddr,
    port: u16,
    v4_only: bool,
) -> Result<tokio::net::TcpListener, NetError> {
    let (socket, sock_addr) = build_dual_stack_socket(addr, port, v4_only, Type::STREAM)?;
    socket.bind(&sock_addr)?;
    // Per Linux/POSIX, `listen()` must precede the conversion into a tokio
    // listener. The backlog mirrors tokio's default (1024) for parity with
    // `tokio::net::TcpListener::bind`.
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket_into_tcp(socket);
    let listener = tokio::net::TcpListener::from_std(std_listener)?;
    Ok(listener)
}

/// Resolve the requested `(addr, port, v4_only)` into a configured
/// [`socket2::Socket`] of the given [`Type`] and the matching [`SockAddr`] to
/// bind. The socket is left unbound; callers invoke `.bind()` and any further
/// configuration (e.g. `listen()` for TCP).
fn build_dual_stack_socket(
    addr: IpAddr,
    port: u16,
    v4_only: bool,
    sock_type: Type,
) -> Result<(Socket, SockAddr), NetError> {
    let protocol = match sock_type {
        Type::STREAM => Some(Protocol::TCP),
        Type::DGRAM => Some(Protocol::UDP),
        _ => None,
    };
    if v4_only {
        let v4_addr: Ipv4Addr = match addr {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => v4,
                None => {
                    return Err(NetError::BindFailed(format!(
                        "v4_only=true incompatible with IPv6 address {v6}",
                    )));
                }
            },
        };
        let socket = Socket::new(Domain::IPV4, sock_type, protocol)?;
        socket.set_nonblocking(true)?;
        let sock_addr: SockAddr = SocketAddr::V4(SocketAddrV4::new(v4_addr, port)).into();
        Ok((socket, sock_addr))
    } else {
        // Dual-stack v6: bind a v6 socket with `IPV6_V6ONLY=false` so the
        // kernel accepts both v4 and v6 on a single descriptor.
        let v6_addr: Ipv6Addr = match addr {
            IpAddr::V6(v6) => v6,
            IpAddr::V4(v4) if v4.is_unspecified() => Ipv6Addr::UNSPECIFIED,
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        };
        let socket = Socket::new(Domain::IPV6, sock_type, protocol)?;
        socket.set_only_v6(false)?;
        socket.set_nonblocking(true)?;
        let sock_addr: SockAddr = SocketAddr::V6(SocketAddrV6::new(v6_addr, port, 0, 0)).into();
        Ok((socket, sock_addr))
    }
}

/// Convert a [`socket2::Socket`] into a [`std::net::UdpSocket`] cross-platform.
/// The path goes via [`OwnedFd`]/[`OwnedSocket`] which is the supported
/// std-conversion idiom (socket2 does not implement `From<Socket> for UdpSocket`
/// directly).
#[cfg(unix)]
fn socket_into_udp(socket: Socket) -> std::net::UdpSocket {
    use std::os::fd::OwnedFd;
    OwnedFd::from(socket).into()
}

#[cfg(windows)]
fn socket_into_udp(socket: Socket) -> std::net::UdpSocket {
    use std::os::windows::io::OwnedSocket;
    OwnedSocket::from(socket).into()
}

/// Convert a [`socket2::Socket`] into a [`std::net::TcpListener`] cross-platform.
#[cfg(unix)]
fn socket_into_tcp(socket: Socket) -> std::net::TcpListener {
    use std::os::fd::OwnedFd;
    OwnedFd::from(socket).into()
}

#[cfg(windows)]
fn socket_into_tcp(socket: Socket) -> std::net::TcpListener {
    use std::os::windows::io::OwnedSocket;
    OwnedSocket::from(socket).into()
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests parse hard-coded literals + bind ephemeral sockets"
)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_ip_v4_mapped_to_v4() {
        let addr: IpAddr = "::ffff:1.2.3.4".parse().unwrap();
        assert_eq!(canonicalize_ip(addr), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn canonicalize_ip_pure_v4_unchanged() {
        let addr: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(canonicalize_ip(addr), addr);
    }

    #[test]
    fn canonicalize_ip_loopback_v6_unchanged() {
        let addr: IpAddr = "::1".parse().unwrap();
        assert_eq!(canonicalize_ip(addr), addr);
    }

    #[test]
    fn canonicalize_ip_global_v6_unchanged() {
        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(canonicalize_ip(addr), addr);
    }

    #[test]
    fn canonicalize_ip_v4_mapped_lower_bound() {
        let addr: IpAddr = "::ffff:0.0.0.0".parse().unwrap();
        assert_eq!(canonicalize_ip(addr), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn canonicalize_ip_v4_mapped_upper_bound() {
        let addr: IpAddr = "::ffff:255.255.255.255".parse().unwrap();
        assert_eq!(canonicalize_ip(addr), IpAddr::V4(Ipv4Addr::BROADCAST));
    }

    #[test]
    fn canonicalize_socket_preserves_port() {
        let addr = SocketAddr::new("::ffff:1.2.3.4".parse().unwrap(), 9000);
        let canonical = canonicalize_socket(addr);
        assert_eq!(
            canonical,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 9000)),
        );
    }

    #[test]
    fn bind_dual_stack_udp_default_is_dual_stack() {
        let socket = bind_dual_stack_udp("::".parse().unwrap(), 0, false).unwrap();
        let local = socket.local_addr().unwrap();
        assert!(
            local.is_ipv6(),
            "default dual-stack bind should produce v6 socket",
        );
        // Re-cast to inspect IPV6_V6ONLY. Cross-platform path goes via
        // OwnedFd / OwnedSocket — socket2 does not implement
        // `From<UdpSocket> for Socket` directly.
        let s2: Socket = udp_into_socket(socket);
        assert!(
            !s2.only_v6().unwrap(),
            "default bind must set IPV6_V6ONLY=false (R12)",
        );
        // Drop releases the underlying fd.
    }

    #[cfg(unix)]
    fn udp_into_socket(s: std::net::UdpSocket) -> Socket {
        use std::os::fd::OwnedFd;
        Socket::from(OwnedFd::from(s))
    }

    #[cfg(windows)]
    fn udp_into_socket(s: std::net::UdpSocket) -> Socket {
        use std::os::windows::io::OwnedSocket;
        Socket::from(OwnedSocket::from(s))
    }

    #[test]
    fn bind_dual_stack_udp_v4_only_is_v4_only() {
        let socket = bind_dual_stack_udp("0.0.0.0".parse().unwrap(), 0, true).unwrap();
        let local = socket.local_addr().unwrap();
        assert!(
            local.is_ipv4(),
            "v4_only=true must produce a v4 socket (got {local})",
        );
    }

    #[test]
    fn bind_dual_stack_udp_v4_only_rejects_specific_v6() {
        let result = bind_dual_stack_udp("2001:db8::1".parse().unwrap(), 0, true);
        assert!(
            matches!(result, Err(NetError::BindFailed(_))),
            "v4_only=true with non-mapped IPv6 must return BindFailed: {result:?}",
        );
    }

    #[tokio::test]
    async fn bind_dual_stack_tcp_default_is_dual_stack() {
        let listener = bind_dual_stack_tcp("::".parse().unwrap(), 0, false)
            .await
            .unwrap();
        let local = listener.local_addr().unwrap();
        assert!(local.is_ipv6());
    }
}
