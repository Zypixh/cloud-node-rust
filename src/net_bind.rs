use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::Context;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};

pub(crate) fn dual_stack_bind_addrs(port: u16) -> [SocketAddr; 2] {
    [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
    ]
}

pub(crate) fn bind_tcp_listener(addr: SocketAddr, backlog: i32) -> anyhow::Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .context("create TCP listener socket")?;
    if addr.is_ipv6() {
        socket
            .set_only_v6(true)
            .context("set IPv6 TCP listener to v6-only")?;
    }
    socket
        .bind(&addr.into())
        .with_context(|| format!("bind TCP listener on {addr}"))?;
    socket
        .listen(backlog)
        .with_context(|| format!("listen on TCP {addr}"))?;
    socket
        .set_nonblocking(true)
        .with_context(|| format!("set TCP listener {addr} nonblocking"))?;
    Ok(TcpListener::from_std(socket.into())?)
}

pub(crate) async fn bind_udp_socket(addr: SocketAddr) -> io::Result<UdpSocket> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_stack_bind_addrs_include_ipv4_and_ipv6_unspecified() {
        let addrs = dual_stack_bind_addrs(8443);
        assert_eq!(
            addrs,
            [
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8443),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 8443),
            ]
        );
    }
}
