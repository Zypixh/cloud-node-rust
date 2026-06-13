use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::Context;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio::time::{Duration, sleep};

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

fn is_addr_in_use(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|err| err.kind() == io::ErrorKind::AddrInUse)
    })
}

pub(crate) async fn bind_tcp_listener_with_retry(
    addr: SocketAddr,
    backlog: i32,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> anyhow::Result<TcpListener> {
    let mut last_error = None;
    for _ in 0..100 {
        match bind_tcp_listener(addr, backlog) {
            Ok(listener) => return Ok(listener),
            Err(err) if is_addr_in_use(&err) => {
                last_error = Some(err);
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        anyhow::bail!("TCP listener shutdown while waiting for port reuse");
                    }
                    _ = sleep(Duration::from_millis(50)) => {}
                }
            }
            Err(err) => return Err(err),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("TCP listener port is still in use")))
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

    #[tokio::test]
    async fn tcp_bind_retry_waits_for_released_port() {
        let first = bind_tcp_listener("127.0.0.1:0".parse().unwrap(), 128).unwrap();
        let addr = first.local_addr().unwrap();
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        let retry =
            tokio::spawn(
                async move { bind_tcp_listener_with_retry(addr, 128, &mut shutdown_rx).await },
            );

        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(first);

        let second = retry.await.unwrap().unwrap();
        assert_eq!(second.local_addr().unwrap(), addr);
    }
}
