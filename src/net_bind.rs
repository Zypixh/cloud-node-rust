use bytes::Bytes;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;
use socket2::{Domain, Protocol, Socket, Type};
#[cfg(target_os = "linux")]
use socket2::{SockAddr, SockAddrStorage};
#[cfg(target_os = "linux")]
use std::mem::size_of;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use tokio::io::Interest;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio::time::{Duration, sleep};

#[cfg(target_os = "linux")]
const UDP_RECEIVE_BATCH_SIZE: usize = 32;
const UDP_MAX_DATAGRAM_SIZE: usize = 65_535;

#[derive(Debug)]
pub(crate) struct ReceivedUdpDatagram {
    pub(crate) peer_addr: SocketAddr,
    pub(crate) payload: Bytes,
    #[cfg(target_os = "linux")]
    pub(crate) rxq_overflow: Option<u32>,
}

pub(crate) struct UdpBatchReceiver {
    socket: Arc<UdpSocket>,
    #[cfg(target_os = "linux")]
    buffers: Vec<[u8; UDP_MAX_DATAGRAM_SIZE]>,
    #[cfg(target_os = "linux")]
    addresses: Vec<libc::sockaddr_storage>,
    #[cfg(target_os = "linux")]
    iovecs: Vec<libc::iovec>,
    #[cfg(target_os = "linux")]
    messages: Vec<libc::mmsghdr>,
    #[cfg(target_os = "linux")]
    controls: Vec<[u64; 8]>,
    #[cfg(not(target_os = "linux"))]
    buffer: Vec<u8>,
}

#[cfg(target_os = "linux")]
// SAFETY: The recvmmsg descriptors contain pointers into allocations owned by
// this receiver. Those allocations are fully initialized before the
// descriptors are created and are never resized afterward. The receiver is
// only accessed through &mut self, so the descriptors cannot be used
// concurrently while the receiver is moved to the Tokio worker thread.
unsafe impl Send for UdpBatchReceiver {}

impl UdpBatchReceiver {
    pub(crate) fn new(socket: Arc<UdpSocket>) -> Self {
        #[cfg(target_os = "linux")]
        {
            let mut buffers = Vec::with_capacity(UDP_RECEIVE_BATCH_SIZE);
            let mut addresses = Vec::with_capacity(UDP_RECEIVE_BATCH_SIZE);
            let mut iovecs = Vec::with_capacity(UDP_RECEIVE_BATCH_SIZE);
            let mut messages = Vec::with_capacity(UDP_RECEIVE_BATCH_SIZE);
            let mut controls = Vec::with_capacity(UDP_RECEIVE_BATCH_SIZE);

            for _ in 0..UDP_RECEIVE_BATCH_SIZE {
                buffers.push([0u8; UDP_MAX_DATAGRAM_SIZE]);
                addresses.push(unsafe { std::mem::zeroed() });
                controls.push([0u64; 8]);
            }
            for buffer in &mut buffers {
                iovecs.push(libc::iovec {
                    iov_base: buffer.as_mut_ptr().cast(),
                    iov_len: UDP_MAX_DATAGRAM_SIZE,
                });
            }
            for index in 0..UDP_RECEIVE_BATCH_SIZE {
                messages.push(libc::mmsghdr {
                    msg_hdr: libc::msghdr {
                        msg_name: (&mut addresses[index] as *mut libc::sockaddr_storage).cast(),
                        msg_namelen: size_of::<libc::sockaddr_storage>() as libc::socklen_t,
                        msg_iov: &mut iovecs[index],
                        msg_iovlen: 1,
                        msg_control: controls[index].as_mut_ptr().cast(),
                        msg_controllen: std::mem::size_of_val(&controls[index]),
                        msg_flags: 0,
                    },
                    msg_len: 0,
                });
            }

            Self {
                socket,
                buffers,
                addresses,
                iovecs,
                messages,
                controls,
            }
        }

        #[cfg(not(target_os = "linux"))]
        Self {
            socket,
            buffer: vec![0u8; UDP_MAX_DATAGRAM_SIZE],
        }
    }

    pub(crate) async fn recv_batch(&mut self) -> io::Result<Vec<ReceivedUdpDatagram>> {
        #[cfg(target_os = "linux")]
        {
            self.recv_batch_linux().await
        }

        #[cfg(not(target_os = "linux"))]
        {
            let (len, peer_addr) = self.socket.recv_from(&mut self.buffer).await?;
            Ok(vec![ReceivedUdpDatagram {
                peer_addr,
                payload: Bytes::copy_from_slice(&self.buffer[..len]),
            }])
        }
    }

    #[cfg(target_os = "linux")]
    async fn recv_batch_linux(&mut self) -> io::Result<Vec<ReceivedUdpDatagram>> {
        loop {
            self.socket.readable().await?;
            for (message, iovec) in self.messages.iter_mut().zip(self.iovecs.iter_mut()) {
                message.msg_hdr.msg_namelen =
                    size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                message.msg_hdr.msg_controllen = std::mem::size_of_val(&self.controls[0]);
                // Re-derive the iovec pointer each call so the descriptor
                // always points at the buffer this receiver owns.
                message.msg_hdr.msg_iov = iovec;
                message.msg_hdr.msg_iovlen = 1;
                message.msg_len = 0;
            }

            let fd = self.socket.as_raw_fd();
            let messages = &mut self.messages;
            let received = self.socket.try_io(Interest::READABLE, || {
                let result = unsafe {
                    libc::recvmmsg(
                        fd,
                        messages.as_mut_ptr(),
                        messages.len() as libc::c_uint,
                        libc::MSG_DONTWAIT,
                        std::ptr::null_mut(),
                    )
                };
                if result < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(result as usize)
                }
            });

            let received = match received {
                Ok(received) => received,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => return Err(err),
            };

            let mut datagrams = Vec::with_capacity(received);
            for ((address, message), buffer) in self
                .addresses
                .iter()
                .zip(messages.iter())
                .zip(self.buffers.iter())
                .take(received)
            {
                let mut storage = SockAddrStorage::zeroed();
                unsafe {
                    *storage.view_as::<libc::sockaddr_storage>() = *address;
                }
                let peer_addr =
                    unsafe { SockAddr::new(storage, message.msg_hdr.msg_namelen) }
                        .as_socket()
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "UDP recvmmsg returned a non-IP peer address",
                            )
                        })?;
                let len = message.msg_len as usize;
                datagrams.push(ReceivedUdpDatagram {
                    peer_addr,
                    payload: Bytes::copy_from_slice(&buffer[..len]),
                    rxq_overflow: parse_rxq_overflow(&message.msg_hdr),
                });
            }
            return Ok(datagrams);
        }
    }
}

#[cfg(target_os = "linux")]
fn parse_rxq_overflow(message: &libc::msghdr) -> Option<u32> {
    let mut control = unsafe { libc::CMSG_FIRSTHDR(message) };
    let minimum_len =
        unsafe { libc::CMSG_LEN(std::mem::size_of::<u32>() as libc::c_uint) } as usize;
    while !control.is_null() {
        let header = unsafe { &*control };
        if header.cmsg_level == libc::SOL_SOCKET
            && header.cmsg_type == libc::SO_RXQ_OVFL
            && (header.cmsg_len as usize) >= minimum_len
        {
            let data = unsafe { libc::CMSG_DATA(control) };
            return Some(unsafe { std::ptr::read_unaligned(data.cast::<u32>()) });
        }
        control = unsafe { libc::CMSG_NXTHDR(message, control) };
    }
    None
}

#[cfg(target_os = "linux")]
pub(crate) fn enable_udp_rxq_overflow(socket: &UdpSocket) -> io::Result<()> {
    let enabled: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RXQ_OVFL,
            (&enabled as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Returns true if an accept error is normally recoverable under load and the
/// listener should keep accepting instead of exiting.
pub(crate) fn is_transient_accept_error(err: &io::Error) -> bool {
    match err.kind() {
        io::ErrorKind::ConnectionAborted
        | io::ErrorKind::Interrupted
        | io::ErrorKind::WouldBlock => true,
        _ => {
            #[cfg(unix)]
            {
                matches!(err.raw_os_error(), Some(libc::EMFILE) | Some(libc::ENFILE))
            }
            #[cfg(not(unix))]
            {
                false
            }
        }
    }
}

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
    let _ = socket.set_reuse_address(true);
    #[cfg(unix)]
    let _ = socket.set_reuse_port(true);
    #[cfg(target_os = "linux")]
    {
        let timeout_secs: libc::c_int = 1;
        let _ = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_DEFER_ACCEPT,
                &timeout_secs as *const _ as *const libc::c_void,
                std::mem::size_of_val(&timeout_secs) as libc::socklen_t,
            )
        };
    }
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
    let _ = socket.set_reuse_address(true);
    #[cfg(unix)]
    let _ = socket.set_reuse_port(true);
    let buffer_size = crate::memory_governor::MEMORY_GOVERNOR.udp_socket_buffer_size();
    let _ = socket.set_recv_buffer_size(buffer_size);
    let _ = socket.set_send_buffer_size(buffer_size);
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

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_udp_bind_allows_two_sockets_on_same_address() {
        let first = bind_udp_socket("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = first.local_addr().unwrap();
        let second = bind_udp_socket(addr).await.unwrap();

        assert_eq!(first.local_addr().unwrap(), addr);
        assert_eq!(second.local_addr().unwrap(), addr);
    }

    #[tokio::test]
    async fn udp_batch_receiver_preserves_order_and_short_datagrams() {
        let receiver_socket = Arc::new(
            bind_udp_socket("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        );
        let receiver_addr = receiver_socket.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let expected = [
            b"a".as_slice(),
            b"medium-payload".as_slice(),
            b"".as_slice(),
        ];

        for payload in expected {
            sender.send_to(payload, receiver_addr).await.unwrap();
        }

        let mut receiver = UdpBatchReceiver::new(receiver_socket);
        let received = tokio::time::timeout(Duration::from_secs(1), async {
            let mut received = Vec::new();
            while received.len() < expected.len() {
                received.extend(
                    receiver
                        .recv_batch()
                        .await
                        .expect("batch receive should succeed")
                        .into_iter()
                        .map(|datagram| datagram.payload),
                );
            }
            received
        })
        .await
        .expect("batch receiver should drain all test datagrams");

        assert_eq!(
            received,
            expected
                .into_iter()
                .map(Bytes::copy_from_slice)
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    #[ignore = "manual high-burst UDP baseline"]
    async fn udp_batch_receiver_high_burst_baseline() {
        let receiver_socket = Arc::new(
            bind_udp_socket("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        );
        #[cfg(target_os = "linux")]
        enable_udp_rxq_overflow(&receiver_socket).unwrap();
        let receiver_addr = receiver_socket.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let attempted = 20_000u64;
        let payload = vec![0xA5; 1_200];
        let mut submitted = 0u64;
        let mut send_errors = 0u64;

        for _ in 0..attempted {
            match sender.send_to(&payload, receiver_addr).await {
                Ok(_) => submitted += 1,
                Err(_) => send_errors += 1,
            }
        }

        let mut receiver = UdpBatchReceiver::new(receiver_socket);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut received = 0u64;
        #[cfg(target_os = "linux")]
        let mut rxq_overflow = 0u32;
        while tokio::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let batch = match tokio::time::timeout(remaining, receiver.recv_batch()).await {
                Ok(Ok(batch)) => batch,
                Ok(Err(err)) => panic!("batch receive failed: {err}"),
                Err(_) => break,
            };
            received += batch.len() as u64;
            #[cfg(target_os = "linux")]
            for datagram in &batch {
                if let Some(value) = datagram.rxq_overflow {
                    rxq_overflow = rxq_overflow.max(value);
                }
            }
            if received >= submitted {
                break;
            }
        }

        println!(
            "udp batch baseline: attempted={attempted} submitted={submitted} \
             send_errors={send_errors} received={received}{}",
            {
                #[cfg(target_os = "linux")]
                {
                    format!(" rxq_overflow={rxq_overflow}")
                }
                #[cfg(not(target_os = "linux"))]
                {
                    String::new()
                }
            }
        );
        assert!(submitted > 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_udp_batch_receiver_can_enable_rxq_overflow_accounting() {
        let socket = bind_udp_socket("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        enable_udp_rxq_overflow(&socket).unwrap();
    }
}
