use super::*;

pub struct AfXdpTcpStream {
    incoming_rx: mpsc::Receiver<Bytes>,
    outgoing_tx: Option<mpsc::Sender<Bytes>>,
    read_buf: Bytes,
    write_permit: Option<TcpWritePermitFuture>,
}

pub struct AfXdpTcpStreamParts {
    pub stream: AfXdpTcpStream,
    pub ingress_tx: mpsc::Sender<Bytes>,
    pub egress_rx: mpsc::Receiver<Bytes>,
}

pub(crate) struct AfXdpVirtualSocket<S> {
    pub(crate) inner: parking_lot::Mutex<S>,
}

impl<S> std::fmt::Debug for AfXdpVirtualSocket<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AfXdpVirtualSocket").finish_non_exhaustive()
    }
}

impl<S> AfXdpVirtualSocket<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner: parking_lot::Mutex::new(inner),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for AfXdpVirtualSocket<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock();
        Pin::new(&mut *inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for AfXdpVirtualSocket<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.inner.lock();
        Pin::new(&mut *inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock();
        Pin::new(&mut *inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock();
        Pin::new(&mut *inner).poll_shutdown(cx)
    }
}

impl<S> pingora_core::protocols::l4::virt::VirtualSocket for AfXdpVirtualSocket<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn set_socket_option(
        &self,
        _opt: pingora_core::protocols::l4::virt::VirtualSockOpt,
    ) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn virtual_l4_stream<S>(
    stream: S,
    client_addr: SocketAddr,
) -> pingora_core::protocols::l4::stream::Stream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use pingora_core::protocols::GetSocketDigest;
    use pingora_core::protocols::SocketDigest;
    use pingora_core::protocols::l4::virt::VirtualSocketStream;
    #[cfg(unix)]
    use std::os::unix::io::AsRawFd;
    #[cfg(windows)]
    use std::os::windows::io::AsRawSocket;

    let mut stream = pingora_core::protocols::l4::stream::Stream::from(
        VirtualSocketStream::new(Box::new(AfXdpVirtualSocket::new(stream))),
    );
    #[cfg(unix)]
    let digest = SocketDigest::from_raw_fd(stream.as_raw_fd());
    #[cfg(windows)]
    let digest = SocketDigest::from_raw_socket(stream.as_raw_socket());
    digest
        .peer_addr
        .set(Some(client_addr.into()))
        .expect("newly created OnceCell must be empty");
    stream.set_socket_digest(digest);
    stream
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) struct AfXdpTcpIngressFrame {
    pub(crate) route: AfXdpRouteMeta,
    pub(crate) flow: AfXdpTcpFlowKey,
    pub(crate) ip_packet: Bytes,
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) struct AfXdpTcpEgressFrame {
    pub(crate) route: Option<AfXdpRouteMeta>,
    pub(crate) ip_packet: Vec<u8>,
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) struct AfXdpTcpSession {
    pub(crate) flow: AfXdpTcpFlowKey,
    pub(crate) route: AfXdpRouteMeta,
    pub(crate) proxy_class: AfXdpTcpProxyClass,
    pub(crate) socket: SocketHandle,
    pub(crate) ingress_tx: Option<mpsc::Sender<Bytes>>,
    pub(crate) egress_rx: Option<mpsc::Receiver<Bytes>>,
    pub(crate) pending_ingress: Bytes,
    pub(crate) pending_egress: Bytes,
    pub(crate) created_at: SmoltcpInstant,
    pub(crate) last_activity: SmoltcpInstant,
    pub(crate) proxy_started: bool,
    pub(crate) closing: bool,
    pub(crate) egress_closed: bool,
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AfXdpTcpProxyClass {
    TcpPlain,
    TcpTls,
    Http,
    Https,
}

#[cfg(any(test, target_os = "linux"))]
impl AfXdpTcpProxyClass {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::TcpPlain => "tcp",
            Self::TcpTls => "tcp_tls",
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    pub(crate) fn requires_client_payload_before_proxy(self) -> bool {
        matches!(self, Self::TcpTls | Self::Http | Self::Https)
    }

    pub(crate) fn slow_first_payload_kind(self) -> crate::l4_defense::L4DefenseKind {
        match self {
            Self::TcpPlain => crate::l4_defense::L4DefenseKind::TcpSlowFirstByte,
            Self::TcpTls | Self::Https => crate::l4_defense::L4DefenseKind::TlsSlowClientHello,
            Self::Http => crate::l4_defense::L4DefenseKind::HttpSlowHeader,
        }
    }
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AfXdpTcpIngestStatus {
    Accepted,
    BlockedByL4,
    IgnoredUnknownFlow,
    NoHandler,
    RefusedAtCapacity,
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Debug)]
pub(crate) struct AfXdpTcpAdmissionFailureTracker {
    consecutive_refusals: u32,
    max_consecutive_refusals: u32,
}

#[cfg(any(test, target_os = "linux"))]
impl AfXdpTcpAdmissionFailureTracker {
    pub(crate) fn new(max_consecutive_refusals: u32) -> Self {
        Self {
            consecutive_refusals: 0,
            max_consecutive_refusals: max_consecutive_refusals.max(1),
        }
    }

    pub(crate) fn record(&mut self, status: AfXdpTcpIngestStatus) -> bool {
        match status {
            AfXdpTcpIngestStatus::Accepted => {
                self.consecutive_refusals = 0;
                false
            }
            AfXdpTcpIngestStatus::BlockedByL4 | AfXdpTcpIngestStatus::NoHandler => {
                self.consecutive_refusals = 0;
                false
            }
            AfXdpTcpIngestStatus::IgnoredUnknownFlow => false,
            AfXdpTcpIngestStatus::RefusedAtCapacity => {
                self.consecutive_refusals = self.consecutive_refusals.saturating_add(1);
                self.consecutive_refusals >= self.max_consecutive_refusals
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn consecutive_refusals(&self) -> u32 {
        self.consecutive_refusals
    }
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) struct SmoltcpAfXdpDevice {
    pub(crate) ingress: std::collections::VecDeque<AfXdpTcpIngressFrame>,
    pub(crate) egress: Vec<AfXdpTcpEgressFrame>,
    pub(crate) current_route: Option<AfXdpRouteMeta>,
    pub(crate) max_transmission_unit: usize,
}

#[cfg(any(test, target_os = "linux"))]
impl SmoltcpAfXdpDevice {
    pub(crate) fn new(max_transmission_unit: usize) -> Self {
        Self {
            ingress: std::collections::VecDeque::new(),
            egress: Vec::new(),
            current_route: None,
            max_transmission_unit,
        }
    }

    pub(crate) fn push_ingress(&mut self, route: AfXdpRouteMeta, flow: AfXdpTcpFlowKey, ip_packet: Bytes) {
        self.ingress.push_back(AfXdpTcpIngressFrame {
            route,
            flow,
            ip_packet,
        });
    }

    pub(crate) fn drain_egress(&mut self) -> impl Iterator<Item = AfXdpTcpEgressFrame> + '_ {
        self.egress.drain(..)
    }
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) struct SmoltcpAfXdpRxToken {
    pub(crate) ip_packet: Bytes,
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) struct SmoltcpAfXdpTxToken<'a> {
    pub(crate) route: Option<AfXdpRouteMeta>,
    pub(crate) egress: &'a mut Vec<AfXdpTcpEgressFrame>,
}

#[cfg(any(test, target_os = "linux"))]
impl SmoltcpDevice for SmoltcpAfXdpDevice {
    type RxToken<'a>
        = SmoltcpAfXdpRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = SmoltcpAfXdpTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmoltcpInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = self.ingress.pop_front()?;
        self.current_route = Some(frame.route.clone());
        tracing::trace!(
            "AF_XDP TCP reactor ingress flow local={} peer={} bytes={}",
            frame.flow.local_addr,
            frame.flow.peer_addr,
            frame.ip_packet.len()
        );
        Some((
            SmoltcpAfXdpRxToken {
                ip_packet: frame.ip_packet,
            },
            SmoltcpAfXdpTxToken {
                route: Some(frame.route),
                egress: &mut self.egress,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmoltcpInstant) -> Option<Self::TxToken<'_>> {
        Some(SmoltcpAfXdpTxToken {
            route: self.current_route.clone(),
            egress: &mut self.egress,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.max_transmission_unit;
        caps.max_burst_size = Some(64);
        // AF_XDP delivers raw wire frames. On virtio/VM-to-VM paths the
        // sender may offload checksum completion to the NIC, which marks
        // the skb CHECKSUM_UNNECESSARY while leaving the field partial in
        // the bytes we receive. The kernel stack trusts that mark; a
        // userspace stack must declare the same capability or it drops
        // perfectly valid frames at checksum verification. We still
        // compute checksums on TX ourselves.
        caps.checksum.tcp = Checksum::Tx;
        caps.checksum.udp = Checksum::Tx;
        caps.checksum.ipv4 = Checksum::Tx;
        caps
    }
}

#[cfg(any(test, target_os = "linux"))]
impl RxToken for SmoltcpAfXdpRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.ip_packet)
    }
}

#[cfg(any(test, target_os = "linux"))]
impl TxToken for SmoltcpAfXdpTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        if let Some(route) = self.route {
            self.egress.push(AfXdpTcpEgressFrame {
                route: Some(route),
                ip_packet: packet,
            });
        } else {
            self.egress.push(AfXdpTcpEgressFrame {
                route: None,
                ip_packet: packet,
            });
        }
        result
    }
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) struct AfXdpTcpReactor {
    iface: SmoltcpInterface,
    sockets: SocketSet<'static>,
    device: SmoltcpAfXdpDevice,
    sessions: HashMap<AfXdpTcpFlowKey, AfXdpTcpSession>,
    session_limit: usize,
    tx_scratch: Vec<u8>,
    rx_scratch: Vec<u8>,
    tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
    http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
    cached_pressure_level: crate::l4_defense::L4PressureLevel,
    cached_proxy_idle_timeout: Duration,
    idle_profile_refreshed_at: SmoltcpInstant,
    #[cfg(test)]
    test_auto_start_proxy: bool,
}

#[cfg(any(test, target_os = "linux"))]
impl AfXdpTcpReactor {
    /// Tests only: production reactors get a per-queue share of the node
    /// session budget from `spawn_queue_reactors`, not the whole budget.
    #[cfg(test)]
    pub(crate) fn new(
        tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
        http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
    ) -> Self {
        let session_limit = af_xdp_tcp_session_limit();
        Self::new_with_session_limit(tcp_manager, http_manager, session_limit)
    }

    #[cfg(test)]
    pub(crate) fn new_with_session_limit_for_test(
        tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
        http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
        session_limit: usize,
    ) -> Self {
        let mut reactor =
            Self::new_with_session_limit(tcp_manager, http_manager, session_limit);
        reactor.test_auto_start_proxy = true;
        reactor
    }

    pub(crate) fn new_with_session_limit(
        tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
        http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
        session_limit: usize,
    ) -> Self {
        let mut device = SmoltcpAfXdpDevice::new(1500);
        let mut config = SmoltcpConfig::new(HardwareAddress::Ip);
        config.random_seed = crate::utils::time::now_timestamp() as u64;
        let mut iface =
            SmoltcpInterface::new(config, &mut device, SmoltcpInstant::from_millis(0));
        iface.set_any_ip(true);
        Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device,
            sessions: HashMap::new(),
            session_limit: session_limit.max(1),
            tx_scratch: Vec::with_capacity(2048),
            rx_scratch: vec![0u8; AF_XDP_TCP_RECV_SCRATCH_BYTES],
            tcp_manager,
            http_manager,
            cached_pressure_level: crate::l4_defense::L4PressureLevel::Normal,
            cached_proxy_idle_timeout: AF_XDP_TCP_SESSION_IDLE_TIMEOUT,
            idle_profile_refreshed_at: SmoltcpInstant::from_millis(0),
            #[cfg(test)]
            test_auto_start_proxy: false,
        }
    }

    pub(crate) fn proxy_class_for_port(&self, port: u16) -> Option<AfXdpTcpProxyClass> {
        if let Some(tcp_manager) = self.tcp_manager.as_ref()
            && let Some((_, is_tls)) = tcp_manager.find_tcp_server_by_port_sync(port)
        {
            return Some(if is_tls {
                AfXdpTcpProxyClass::TcpTls
            } else {
                AfXdpTcpProxyClass::TcpPlain
            });
        }
        if let Some(http_manager) = self.http_manager.as_ref()
            && let Some(kind) = http_manager.af_xdp_http_port_kind_sync(port)
        {
            return Some(match kind {
                crate::http_proxy_manager::AfXdpHttpPortKind::Http => AfXdpTcpProxyClass::Http,
                crate::http_proxy_manager::AfXdpHttpPortKind::Https => {
                    AfXdpTcpProxyClass::Https
                }
            });
        }
        None
    }

    pub(crate) fn is_l4_blocked(&self, ip: IpAddr) -> bool {
        self.tcp_manager
            .as_ref()
            .is_some_and(|manager| manager.af_xdp_is_l4_blocked(ip))
            || self
                .http_manager
                .as_ref()
                .is_some_and(|manager| manager.af_xdp_is_l4_blocked(ip))
    }

    pub(crate) fn record_l4_event_for_ip(
        &self,
        ip: IpAddr,
        kind: crate::l4_defense::L4DefenseKind,
        pressure_level: crate::l4_defense::L4PressureLevel,
        detail: String,
    ) {
        if let Some(tcp_manager) = self.tcp_manager.as_ref() {
            let _ = tcp_manager.record_af_xdp_l4_event_with_pressure(
                ip,
                kind,
                pressure_level,
                detail,
            );
            return;
        }
        if let Some(http_manager) = self.http_manager.as_ref() {
            let _ = http_manager.record_af_xdp_l4_event_with_pressure(
                ip,
                kind,
                pressure_level,
                detail,
            );
        }
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn should_ignore_unknown_non_syn(&self, flow: &AfXdpTcpFlowKey, flags: u8) -> bool {
        !self.sessions.contains_key(flow) && !tcp_flags_are_initial_syn(flags)
    }

    /// EN-05 congestion gate: while the queue's TX path is backpressured the
    /// bridge refuses *new* session admissions but keeps feeding existing
    /// sessions, so pressure is shed at the admission boundary instead of
    /// collapsing the whole queue.
    #[cfg(target_os = "linux")]
    pub(crate) fn has_session(&self, flow: &AfXdpTcpFlowKey) -> bool {
        self.sessions.contains_key(flow)
    }

    pub(crate) fn record_ignored_unknown_non_syn(&self, flow: AfXdpTcpFlowKey, bytes: usize) {
        #[cfg(target_os = "linux")]
        AF_XDP_TCP_DIAG_IGNORED_UNKNOWN.fetch_add(1, Ordering::Relaxed);
        tracing::trace!(
            "AF_XDP TCP reactor dropped non-SYN packet for unknown flow local={} peer={} bytes={}",
            flow.local_addr,
            flow.peer_addr,
            bytes
        );
    }

    pub(crate) fn ingest(
        &mut self,
        route: AfXdpRouteMeta,
        flow: AfXdpTcpFlowKey,
        ip_packet: Bytes,
    ) -> AfXdpTcpIngestStatus {
        let existing_session = self.sessions.contains_key(&flow);
        let flags = tcp_flags_from_ip_packet(&ip_packet).unwrap_or(0);
        if !existing_session && !tcp_flags_are_initial_syn(flags) {
            self.record_ignored_unknown_non_syn(flow, ip_packet.len());
            return AfXdpTcpIngestStatus::IgnoredUnknownFlow;
        }

        if self.is_l4_blocked(flow.peer_addr.ip()) {
            if let Some(session) = self.sessions.get_mut(&flow) {
                let socket = self
                    .sockets
                    .get_mut::<SmoltcpTcp::Socket<'static>>(session.socket);
                socket.abort();
                session.closing = true;
            }
            return AfXdpTcpIngestStatus::BlockedByL4;
        }

        let proxy_class = if existing_session {
            None
        } else {
            match self.proxy_class_for_port(flow.local_addr.port()) {
                Some(proxy_class) => Some(proxy_class),
                None => {
                    #[cfg(test)]
                    if self.test_auto_start_proxy {
                        return if !self.ensure_session(
                            route.clone(),
                            flow,
                            AfXdpTcpProxyClass::TcpPlain,
                        ) {
                            AfXdpTcpIngestStatus::RefusedAtCapacity
                        } else {
                            #[cfg(target_os = "linux")]
                            AF_XDP_TCP_DIAG_ACCEPTED.fetch_add(1, Ordering::Relaxed);
                            self.device.push_ingress(route, flow, ip_packet);
                            AfXdpTcpIngestStatus::Accepted
                        };
                    }
                    tracing::debug!(
                        "AF_XDP TCP reactor has no handler for local={} peer={}",
                        flow.local_addr,
                        flow.peer_addr
                    );
                    return AfXdpTcpIngestStatus::NoHandler;
                }
            }
        };

        if !self.ensure_session(
            route.clone(),
            flow,
            proxy_class.unwrap_or(AfXdpTcpProxyClass::TcpPlain),
        ) {
            #[cfg(target_os = "linux")]
            AF_XDP_TCP_DIAG_REFUSED_AT_CAPACITY.fetch_add(1, Ordering::Relaxed);
            self.record_l4_event_for_ip(
                flow.peer_addr.ip(),
                crate::l4_defense::L4DefenseKind::SynBacklogPressure,
                crate::l4_defense::current_pressure_level()
                    .max(crate::l4_defense::L4PressureLevel::High),
                format!(
                    "peer={} local={} phase=af_xdp_tcp_reactor_capacity sessions={} limit={}",
                    flow.peer_addr,
                    flow.local_addr,
                    self.sessions.len(),
                    self.session_limit
                ),
            );
            tracing::debug!(
                "AF_XDP TCP reactor refused new session at limit local={} peer={} limit={}",
                flow.local_addr,
                flow.peer_addr,
                self.session_limit
            );
            return AfXdpTcpIngestStatus::RefusedAtCapacity;
        }
        #[cfg(target_os = "linux")]
        AF_XDP_TCP_DIAG_ACCEPTED.fetch_add(1, Ordering::Relaxed);
        self.device.push_ingress(route, flow, ip_packet);
        AfXdpTcpIngestStatus::Accepted
    }

    pub(crate) fn poll(&mut self) -> Vec<(AfXdpRouteMeta, Vec<u8>)> {
        let now = SmoltcpInstant::from_millis(crate::utils::time::now_timestamp_millis());
        self.poll_at(now)
    }

    #[cfg(test)]
    pub(crate) fn poll_at_for_test(
        &mut self,
        now: SmoltcpInstant,
    ) -> Vec<(AfXdpRouteMeta, Vec<u8>)> {
        self.poll_at(now)
    }

    pub(crate) fn poll_at(&mut self, now: SmoltcpInstant) -> Vec<(AfXdpRouteMeta, Vec<u8>)> {
        loop {
            match self
                .iface
                .poll_ingress_single(now, &mut self.device, &mut self.sockets)
            {
                PollIngressSingleResult::None => break,
                PollIngressSingleResult::PacketProcessed
                | PollIngressSingleResult::SocketStateChanged => {}
            }
        }
        let _ = self
            .iface
            .poll_egress(now, &mut self.device, &mut self.sockets);
        self.pump_sessions(now);
        let frames = self.device.drain_egress().collect::<Vec<_>>();
        let mut egress = Vec::with_capacity(frames.len());
        for frame in frames {
            let route = frame.route.or_else(|| {
                reply_flow_key_from_ip_packet(&frame.ip_packet).and_then(|flow| {
                    self.sessions
                        .get(&flow)
                        .map(|session| session.route.clone())
                })
            });
            match route {
                Some(route) => egress.push((route, frame.ip_packet)),
                None => tracing::debug!(
                    "AF_XDP TCP reactor dropped egress packet without route bytes={}",
                    frame.ip_packet.len()
                ),
            }
        }
        self.retain_live_sessions(now);
        egress
    }

    pub(crate) fn encode_egress_frame(
        &mut self,
        route: &AfXdpRouteMeta,
        ip_packet: &[u8],
    ) -> Option<Vec<u8>> {
        encode_ip_reply_frame(&route.link, ip_packet, &mut self.tx_scratch)?;
        Some(self.tx_scratch.clone())
    }

    #[cfg(test)]
    pub(crate) fn session_count(&self) -> usize {
        self.sessions.len()
    }

    #[cfg(test)]
    pub(crate) fn close_session_and_push_routeless_egress_for_test(
        &mut self,
        flow: AfXdpTcpFlowKey,
        ip_packet: Vec<u8>,
    ) {
        if let Some(session) = self.sessions.get_mut(&flow) {
            session.closing = true;
            let socket = self
                .sockets
                .get_mut::<SmoltcpTcp::Socket<'static>>(session.socket);
            socket.abort();
        }
        self.device.egress.push(AfXdpTcpEgressFrame {
            route: None,
            ip_packet,
        });
    }

    pub(crate) fn ensure_session(
        &mut self,
        route: AfXdpRouteMeta,
        flow: AfXdpTcpFlowKey,
        proxy_class: AfXdpTcpProxyClass,
    ) -> bool {
        let now = SmoltcpInstant::from_millis(crate::utils::time::now_timestamp_millis());
        self.ensure_session_at(route, flow, proxy_class, now)
    }

    pub(crate) fn ensure_session_at(
        &mut self,
        route: AfXdpRouteMeta,
        flow: AfXdpTcpFlowKey,
        proxy_class: AfXdpTcpProxyClass,
        now: SmoltcpInstant,
    ) -> bool {
        if let Some(session) = self.sessions.get_mut(&flow) {
            session.route = route;
            session.last_activity = now;
            return true;
        }
        if self.sessions.len() >= self.session_limit {
            return false;
        }

        self.ensure_local_ip(flow.local_addr.ip());
        let rx_buffer = SmoltcpTcp::SocketBuffer::new(vec![0; AF_XDP_TCP_SOCKET_BUFFER_BYTES]);
        let tx_buffer = SmoltcpTcp::SocketBuffer::new(vec![0; AF_XDP_TCP_SOCKET_BUFFER_BYTES]);
        let mut socket = SmoltcpTcp::Socket::new(rx_buffer, tx_buffer);
        socket.set_nagle_enabled(false);
        if let Err(err) =
            socket.listen(IpListenEndpoint::from(IpEndpoint::from(flow.local_addr)))
        {
            tracing::debug!(
                "AF_XDP TCP reactor failed to listen local={} peer={}: {:?}",
                flow.local_addr,
                flow.peer_addr,
                err
            );
            return false;
        }

        let socket = self.sockets.add(socket);
        let session = AfXdpTcpSession {
            flow,
            route,
            proxy_class,
            socket,
            ingress_tx: None,
            egress_rx: None,
            pending_ingress: Bytes::new(),
            pending_egress: Bytes::new(),
            created_at: now,
            last_activity: now,
            proxy_started: {
                #[cfg(test)]
                {
                    self.test_auto_start_proxy
                }
                #[cfg(not(test))]
                {
                    false
                }
            },
            closing: false,
            egress_closed: false,
        };
        self.sessions.insert(flow, session);
        true
    }

    pub(crate) fn ensure_local_ip(&mut self, ip: IpAddr) {
        let cidr = SmoltcpIpCidr::new(
            SmoltcpIpAddress::from(ip),
            if ip.is_ipv4() { 32 } else { 128 },
        );
        if self.iface.ip_addrs().contains(&cidr) {
            return;
        }
        let mut inserted = false;
        self.iface.update_ip_addrs(|addrs| {
            if !addrs.contains(&cidr) {
                inserted = addrs.push(cidr).is_ok();
            }
        });
        if !inserted {
            tracing::debug!("AF_XDP TCP reactor local IP table is full; ip={}", ip);
        }
    }

    pub(crate) fn spawn_proxy_task_with_managers(
        tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
        http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
        session: &mut AfXdpTcpSession,
    ) -> bool {
        let peer_addr = session.flow.peer_addr;
        let listen_addr = session.flow.local_addr;
        let listen_port = listen_addr.port();
        let AfXdpTcpStreamParts {
            stream,
            ingress_tx,
            egress_rx,
        } = AfXdpTcpStream::default_channel_pair();
        match session.proxy_class {
            AfXdpTcpProxyClass::TcpPlain | AfXdpTcpProxyClass::TcpTls => {
                let Some(tcp_manager) = tcp_manager else {
                    return false;
                };
                let Some((server, is_tls)) =
                    tcp_manager.find_tcp_server_by_port_sync(listen_port)
                else {
                    return false;
                };
                session.ingress_tx = Some(ingress_tx);
                session.egress_rx = Some(egress_rx);
                session.proxy_started = true;
                #[cfg(target_os = "linux")]
                AF_XDP_TCP_DIAG_PROXY_STARTED.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let result = if is_tls {
                        tcp_manager
                            .handle_af_xdp_tls_tcp_stream(stream, peer_addr, server, listen_addr)
                            .await
                    } else {
                        tcp_manager
                            .handle_af_xdp_tcp_stream(stream, peer_addr, server, listen_addr)
                            .await
                    };
                    if let Err(err) = result {
                        tracing::debug!(
                            "AF_XDP TCP proxy stream failed peer={}: {}",
                            peer_addr,
                            err
                        );
                    }
                });
                true
            }
            AfXdpTcpProxyClass::Http | AfXdpTcpProxyClass::Https => {
                let Some(http_manager) = http_manager else {
                    return false;
                };
                let Some(kind) = http_manager.af_xdp_http_port_kind_sync(listen_port) else {
                    return false;
                };
                session.ingress_tx = Some(ingress_tx);
                session.egress_rx = Some(egress_rx);
                session.proxy_started = true;
                #[cfg(target_os = "linux")]
                AF_XDP_TCP_DIAG_PROXY_STARTED.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    if let Err(err) = http_manager
                        .handle_af_xdp_http_stream(stream, peer_addr, listen_port, kind)
                        .await
                    {
                        tracing::debug!(
                            "AF_XDP HTTP stream failed peer={} port={}: {}",
                            peer_addr,
                            listen_port,
                            err
                        );
                    }
                });
                true
            }
        }
    }

    pub(crate) fn pump_sessions(&mut self, now: SmoltcpInstant) {
        let tcp_manager = self.tcp_manager.clone();
        let http_manager = self.http_manager.clone();
        for session in self.sessions.values_mut() {
            let socket = self
                .sockets
                .get_mut::<SmoltcpTcp::Socket<'static>>(session.socket);

            if !session.proxy_started {
                if af_xdp_tcp_proxy_ready(session.proxy_class, socket) {
                    if !Self::spawn_proxy_task_with_managers(
                        tcp_manager.clone(),
                        http_manager.clone(),
                        session,
                    ) {
                        socket.abort();
                        session.closing = true;
                        continue;
                    }
                } else {
                    continue;
                }
            }

            if let Some(ingress_tx) = session.ingress_tx.as_ref() {
                match flush_pending_ingress(ingress_tx, &mut session.pending_ingress) {
                    IngressDelivery::Delivered => {}
                    IngressDelivery::Backpressured => {
                        tracing::debug!(
                            "AF_XDP TCP reactor ingress channel still full local={} peer={} pending={}",
                            session.flow.local_addr,
                            session.flow.peer_addr,
                            session.pending_ingress.len()
                        );
                        continue;
                    }
                    IngressDelivery::Closed => {
                        socket.close();
                        session.closing = true;
                        continue;
                    }
                }
            }

            while socket.can_recv() {
                match socket.recv_slice(&mut self.rx_scratch) {
                    Ok(0) => break,
                    Ok(n) => {
                        session.last_activity = now;
                        #[cfg(target_os = "linux")]
                        AF_XDP_TCP_DIAG_SOCKET_RECV_BYTES
                            .fetch_add(n as u64, Ordering::Relaxed);
                        let bytes = Bytes::copy_from_slice(&self.rx_scratch[..n]);
                        if let Some(ingress_tx) = session.ingress_tx.as_ref() {
                            match send_or_store_ingress(
                                ingress_tx,
                                &mut session.pending_ingress,
                                bytes.clone(),
                            ) {
                                IngressDelivery::Delivered => {
                                    #[cfg(target_os = "linux")]
                                    AF_XDP_TCP_DIAG_STREAM_INGRESS_BYTES
                                        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                                }
                                IngressDelivery::Backpressured => {
                                    tracing::debug!(
                                        "AF_XDP TCP reactor ingress channel full local={} peer={} pending={}",
                                        session.flow.local_addr,
                                        session.flow.peer_addr,
                                        session.pending_ingress.len()
                                    );
                                    break;
                                }
                                IngressDelivery::Closed => {
                                    socket.close();
                                    session.closing = true;
                                    break;
                                }
                            }
                        } else {
                            tracing::debug!(
                                "AF_XDP TCP reactor discarded ingress after stream read side closed local={} peer={} bytes={}",
                                session.flow.local_addr,
                                session.flow.peer_addr,
                                n
                            );
                            break;
                        }
                    }
                    Err(err) => {
                        tracing::debug!(
                            "AF_XDP TCP reactor recv failed local={} peer={}: {:?}",
                            session.flow.local_addr,
                            session.flow.peer_addr,
                            err
                        );
                        session.closing = true;
                        break;
                    }
                }
            }
            if af_xdp_tcp_stream_read_side_closed(socket.state())
                && session.pending_ingress.is_empty()
                && socket.recv_queue() == 0
            {
                session.ingress_tx = None;
            }

            while socket.can_send() {
                if session.pending_egress.is_empty() {
                    let Some(egress_rx) = session.egress_rx.as_mut() else {
                        break;
                    };
                    match egress_rx.try_recv() {
                        Ok(bytes) if bytes.is_empty() => continue,
                        Ok(bytes) => {
                            session.last_activity = now;
                            #[cfg(target_os = "linux")]
                            AF_XDP_TCP_DIAG_STREAM_EGRESS_BYTES
                                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                            session.pending_egress = bytes;
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            session.egress_closed = true;
                            break;
                        }
                    }
                }

                match socket.send_slice(&session.pending_egress) {
                    Ok(0) => break,
                    Ok(sent) if sent < session.pending_egress.len() => {
                        tracing::debug!(
                            "AF_XDP TCP reactor partially queued egress local={} peer={} sent={} total={}",
                            session.flow.local_addr,
                            session.flow.peer_addr,
                            sent,
                            session.pending_egress.len()
                        );
                        let _ = session.pending_egress.split_to(sent);
                        break;
                    }
                    Ok(_) => {
                        session.last_activity = now;
                        session.pending_egress.clear();
                    }
                    Err(err) => {
                        tracing::debug!(
                            "AF_XDP TCP reactor send failed local={} peer={}: {:?}",
                            session.flow.local_addr,
                            session.flow.peer_addr,
                            err
                        );
                        session.closing = true;
                        break;
                    }
                }
            }
            if session.egress_closed && session.pending_egress.is_empty() {
                let socket = self
                    .sockets
                    .get_mut::<SmoltcpTcp::Socket<'static>>(session.socket);
                if socket.send_queue() == 0 {
                    socket.close();
                    session.closing = true;
                }
            }
        }
    }

    pub(crate) fn retain_live_sessions(&mut self, now: SmoltcpInstant) {
        if self.sessions.is_empty() {
            return;
        }
        self.refresh_idle_profile_if_due(now);
        let pressure_level = self.cached_pressure_level;
        let proxy_idle_timeout = self.cached_proxy_idle_timeout;
        let mut finished = Vec::new();
        let mut pre_proxy_timeouts = Vec::new();
        for (flow, session) in &self.sessions {
            let socket = self
                .sockets
                .get::<SmoltcpTcp::Socket<'static>>(session.socket);
            let idle_timeout = if session.proxy_started {
                proxy_idle_timeout
            } else {
                effective_af_xdp_tcp_pre_proxy_timeout(session.proxy_class, pressure_level)
            };
            let idle_since = if session.proxy_started {
                session.last_activity
            } else {
                session.created_at
            };
            let idle_for = session_idle_for(now, idle_since);
            if !session.closing && idle_for >= idle_timeout {
                tracing::debug!(
                    "AF_XDP TCP reactor closing idle session local={} peer={} class={} proxy_started={} idle_ms={} timeout_ms={}",
                    session.flow.local_addr,
                    session.flow.peer_addr,
                    session.proxy_class.label(),
                    session.proxy_started,
                    idle_for.as_millis(),
                    idle_timeout.as_millis()
                );
                if !session.proxy_started {
                    pre_proxy_timeouts.push((
                        *flow,
                        session.proxy_class.slow_first_payload_kind(),
                        idle_for,
                        idle_timeout,
                    ));
                }
                finished.push(*flow);
            } else if af_xdp_tcp_session_reapable(session.closing, socket.state()) {
                finished.push(*flow);
            }
        }
        for (flow, kind, idle_for, idle_timeout) in pre_proxy_timeouts {
            #[cfg(target_os = "linux")]
            AF_XDP_TCP_DIAG_PRE_PROXY_TIMEOUT.fetch_add(1, Ordering::Relaxed);
            self.record_l4_event_for_ip(
                flow.peer_addr.ip(),
                kind,
                pressure_level,
                format!(
                    "peer={} local={} phase=af_xdp_pre_proxy_idle idle_ms={} timeout_ms={}",
                    flow.peer_addr,
                    flow.local_addr,
                    idle_for.as_millis(),
                    idle_timeout.as_millis()
                ),
            );
        }
        for flow in finished {
            if let Some(session) = self.sessions.remove(&flow) {
                let socket = self
                    .sockets
                    .get_mut::<SmoltcpTcp::Socket<'static>>(session.socket);
                socket.abort();
                let _ = self.sockets.remove(session.socket);
            }
        }
    }

    pub(crate) fn refresh_idle_profile_if_due(&mut self, now: SmoltcpInstant) {
        if session_idle_for(now, self.idle_profile_refreshed_at)
            < AF_XDP_TCP_IDLE_PROFILE_REFRESH_INTERVAL
        {
            return;
        }
        self.cached_pressure_level = crate::l4_defense::current_pressure_level();
        self.cached_proxy_idle_timeout = effective_af_xdp_tcp_idle_timeout();
        self.idle_profile_refreshed_at = now;
    }
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn af_xdp_tcp_session_reapable(closing: bool, state: SmoltcpTcp::State) -> bool {
    closing
        && matches!(
            state,
            SmoltcpTcp::State::Closed | SmoltcpTcp::State::TimeWait
        )
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn af_xdp_tcp_stream_read_side_closed(state: SmoltcpTcp::State) -> bool {
    matches!(
        state,
        SmoltcpTcp::State::Closing
            | SmoltcpTcp::State::LastAck
            | SmoltcpTcp::State::TimeWait
            | SmoltcpTcp::State::Closed
    )
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn effective_af_xdp_tcp_idle_timeout() -> Duration {
    crate::memory_governor::MEMORY_GOVERNOR
        .tcp_relay_pressure_idle_timeout()
        .unwrap_or(AF_XDP_TCP_SESSION_IDLE_TIMEOUT)
        .min(AF_XDP_TCP_SESSION_IDLE_TIMEOUT)
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn effective_af_xdp_tcp_pre_proxy_timeout(
    proxy_class: AfXdpTcpProxyClass,
    level: crate::l4_defense::L4PressureLevel,
) -> Duration {
    if proxy_class.requires_client_payload_before_proxy() {
        return crate::l4_defense::first_byte_timeout(level);
    }
    match level {
        crate::l4_defense::L4PressureLevel::Normal => Duration::from_secs(3),
        crate::l4_defense::L4PressureLevel::Elevated => Duration::from_secs(2),
        crate::l4_defense::L4PressureLevel::High => Duration::from_secs(1),
        crate::l4_defense::L4PressureLevel::Critical => Duration::from_millis(500),
    }
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn af_xdp_tcp_proxy_ready(
    proxy_class: AfXdpTcpProxyClass,
    socket: &SmoltcpTcp::Socket<'static>,
) -> bool {
    if proxy_class.requires_client_payload_before_proxy() {
        return socket.can_recv() || socket.recv_queue() > 0;
    }
    matches!(
        socket.state(),
        SmoltcpTcp::State::Established | SmoltcpTcp::State::CloseWait
    ) || socket.can_recv()
        || socket.recv_queue() > 0
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn af_xdp_tcp_session_limit() -> usize {
    let snapshot = crate::memory_governor::MEMORY_GOVERNOR
        .snapshot(crate::memory_governor::MEMORY_GOVERNOR.pingora_worker_threads());
    af_xdp_tcp_session_limit_from_budget(snapshot.connection_budget_bytes)
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn af_xdp_tcp_session_limit_from_budget(connection_budget_bytes: u64) -> usize {
    let memory_limit = connection_budget_bytes
        .saturating_div(AF_XDP_TCP_SESSION_ESTIMATED_BYTES.max(1))
        .max(1) as usize;
    memory_limit.clamp(AF_XDP_TCP_MIN_SESSION_LIMIT, AF_XDP_TCP_MAX_SESSION_LIMIT)
}

/// EN-12 queue-local share of the node session budget: the whole-node limit
/// is divided across AF_XDP workers so adding queues does not multiply the
/// aggregate session quota. The floor of 1 keeps a degenerate config able to
/// admit a session; the aggregate stays bounded by worker count.
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn af_xdp_tcp_session_limit_per_worker(node_limit: usize, worker_count: usize) -> usize {
    (node_limit / worker_count.max(1)).max(1)
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn session_idle_for(now: SmoltcpInstant, last_activity: SmoltcpInstant) -> Duration {
    let elapsed_ms = now
        .total_millis()
        .saturating_sub(last_activity.total_millis())
        .max(0) as u64;
    Duration::from_millis(elapsed_ms)
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn flush_pending_ingress(
    ingress_tx: &mpsc::Sender<Bytes>,
    pending_ingress: &mut Bytes,
) -> IngressDelivery {
    if pending_ingress.is_empty() {
        return IngressDelivery::Delivered;
    }
    let bytes = std::mem::take(pending_ingress);
    send_or_store_ingress(ingress_tx, pending_ingress, bytes)
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn send_or_store_ingress(
    ingress_tx: &mpsc::Sender<Bytes>,
    pending_ingress: &mut Bytes,
    bytes: Bytes,
) -> IngressDelivery {
    match ingress_tx.try_send(bytes) {
        Ok(()) => IngressDelivery::Delivered,
        Err(mpsc::error::TrySendError::Full(bytes)) => {
            *pending_ingress = bytes;
            IngressDelivery::Backpressured
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            pending_ingress.clear();
            IngressDelivery::Closed
        }
    }
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn proxy_bridge_should_idle(
    polled_packets: usize,
    parsed_frames: usize,
    downstream_datagrams: usize,
    tcp_egress_frames: usize,
    downstream_budget_exhausted: bool,
) -> bool {
    if downstream_budget_exhausted {
        return false;
    }
    polled_packets == 0
        && parsed_frames == 0
        && downstream_datagrams == 0
        && tcp_egress_frames == 0
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn proxy_bridge_should_continue(manager: &Arc<XdpManager>) -> bool {
    manager_is_current(manager)
        && !manager.attached.read().is_empty()
        && (manager.proxy_redirect_ready() || manager.proxy_workers_starting())
}

impl AfXdpTcpStream {
    pub fn channel_pair(buffer: usize) -> AfXdpTcpStreamParts {
        let depth = buffer.max(1);
        let (ingress_tx, incoming_rx) = mpsc::channel(depth);
        let (outgoing_tx, egress_rx) = mpsc::channel(depth);
        AfXdpTcpStreamParts {
            stream: Self {
                incoming_rx,
                outgoing_tx: Some(outgoing_tx),
                read_buf: Bytes::new(),
                write_permit: None,
            },
            ingress_tx,
            egress_rx,
        }
    }

    pub fn default_channel_pair() -> AfXdpTcpStreamParts {
        Self::channel_pair(AF_XDP_TCP_STREAM_CHANNEL_DEPTH)
    }
}

impl AsyncRead for AfXdpTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.read_buf.is_empty() {
                let len = self.read_buf.len().min(buf.remaining());
                let chunk = self.read_buf.split_to(len);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut self.incoming_rx).poll_recv(cx) {
                Poll::Ready(Some(chunk)) if chunk.is_empty() => continue,
                Poll::Ready(Some(chunk)) => {
                    self.read_buf = chunk;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for AfXdpTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.outgoing_tx.is_none() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "AF_XDP TCP stream write side is closed",
            )));
        }
        if self.write_permit.is_none() {
            let tx = self.outgoing_tx.as_ref().expect("checked above").clone();
            self.write_permit = Some(Box::pin(tx.reserve_owned()));
        }
        let permit = match self
            .write_permit
            .as_mut()
            .expect("created above")
            .as_mut()
            .poll(cx)
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(permit)) => {
                self.write_permit = None;
                permit
            }
            Poll::Ready(Err(_)) => {
                self.write_permit = None;
                self.outgoing_tx = None;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "AF_XDP TCP stream command channel is closed",
                )));
            }
        };
        let len = buf.len().min(AF_XDP_TCP_STREAM_WRITE_CHUNK);
        permit.send(Bytes::copy_from_slice(&buf[..len]));
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write_permit = None;
        self.outgoing_tx = None;
        Poll::Ready(Ok(()))
    }
}
