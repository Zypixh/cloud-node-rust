use super::*;
use crate::memory_governor::{MEMORY_GOVERNOR, StaticTcpQueueBytePermit};

/// EN-17/F3: payload bytes charged against the node-wide AF_XDP TCP queue
/// ledger. The RAII permit lives exactly as long as the queued bytes —
/// stream channels, reactor pendings and device ingress frames all carry
/// it — so queue memory is accounted through its full lifecycle and the
/// budget cannot be exceeded silently.
pub struct AfXdpTcpChargedBytes {
    bytes: Bytes,
    _permit: Option<StaticTcpQueueBytePermit>,
}

impl AfXdpTcpChargedBytes {
    pub(crate) fn empty() -> Self {
        Self {
            bytes: Bytes::new(),
            _permit: None,
        }
    }

    /// Reserve `bytes.len()` in the ledger first; `None` means the budget
    /// is exhausted and the caller must apply explicit backpressure.
    #[cfg(test)]
    pub(crate) fn charged(bytes: Bytes) -> Option<Self> {
        MEMORY_GOVERNOR
            .try_reserve_tcp_queue_bytes(bytes.len())
            .map(|permit| Self {
                bytes,
                _permit: Some(permit),
            })
    }

    /// Wrap bytes under a pre-acquired permit. Used when the reservation
    /// must happen before the payload exists (e.g. smoltcp `recv`, where
    /// the copy consumes the socket buffer inside the closure).
    pub(crate) fn with_permit(bytes: Bytes, permit: StaticTcpQueueBytePermit) -> Self {
        Self {
            bytes,
            _permit: Some(permit),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub(crate) fn clear(&mut self) {
        self.bytes = Bytes::new();
        self._permit = None;
    }

    pub(crate) fn split_to(&mut self, at: usize) -> Bytes {
        self.bytes.split_to(at)
    }
}

impl Default for AfXdpTcpChargedBytes {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::ops::Deref for AfXdpTcpChargedBytes {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

/// EN-17/F3: wakers of proxy tasks suspended on the TCP queue byte budget.
/// Drained by the reactor once ledger headroom returns — each re-polled
/// task either writes or re-registers, so the set stays bounded by the
/// number of concurrently stalled writers.
pub(crate) type AfXdpTcpBudgetStallSet = Arc<parking_lot::Mutex<Vec<std::task::Waker>>>;

pub struct AfXdpTcpStream {
    incoming_rx: mpsc::Receiver<AfXdpTcpChargedBytes>,
    outgoing_tx: Option<mpsc::Sender<AfXdpTcpChargedBytes>>,
    /// EN-17: after queueing egress bytes the stream marks its flow dirty in
    /// the shared wake set so the session is pumped without a table scan.
    wake: Option<(AfXdpTcpFlowKey, Arc<DashMap<AfXdpTcpFlowKey, ()>>)>,
    /// EN-17/F3: shared stall registry — a writer suspended on the queue
    /// byte budget registers here and the reactor wakes it on headroom.
    budget_stall: AfXdpTcpBudgetStallSet,
    read_buf: AfXdpTcpChargedBytes,
    write_permit: Option<TcpWritePermitFuture>,
}

pub struct AfXdpTcpStreamParts {
    pub stream: AfXdpTcpStream,
    pub ingress_tx: mpsc::Sender<AfXdpTcpChargedBytes>,
    pub egress_rx: mpsc::Receiver<AfXdpTcpChargedBytes>,
    /// EN-17/F3: the stall set shared by this stream — reactors keep the
    /// authoritative copy and drain it when the byte budget frees.
    pub budget_stall: AfXdpTcpBudgetStallSet,
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
    /// EN-17/F3: queue-byte charge held while the frame waits for smoltcp
    /// to consume it — released when the frame is popped or dropped.
    pub(crate) _charge: Option<StaticTcpQueueBytePermit>,
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
    pub(crate) ingress_tx: Option<mpsc::Sender<AfXdpTcpChargedBytes>>,
    pub(crate) egress_rx: Option<mpsc::Receiver<AfXdpTcpChargedBytes>>,
    pub(crate) pending_ingress: AfXdpTcpChargedBytes,
    pub(crate) pending_egress: AfXdpTcpChargedBytes,
    pub(crate) created_at: SmoltcpInstant,
    pub(crate) last_activity: SmoltcpInstant,
    pub(crate) proxy_started: bool,
    pub(crate) closing: bool,
    pub(crate) egress_closed: bool,
    /// EN-17: queued in `hot_sessions` — dedup flag so each flow key is in
    /// the hot queue at most once.
    pub(crate) hot: bool,
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
    /// EN-17: the per-reactor unprocessed-ingress queue is full — an
    /// explicit bounded-capacity refusal, counted, never silent growth.
    IngressQueueFull,
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

    /// Returns true exactly once when the consecutive-refusal streak reaches
    /// the threshold — a warn edge, not a teardown signal. F2: capacity
    /// refusals only shed new work; the worker keeps serving existing
    /// sessions and admissions resume as soon as capacity frees (the streak
    /// resets on the next Accepted/non-capacity outcome).
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
            AfXdpTcpIngestStatus::RefusedAtCapacity
            | AfXdpTcpIngestStatus::IngressQueueFull => {
                self.consecutive_refusals = self.consecutive_refusals.saturating_add(1);
                self.consecutive_refusals == self.max_consecutive_refusals
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

    pub(crate) fn push_ingress(
        &mut self,
        route: AfXdpRouteMeta,
        flow: AfXdpTcpFlowKey,
        ip_packet: Bytes,
        charge: StaticTcpQueueBytePermit,
    ) {
        self.ingress.push_back(AfXdpTcpIngressFrame {
            route,
            flow,
            ip_packet,
            _charge: Some(charge),
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
    /// EN-17: sessions with observed work (ingress packet or egress wake).
    /// Entries are dedup'd by `AfXdpTcpSession.hot`; stale keys are skipped.
    hot_sessions: std::collections::VecDeque<AfXdpTcpFlowKey>,
    /// EN-17: shared dirty set — proxy tasks insert their flow key after
    /// queueing egress bytes. Hard-bounded by `session_limit` (at most one
    /// entry per live flow plus in-flight stale keys), insert is lossless
    /// (no "full" path), and the map key dedups at enqueue time.
    pub(crate) wake_set: Arc<DashMap<AfXdpTcpFlowKey, ()>>,
    /// EN-17: incremental sweep cursor — a bounded batch is processed per
    /// round instead of one unbounded full-table pass. `sweep_active`
    /// distinguishes "a cycle is mid-flight" from "idle between cycles":
    /// `sweep_pos >= sweep_keys.len()` is true in both states, so without
    /// the flag every poll round would look like a just-completed sweep and
    /// keep pushing `last_sweep` forward — under continuous fast polling the
    /// 250ms interval would then never elapse and the backstop never run.
    sweep_keys: Vec<AfXdpTcpFlowKey>,
    sweep_pos: usize,
    sweep_active: bool,
    /// EN-17: completion time of the last amortized full-table sweep.
    last_sweep: SmoltcpInstant,
    /// EN-17: last reaping pass — cadence-gated, independent of `last_sweep`.
    last_retain: SmoltcpInstant,
    /// EN-17/F3: wakers of stream writers suspended on the node TCP queue
    /// byte budget — shared with every spawned stream so a writer parked on
    /// budget gets woken as soon as any session's queued bytes free up.
    pub(crate) budget_stall: AfXdpTcpBudgetStallSet,
    /// EN-17/F3: sessions that stopped draining `socket.recv` because the
    /// queue byte budget was exhausted. Re-marked hot (bounded retry) once
    /// the ledger has headroom again; TCP window shrinks meanwhile.
    ingress_stalled: std::collections::HashSet<AfXdpTcpFlowKey>,
    session_limit: usize,
    tx_scratch: Vec<u8>,
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
        let wake_set = Arc::new(DashMap::new());
        Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device,
            sessions: HashMap::new(),
            hot_sessions: std::collections::VecDeque::new(),
            wake_set,
            sweep_keys: Vec::new(),
            sweep_pos: 0,
            sweep_active: false,
            last_sweep: SmoltcpInstant::from_millis(0),
            last_retain: SmoltcpInstant::from_millis(0),
            budget_stall: Arc::new(parking_lot::Mutex::new(Vec::new())),
            ingress_stalled: std::collections::HashSet::new(),
            session_limit: session_limit.max(1),
            tx_scratch: Vec::with_capacity(2048),
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
                            if !self.enqueue_ingress(route, flow, ip_packet) {
                                return AfXdpTcpIngestStatus::IngressQueueFull;
                            }
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
        if !self.enqueue_ingress(route, flow, ip_packet) {
            return AfXdpTcpIngestStatus::IngressQueueFull;
        }
        AfXdpTcpIngestStatus::Accepted
    }

    /// EN-17: queue a packet for the bounded smoltcp ingress loop and mark
    /// its session hot. Returns false (explicit refusal, counted) when the
    /// per-reactor ingress queue or the node TCP byte budget is full —
    /// memory stays bounded under an RX flood; TCP retransmit is the
    /// recovery path.
    fn enqueue_ingress(
        &mut self,
        route: AfXdpRouteMeta,
        flow: AfXdpTcpFlowKey,
        ip_packet: Bytes,
    ) -> bool {
        if self.device.ingress.len() >= AF_XDP_TCP_INGRESS_QUEUE_MAX {
            #[cfg(target_os = "linux")]
            AF_XDP_TCP_DIAG_INGRESS_QUEUE_DROPPED.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let Some(charge) = MEMORY_GOVERNOR.try_reserve_tcp_queue_bytes(ip_packet.len()) else {
            #[cfg(target_os = "linux")]
            AF_XDP_TCP_DIAG_INGRESS_BUDGET_DROPPED.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        self.device.push_ingress(route, flow, ip_packet, charge);
        self.mark_hot(flow);
        true
    }

    /// EN-17: queue `flow` for pumping this round (dedup via `hot` flag).
    fn mark_hot(&mut self, flow: AfXdpTcpFlowKey) {
        if let Some(session) = self.sessions.get_mut(&flow)
            && !session.hot
        {
            session.hot = true;
            self.hot_sessions.push_back(flow);
        }
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
        // EN-17: bounded ingress processing per round — an RX flood cannot
        // postpone session pumping, egress TX or timer work indefinitely.
        // Leftover packets stay in the bounded queue for the next round.
        for _ in 0..AF_XDP_TCP_INGRESS_BUDGET {
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
        self.release_budget_backpressure();
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

    /// EN-17 test hooks: observe hot-set scheduling state.
    #[cfg(test)]
    pub(crate) fn hot_session_count(&self) -> usize {
        self.hot_sessions.len()
    }

    #[cfg(test)]
    pub(crate) fn pending_wake_count(&self) -> usize {
        self.wake_set.len()
    }

    /// Tests only: completion timestamp of the last real sweep cycle. The
    /// sweep must keep its own cadence — under continuous sub-interval
    /// polling this timestamp must stay pinned at the last completed cycle,
    /// not drift forward with every poll.
    #[cfg(test)]
    pub(crate) fn last_sweep_at(&self) -> SmoltcpInstant {
        self.last_sweep
    }

    #[cfg(test)]
    pub(crate) fn queued_ingress_count(&self) -> usize {
        self.device.ingress.len()
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
        // F8: AF_XDP TCP must run a real congestion controller — without an
        // explicit selection smoltcp silently falls back to NoControl
        // (window = usize::MAX), which XDP pps budgets cannot replace.
        // Cubic is the production default until the transport crate lands.
        socket.set_congestion_control(SmoltcpTcp::CongestionControl::Cubic);
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
            pending_ingress: AfXdpTcpChargedBytes::empty(),
            pending_egress: AfXdpTcpChargedBytes::empty(),
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
            hot: false,
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
        wake_set: Arc<DashMap<AfXdpTcpFlowKey, ()>>,
        budget_stall: AfXdpTcpBudgetStallSet,
    ) -> bool {
        let peer_addr = session.flow.peer_addr;
        let listen_addr = session.flow.local_addr;
        let listen_port = listen_addr.port();
        let AfXdpTcpStreamParts {
            stream,
            ingress_tx,
            egress_rx,
            budget_stall: _,
        } = AfXdpTcpStream::channel_pair_with_wake(
            AF_XDP_TCP_STREAM_CHANNEL_DEPTH,
            session.flow,
            wake_set,
            budget_stall,
        );
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

    /// EN-17: bounded session scheduling. Each poll round pumps only the
    /// "hot" set — sessions with an observed work signal (ingress packet
    /// via `enqueue_ingress`, egress write via the stream wake channel, or
    /// leftover pending state from the previous round) — capped by
    /// `AF_XDP_TCP_PUMP_BUDGET`. Every `AF_XDP_TCP_SWEEP_INTERVAL` a full
    /// sweep runs as backstop so an unsignaled transition still progresses
    /// within a bounded delay.
    pub(crate) fn pump_sessions(&mut self, now: SmoltcpInstant) {
        // Drain at most WAKE_DRAIN_BUDGET dirty marks per round; entries not
        // drained stay in the set (lossless) and are retried next round.
        if !self.wake_set.is_empty() {
            let mut drained = Vec::new();
            self.wake_set.retain(|flow, _| {
                if drained.len() < AF_XDP_TCP_WAKE_DRAIN_BUDGET {
                    drained.push(*flow);
                    false
                } else {
                    true
                }
            });
            #[cfg(target_os = "linux")]
            AF_XDP_TCP_DIAG_WAKE_SIGNALS.fetch_add(drained.len() as u64, Ordering::Relaxed);
            for flow in drained {
                self.mark_hot(flow);
            }
        }
        // A sweep cycle starts when the interval elapsed: the key set is
        // collected once, then the cursor advances a bounded batch per round
        // — a large table never monopolizes a single poll round. Sessions
        // already queued in the hot set are skipped (their pump comes via
        // the queue); sessions created mid-cycle are hot by construction and
        // join the next cycle.
        if !self.sweep_active
            && session_idle_for(now, self.last_sweep) >= AF_XDP_TCP_SWEEP_INTERVAL
        {
            self.sweep_keys.clear();
            self.sweep_keys.extend(self.sessions.keys().copied());
            self.sweep_pos = 0;
            self.sweep_active = true;
        }
        let mut budget = AF_XDP_TCP_PUMP_BUDGET;
        while budget > 0 {
            let Some(flow) = self.hot_sessions.pop_front() else {
                break;
            };
            let Some(session) = self.sessions.get_mut(&flow) else {
                continue; // reaped while queued
            };
            session.hot = false;
            budget -= 1;
            self.pump_session(now, flow);
            if self.session_still_active(flow) {
                self.mark_hot(flow);
            }
        }
        // Batched sweep progress — each round advances the cursor by at most
        // SWEEP_BATCH entries regardless of table size.
        if self.sweep_active {
            let mut swept = 0usize;
            while self.sweep_pos < self.sweep_keys.len()
                && swept < AF_XDP_TCP_SWEEP_BATCH_BUDGET
            {
                let flow = self.sweep_keys[self.sweep_pos];
                self.sweep_pos += 1;
                swept += 1;
                if self.sessions.get(&flow).is_some_and(|s| s.hot) {
                    continue;
                }
                self.pump_session(now, flow);
                if self.session_still_active(flow) {
                    self.mark_hot(flow);
                }
            }
            if self.sweep_pos >= self.sweep_keys.len() {
                // Only a real completed cycle retires the sweep timestamp;
                // an idle round must not push `last_sweep` forward.
                self.sweep_active = false;
                self.sweep_keys.clear();
                self.last_sweep = now;
            }
        }
    }

    /// EN-17: a session keeps its hot slot while it still has observable
    /// work — undelivered ingress, unflushed egress, an unstarted proxy, a
    /// close in flight, or more socket receive data.
    fn session_still_active(&self, flow: AfXdpTcpFlowKey) -> bool {
        let Some(session) = self.sessions.get(&flow) else {
            return false;
        };
        let socket = self
            .sockets
            .get::<SmoltcpTcp::Socket<'static>>(session.socket);
        // A reapable session is the cadence-gated reaper's job — keeping it
        // hot would just re-run an already-dead pump every round.
        if af_xdp_tcp_session_reapable(session.closing, socket.state()) {
            return false;
        }
        if session.closing
            || !session.proxy_started
            || !session.pending_ingress.is_empty()
            || !session.pending_egress.is_empty()
        {
            return true;
        }
        // F3: a session parked on the queue byte budget keeps `can_recv`
        // true while data sits in the socket — staying hot would busy-pump
        // it every round. The budget release path re-marks it instead.
        if self.ingress_stalled.contains(&flow) {
            return false;
        }
        socket.can_recv()
    }

    fn pump_session(&mut self, now: SmoltcpInstant, flow: AfXdpTcpFlowKey) {
        let tcp_manager = self.tcp_manager.clone();
        let http_manager = self.http_manager.clone();
        let Some(session) = self.sessions.get_mut(&flow) else {
            return;
        };
        {
            let socket = self
                .sockets
                .get_mut::<SmoltcpTcp::Socket<'static>>(session.socket);

            if !session.proxy_started {
                if af_xdp_tcp_proxy_ready(session.proxy_class, socket) {
                    // F8: a connected socket must never run NoControl — the
                    // controller is set at creation; if it is ever missing
                    // the failure must be loud, not a silent unbounded
                    // window.
                    if socket.congestion_control() == SmoltcpTcp::CongestionControl::None {
                        tracing::error!(
                            "AF_XDP TCP connected socket has no congestion control local={} peer={}",
                            flow.local_addr,
                            flow.peer_addr
                        );
                    }
                    if !Self::spawn_proxy_task_with_managers(
                        tcp_manager.clone(),
                        http_manager.clone(),
                        session,
                        self.wake_set.clone(),
                        self.budget_stall.clone(),
                    ) {
                        socket.abort();
                        session.closing = true;
                        return;
                    }
                } else {
                    return;
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
                        return;
                    }
                    IngressDelivery::Closed => {
                        socket.close();
                        session.closing = true;
                        return;
                    }
                }
            }

            while socket.can_recv() {
                // EN-17/F3: reserve queue bytes BEFORE consuming the socket
                // buffer — `recv` is destructive, so a budget failure after
                // the copy would leave the payload uncharged. On refusal the
                // bytes stay in smoltcp's buffer (window shrinks → peer
                // backs off); the session parks in `ingress_stalled` and is
                // re-marked hot once the ledger frees.
                let want = socket.recv_queue().min(AF_XDP_TCP_RECV_SCRATCH_BYTES);
                if want == 0 {
                    break;
                }
                let Some(charge) = MEMORY_GOVERNOR.try_reserve_tcp_queue_bytes(want) else {
                    #[cfg(target_os = "linux")]
                    AF_XDP_TCP_DIAG_BUDGET_STALLS.fetch_add(1, Ordering::Relaxed);
                    self.ingress_stalled.insert(flow);
                    break;
                };
                // EN-17: single copy — smoltcp's receive buffer is copied
                // straight into the egress `Bytes`; no scratch round-trip.
                match socket.recv(|data| {
                    let n = data.len().min(AF_XDP_TCP_RECV_SCRATCH_BYTES);
                    (n, Bytes::copy_from_slice(&data[..n]))
                }) {
                    Ok(bytes) if bytes.is_empty() => break,
                    Ok(bytes) => {
                        let n = bytes.len();
                        session.last_activity = now;
                        #[cfg(target_os = "linux")]
                        AF_XDP_TCP_DIAG_SOCKET_RECV_BYTES
                            .fetch_add(n as u64, Ordering::Relaxed);
                        if let Some(ingress_tx) = session.ingress_tx.as_ref() {
                            match send_or_store_ingress(
                                ingress_tx,
                                &mut session.pending_ingress,
                                AfXdpTcpChargedBytes::with_permit(bytes, charge),
                            ) {
                                IngressDelivery::Delivered => {
                                    #[cfg(target_os = "linux")]
                                    AF_XDP_TCP_DIAG_STREAM_INGRESS_BYTES
                                        .fetch_add(n as u64, Ordering::Relaxed);
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
        // EN-17: reaping is cadence-gated — idle timeouts are seconds-scale
        // and closing sessions are re-pumped via the hot set meanwhile, so a
        // per-poll full-table scan buys nothing.
        if session_idle_for(now, self.last_retain) < AF_XDP_TCP_SWEEP_INTERVAL {
            return;
        }
        self.last_retain = now;
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
            self.ingress_stalled.remove(&flow);
            if let Some(session) = self.sessions.remove(&flow) {
                let socket = self
                    .sockets
                    .get_mut::<SmoltcpTcp::Socket<'static>>(session.socket);
                socket.abort();
                let _ = self.sockets.remove(session.socket);
            }
        }
    }

    /// EN-17/F3: byte-budget recovery — when the node TCP queue ledger has
    /// headroom again, wake writers parked in `poll_write` and re-mark
    /// ingress-stalled sessions hot so `socket.recv` resumes. Headroom for
    /// a full write chunk is required so released tasks do not immediately
    /// re-stall on a sliver of budget.
    fn release_budget_backpressure(&mut self) {
        if self.ingress_stalled.is_empty() && self.budget_stall.lock().is_empty() {
            return;
        }
        let budget = MEMORY_GOVERNOR.tcp_queue_bytes_budget();
        let used = MEMORY_GOVERNOR.tcp_queue_bytes();
        if used.saturating_add(AF_XDP_TCP_STREAM_WRITE_CHUNK as u64) > budget {
            return;
        }
        let wakers = std::mem::take(&mut *self.budget_stall.lock());
        for waker in wakers {
            waker.wake();
        }
        let stalled = std::mem::take(&mut self.ingress_stalled);
        for flow in stalled {
            self.mark_hot(flow);
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
    ingress_tx: &mpsc::Sender<AfXdpTcpChargedBytes>,
    pending_ingress: &mut AfXdpTcpChargedBytes,
) -> IngressDelivery {
    if pending_ingress.is_empty() {
        return IngressDelivery::Delivered;
    }
    let bytes = std::mem::take(pending_ingress);
    send_or_store_ingress(ingress_tx, pending_ingress, bytes)
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn send_or_store_ingress(
    ingress_tx: &mpsc::Sender<AfXdpTcpChargedBytes>,
    pending_ingress: &mut AfXdpTcpChargedBytes,
    bytes: AfXdpTcpChargedBytes,
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
        Self::channel_pair_with_budget(buffer, Arc::new(parking_lot::Mutex::new(Vec::new())))
    }

    fn channel_pair_with_budget(
        buffer: usize,
        budget_stall: AfXdpTcpBudgetStallSet,
    ) -> AfXdpTcpStreamParts {
        let depth = buffer.max(1);
        let (ingress_tx, incoming_rx) = mpsc::channel(depth);
        let (outgoing_tx, egress_rx) = mpsc::channel(depth);
        AfXdpTcpStreamParts {
            stream: Self {
                incoming_rx,
                outgoing_tx: Some(outgoing_tx),
                wake: None,
                budget_stall: budget_stall.clone(),
                read_buf: AfXdpTcpChargedBytes::empty(),
                write_permit: None,
            },
            ingress_tx,
            egress_rx,
            budget_stall,
        }
    }

    /// EN-17: channel pair whose stream wakes the reactor after every
    /// queued egress write / shutdown so pumping needs no table scan. The
    /// reactor's budget-stall set is shared so suspended writers get woken
    /// the round the queue byte budget frees.
    pub fn channel_pair_with_wake(
        buffer: usize,
        flow: AfXdpTcpFlowKey,
        wake_set: Arc<DashMap<AfXdpTcpFlowKey, ()>>,
        budget_stall: AfXdpTcpBudgetStallSet,
    ) -> AfXdpTcpStreamParts {
        let mut parts = Self::channel_pair_with_budget(buffer, budget_stall);
        parts.stream.wake = Some((flow, wake_set));
        parts
    }

    pub fn default_channel_pair() -> AfXdpTcpStreamParts {
        Self::channel_pair(AF_XDP_TCP_STREAM_CHANNEL_DEPTH)
    }

    /// Mark this flow dirty for the reactor. Insert is lossless and dedup'd
    /// by the map — a second mark while the entry is still pending costs
    /// nothing and nothing can be dropped.
    fn signal_wake(&self) {
        if let Some((flow, set)) = &self.wake {
            set.insert(*flow, ());
        }
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
        // F3: charge the node TCP queue ledger before queueing. On refusal
        // the write suspends (register + Pending) — explicit backpressure
        // toward the application; the reactor wakes registered writers once
        // ledger headroom returns. Never drop or bypass the charge.
        let Some(byte_charge) = MEMORY_GOVERNOR.try_reserve_tcp_queue_bytes(len) else {
            #[cfg(target_os = "linux")]
            AF_XDP_TCP_DIAG_BUDGET_STALLS.fetch_add(1, Ordering::Relaxed);
            let mut stall = self.budget_stall.lock();
            if stall.len() < AF_XDP_TCP_BUDGET_STALL_MAX {
                stall.push(cx.waker().clone());
            } else {
                tracing::warn!(
                    "AF_XDP TCP budget stall set at capacity len={} — writer stays parked until a stalled peer wakes",
                    stall.len()
                );
            }
            return Poll::Pending;
        };
        permit.send(AfXdpTcpChargedBytes::with_permit(
            Bytes::copy_from_slice(&buf[..len]),
            byte_charge,
        ));
        self.signal_wake();
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write_permit = None;
        self.outgoing_tx = None;
        self.signal_wake();
        Poll::Ready(Ok(()))
    }
}

/// Dropping the stream (proxy task finished, app dropped the handle, or the
/// task was cancelled) must not wait for the sweep backstop to be noticed:
/// mark the flow dirty so the next pump round observes the closed channels
/// and transitions the session to closing within one reactor round.
impl Drop for AfXdpTcpStream {
    fn drop(&mut self) {
        self.signal_wake();
    }
}
