use super::*;
use crate::memory_governor::{MEMORY_GOVERNOR, StaticTcpQueueBytePermit};
#[cfg(any(test, target_os = "linux"))]
use crate::transport_clock::TransportClock;

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

    #[cfg(any(test, target_os = "linux"))]
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
    /// Optional interrupt for the reactor's event-driven idle wait —
    /// without it a queued egress write would only be noticed at the next
    /// poll round.
    wake_notify: Option<Arc<tokio::sync::Notify>>,
    /// EN-17/F3: shared stall registry — a writer suspended on the queue
    /// byte budget registers here and the reactor wakes it on headroom.
    budget_stall: AfXdpTcpBudgetStallSet,
    read_buf: AfXdpTcpChargedBytes,
    write_permit: Option<TcpWritePermitFuture>,
    /// T4-6: flow endpoints for upstream-facing callers that need
    /// `local_addr`/`peer_addr` (e.g. `toa::connect_upstream`).
    flow: Option<AfXdpTcpFlowKey>,
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
    /// T9: the queued packet carries no ledger charge — the ingress queue
    /// is entry-bounded (≤ ~750 KiB worst case), and a per-packet charge
    /// here let a saturated ledger starve the front door: established
    /// sessions' data packets and new SYNs died at enqueue even though
    /// their memory was already bounded. Held-memory accounting lives on
    /// the session side (buffers, channel residency, pending).
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
    /// T4: this session was node-dialed (outbound connect through the
    /// AF_XDP stack) rather than accepted. Dialed sessions skip the
    /// proxy-class machinery: on Established the stream is delivered to
    /// the dialer's `dial_reply` oneshot; on RST/timeout the dial fails
    /// explicitly.
    pub(crate) dialed: bool,
    pub(crate) dial_reply: Option<tokio::sync::oneshot::Sender<io::Result<AfXdpTcpStream>>>,
    /// Absolute connect deadline (transport clock): a SynSent session
    /// that outlives it is aborted and the dial answered with a timeout
    /// error — a dialed flow must never linger unbounded.
    pub(crate) dial_deadline: Option<SmoltcpInstant>,
    /// Ledger charges for the socket's rx+tx buffer *capacity* — one
    /// permit per allocation event (initial pair + every T9 in-session
    /// growth step). Held for the session's whole life so smoltcp's
    /// `vec![0; buf]` allocations are accounted memory — released on
    /// reap. This is what lets `socket_buffer_bytes` size by
    /// live-session share instead of dividing the budget across the
    /// capacity limit.
    pub(crate) socket_buf_permits: Vec<StaticTcpQueueBytePermit>,
    /// T9: cumulative payload bytes drained from the socket since the
    /// last rx growth attempt. Occupancy sampling (`recv_queue ≥ 50%`)
    /// misses paced senders — a kernel-paced peer whose cwnd is smaller
    /// than our window never leaves half a window queued, yet is still
    /// window-limited on average. Accumulated drain volume ≥ half the
    /// current capacity is pacing-immune proof the peer keeps the
    /// window full; reset on every growth attempt so the next step
    /// requires fresh demand at the new size.
    pub(crate) rx_growth_probe: u64,
    /// T9: first instant this session parked in `ingress_stalled` without
    /// a successful drain since. Retransmissions refresh `last_activity`,
    /// so an idle-timeout-only reap would keep a stalled session (and
    /// its buffer permits) alive forever — `retain_live_sessions` reaps
    /// it once this exceeds AF_XDP_TCP_BUDGET_STALL_DEADLINE regardless
    /// of arriving traffic. Cleared on the next successful drain.
    pub(crate) stalled_since: Option<SmoltcpInstant>,
    /// T9: first instant this session parked on its fair-share *drain
    /// cap* — a consumer-progress bound, NOT the ledger. Kept separate
    /// from `stalled_since`: a session whose proxy reader is merely slow
    /// must not be reaped on the ledger-zombie deadline, but one whose
    /// reader is dead must not live forever either. Cleared whenever
    /// channel space frees (consumer progress) or a drain succeeds.
    pub(crate) cap_parked_since: Option<SmoltcpInstant>,
    /// T9: per-direction socket buffer capacity reserved at admission.
    /// Growth pushes extra permits onto `socket_buf_permits`; an idle
    /// session resizes both buffers back to this floor and truncates the
    /// permit stack to its first entry — charge returns to exactly the
    /// admitted pair, keeping `Σ charge == Σ capacity` intact.
    pub(crate) socket_buf_floor_bytes: usize,
    /// T9: do not attempt another ledger charge for buffer growth before
    /// this instant. Set when a growth charge is refused — without it a
    /// full ledger gets a bounded-but-per-pump retry burst from every
    /// demand-showing session, which on a single-threaded reactor is a
    /// measurable CAS storm.
    pub(crate) growth_retry_after: Option<SmoltcpInstant>,
}

#[cfg(any(test, target_os = "linux"))]
impl AfXdpTcpSession {
    /// Total ledger-held socket buffer capacity (rx + tx, all growth
    /// steps summed).
    pub(crate) fn socket_buf_charge_bytes(&self) -> u64 {
        self.socket_buf_permits.iter().map(|p| p.bytes()).sum()
    }
}

/// T4: a dial request delivered to the owning queue's reactor loop. All
/// caller-side preparation (route resolution, port allocation, out-CT
/// registration, demux table entry) has already succeeded; the reactor
/// only has to build the socket and answer `reply` once the handshake
/// resolves — Ok(stream) on Established, Err on RST/timeout/refusal.
#[cfg(any(test, target_os = "linux"))]
pub(crate) struct AfXdpTcpDialRequest {
    /// Upstream peer (remote endpoint).
    pub(crate) remote: SocketAddr,
    /// Resolved egress endpoint: interface source address + allocated
    /// reserved-range port.
    pub(crate) local: SocketAddr,
    /// L2 route for egress frames — the resolved next-hop MAC.
    pub(crate) route: AfXdpRouteMeta,
    /// Verbatim SYN option bytes (TOA etc.); empty for a plain SYN.
    pub(crate) syn_extra_options: Vec<u8>,
    pub(crate) reply: tokio::sync::oneshot::Sender<io::Result<AfXdpTcpStream>>,
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
    ) {
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
        // AF_XDP delivers raw wire frames with no RX checksum metadata —
        // the kernel's CHECKSUM_UNNECESSARY mark never reaches this layer,
        // so a userspace stack cannot inherit "the skb was verified" trust.
        // A real sender's NIC completes TX checksum offload before the
        // frame reaches the wire, so valid wire frames always carry
        // complete checksums; verify them in software and let corrupt
        // frames drop here instead of being fed to the socket layer.
        // Isolated veth test links are the exception (peer TX offload
        // leaves the field partial); such senders must run with checksum
        // offload disabled, never by weakening verification.
        caps.checksum.tcp = Checksum::Both;
        caps.checksum.udp = Checksum::Both;
        caps.checksum.ipv4 = Checksum::Both;
        caps.checksum.icmpv4 = Checksum::Both;
        caps.checksum.icmpv6 = Checksum::Both;
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
    /// Streams signal this when they queue egress — the bridge's
    /// event-driven idle wait wakes on it immediately instead of polling.
    wake_notify: Arc<tokio::sync::Notify>,
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
    /// Accepted sessions that have not started proxying yet (handshake or
    /// first payload pending). This is the noise class — bounded by
    /// `pre_proxy_budget()` and churned oldest-first under pressure so
    /// scanners/SYN floods cannot occupy slots reserved for verified work.
    pre_proxy_sessions: usize,
    /// Per-source-IP count of the same unverified class — bounds
    /// single-source half-open churn independently of the global budget.
    pre_proxy_per_ip: HashMap<std::net::IpAddr, usize>,
    session_limit: usize,
    /// T1: monotonic µs transport clock — all protocol time (smoltcp
    /// instants, sweep cadence, idle reaping) derives from it; wall clock
    /// steps cannot move a deadline.
    clock: TransportClock,
    /// T1: "iface:queue" label used as the snapshot-map key prefix so the
    /// same 4-tuple on different queues does not collide in /status.
    label: String,
    tx_scratch: Vec<u8>,
    tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
    http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
    cached_pressure_level: crate::l4_defense::L4PressureLevel,
    cached_proxy_idle_timeout: Duration,
    idle_profile_refreshed_at: SmoltcpInstant,
    /// T4: shared dial-flow registry — set by the bridge before the loop
    /// runs. Reaping a dialed session releases its demux entry, source
    /// port and XDP_OUT_CT row through this handle.
    #[cfg(target_os = "linux")]
    dial_registry: Option<Arc<AfXdpDialRegistry>>,
    /// T5: transport-controller selection for AF_XDP-terminated flows —
    /// `cubic` is the validated default; `edgecc` installs the decision
    /// layer (with worker-local aggregate + path priors when enabled).
    transport_controller: crate::runtime_mode::XdpTransportController,
    /// D-D2: CE marks trusted at full weight on controlled links.
    trusted_ecn: bool,
    /// T6: worker-local shared-bottleneck aggregate (EdgeCC only).
    /// `Rc<RefCell>` — never a cross-worker lock, never on the ACK path.
    aggregate: Option<
        std::rc::Rc<std::cell::RefCell<cloud_node_transport::Aggregate>>,
    >,
    /// T6: worker-local bounded path-prior table (§2.2 长期先验).
    path_table:
        std::rc::Rc<std::cell::RefCell<cloud_node_transport::PathTable>>,
    /// Aggregate arbitration tick watermark (~100ms periods).
    last_agg_period: SmoltcpInstant,
    /// Runtime that owns per-session L7 proxy tasks (TLS, HTTP, upstream
    /// I/O). Production installs the process multi-thread runtime — a
    /// proxy task's synchronous crypto must never serialize behind the
    /// reactor's poll loop on the same thread. `None` falls back to
    /// `tokio::spawn` (tests under `#[tokio::test]` still resolve a
    /// current-thread context).
    proxy_rt: Option<tokio::runtime::Handle>,
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
            wake_notify: Arc::new(tokio::sync::Notify::new()),
            sweep_keys: Vec::new(),
            sweep_pos: 0,
            sweep_active: false,
            last_sweep: SmoltcpInstant::from_millis(0),
            last_retain: SmoltcpInstant::from_millis(0),
            budget_stall: Arc::new(parking_lot::Mutex::new(Vec::new())),
            ingress_stalled: std::collections::HashSet::new(),
            pre_proxy_sessions: 0,
            pre_proxy_per_ip: HashMap::new(),
            session_limit: session_limit.max(1),
            clock: TransportClock::real(),
            label: String::new(),
            tx_scratch: Vec::with_capacity(2048),
            tcp_manager,
            http_manager,
            cached_pressure_level: crate::l4_defense::L4PressureLevel::Normal,
            cached_proxy_idle_timeout: AF_XDP_TCP_SESSION_IDLE_TIMEOUT,
            idle_profile_refreshed_at: SmoltcpInstant::from_millis(0),
            #[cfg(target_os = "linux")]
            dial_registry: None,
            transport_controller: crate::runtime_mode::XdpTransportController::default(),
            trusted_ecn: false,
            aggregate: None,
            path_table: std::rc::Rc::new(std::cell::RefCell::new(
                cloud_node_transport::PathTable::new(
                    cloud_node_transport::path_table::DEFAULT_CAPACITY,
                    cloud_node_transport::path_table::DEFAULT_TTL,
                ),
            )),
            last_agg_period: SmoltcpInstant::from_millis(0),
            proxy_rt: None,
            #[cfg(test)]
            test_auto_start_proxy: false,
        }
    }

    /// Install the runtime that owns spawned per-session proxy tasks.
    /// Called by the bridge before the loop runs with the process
    /// multi-thread handle — session L7 work (TLS handshake crypto,
    /// protocol parsing, upstream kernel I/O) is CPU work that must not
    /// serialize behind dataplane polls on this thread.
    #[cfg(target_os = "linux")]
    pub(crate) fn set_proxy_runtime(&mut self, rt: tokio::runtime::Handle) {
        self.proxy_rt = Some(rt);
    }

    /// T5/T6: install the dataplane's transport policy. Called by the
    /// worker before the loop runs; production pins EdgeCC (the config
    /// controller field is parse-compat only), ablation controllers stay
    /// reachable for validation harnesses.
    pub(crate) fn set_transport_policy(
        &mut self,
        policy: &crate::runtime_mode::XdpTransportSettings,
    ) {
        self.transport_controller = policy.controller;
        self.trusted_ecn = policy.trusted_ecn;
        if policy.aggregation_enabled() && self.aggregate.is_none() {
            self.aggregate = Some(cloud_node_transport::Aggregate::shared());
        }
    }

    /// §2.6 arbitration tick — one `on_period` per ~100ms while an
    /// aggregate exists (merge/split hysteresis, probe leasing, tiered
    /// allocation). Bounded O(members); never per-ACK.
    pub(crate) fn tick_aggregate(&mut self, now: SmoltcpInstant) {
        let Some(agg) = self.aggregate.as_ref() else {
            return;
        };
        if session_idle_for(now, self.last_agg_period) < Duration::from_millis(100) {
            return;
        }
        self.last_agg_period = now;
        agg.borrow_mut().on_period();
    }

    /// Tests only: arbitration periods run so far (tick-cadence audit).
    #[cfg(test)]
    pub(crate) fn aggregate_periods(&self) -> Option<u64> {
        self.aggregate.as_ref().map(|a| a.borrow().stats().periods)
    }

    /// Tests only: the worker-local path table handle (prior audit).
    #[cfg(test)]
    pub(crate) fn path_table(
        &self,
    ) -> std::rc::Rc<std::cell::RefCell<cloud_node_transport::PathTable>> {
        std::rc::Rc::clone(&self.path_table)
    }

    /// Tests only (T9): a session's current ledger-held socket buffer
    /// charge — initial pair + every growth step.
    #[cfg(test)]
    pub(crate) fn session_socket_buf_charge(
        &self,
        flow: &AfXdpTcpFlowKey,
    ) -> Option<u64> {
        self.sessions.get(flow).map(|s| s.socket_buf_charge_bytes())
    }

    /// Tests only (T9): a session socket's current receive-buffer
    /// capacity — proves in-session growth landed.
    #[cfg(test)]
    pub(crate) fn session_recv_capacity(
        &self,
        flow: &AfXdpTcpFlowKey,
    ) -> Option<usize> {
        self.sessions.get(flow).map(|s| {
            self.sockets
                .get::<SmoltcpTcp::Socket<'static>>(s.socket)
                .recv_capacity()
        })
    }

    /// Tests only: current clock reading so recorded samples line up
    /// with `path_prior`'s lookup instant.
    #[cfg(test)]
    pub(crate) fn clock_now_micros(&self) -> i64 {
        self.clock.now_micros()
    }

    /// §2.2 prior lookup: client/peer prefix (/24 v4, /64 v6) anchored
    /// on the local address. Exact-key; prefix masking is done here.
    pub(crate) fn path_prior(
        &self,
        peer: IpAddr,
        local: IpAddr,
    ) -> Option<cloud_node_transport::PathPrior> {
        let (dst_prefix, prefix_len) = match peer {
            IpAddr::V4(v4) => (
                IpAddr::V4(std::net::Ipv4Addr::from(
                    u32::from(v4) & 0xffff_ff00,
                )),
                24,
            ),
            IpAddr::V6(v6) => (
                IpAddr::V6(std::net::Ipv6Addr::from(
                    u128::from(v6) & !0xffff_ffff_ffff_ffffu128,
                )),
                64,
            ),
        };
        let key = cloud_node_transport::PathKey {
            egress_ifindex: 0,
            local_ip: local,
            dst_prefix,
            prefix_len,
        };
        let now = cloud_node_transport::TransportInstant::from_micros(
            self.clock.now_micros().max(0) as u64,
        );
        self.path_table.borrow_mut().lookup(&key, now)
    }

    /// T9 (§2.7): adaptive per-socket buffer sizing — `2×BDP` from the
    /// path prior when one exists (32KiB floor otherwise), capped by the
    /// per-connection share of the *real* TCP queue budget. The share is
    /// divided across sessions actually present (plus the incoming one),
    /// not the capacity limit: buffer capacity itself is charged to the
    /// ledger at creation (`reserve_socket_buffers`), so the sum stays
    /// bounded without starving windows on an idle node. Under pressure
    /// the share shrinks and the socket advertises a smaller rwnd.
    pub(crate) fn socket_buffer_bytes(&self, peer: IpAddr, local: IpAddr) -> usize {
        /// Candidate lower bound from the plan (§2.7): 32KiB.
        const FLOOR: usize = 32 * 1024;
        /// Viability floor — below ~3 MSS the connection cannot make
        /// progress at all; only reachable when the real share is this
        /// small, in which case the share itself is the bound.
        const MIN_VIABLE: usize = 4 * 1024;
        let est = self
            .path_prior(peer, local)
            .filter(|p| p.confidence > 0.0 && p.bw_bps > 0)
            .map(|p| {
                (p.bw_bps as f64 * p.base_rtt.as_secs_f64() * 2.0) as usize
            })
            .unwrap_or(FLOOR);
        let live = self.contender_sessions().saturating_add(1);
        let per_conn_dir = (tcp_buffer_pool_budget() / (live * 2))
            .min(usize::MAX as u64) as usize;
        // The upper bound is ALSO the socket ceiling: a path prior with an
        // inflated bw×rtt product must not size the initial allocation past
        // what the socket can ever use — observed live as a single fresh
        // session charging ~19MB of ledger (and real `vec![0; n]` memory)
        // before its first byte moved.
        let ceiling = per_conn_dir.clamp(MIN_VIABLE, AF_XDP_TCP_SOCKET_BUFFER_MAX);
        est.clamp(per_conn_dir.min(MIN_VIABLE), ceiling)
    }

    /// T9: sessions actually contending for queue bytes right now — the
    /// hot queue plus every session parked on the ledger or its drain
    /// cap. Fair-share denominators must use this, not `sessions.len()`:
    /// under churn the table fills with idle/keepalive sessions that hold
    /// ~32KiB floors and no pending work, and dividing the pool across
    /// them pinned each transferring session to ~budget/(240·2) ≈ 300KB
    /// — measured on-node as a ~14 Mbps ceiling exactly matching
    /// share/RTT arithmetic. The ledger CAS remains the fail-closed
    /// bound, so an undercount here only risks optimistic sizing that a
    /// refused charge corrects on the next attempt.
    fn contender_sessions(&self) -> u64 {
        (self.hot_sessions.len() + self.ingress_stalled.len() + 1) as u64
    }

    /// Reserve socket-buffer *capacity* in the node TCP queue ledger,
    /// halving the wanted size until the reservation fits or the
    /// viability floor is reached. `None` means the budget cannot cover
    /// even a minimal socket pair — the caller must refuse the session;
    /// allocating uncharged buffers would break the accounting
    /// invariant `Σ buffer capacity + queued payload ≤ budget`.
    fn reserve_socket_buffers(
        want_per_dir: usize,
    ) -> Option<(usize, StaticTcpQueueBytePermit)> {
        /// Same floor as `socket_buffer_bytes` — ~3 MSS of progress.
        const MIN_VIABLE: usize = 4 * 1024;
        let mut size = want_per_dir.max(MIN_VIABLE);
        loop {
            if let Some(permit) =
                MEMORY_GOVERNOR.try_reserve_tcp_queue_bytes(size.saturating_mul(2))
            {
                return Some((size, permit));
            }
            if size <= MIN_VIABLE {
                return None;
            }
            size = (size / 2).max(MIN_VIABLE);
        }
    }

    /// T9: in-session buffer autotune. smoltcp allocates socket buffers
    /// at construction, so within a session size is learned here: when
    /// the peer demonstrates rx demand (`rx_demand`: queue half-full at
    /// pump start, or ≥ half the window drained since the last attempt)
    /// or tx demand (`tx_demand`: queue ≥75%, or unsent producer bytes),
    /// the buffer jumps to its ceiling in one charged step (bulk flows
    /// self-select into big windows; quiet flows never trigger and stay
    /// small). Every grown byte is charged to the queue ledger — a
    /// refused charge just keeps the current size this round, never a
    /// mid-connection refusal. The rx ceiling additionally respects the
    /// negotiated wire scale (`rx_window_wire_cap`): a peer without RFC
    /// 1323 pins it to 64 KiB, and the live fair-share keeps one greedy
    /// flow from eating the budget under real load.
    /// Static: called while `self.sessions` is mutably borrowed.
    fn grow_socket_buffers(
        socket: &mut SmoltcpTcp::Socket<'static>,
        session: &mut AfXdpTcpSession,
        live_sessions: u64,
        rx_demand: bool,
        tx_demand: bool,
        now: SmoltcpInstant,
    ) {
        if session.closing {
            return;
        }
        // T9: a refused charge cools down for GROWTH_RETRY_BACKOFF —
        // without it every pump of every demand-showing session retries
        // the full-ledger CAS, a measured ~11M-attempt/min storm that
        // starves this single thread by itself.
        if session
            .growth_retry_after
            .is_some_and(|retry_after| now < retry_after)
        {
            return;
        }
        let fair_share = (tcp_buffer_pool_budget() / (live_sessions.max(1) * 2))
            .min(usize::MAX as u64) as usize;
        if rx_demand {
            session.rx_growth_probe = 0;
            let cap = socket.recv_capacity();
            let limit = AF_XDP_TCP_SOCKET_BUFFER_MAX
                .min(socket.rx_window_wire_cap())
                .min(fair_share);
            if limit > cap {
                match Self::charge_buffer_growth(cap, limit) {
                    Some((delta, permit)) => {
                        if socket.grow_recv_buffer(cap + delta) {
                            session.socket_buf_permits.push(permit);
                            #[cfg(target_os = "linux")]
                            AF_XDP_TCP_DIAG_BUFFER_GROWTH.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    None => {
                        session.growth_retry_after =
                            Some(now + SmolDuration::from(AF_XDP_TCP_GROWTH_RETRY_BACKOFF));
                    }
                }
            }
        }
        if tx_demand {
            let cap = socket.send_capacity();
            let limit = AF_XDP_TCP_SOCKET_BUFFER_MAX.min(fair_share);
            if limit > cap {
                match Self::charge_buffer_growth(cap, limit) {
                    Some((delta, permit)) => {
                        if socket.grow_send_buffer(cap + delta) {
                            session.socket_buf_permits.push(permit);
                            #[cfg(target_os = "linux")]
                            AF_XDP_TCP_DIAG_BUFFER_GROWTH.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    None => {
                        session.growth_retry_after =
                            Some(now + SmolDuration::from(AF_XDP_TCP_GROWTH_RETRY_BACKOFF));
                    }
                }
            }
        }
    }

    /// T9: charge `limit - current` growth bytes, halving toward
    /// GROW_MIN_DELTA until the ledger accepts. `None` means even the
    /// minimum step does not fit — growth waits for a later round.
    /// Returns the charged delta; the caller grows by exactly that.
    fn charge_buffer_growth(
        current: usize,
        limit: usize,
    ) -> Option<(usize, StaticTcpQueueBytePermit)> {
        if limit <= current {
            return None;
        }
        let mut delta = limit - current;
        loop {
            if let Some(permit) = MEMORY_GOVERNOR.try_reserve_tcp_queue_bytes(delta)
            {
                return Some((delta, permit));
            }
            if delta <= AF_XDP_TCP_BUFFER_GROW_MIN_DELTA {
                #[cfg(target_os = "linux")]
                AF_XDP_TCP_DIAG_BUFFER_GROW_STALL.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            delta = (delta / 2).max(AF_XDP_TCP_BUFFER_GROW_MIN_DELTA);
        }
    }

    /// T5: build the session's congestion controller per policy.
    /// Reference controllers are validation-only selections.
    pub(crate) fn make_transport_controller(
        &self,
        peer: IpAddr,
        local: IpAddr,
    ) -> Box<dyn cloud_node_transport::cc::CongestionController> {
        use crate::runtime_mode::XdpTransportController as Ctl;
        use cloud_node_transport::cc as tcc;
        match self.transport_controller {
            Ctl::Cubic => Box::new(tcc::CubicRef::new(536)),
            Ctl::NewReno => Box::new(tcc::NewRenoRef::new(536)),
            Ctl::Bbr3 => Box::new(tcc::Bbr3Ref::new(536)),
            Ctl::LossBlind => Box::new(tcc::LossBlindRef::new(
                536,
                cloud_node_transport::Tier::T1,
                None,
                self.trusted_ecn,
            )),
            Ctl::Edgecc => {
                let mut cc = cloud_node_transport::EdgeCc::new(
                    536,
                    cloud_node_transport::Tier::T1,
                    self.path_prior(peer, local),
                    self.trusted_ecn,
                );
                if let Some(agg) = self.aggregate.as_ref()
                    && let Some(lease) = cloud_node_transport::Aggregate::join(agg)
                {
                    cc.set_aggregate(Box::new(lease));
                }
                Box::new(cc)
            }
        }
    }

    /// T6: fold a closed flow's controller snapshot into the path table
    /// (fresh samples validate priors — §2.2 fresh-sample contract).
    /// Static: the reap path calls this while `self.sockets` is borrowed.
    pub(crate) fn record_path_sample(
        table: &std::rc::Rc<
            std::cell::RefCell<cloud_node_transport::PathTable>,
        >,
        clock_us: i64,
        peer: IpAddr,
        local: IpAddr,
        snap: &cloud_node_transport::cc::CcSnapshot,
        failed: bool,
    ) {
        let (dst_prefix, prefix_len) = match peer {
            IpAddr::V4(v4) => (
                IpAddr::V4(std::net::Ipv4Addr::from(
                    u32::from(v4) & 0xffff_ff00,
                )),
                24,
            ),
            IpAddr::V6(v6) => (
                IpAddr::V6(std::net::Ipv6Addr::from(
                    u128::from(v6) & !0xffff_ffff_ffff_ffffu128,
                )),
                64,
            ),
        };
        let key = cloud_node_transport::PathKey {
            egress_ifindex: 0,
            local_ip: local,
            dst_prefix,
            prefix_len,
        };
        let now = cloud_node_transport::TransportInstant::from_micros(
            clock_us.max(0) as u64,
        );
        table.borrow_mut().record(
            key,
            cloud_node_transport::PathSample {
                bw_bps: snap.bandwidth_lo_bps.or(snap.bandwidth_hi_bps).unwrap_or(0),
                base_rtt: snap.min_rtt.unwrap_or_default(),
                p_rand: snap.p_rand_milli.unwrap_or(0) as f64 / 1000.0,
                alpha: snap.ecn_alpha_milli.unwrap_or(0) as f64 / 1000.0,
                reorder: 0.0,
                connect_rtt: None,
                failed,
            },
            now,
        );
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
    /// F1 explicit teardown: abort every live smoltcp session so the next
    /// `poll` emits RST frames on the wire. Callers must flush the egress
    /// to TX before dropping the queue — a retired dataplane terminates
    /// peers visibly instead of leaving silently hung sockets.
    #[cfg(target_os = "linux")]
    pub(crate) fn abort_all_sessions(&mut self) -> usize {
        let mut aborted = 0usize;
        for session in self.sessions.values_mut() {
            if session.closing {
                continue;
            }
            let socket = self
                .sockets
                .get_mut::<SmoltcpTcp::Socket<'static>>(session.socket);
            socket.abort();
            session.closing = true;
            aborted += 1;
        }
        aborted
    }

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
        if !existing_session {
            AF_XDP_TCP_DIAG_ACCEPTED.fetch_add(1, Ordering::Relaxed);
        }
        if !self.enqueue_ingress(route, flow, ip_packet) {
            return AfXdpTcpIngestStatus::IngressQueueFull;
        }
        AfXdpTcpIngestStatus::Accepted
    }

    /// EN-17: queue a packet for the bounded smoltcp ingress loop and mark
    /// its session hot. Returns false (explicit refusal, counted) only
    /// when the per-reactor ingress queue is full — the entry bound is
    /// the memory bound for this queue (≤ ~750 KiB). T9: there is no
    /// per-packet ledger charge here on purpose — a saturated ledger
    /// would otherwise starve the front door, dropping established
    /// sessions' data and every new SYN, which is how one speed test
    /// took the whole node offline. Held memory is accounted per
    /// session (socket buffers, channel residency, pending) instead.
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
        self.device.push_ingress(route, flow, ip_packet);
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

    /// T1: bridge labels the reactor "iface:queue" so per-session snapshots
    /// in the shared map are unambiguous across workers.
    #[cfg(target_os = "linux")]
    pub(crate) fn set_label(&mut self, label: String) {
        self.label = label;
    }

    /// T1: tests install a manual clock and drive protocol time with
    /// `advance` — sweep cadence and idle reaping become deterministic.
    #[cfg(test)]
    pub(crate) fn install_manual_clock_for_test(&mut self) -> TransportClock {
        let clock = TransportClock::manual();
        self.clock = clock.clone();
        clock
    }

    pub(crate) fn poll(&mut self) -> Vec<(AfXdpRouteMeta, Vec<u8>)> {
        let now = SmoltcpInstant::from_micros(self.clock.now_micros());
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
        // §2.6: arbitration tick — merge/split hysteresis, probe leasing,
        // tiered allocation. No-op when aggregation isn't configured.
        self.tick_aggregate(now);
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

    /// Work already queued for the reactor — hot sessions, dirty wake
    /// marks or undrained ingress. None of these carries its own wake
    /// source, so the bridge must not enter an event wait while any is
    /// non-empty.
    pub(crate) fn has_queued_work(&self) -> bool {
        !self.hot_sessions.is_empty()
            || !self.wake_set.is_empty()
            || !self.device.ingress.is_empty()
    }

    /// Shared notify the stream tasks signal when they queue egress —
    /// the bridge waits on it so a writer's bytes are pumped immediately
    /// rather than at the next poll round.
    #[cfg(target_os = "linux")]
    pub(crate) fn wake_notify(&self) -> Arc<tokio::sync::Notify> {
        self.wake_notify.clone()
    }

    /// Time until the smoltcp stack next needs polling (retransmit,
    /// delayed ACK, time-wait expiry). `poll_delay` returns a relative
    /// duration. None when no timer is armed — the only remaining wake
    /// sources are RX frames and channel items.
    #[cfg(target_os = "linux")]
    pub(crate) fn next_timer_delay(&mut self) -> Option<Duration> {
        let now = SmoltcpInstant::from_micros(self.clock.now_micros());
        self.iface
            .poll_delay(now, &self.sockets)
            .map(|delay| Duration::from_micros(delay.total_micros()))
    }

    /// EN-17 test hooks: observe hot-set scheduling state.
    #[cfg(test)]
    pub(crate) fn hot_session_count(&self) -> usize {
        self.hot_sessions.len()
    }

    /// EN-17 test hook: observe the batched sweep cursor.
    #[cfg(test)]
    pub(crate) fn sweep_cursor(&self) -> usize {
        self.sweep_pos
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

    /// Test hook: count of sessions still in the unverified (pre-proxy)
    /// class — the budgeted noise pool.
    #[cfg(test)]
    pub(crate) fn pre_proxy_session_count(&self) -> usize {
        self.pre_proxy_sessions
    }

    /// Test hook: the bounded share of the table the unverified class may
    /// hold at this session limit.
    #[cfg(test)]
    pub(crate) fn pre_proxy_budget_for_test(&self) -> usize {
        self.pre_proxy_budget()
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

    /// T9 test hook: park `flow` in `ingress_stalled` as if its drain
    /// stalled at `since` — reproduces the production zombie shape
    /// without having to saturate the real ledger.
    #[cfg(test)]
    pub(crate) fn force_stalled_since_for_test(
        &mut self,
        flow: &AfXdpTcpFlowKey,
        since: SmoltcpInstant,
    ) {
        if let Some(session) = self.sessions.get_mut(flow) {
            session.stalled_since = Some(since);
            self.ingress_stalled.insert(*flow);
        }
    }

    /// T9 test hook: park `flow` in `ingress_stalled` on its drain cap —
    /// same shape as `force_stalled_since_for_test` but for the
    /// consumer-progress clock.
    #[cfg(test)]
    pub(crate) fn force_cap_parked_since_for_test(
        &mut self,
        flow: &AfXdpTcpFlowKey,
        since: SmoltcpInstant,
    ) {
        if let Some(session) = self.sessions.get_mut(flow) {
            session.cap_parked_since = Some(since);
            self.ingress_stalled.insert(*flow);
        }
    }

    /// Test hook: mark `flow` closing without aborting the socket —
    /// the FIN-WAIT-2 zombie shape (close handshake stalled, socket
    /// still in a non-terminal state).
    #[cfg(test)]
    pub(crate) fn force_closing_for_test(&mut self, flow: &AfXdpTcpFlowKey) {
        if let Some(session) = self.sessions.get_mut(flow) {
            session.closing = true;
        }
    }

    /// Test hook: stage an unflushed app-egress chunk — the shape a
    /// send-buffer-full session presents to `session_still_active`.
    #[cfg(test)]
    pub(crate) fn force_pending_egress_for_test(
        &mut self,
        flow: &AfXdpTcpFlowKey,
        bytes: Bytes,
    ) {
        if let Some(session) = self.sessions.get_mut(flow) {
            session.pending_egress = AfXdpTcpChargedBytes::charged(bytes)
                .expect("test ledger must cover pending egress");
        }
    }

    /// Tests only: bytes still waiting for socket send-buffer room.
    #[cfg(test)]
    pub(crate) fn session_pending_egress_bytes(
        &self,
        flow: &AfXdpTcpFlowKey,
    ) -> Option<usize> {
        self.sessions.get(flow).map(|s| s.pending_egress.len())
    }

    /// Tests only: socket send-buffer fill/capacity — `(queue, capacity)`.
    #[cfg(test)]
    pub(crate) fn session_send_buffer_fill(
        &self,
        flow: &AfXdpTcpFlowKey,
    ) -> Option<(usize, usize)> {
        self.sessions.get(flow).map(|s| {
            let socket = self
                .sockets
                .get::<SmoltcpTcp::Socket<'static>>(s.socket);
            (socket.send_queue(), socket.send_capacity())
        })
    }

    pub(crate) fn ensure_session(
        &mut self,
        route: AfXdpRouteMeta,
        flow: AfXdpTcpFlowKey,
        proxy_class: AfXdpTcpProxyClass,
    ) -> bool {
        let now = SmoltcpInstant::from_micros(self.clock.now_micros());
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
        let peer_ip = flow.peer_addr.ip();
        // Admission is tiered, never first-come-at-any-price: when space is
        // short the oldest still-unverified session is sacrificed first —
        // its peer committed nothing and a retransmitted SYN starts over,
        // while established proxied and node-dialed flows carry real work.
        // Only a table with nothing evictable left refuses.
        if self.sessions.len() >= self.session_limit && !self.evict_oldest_pre_proxy(None) {
            return false;
        }
        if self.pre_proxy_per_ip.get(&peer_ip).copied().unwrap_or(0)
            >= AF_XDP_TCP_PRE_PROXY_PER_IP_LIMIT
            && !self.evict_oldest_pre_proxy(Some(peer_ip))
        {
            #[cfg(target_os = "linux")]
            AF_XDP_TCP_DIAG_PRE_PROXY_REFUSED.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if self.pre_proxy_sessions >= self.pre_proxy_budget()
            && !self.evict_oldest_pre_proxy(None)
        {
            #[cfg(target_os = "linux")]
            AF_XDP_TCP_DIAG_PRE_PROXY_REFUSED.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        self.ensure_local_ip(flow.local_addr.ip());
        let want = self.socket_buffer_bytes(flow.peer_addr.ip(), flow.local_addr.ip());
        let Some((buf_bytes, buf_permit)) = Self::reserve_socket_buffers(want) else {
            #[cfg(target_os = "linux")]
            AF_XDP_TCP_DIAG_BUFFER_REFUSED.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let rx_buffer = SmoltcpTcp::SocketBuffer::new(vec![0; buf_bytes]);
        let tx_buffer = SmoltcpTcp::SocketBuffer::new(vec![0; buf_bytes]);
        let mut socket = SmoltcpTcp::Socket::new(rx_buffer, tx_buffer);
        // T9: negotiate the window shift for the growth ceiling, not the
        // initial capacity — the buffer starts small (cheap, charged) and
        // `grow_socket_buffers` expands it in-session while the wire
        // encoding already covers the ceiling.
        socket.set_rx_window_shift_for_ceiling(AF_XDP_TCP_SOCKET_BUFFER_MAX);
        socket.set_nagle_enabled(false);
        // F8: AF_XDP TCP must run a real congestion controller — without an
        // explicit selection smoltcp silently falls back to NoControl
        // (window = usize::MAX), which XDP pps budgets cannot replace.
        socket.set_congestion_control(SmoltcpTcp::CongestionControl::Cubic);
        // T3/T5: the external transport controller is policy-selected —
        // CubicRef (default, validated) or EdgeCc with a worker-local
        // aggregate lease and a path-table prior when enabled. The
        // builtin Cubic stays installed but is not consulted while ext
        // is set. Initial MSS is conservative; `on_mss_update` refines.
        socket.set_transport_controller(
            self.make_transport_controller(flow.peer_addr.ip(), flow.local_addr.ip()),
        );
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
            dialed: false,
            dial_reply: None,
            dial_deadline: None,
            socket_buf_permits: vec![buf_permit],
            rx_growth_probe: 0,
            stalled_since: None,
            cap_parked_since: None,
            socket_buf_floor_bytes: buf_bytes,
            growth_retry_after: None,
        };
        let count_pre_proxy = !session.proxy_started;
        self.sessions.insert(flow, session);
        if count_pre_proxy {
            self.note_pre_proxy_admitted(peer_ip);
        }
        self.publish_session_gauges();
        #[cfg(target_os = "linux")]
        if let Some(session) = self.sessions.get(&flow) {
            self.publish_session_snapshot(&flow, session);
        }
        true
    }

    /// Bounded share of the session table available to still-unverified
    /// (pre-proxy) sessions — one eighth of capacity, floored so small
    /// limits still admit handshakes, capped so it never exceeds the
    /// table itself.
    fn pre_proxy_budget(&self) -> usize {
        (self.session_limit / AF_XDP_TCP_PRE_PROXY_BUDGET_DIVISOR)
            .max(AF_XDP_TCP_PRE_PROXY_MIN_BUDGET)
            .min(self.session_limit)
    }

    fn note_pre_proxy_admitted(&mut self, peer_ip: std::net::IpAddr) {
        self.pre_proxy_sessions = self.pre_proxy_sessions.saturating_add(1);
        *self.pre_proxy_per_ip.entry(peer_ip).or_insert(0) += 1;
    }

    /// A session left the unverified class — graduated to proxying,
    /// reaped, or evicted.
    fn note_pre_proxy_departed(&mut self, peer_ip: std::net::IpAddr) {
        self.pre_proxy_sessions = self.pre_proxy_sessions.saturating_sub(1);
        if let Some(count) = self.pre_proxy_per_ip.get_mut(&peer_ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.pre_proxy_per_ip.remove(&peer_ip);
            }
        }
    }

    /// Evict the oldest still-unverified session (optionally restricted to
    /// one peer IP) so a new admission can take its slot. The session is
    /// reaped synchronously — the slot is free before the caller proceeds.
    /// Returns false when nothing evictable exists (every unverified slot
    /// is already closing, or the table holds only verified flows).
    fn evict_oldest_pre_proxy(&mut self, only_peer: Option<std::net::IpAddr>) -> bool {
        let victim = self
            .sessions
            .iter()
            .filter(|(flow, session)| {
                !session.proxy_started
                    && !session.dialed
                    && !session.closing
                    && only_peer.is_none_or(|ip| flow.peer_addr.ip() == ip)
            })
            .min_by_key(|(_, session)| session.created_at)
            .map(|(flow, _)| *flow);
        let Some(flow) = victim else {
            return false;
        };
        self.ingress_stalled.remove(&flow);
        #[cfg(target_os = "linux")]
        self.drop_session_snapshot(&flow);
        if let Some(session) = self.sessions.remove(&flow) {
            let socket = self
                .sockets
                .get_mut::<SmoltcpTcp::Socket<'static>>(session.socket);
            socket.abort();
            let _ = self.sockets.remove(session.socket);
        }
        self.note_pre_proxy_departed(flow.peer_addr.ip());
        self.publish_session_gauges();
        #[cfg(target_os = "linux")]
        if only_peer.is_some() {
            AF_XDP_TCP_DIAG_PER_IP_EVICTED.fetch_add(1, Ordering::Relaxed);
        } else {
            AF_XDP_TCP_DIAG_PRE_PROXY_EVICTED.fetch_add(1, Ordering::Relaxed);
        }
        self.record_l4_event_for_ip(
            flow.peer_addr.ip(),
            crate::l4_defense::L4DefenseKind::SynBacklogPressure,
            crate::l4_defense::L4PressureLevel::High,
            format!(
                "peer={} local={} phase=af_xdp_pre_proxy_evicted sessions={} pre_proxy={} budget={} per_ip={}",
                flow.peer_addr,
                flow.local_addr,
                self.sessions.len(),
                self.pre_proxy_sessions,
                self.pre_proxy_budget(),
                only_peer.is_some(),
            ),
        );
        tracing::debug!(
            "AF_XDP TCP reactor evicted oldest pre-proxy session local={} peer={} pre_proxy={} budget={} per_ip={}",
            flow.local_addr,
            flow.peer_addr,
            self.pre_proxy_sessions,
            self.pre_proxy_budget(),
            only_peer.is_some(),
        );
        true
    }

    fn publish_session_gauges(&self) {
        #[cfg(target_os = "linux")]
        publish_tcp_session_count(
            &self.label,
            self.sessions.len() as u64,
            self.pre_proxy_sessions as u64,
        );
    }

    /// T4: the bridge installs the generation's dial registry before the
    /// loop runs so dialed-session reaping can release the demux entry,
    /// source port and out-CT row.
    #[cfg(target_os = "linux")]
    pub(crate) fn set_dial_registry(&mut self, registry: Arc<AfXdpDialRegistry>) {
        self.dial_registry = Some(registry);
    }

    /// T4: open an outbound connection through this reactor. The caller
    /// (the dial registry's `dial_tcp`) has already resolved the route,
    /// allocated the reserved-range source port, registered XDP_OUT_CT
    /// and the cross-queue demux entry — everything after this point is
    /// smoltcp session lifecycle, identical to the accepted path minus
    /// the proxy-class machinery.
    ///
    /// Any refusal answers `req.reply` with an explicit error and creates
    /// no state; the caller unwinds the pre-registered maps on Err.
    pub(crate) fn dial(&mut self, req: AfXdpTcpDialRequest) {
        let flow = AfXdpTcpFlowKey {
            local_addr: req.local,
            peer_addr: req.remote,
        };
        if self.sessions.contains_key(&flow) {
            let _ = req.reply.send(Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("AF_XDP dialed flow {} -> {} already exists", req.local, req.remote),
            )));
            return;
        }
        // A node-dialed flow is verified work by definition — inbound
        // noise holding unverified slots must not starve it.
        if self.sessions.len() >= self.session_limit {
            self.evict_oldest_pre_proxy(None);
        }
        if self.sessions.len() >= self.session_limit {
            let _ = req.reply.send(Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                format!(
                    "AF_XDP dialed flow refused at session limit {}",
                    self.session_limit
                ),
            )));
            return;
        }
        self.ensure_local_ip(req.local.ip());
        let want = self.socket_buffer_bytes(req.remote.ip(), req.local.ip());
        let Some((buf_bytes, buf_permit)) = Self::reserve_socket_buffers(want) else {
            #[cfg(target_os = "linux")]
            AF_XDP_TCP_DIAG_BUFFER_REFUSED.fetch_add(1, Ordering::Relaxed);
            let _ = req.reply.send(Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                "AF_XDP TCP queue budget exhausted: socket buffers unreservable",
            )));
            return;
        };
        let rx_buffer = SmoltcpTcp::SocketBuffer::new(vec![0; buf_bytes]);
        let tx_buffer = SmoltcpTcp::SocketBuffer::new(vec![0; buf_bytes]);
        let mut socket = SmoltcpTcp::Socket::new(rx_buffer, tx_buffer);
        // T9: same growth-headroom negotiation as accepted sessions —
        // the shift is fixed in our SYN, so it must be set pre-connect.
        socket.set_rx_window_shift_for_ceiling(AF_XDP_TCP_SOCKET_BUFFER_MAX);
        socket.set_nagle_enabled(false);
        // F8/T3/T5: dialed sessions run the same policy-selected external
        // controller as accepted ones — never NoControl.
        socket.set_congestion_control(SmoltcpTcp::CongestionControl::Cubic);
        socket.set_transport_controller(
            self.make_transport_controller(req.remote.ip(), req.local.ip()),
        );
        // T7: actively offer AccECN on dialed flows only when the
        // path is a controlled link (xdp.transport.trusted_ecn —
        // D-D2); public-internet dials keep the stock non-ECN SYN.
        socket.set_ecn_active_offered(self.trusted_ecn);
        if !req.syn_extra_options.is_empty()
            && let Err(err) = socket.set_syn_extra_options(&req.syn_extra_options)
        {
            let _ = req.reply.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("AF_XDP dial SYN options rejected: {err}"),
            )));
            return;
        }
        if let Err(err) = socket.connect(self.iface.context(), req.remote, req.local) {
            let _ = req.reply.send(Err(io::Error::other(format!(
                "AF_XDP dial connect {} -> {} failed: {err}",
                req.local, req.remote
            ))));
            return;
        }
        let socket = self.sockets.add(socket);
        let now = SmoltcpInstant::from_micros(self.clock.now_micros());
        let session = AfXdpTcpSession {
            flow,
            route: req.route,
            // The proxy class is a placeholder — a dialed session never
            // spawns a proxy task; `dialed` gates its lifecycle.
            proxy_class: AfXdpTcpProxyClass::TcpPlain,
            socket,
            ingress_tx: None,
            egress_rx: None,
            pending_ingress: AfXdpTcpChargedBytes::empty(),
            pending_egress: AfXdpTcpChargedBytes::empty(),
            created_at: now,
            last_activity: now,
            proxy_started: false,
            closing: false,
            egress_closed: false,
            hot: false,
            dialed: true,
            dial_reply: Some(req.reply),
            dial_deadline: Some(now + SmolDuration::from(AF_XDP_TCP_DIAL_TIMEOUT)),
            socket_buf_permits: vec![buf_permit],
            rx_growth_probe: 0,
            stalled_since: None,
            cap_parked_since: None,
            socket_buf_floor_bytes: buf_bytes,
            growth_retry_after: None,
        };
        self.sessions.insert(flow, session);
        self.mark_hot(flow);
        self.publish_session_gauges();
        #[cfg(target_os = "linux")]
        if let Some(session) = self.sessions.get(&flow) {
            self.publish_session_snapshot(&flow, session);
        }
    }

    /// T1: publish this session's transport snapshot into the shared
    /// /status table. T3 (smoltcp-edge): sessions with an external
    /// transport controller surface the real `CcSnapshot` — cwnd,
    /// ssthresh, pacing, min-RTT and the EdgeCC observability fields;
    /// fields the controller does not track stay `null`, never
    /// fabricated.
    #[cfg(target_os = "linux")]
    fn publish_session_snapshot(&self, flow: &AfXdpTcpFlowKey, session: &AfXdpTcpSession) {
        let socket = self
            .sockets
            .get::<SmoltcpTcp::Socket<'static>>(session.socket);
        let cc = socket.transport_snapshot();
        publish_tcp_session_snapshot(
            format!("{}|{}|{}", self.label, flow.local_addr, flow.peer_addr),
            serde_json::json!({
                "ifaceQueue": self.label,
                "local": flow.local_addr.to_string(),
                "peer": flow.peer_addr.to_string(),
                "direction": "accepted",
                "class": session.proxy_class.label(),
                "state": socket.state().to_string(),
                // Builtin variants are feature-gated; format whatever
                // the enabled feature set produced.
                "ccAlgorithm": cc.as_ref().map(|c| c.algo.to_string())
                    .unwrap_or_else(|| format!("{:?}", socket.congestion_control()).to_lowercase()),
                "ccImpl": if cc.is_some() { "smoltcp-edge" } else { "smoltcp-0.14" },
                "ccVersionPin": cc.as_ref().map(|c| c.version_pin),
                "ccMode": cc.as_ref().map(|c| c.mode),
                "reasonCode": cc.as_ref().map(|c| c.reason_code),
                "cwndBytes": cc.as_ref().map(|c| c.cwnd_bytes),
                "ssthreshBytes": cc.as_ref().map(|c| c.ssthresh_bytes),
                "inFlightBytes": serde_json::Value::Null,
                "srttMicros": serde_json::Value::Null,
                "minRttMicros": cc.as_ref()
                    .and_then(|c| c.min_rtt)
                    .map(|d| d.as_micros() as u64),
                "pacingRateBps": cc.as_ref().and_then(|c| c.pacing_rate_bps),
                "delivered": serde_json::Value::Null,
                "lost": serde_json::Value::Null,
                "ecnMode": serde_json::Value::Null,
                "beliefMilli": cc.as_ref().and_then(|c| c.belief_milli),
                "queueEstimateBytes": cc.as_ref().and_then(|c| c.queue_estimate_bytes),
                "pRandMilli": cc.as_ref().and_then(|c| c.p_rand_milli),
                "bwSigmaBps": cc.as_ref().and_then(|c| c.bw_sigma_bps),
                "envelopeBytes": cc.as_ref().and_then(|c| c.envelope_bytes),
                "sendQueueBytes": socket.send_queue(),
                "recvQueueBytes": socket.recv_queue(),
                // Emit-side gates — the difference between "socket holds
                // data" and "socket cannot emit": zero remote window,
                // scoreboard pipe covering cwnd, pacing due in the
                // future, or a timer that hasn't fired yet.
                "remoteWinBytes": socket.remote_window(),
                "unackedBytes": socket.unacked_bytes(),
                "pipeBytes": socket.transport_pipe(),
                "timerState": socket.timer_state(),
                // Ledger charge for this socket's rx+tx buffer capacity —
                // makes the fair-share sizing observable per session.
                "socketBufChargeBytes": session.socket_buf_charge_bytes(),
                "pendingIngressBytes": session.pending_ingress.len(),
                "pendingEgressBytes": session.pending_egress.len(),
                "proxyStarted": session.proxy_started,
                "closing": session.closing,
            }),
        );
    }

    #[cfg(target_os = "linux")]
    fn drop_session_snapshot(&self, flow: &AfXdpTcpFlowKey) {
        remove_tcp_session_snapshot(&format!(
            "{}|{}|{}",
            self.label, flow.local_addr, flow.peer_addr
        ));
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
        wake_notify: Arc<tokio::sync::Notify>,
        budget_stall: AfXdpTcpBudgetStallSet,
        proxy_rt: Option<tokio::runtime::Handle>,
    ) -> bool {
        let peer_addr = session.flow.peer_addr;
        let listen_addr = session.flow.local_addr;
        let listen_port = listen_addr.port();
        let AfXdpTcpStreamParts {
            mut stream,
            ingress_tx,
            egress_rx,
            budget_stall: _,
        } = AfXdpTcpStream::channel_pair_with_wake(
            AF_XDP_TCP_STREAM_CHANNEL_DEPTH,
            session.flow,
            wake_set,
            budget_stall,
        );
        stream.set_wake_notify(wake_notify);
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
                spawn_session_task(&proxy_rt, async move {
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
                spawn_session_task(&proxy_rt, async move {
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

    /// T4-7: apply an ICMP-reported path MTU to a dialed session's
    /// socket. `None` (non-PTB error kinds) is ignored — unreachable
    /// reports never kill a live session; the retransmit timers own
    /// stalls. A `Some(mtu)` clamps every new segment's effective MSS
    /// via `set_path_mtu` until another report updates it.
    pub(crate) fn apply_pmtu(&mut self, flow: &AfXdpTcpFlowKey, mtu: Option<u32>) {
        let Some(mtu) = mtu else {
            // Non-PTB ICMP error (unreachable, time-exceeded…): the
            // session stays alive — retransmission/timeout logic owns
            // stall detection, matching kernel TCP behavior.
            tracing::debug!(
                "AF_XDP session {} -> {} received non-PTB ICMP error; session continues",
                flow.local_addr,
                flow.peer_addr
            );
            return;
        };
        let Some(session) = self.sessions.get(flow) else {
            tracing::debug!(
                "AF_XDP PMTU update {} -> {} arrived after session teardown; ignored",
                flow.local_addr,
                flow.peer_addr
            );
            return;
        };
        let socket = self
            .sockets
            .get_mut::<SmoltcpTcp::Socket<'static>>(session.socket);
        socket.set_path_mtu(mtu as usize);
        tracing::debug!(
            "AF_XDP session {} -> {} path MTU clamped to {mtu}",
            flow.local_addr,
            flow.peer_addr
        );
    }

    /// Test hook: the session's installed path-MTU cap (outer None =
    /// unknown flow, inner None = uncapped).
    #[cfg(test)]
    pub(crate) fn session_path_mtu(
        &self,
        flow: &AfXdpTcpFlowKey,
    ) -> Option<Option<usize>> {
        let session = self.sessions.get(flow)?;
        Some(
            self.sockets
                .get::<SmoltcpTcp::Socket<'static>>(session.socket)
                .path_mtu(),
        )
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
                #[cfg(target_os = "linux")]
                if let Some(session) = self.sessions.get(&flow) {
                    self.publish_session_snapshot(&flow, session);
                }
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
    /// work — undelivered ingress, unflushed egress, a close in flight, or
    /// more socket receive data. A pre-proxy session awaiting its peer's
    /// next move is NOT work: the completing ACK marks it hot via
    /// `enqueue_ingress`, handshake retransmits are driven by the smoltcp
    /// poll-delay wake, and the pre-proxy idle reap is sweep/retainer
    /// cadence. Keeping every unverified session hot here would busy-pump
    /// the whole SYN-noise population every round — on a public port that
    /// population never empties, so the reactor would never idle.
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
        // A pending chunk counts as work only when its destination can
        // accept it this round. Re-pumping a channel-full (ingress) or
        // send-buffer-full (egress) session is guaranteed zero progress —
        // with a few hundred blocked sessions that busy-pump alone pinned
        // the reactor core at 100% while no packets moved (observed live:
        // ~100pps wire traffic, afxdp thread pegged). The blocker's own
        // completion re-marks the flow: a drained channel signals via the
        // stream wake, send-buffer room arrives with the next ACK
        // (`enqueue_ingress` marks hot), and the sweep backstops both.
        if !session.pending_ingress.is_empty()
            && session
                .ingress_tx
                .as_ref()
                .is_some_and(|tx| tx.capacity() > 0)
        {
            return true;
        }
        if !session.pending_egress.is_empty()
            && socket.can_send()
            && socket.send_queue() < socket.send_capacity()
        {
            return true;
        }
        // F3: a session parked on the queue byte budget keeps `can_recv`
        // true while data sits in the socket — staying hot would busy-pump
        // it every round. The budget release path re-marks it instead.
        if self.ingress_stalled.contains(&flow) {
            return false;
        }
        // A closing session still needs pump rounds for disconnect
        // detection and the final drain — but only when the socket still
        // has observable work. `can_send` with a full send buffer is the
        // same zero-progress shape as pending_egress above; a FIN-wait
        // zombie holding neither has none: `poll_egress` drives the close
        // handshake, the sweep re-checks at cadence.
        if session.closing {
            return socket.can_recv()
                || (socket.can_send() && socket.send_queue() < socket.send_capacity());
        }
        socket.can_recv()
    }

    fn pump_session(&mut self, now: SmoltcpInstant, flow: AfXdpTcpFlowKey) {
        let tcp_manager = self.tcp_manager.clone();
        let http_manager = self.http_manager.clone();
        // T9 fair-share input — read before `session` mutably borrows the
        // table for the rest of this call. Denominator is *contending*
        // sessions (hot + parked), not the whole table: idle established
        // sessions hold ~floor buffers and no pending work, and counting
        // them shrank every transferring session's share to ~300KB under
        // speedtest churn (≈ share/RTT → a ~14 Mbps ceiling).
        let live_sessions = self.contender_sessions();
        #[cfg(target_os = "linux")]
        let sessions_len = self.sessions.len() as u64;
        let Some(session) = self.sessions.get_mut(&flow) else {
            return;
        };
        {
            let socket = self
                .sockets
                .get_mut::<SmoltcpTcp::Socket<'static>>(session.socket);

            // T4: dialed-session handshake resolution runs before the
            // proxy-start gate — a dialed session never spawns a proxy
            // task; Established delivers the stream to the dialer, a
            // refused/closed socket or an expired deadline fails the
            // dial explicitly.
            if session.dialed && session.dial_reply.is_some() {
                match socket.state() {
                    SmoltcpTcp::State::Established | SmoltcpTcp::State::CloseWait => {
                        let AfXdpTcpStreamParts {
                            mut stream,
                            ingress_tx,
                            egress_rx,
                            ..
                        } = AfXdpTcpStream::channel_pair_with_wake(
                            AF_XDP_TCP_STREAM_CHANNEL_DEPTH,
                            session.flow,
                            self.wake_set.clone(),
                            self.budget_stall.clone(),
                        );
                        stream.set_wake_notify(self.wake_notify.clone());
                        session.ingress_tx = Some(ingress_tx);
                        session.egress_rx = Some(egress_rx);
                        session.proxy_started = true;
                        if let Some(reply) = session.dial_reply.take() {
                            let _ = reply.send(Ok(stream));
                        }
                    }
                    SmoltcpTcp::State::Closed | SmoltcpTcp::State::Listen => {
                        if let Some(reply) = session.dial_reply.take() {
                            let _ = reply.send(Err(io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                format!(
                                    "AF_XDP dial {} -> {} refused or reset",
                                    flow.local_addr, flow.peer_addr
                                ),
                            )));
                        }
                        session.closing = true;
                        return;
                    }
                    _ => {
                        if let Some(deadline) = session.dial_deadline
                            && now >= deadline
                        {
                            socket.abort();
                            if let Some(reply) = session.dial_reply.take() {
                                let _ = reply.send(Err(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    format!(
                                        "AF_XDP dial {} -> {} timed out after {}ms",
                                        flow.local_addr,
                                        flow.peer_addr,
                                        AF_XDP_TCP_DIAL_TIMEOUT.as_millis()
                                    ),
                                )));
                            }
                            session.closing = true;
                        }
                        // Still handshaking — no data-plane work yet.
                        return;
                    }
                }
            }

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
                        self.wake_notify.clone(),
                        self.budget_stall.clone(),
                        self.proxy_rt.clone(),
                    ) {
                        socket.abort();
                        session.closing = true;
                        return;
                    }
                    // The session just graduated out of the unverified
                    // class (spawn sets proxy_started). Disjoint field
                    // borrows: `session` borrows self.sessions while these
                    // counters are separate fields.
                    self.pre_proxy_sessions =
                        self.pre_proxy_sessions.saturating_sub(1);
                    if let Some(count) =
                        self.pre_proxy_per_ip.get_mut(&flow.peer_addr.ip())
                    {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            self.pre_proxy_per_ip.remove(&flow.peer_addr.ip());
                        }
                    }
                    #[cfg(target_os = "linux")]
                    publish_tcp_session_count(
                        &self.label,
                        sessions_len,
                        self.pre_proxy_sessions as u64,
                    );
                } else {
                    // A pre-proxy socket that reached a terminal state on
                    // its own (peer RST during the handshake) has no
                    // stream channels to drain — mark it closing so the
                    // sweep reaps it on cadence instead of billing the
                    // session table slot until the pre-proxy idle timeout.
                    if matches!(
                        socket.state(),
                        SmoltcpTcp::State::Closed | SmoltcpTcp::State::TimeWait
                    ) {
                        session.closing = true;
                    }
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

            // T9: the peer had ≥ half our advertised window in flight when
            // this pump ran — the window is the constraint. Captured before
            // the drain loop empties the buffer (post-drain occupancy is
            // always ~0 and would hide the signal).
            let rx_fill = socket.recv_queue() * 2 >= socket.recv_capacity();
            // T9: per-session held-charge cap — a session already holding
            // its fair share of drained-but-unconsumed bytes (stream
            // channel residency + pending chunk) stops pulling more out
            // of the socket. Data then stays in the already-charged
            // socket buffer, the advertised window closes, and TCP flow
            // control paces the sender to the consumer's rate. Without
            // this, ~140 busy sessions × channel backlog saturated the
            // queue ledger outright — measured live at 194 MiB pinned.
            let drain_cap =
                tcp_buffer_pool_budget() / (live_sessions.max(1) * 2);
            while socket.can_recv() {
                // EN-17/F3: reserve queue bytes BEFORE consuming the socket
                // buffer — `recv` is destructive, so a budget failure after
                // the copy would leave the payload uncharged. On refusal the
                // bytes stay in smoltcp's buffer (window shrinks → peer
                // backs off); the session parks in `ingress_stalled` and is
                // re-marked hot once the ledger frees.
                // T9: channel occupancy is re-read every iteration — it
                // shrinks as this loop pushes chunks in.
                let channel_held = session
                    .ingress_tx
                    .as_ref()
                    .map(|tx| {
                        AF_XDP_TCP_STREAM_CHANNEL_DEPTH
                            .saturating_sub(tx.capacity())
                            .saturating_mul(AF_XDP_TCP_RECV_SCRATCH_BYTES)
                            as u64
                    })
                    .unwrap_or(0);
                let session_held =
                    channel_held.saturating_add(session.pending_ingress.len() as u64);
                if session_held >= drain_cap {
                    // T9: fair-share park — consumer-bound, NOT a ledger
                    // refusal. A separate clock so the 10s zombie deadline
                    // can't kill a session whose reader is merely slow;
                    // `cap_parked_since` reaps only after 30s with zero
                    // channel progress (dead reader), and clears on any
                    // freed space — observed live as uploads dying at the
                    // 10s mark while the ledger still had room.
                    session.cap_parked_since = session.cap_parked_since.or(Some(now));
                    #[cfg(target_os = "linux")]
                    AF_XDP_TCP_DIAG_CAP_PARKS.fetch_add(1, Ordering::Relaxed);
                    self.ingress_stalled.insert(flow);
                    break;
                }
                // Space below the cap is consumer progress — any parked
                // clock resets here, even if the socket then has nothing
                // to drain this round.
                session.cap_parked_since = None;
                let want = socket.recv_queue().min(AF_XDP_TCP_RECV_SCRATCH_BYTES);
                if want == 0 {
                    break;
                }
                let Some(charge) = MEMORY_GOVERNOR.try_reserve_tcp_queue_bytes(want) else {
                    #[cfg(target_os = "linux")]
                    AF_XDP_TCP_DIAG_BUDGET_STALLS.fetch_add(1, Ordering::Relaxed);
                    // T9: keep the FIRST stall instant — the deadline
                    // measures cumulative time parked on the ledger, and
                    // a session flapping in/out of stall without ever
                    // draining is still a zombie.
                    session.stalled_since = session.stalled_since.or(Some(now));
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
                        // T9: a successful drain is real progress — both
                        // park clocks restart from here.
                        if session.stalled_since.is_some()
                            || session.cap_parked_since.is_some()
                        {
                            session.stalled_since = None;
                            session.cap_parked_since = None;
                            self.ingress_stalled.remove(&flow);
                        }
                        session.rx_growth_probe =
                            session.rx_growth_probe.saturating_add(n as u64);
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
            if session.egress_closed
                && session.pending_egress.is_empty()
                && socket.send_queue() == 0
            {
                socket.close();
                session.closing = true;
            }
            // T9: in-session window autotune. rx demand = either a
            // half-full queue at pump start (burst senders) OR ≥ half
            // the window drained since the last attempt (paced senders —
            // occupancy alone misses them because the drain loop keeps
            // the queue near zero even while the peer is window-bound).
            // tx demand = send queue ≥75% OR the producer still holds
            // unsent bytes (direct proof the buffer is the constraint).
            // Every grown byte is charged to the queue ledger; a refused
            // charge just keeps the current size — never a refusal
            // mid-connection.
            let rx_demand = rx_fill
                || session.rx_growth_probe.saturating_mul(2)
                    >= socket.recv_capacity() as u64;
            let tx_demand = socket.send_queue() * 4 >= socket.send_capacity() * 3
                || !session.pending_egress.is_empty();
            Self::grow_socket_buffers(socket, session, live_sessions, rx_demand, tx_demand, now);
            // A proxy-started socket that reached a terminal state on its
            // own (peer RST → Closed, or TimeWait drain finished) is dead
            // weight: it can neither receive nor send, so mark it closing
            // and let the sweep reap it on cadence instead of waiting out
            // the idle timeout. Reaping drops the stream channels, which
            // wakes a writer parked in `poll_write` with BrokenPipe — the
            // task, its upstream socket, and its permits release promptly.
            if matches!(
                socket.state(),
                SmoltcpTcp::State::Closed | SmoltcpTcp::State::TimeWait
            ) {
                session.closing = true;
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
        let mut shrink_candidates = Vec::new();
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
            // T9: a session parked on the queue ledger past the stall
            // deadline is a zombie — retransmissions keep refreshing
            // `last_activity` so the idle timeout below can never fire,
            // while its buffer permits pin the ledger for every other
            // session. Reap it outright; its permits and pending bytes
            // return to the budget on drop.
            if let Some(since) = session.stalled_since
                && !session.closing
                && session_idle_for(now, since) >= AF_XDP_TCP_BUDGET_STALL_DEADLINE
            {
                #[cfg(target_os = "linux")]
                AF_XDP_TCP_DIAG_STALL_REAPED.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    "AF_XDP TCP reactor reaping budget-stalled session local={} peer={} stall_ms={} deadline_ms={}",
                    flow.local_addr,
                    flow.peer_addr,
                    session_idle_for(now, since).as_millis(),
                    AF_XDP_TCP_BUDGET_STALL_DEADLINE.as_millis()
                );
                finished.push(*flow);
                continue;
            }
            // T9: parked on the fair-share drain cap with zero consumer
            // progress for the whole deadline — the reader (proxy task or
            // dialed-leg forwarder) is dead while peer traffic keeps
            // `last_activity` fresh. Same zombie shape as the ledger
            // stall above, just slower-burning because the parked bytes
            // are already bounded.
            if let Some(since) = session.cap_parked_since
                && !session.closing
                && session_idle_for(now, since) >= AF_XDP_TCP_CAP_PARK_DEADLINE
            {
                #[cfg(target_os = "linux")]
                AF_XDP_TCP_DIAG_CAP_REAPED.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    "AF_XDP TCP reactor reaping cap-parked session local={} peer={} parked_ms={} deadline_ms={}",
                    flow.local_addr,
                    flow.peer_addr,
                    session_idle_for(now, since).as_millis(),
                    AF_XDP_TCP_CAP_PARK_DEADLINE.as_millis()
                );
                finished.push(*flow);
                continue;
            }
            // T9: idle session holding grown buffers — return them to the
            // ledger now instead of at reap time. Requires every queue
            // stage empty so the resize can land at the admission floor
            // and the whole growth-permit stack unwinds exactly.
            if !session.closing
                && session.socket_buf_permits.len() > 1
                && socket.recv_queue() == 0
                && socket.send_queue() == 0
                && session.pending_ingress.is_empty()
                && session.pending_egress.is_empty()
                && session
                    .ingress_tx
                    .as_ref()
                    .is_none_or(|tx| tx.capacity() == AF_XDP_TCP_STREAM_CHANNEL_DEPTH)
                && idle_for >= AF_XDP_TCP_IDLE_SHRINK_AFTER
            {
                shrink_candidates.push(*flow);
            }
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
            } else if session.closing && idle_for >= AF_XDP_TCP_CLOSING_REAP_AFTER {
                // The close handshake stalled — FIN-WAIT-2 has no protocol
                // timeout, so a silent peer would pin the session's buffer
                // permits forever. Force-reap; the removal path aborts the
                // socket (RST) so nothing dangles kernel-side either.
                tracing::debug!(
                    "AF_XDP TCP reactor reaping stalled closing session local={} peer={} state={} idle_ms={}",
                    session.flow.local_addr,
                    session.flow.peer_addr,
                    socket.state(),
                    idle_for.as_millis()
                );
                finished.push(*flow);
            } else if af_xdp_tcp_session_reapable(session.closing, socket.state()) {
                finished.push(*flow);
            }
        }
        let pre_proxy_timed_out: std::collections::HashSet<AfXdpTcpFlowKey> =
            pre_proxy_timeouts.iter().map(|(f, ..)| *f).collect();
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
            #[cfg(target_os = "linux")]
            self.drop_session_snapshot(&flow);
            if let Some(mut session) = self.sessions.remove(&flow) {
                if !session.proxy_started && !session.dialed {
                    self.note_pre_proxy_departed(flow.peer_addr.ip());
                }
                self.publish_session_gauges();
                if session.dialed {
                    // T4: every terminal reap of a dialed flow releases
                    // its registry state (source port, demux entry,
                    // XDP_OUT_CT row); a still-pending dial is failed
                    // explicitly rather than left to time out.
                    if let Some(reply) = session.dial_reply.take() {
                        let _ = reply.send(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            format!(
                                "AF_XDP dial {} -> {} aborted during handshake",
                                flow.local_addr, flow.peer_addr
                            ),
                        )));
                    }
                    #[cfg(target_os = "linux")]
                    if let Some(registry) = self.dial_registry.clone() {
                        registry.release(&flow);
                    }
                }
                // T6 inputs are cloned before the socket borrow so the
                // path-table write does not tangle the borrow graph.
                let path_table = std::rc::Rc::clone(&self.path_table);
                let clock_us = self.clock.now_micros();
                let socket = self
                    .sockets
                    .get_mut::<SmoltcpTcp::Socket<'static>>(session.socket);
                // T6: fold the closed flow's transport evidence into the
                // worker-local path table before the socket drops.
                if let Some(snap) = socket.transport_snapshot() {
                    let failed = pre_proxy_timed_out.contains(&flow);
                    Self::record_path_sample(
                        &path_table,
                        clock_us,
                        flow.peer_addr.ip(),
                        flow.local_addr.ip(),
                        &snap,
                        failed,
                    );
                }
                // T1: final transport snapshot to tracing — per-session
                // lifecycle is observable even when the flow was never
                // scraped through /status.
                tracing::debug!(
                    "AF_XDP TCP session reaped iface_queue={} local={} peer={} class={} state={} cc={:?} send_queue={} recv_queue={} proxy_started={} buf_charge={}",
                    self.label,
                    session.flow.local_addr,
                    session.flow.peer_addr,
                    session.proxy_class.label(),
                    socket.state(),
                    socket.congestion_control(),
                    socket.send_queue(),
                    socket.recv_queue(),
                    session.proxy_started,
                    session.socket_buf_charge_bytes(),
                );
                socket.abort();
                let _ = self.sockets.remove(session.socket);
            }
        }
        // T9: return grown buffers of idle sessions. Runs after `finished`
        // so reaped flows are already gone (`get_mut` misses them). The
        // candidate filter above guaranteed empty queues and an idle gap,
        // so `resize` down to the admission floor cannot lose data; only
        // when BOTH buffers sit at/below the floor do we unwind the whole
        // growth-permit stack — partial failure leaves permits held, which
        // keeps charge ≥ capacity (the safe direction).
        for flow in shrink_candidates {
            let Some(session) = self.sessions.get_mut(&flow) else {
                continue;
            };
            let floor = session.socket_buf_floor_bytes;
            let socket = self
                .sockets
                .get_mut::<SmoltcpTcp::Socket<'static>>(session.socket);
            if socket.recv_capacity() > floor {
                socket.grow_recv_buffer(floor);
            }
            if socket.send_capacity() > floor {
                socket.grow_send_buffer(floor);
            }
            if socket.recv_capacity() <= floor && socket.send_capacity() <= floor {
                session.socket_buf_permits.truncate(1);
                #[cfg(target_os = "linux")]
                AF_XDP_TCP_DIAG_BUFFER_SHRINKS.fetch_add(1, Ordering::Relaxed);
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
        // Session occupancy is its own pressure channel: the shared L4
        // ladder is computed from connection-admission bytes, kernel SYN
        // backlog and fd usage — none of which see the smoltcp session
        // table. Without this feed the table could fill to the refusal
        // limit while pressure stayed Normal, so the timeout ladder and
        // pre-proxy budget never tightened before capacity ran out.
        self.cached_pressure_level = crate::l4_defense::current_pressure_level()
            .max(af_xdp_session_occupancy_pressure_level(
                self.sessions.len(),
                self.session_limit,
            ));
        // Occupancy also tightens the established-session idle timeout:
        // a table under real pressure sheds its idlest verified sessions
        // first, so slow-drip keepalive traffic cannot hold the table.
        self.cached_proxy_idle_timeout = match self.cached_pressure_level {
            crate::l4_defense::L4PressureLevel::Critical => effective_af_xdp_tcp_idle_timeout()
                .min(Duration::from_secs(60)),
            crate::l4_defense::L4PressureLevel::High => effective_af_xdp_tcp_idle_timeout()
                .min(Duration::from_secs(120)),
            _ => effective_af_xdp_tcp_idle_timeout(),
        };
        self.idle_profile_refreshed_at = now;
    }
}

/// Session-table occupancy mapped onto the same 70/85/95 escalation
/// thresholds the shared utilization ladder uses. Kept separate from
/// `utilization_pressure_level_hysteretic` because that function owns
/// global hysteresis state for the byte-based connection signal.
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn af_xdp_session_occupancy_pressure_level(
    sessions: usize,
    session_limit: usize,
) -> crate::l4_defense::L4PressureLevel {
    let pct = (sessions as u64)
        .saturating_mul(100)
        .saturating_div(session_limit.max(1) as u64);
    if pct >= 95 {
        crate::l4_defense::L4PressureLevel::Critical
    } else if pct >= 85 {
        crate::l4_defense::L4PressureLevel::High
    } else if pct >= 70 {
        crate::l4_defense::L4PressureLevel::Elevated
    } else {
        crate::l4_defense::L4PressureLevel::Normal
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
    // CloseWait is the peer's FIN: no further inbound data can arrive, so
    // the stream's read side must observe EOF even though our send half is
    // still open. Without it a graceful peer close parks `poll_read`
    // forever — the relay task, its upstream socket, and every admission
    // permit it holds leak until the idle reaper runs (observed: sessions
    // stuck in CLOSE-WAIT wedged the node at the fd-derived limit).
    matches!(
        state,
        SmoltcpTcp::State::CloseWait
            | SmoltcpTcp::State::Closing
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

/// T9: the share of the TCP queue budget that socket-buffer reservations
/// may aim at — ⅞ of the total. The remaining ⅛ is standing headroom for
/// in-flight byte charges (the drain loop) and new-session minimum
/// buffers: buffer growth that could starve data movement or admissions
/// would be refused by the ledger anyway, but the discounted pool makes
/// those refusals rare instead of routine. A fraction (not flat) reserve
/// scales with the now-dynamic queue budget — ~32 MiB headroom at
/// ~260 MiB, still ~2 MiB at the 16 MiB floor.
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn tcp_buffer_pool_budget() -> u64 {
    MEMORY_GOVERNOR
        .tcp_queue_bytes_budget()
        .saturating_mul(7)
        / 8
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

/// Spawn a per-session proxy task on the production runtime when one is
/// installed, else on the ambient context (`#[tokio::test]` resolve).
/// The reactor's current-thread runtime must never host these — one TLS
/// handshake's synchronous crypto would stall every session's timers.
#[cfg(any(test, target_os = "linux"))]
fn spawn_session_task<F>(rt: &Option<tokio::runtime::Handle>, fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    match rt {
        Some(rt) => drop(rt.spawn(fut)),
        None => drop(tokio::spawn(fut)),
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

/// F1: worker liveness gate. Polling continues while the dataplane lease
/// is alive and its *current owner* manager has redirect armed — manager
/// replacement under an adopted dataplane never stops a worker that still
/// owns live sessions.
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn proxy_bridge_should_continue(
    lease: &crate::xdp::AfXdpDataplaneLease,
) -> bool {
    if lease.is_retired() {
        return false;
    }
    let owner = lease.owner();
    !owner.attached.read().is_empty()
        && (owner.proxy_redirect_ready() || owner.proxy_workers_starting())
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
                wake_notify: None,
                budget_stall: budget_stall.clone(),
                read_buf: AfXdpTcpChargedBytes::empty(),
                write_permit: None,
                flow: None,
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
        parts.stream.flow = Some(flow);
        parts
    }

    /// Local endpoint of the underlying flow — dialed streams report the
    /// allocated reserved-range source port.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.flow.map(|flow| flow.local_addr).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "AF_XDP stream has no flow endpoints")
        })
    }

    /// Remote endpoint of the underlying flow — for dialed streams this
    /// is the upstream server.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.flow.map(|flow| flow.peer_addr).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "AF_XDP stream has no flow endpoints")
        })
    }

    pub fn default_channel_pair() -> AfXdpTcpStreamParts {
        Self::channel_pair(AF_XDP_TCP_STREAM_CHANNEL_DEPTH)
    }

    /// Attach the reactor's wake notify — `signal_wake` then also
    /// interrupts the reactor's event-driven idle wait instead of only
    /// being noticed at the next poll round.
    #[cfg(any(test, target_os = "linux"))]
    pub(crate) fn set_wake_notify(&mut self, notify: Arc<tokio::sync::Notify>) {
        self.wake_notify = Some(notify);
    }

    /// Mark this flow dirty for the reactor. Insert is lossless and dedup'd
    /// by the map — a second mark while the entry is still pending costs
    /// nothing and nothing can be dropped.
    fn signal_wake(&self) {
        if let Some((flow, set)) = &self.wake {
            set.insert(*flow, ());
        }
        if let Some(notify) = &self.wake_notify {
            notify.notify_one();
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
                    // The freed channel slot is the pending-ingress
                    // producer's retry signal — parked sessions are only
                    // re-marked on wakes, packets or the 250ms sweep.
                    self.signal_wake();
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
            AF_XDP_TCP_DIAG_WRITE_STALLS.fetch_add(1, Ordering::Relaxed);
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

/// T1: a dying reactor purges its /status snapshot rows — a dead queue's
/// sessions must never linger in the export.
#[cfg(target_os = "linux")]
impl Drop for AfXdpTcpReactor {
    fn drop(&mut self) {
        purge_tcp_session_snapshots(&self.label);
        remove_tcp_session_count(&self.label);
        // T4: reactor teardown fails every unresolved dial and releases
        // each dialed flow's registry state — no source port, demux
        // entry, or XDP_OUT_CT row may outlive its owner.
        let registry = self.dial_registry.clone();
        for (flow, session) in self.sessions.iter_mut() {
            if !session.dialed {
                continue;
            }
            if let Some(reply) = session.dial_reply.take() {
                let _ = reply.send(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!(
                        "AF_XDP reactor {} shut down during dial {} -> {}",
                        self.label, flow.local_addr, flow.peer_addr
                    ),
                )));
            }
            if let Some(registry) = &registry {
                registry.release(flow);
            }
        }
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
