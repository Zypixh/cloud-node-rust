use super::*;

#[derive(Clone, Debug, Default)]
pub struct AfXdpRuntime {
    pub enabled: bool,
    pub ready: bool,
    pub detail: String,
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone)]
pub(crate) struct AfXdpUdpRouteEntry {
    pub(crate) route: AfXdpRouteMeta,
    pub(crate) last_seen_ms: u64,
}

/// Cross-interface forwarding between per-queue reactor threads. TX on any
/// queue of the same interface delivers identically, so forwarding is only
/// needed when a flow's L2 route resolves to a different interface than the
/// draining thread owns.
#[cfg(target_os = "linux")]
pub(crate) enum AfXdpForward {
    Udp(crate::udp_proxy::DownstreamUdpDatagram),
    TcpFrame(Vec<u8>),
}

/// T8: bounded TX deferral. A TX-ring-full frame is deferred to the next
/// loop round instead of dropped on the floor; only a *full* retry queue
/// sheds — counted explicitly, never silent. `Bytes` keeps a deferred UDP
/// payload refcounted (no copy).
#[cfg(target_os = "linux")]
pub(crate) enum PendingTxKind {
    Udp {
        link: AfXdpLinkMeta,
        listen_addr: SocketAddr,
        peer_addr: SocketAddr,
        payload: bytes::Bytes,
        ecn: Option<u8>,
    },
    /// Already-encoded L2 frame (TCP egress / cross-interface forward).
    Frame(Vec<u8>),
}

/// T8/T9: a deferred TX unit with scheduler metadata. `flow`/`tier` feed
/// the tiered-DRR `Scheduler`; `ecn` + `enqueued_us` feed the real-queue
/// CoDel AQM (sojourn measured dequeue-side, RFC 8289).
#[cfg(target_os = "linux")]
pub(crate) struct PendingTx {
    flow: u64,
    tier: u8,
    ecn: u8,
    enqueued_us: u64,
    kind: PendingTxKind,
}

#[cfg(target_os = "linux")]
impl PendingTx {
    fn udp(
        link: AfXdpLinkMeta,
        listen_addr: SocketAddr,
        peer_addr: SocketAddr,
        payload: bytes::Bytes,
        ecn: Option<u8>,
        now_us: u64,
    ) -> Self {
        Self {
            flow: udp_flow_hash(&listen_addr, &peer_addr),
            tier: 1,
            ecn: ecn.unwrap_or(0),
            enqueued_us: now_us,
            kind: PendingTxKind::Udp {
                link,
                listen_addr,
                peer_addr,
                payload,
                ecn,
            },
        }
    }

    fn frame(frame: Vec<u8>, now_us: u64) -> Self {
        let (flow, tier, ecn) = frame_sched_meta(&frame);
        Self {
            flow,
            tier,
            ecn,
            enqueued_us: now_us,
            kind: PendingTxKind::Frame(frame),
        }
    }

    fn len(&self) -> u64 {
        match &self.kind {
            PendingTxKind::Udp { payload, .. } => payload.len() as u64,
            PendingTxKind::Frame(f) => f.len() as u64,
        }
    }

    /// T9/D-AQM: apply a CE mark in place. UDP datagrams carry their ECN
    /// codepoint as metadata — set it before encode. Pre-encoded frames
    /// get their IP header rewritten (+ v4 checksum fix). Returns false
    /// when the unit cannot be marked (Not-ECT or unparseable).
    fn mark_ce(&mut self) -> bool {
        match &mut self.kind {
            PendingTxKind::Udp { ecn, .. } => match *ecn {
                Some(0b01) | Some(0b10) => {
                    *ecn = Some(0b11);
                    true
                }
                _ => false,
            },
            PendingTxKind::Frame(f) => frame_mark_ce(f),
        }
    }
}

/// T8: per-worker TX retry capacity — 64 × ≤2KiB ≈ 128KiB worst case,
/// worker-local, never cross-thread.
#[cfg(target_os = "linux")]
const AF_XDP_TX_RETRY_CAP: usize = 64;

/// CAKE-style per-frame overhead charged to the egress token bucket
/// (Ethernet preamble+IFG+header+FCS ≈ 38B).
#[cfg(target_os = "linux")]
const AF_XDP_EGRESS_OVERHEAD_BYTES: u64 = 38;

/// FNV-1a over (proto, src, dst, ports) — the scheduler's flow key.
#[cfg(target_os = "linux")]
fn fnv1a(flow: u64, bytes: &[u8]) -> u64 {
    let mut h = flow;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[cfg(target_os = "linux")]
fn udp_flow_hash(listen_addr: &SocketAddr, peer_addr: &SocketAddr) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    h = fnv1a(h, &[17]);
    match (listen_addr, peer_addr) {
        (SocketAddr::V4(l), SocketAddr::V4(p)) => {
            h = fnv1a(h, &l.ip().octets());
            h = fnv1a(h, &p.ip().octets());
        }
        (SocketAddr::V6(l), SocketAddr::V6(p)) => {
            h = fnv1a(h, &l.ip().octets());
            h = fnv1a(h, &p.ip().octets());
        }
        _ => {}
    }
    h = fnv1a(h, &listen_addr.port().to_be_bytes());
    fnv1a(h, &peer_addr.port().to_be_bytes())
}

/// Parse an already-encoded egress frame for scheduling metadata:
/// `(flow, tier, ecn)`. Tier 0 = TCP control (zero payload — ACK/RST/
/// FIN/SYN retransmit protection), tier 1 = data. Unparseable frames
/// (extension headers, non-TCP/UDP) group under flow 0/tier 1 — they are
/// still sent, just without per-flow fairness metadata.
#[cfg(target_os = "linux")]
fn frame_sched_meta(frame: &[u8]) -> (u64, u8, u8) {
    let Some(l3) = frame_l3_offset(frame) else {
        return (0, 1, 0);
    };
    let ethertype = u16::from_be_bytes([frame[l3 - 2], frame[l3 - 1]]);
    let (proto, l4, l4_total, src, dst): (u8, usize, usize, &[u8], &[u8]) = match ethertype {
        0x0800 => {
            let Some(ip) = frame.get(l3..) else {
                return (0, 1, 0);
            };
            let ihl = usize::from(ip[0] & 0x0f) * 4;
            if ihl < 20 || ip.len() < ihl {
                return (0, 1, 0);
            }
            let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
            (
                ip[9],
                l3 + ihl,
                total.saturating_sub(ihl),
                &frame[l3 + 12..l3 + 16],
                &frame[l3 + 16..l3 + 20],
            )
        }
        0x86dd => {
            let Some(ip) = frame.get(l3..) else {
                return (0, 1, 0);
            };
            if ip.len() < 40 {
                return (0, 1, 0);
            }
            // Extension headers are not walked — those frames group
            // under the default flow rather than being misparsed.
            let proto = ip[6];
            if !matches!(proto, 6 | 17) {
                return (0, 1, 0);
            }
            let plen = usize::from(u16::from_be_bytes([ip[4], ip[5]]));
            (
                proto,
                l3 + 40,
                plen,
                &frame[l3 + 8..l3 + 24],
                &frame[l3 + 24..l3 + 40],
            )
        }
        _ => return (0, 1, 0),
    };
    let ecn = match ethertype {
        0x0800 => frame[l3 + 1] & 0b11,
        _ => (frame[l3 + 1] >> 4) & 0b11,
    };
    let Some(seg) = frame.get(l4..l4 + 4) else {
        return (0, 1, 0);
    };
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    h = fnv1a(h, &[proto]);
    h = fnv1a(h, src);
    h = fnv1a(h, dst);
    h = fnv1a(h, seg);
    let tier = if proto == 6 {
        match frame.get(l4 + 12) {
            Some(&off_flags) => {
                let tcp_hlen = usize::from(off_flags >> 4) * 4;
                if tcp_hlen >= 20 && l4_total <= tcp_hlen {
                    0 // no payload → control segment
                } else {
                    1
                }
            }
            None => 1,
        }
    } else {
        1
    };
    (h, tier, ecn)
}

/// Locate the L3 header offset past Ethernet (+ any VLAN/QinQ tags).
/// Returns None when the frame is too short or not IPv4/IPv6.
#[cfg(target_os = "linux")]
fn frame_l3_offset(frame: &[u8]) -> Option<usize> {
    if frame.len() < 14 {
        return None;
    }
    let mut l3 = 14usize;
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
        if frame.len() < l3 + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[l3 + 2], frame[l3 + 3]]);
        l3 += 4;
    }
    matches!(ethertype, 0x0800 | 0x86dd).then_some(l3)
}

/// T9/D-AQM: mark CE on an already-encoded frame's IP header. Only ECT
/// frames are marked (RFC 3168); IPv4 header checksum is recomputed
/// incrementally per RFC 1624. Returns false for Not-ECT/unparseable.
#[cfg(target_os = "linux")]
fn frame_mark_ce(frame: &mut [u8]) -> bool {
    let Some(l3) = frame_l3_offset(frame) else {
        return false;
    };
    let ethertype = u16::from_be_bytes([frame[l3 - 2], frame[l3 - 1]]);
    match ethertype {
        0x0800 => {
            let ihl = usize::from(frame[l3] & 0x0f) * 4;
            if ihl < 20 || frame.len() < l3 + ihl {
                return false;
            }
            let tos = frame[l3 + 1];
            if !matches!(tos & 0b11, 0b01 | 0b10) {
                return false; // Not-ECT or already CE — not markable
            }
            let new_tos = tos | 0b11;
            frame[l3 + 1] = new_tos;
            // RFC 1624/1141 incremental update on the stored checksum:
            // HC' = ~( ~HC + ~m + m' ) with end-around carry, where m/m'
            // are the 16-bit word containing the TOS byte (low byte of
            // the ver_ihl/TOS word).
            let word_old = u32::from(u16::from_be_bytes([frame[l3], tos]));
            let word_new = u32::from(u16::from_be_bytes([frame[l3], new_tos]));
            let hc = u32::from(u16::from_be_bytes([frame[l3 + 10], frame[l3 + 11]]));
            let mut sum = (!hc & 0xffff) + (!word_old & 0xffff) + word_new;
            sum = (sum & 0xffff) + (sum >> 16);
            sum = (sum & 0xffff) + (sum >> 16);
            let hc_new = !sum & 0xffff;
            frame[l3 + 10..l3 + 12].copy_from_slice(&(hc_new as u16).to_be_bytes());
            true
        }
        0x86dd => {
            if frame.len() < l3 + 40 {
                return false;
            }
            let ecn = (frame[l3 + 1] >> 4) & 0b11;
            if !matches!(ecn, 0b01 | 0b10) {
                return false;
            }
            frame[l3 + 1] |= 0b11 << 4;
            true
        }
        _ => false,
    }
}

/// T8: push a deferred frame into the bounded per-flow retry store and
/// register it with the scheduler (due = now → immediately eligible).
/// Returns false when the queue is full — the only shed point, and it is
/// counted by the caller (`congested_drops`), never silent.
#[cfg(target_os = "linux")]
fn queue_deferred_tx(
    pending: &mut std::collections::HashMap<u64, std::collections::VecDeque<PendingTx>>,
    total: &mut usize,
    sched: &mut cloud_node_transport::sched::Scheduler,
    now: cloud_node_transport::TransportInstant,
    p: PendingTx,
) -> bool {
    if *total >= AF_XDP_TX_RETRY_CAP {
        return false;
    }
    sched.schedule(p.flow, p.tier, now);
    pending.entry(p.flow).or_default().push_back(p);
    *total += 1;
    true
}

/// T8: send one deferred entry — same semantics as the live paths.
#[cfg(target_os = "linux")]
fn send_pending_tx(
    queue_handle: &mut linux::AfXdpQueueHandle,
    p: &mut PendingTx,
) -> anyhow::Result<bool> {
    match &mut p.kind {
        PendingTxKind::Frame(frame) => queue_handle.send_raw_frame(frame),
        PendingTxKind::Udp {
            link,
            listen_addr,
            peer_addr,
            payload,
            ecn,
        } => queue_handle.send_udp_datagram(link, *listen_addr, *peer_addr, payload, *ecn),
    }
}

/// Per-queue reactor context shared at spawn time.
#[cfg(target_os = "linux")]
pub(crate) struct AfXdpQueueCtx {
    pub(crate) downstream_tx: mpsc::Sender<crate::udp_proxy::DownstreamUdpDatagram>,
    pub(crate) downstream_rx: mpsc::Receiver<crate::udp_proxy::DownstreamUdpDatagram>,
    pub(crate) fwd_rx: mpsc::Receiver<AfXdpForward>,
    /// T4: dial requests and cross-queue reply injects for this queue's
    /// TCP reactor — drained once per poll round under a bounded budget.
    pub(crate) request_rx: mpsc::Receiver<AfXdpReactorRequest>,
    /// T4: shared dial registry — reply demux lookups plus the reactor's
    /// release-on-reap hook.
    pub(crate) dial_registry: Arc<AfXdpDialRegistry>,
    /// Route cache shared by all queue threads: ingress on queue A may be
    /// answered by the demux/H3 endpoint on queue B's channel, so lookups
    /// must see every queue's learned L2 routes.
    pub(crate) udp_routes: Arc<DashMap<(SocketAddr, SocketAddr), AfXdpUdpRouteEntry>>,
    /// First channel per interface for cross-interface forwarding.
    pub(crate) iface_fwd: Arc<HashMap<String, mpsc::Sender<AfXdpForward>>>,
    /// F1: dataplane lease — workers gate on this, never on manager
    /// staleness, so a compatible reload keeps sessions polling while the
    /// manager generation changes underneath them.
    pub(crate) lease: Arc<crate::xdp::AfXdpDataplaneLease>,
    /// T8 (D-G2): this worker's share of `xdp.egressRateBps`. `None` =
    /// no shaping (configured budget split evenly across workers).
    pub(crate) egress_rate_bps: Option<u64>,
}

pub fn runtime() -> AfXdpRuntime {
    let status = status_snapshot();
    AfXdpRuntime {
        enabled: status.enabled,
        ready: status.available
            && status
                .interfaces
                .iter()
                .any(|interface| interface.mode == "proxy" && interface.xsk_ready),
        detail: status.fallback_reason,
    }
}

pub async fn start_proxy_bridge(
    quic_demux: Arc<crate::quic_udp_demux::QuicUdpDemuxManager>,
    tcp_manager: Arc<crate::tcp_proxy::TcpProxyManager>,
    http_manager: Arc<crate::http_proxy_manager::HttpProxyManager>,
) {
    start_proxy_bridge_inner(quic_demux, Some(tcp_manager), Some(http_manager)).await;
}

pub(crate) async fn start_proxy_bridge_inner(
    quic_demux: Arc<crate::quic_udp_demux::QuicUdpDemuxManager>,
    tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
    http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
) {
    let manager = manager_from_runtime();
    if !XDP_PROXY_DATAPLANE_ACTIVE {
        manager.set_proxy_fallback_reason(
            "AF_XDP UDP bridge is compiled but TX dataplane is not active; traffic will PASS",
        );
        return;
    }
    #[cfg(target_os = "linux")]
    {
        // EN-12: supervise the bridge across manager generations. A config
        // reload detaches the old manager — its workers exit on the stale
        // check — and the replacement manager owns fresh sockets that still
        // need a bridge. Respawn only when the manager changed: a bridge
        // dying under a still-current manager is a recorded hard failure,
        // not a reason to hot-loop restarts.
        let mut served = manager;
        loop {
            if served.config.enabled {
                run_proxy_bridge(
                    served.clone(),
                    quic_demux.clone(),
                    tcp_manager.clone(),
                    http_manager.clone(),
                )
                .await;
                if manager_is_current(&served) {
                    // The bridge stopped while its manager is still
                    // current: the failure path already recorded an
                    // explicit fallback reason. Do not hot-respawn.
                    return;
                }
            }
            // Disabled or stale manager: wait for the next generation to
            // become current and finish attaching (its AF_XDP runtime is
            // only populated by `initialize`), then serve it. Poll —
            // manager identity changes are rare and the gap between
            // generations is transient.
            loop {
                tokio::time::sleep(Duration::from_millis(200)).await;
                let current = manager_from_runtime();
                if !Arc::ptr_eq(&current, &served) {
                    served = current;
                }
                // Serve the generation once `initialize` has finished its
                // AF_XDP setup (or skip waiting while XDP is disabled or
                // has no proxy interfaces). `af_xdp` is populated by
                // `configure_af_xdp_runtime` — success *or* recorded
                // per-queue failure — so this gate never waits forever on
                // a failed setup.
                let proxy_ifaces = served
                    .config
                    .interfaces
                    .iter()
                    .any(|interface| interface.mode == XdpRuntimeMode::Proxy);
                let attached = !served.attached.read().is_empty();
                let af_xdp_settled = !proxy_ifaces
                    || served.af_xdp.lock().is_some()
                    || !served.xsk_status.read().is_empty();
                if !served.config.enabled || (attached && af_xdp_settled) {
                    break;
                }
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = quic_demux;
        let _ = tcp_manager;
        let _ = http_manager;
        manager.set_proxy_fallback_reason("AF_XDP proxy bridge is supported on Linux only");
    }
}

#[allow(dead_code)]
pub async fn start_udp_bridge(quic_demux: Arc<crate::quic_udp_demux::QuicUdpDemuxManager>) {
    start_proxy_bridge_inner(quic_demux, None, None).await;
}

#[cfg(target_os = "linux")]
pub(crate) fn pin_current_thread_to_cpu(cpu: u32) -> bool {
    // SAFETY: `set` is zeroed before CPU_SET marks exactly one bit; pid 0
    // targets the calling thread. cpu_set_t is a plain bitmask with no
    // pointers.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu as usize, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) == 0
    }
}

/// Resolve the CPU a queue reactor should pin to: explicit `cpus[]` entry
/// aligned with `queues[]`, else round-robin the global queue ordinal over
/// online CPUs.
#[cfg(target_os = "linux")]
pub(crate) fn af_xdp_queue_cpu(
    config: &XdpConfig,
    interface: &str,
    queue: u32,
    ordinal: usize,
    online_cpus: usize,
) -> u32 {
    if let Some(cfg) = config
        .interfaces
        .iter()
        .find(|interface_cfg| interface_cfg.name == interface)
        && let Some(position) = cfg.queues.iter().position(|candidate| *candidate == queue)
        && let Some(cpu) = cfg.cpus.get(position)
    {
        return *cpu;
    }
    (ordinal % online_cpus.max(1)) as u32
}

#[cfg(target_os = "linux")]
pub(crate) async fn run_proxy_bridge(
    manager: Arc<XdpManager>,
    quic_demux: Arc<crate::quic_udp_demux::QuicUdpDemuxManager>,
    tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
    http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
) {
    // Per-queue reactor threads: each AF_XDP queue is owned by a dedicated
    // CPU-pinned OS thread running an isolated smoltcp reactor. The shared
    // af_xdp mutex and single poll loop are removed from the dataplane;
    // RSS flow-to-queue affinity keeps flows on one reactor.
    let mut queue_handles = {
        let mut runtime = manager.af_xdp.lock();
        match runtime.as_mut() {
            Some(runtime) => runtime.take_queues(),
            None => {
                manager.set_proxy_fallback_reason(
                    "AF_XDP proxy bridge cannot start; AF_XDP runtime is not initialized",
                );
                return;
            }
        }
    };
    if queue_handles.is_empty() {
        // F1: an adopted runtime has no queues left — they are owned by the
        // still-running workers of the previous generation. A retired lease
        // means those workers exited; rebuild a fresh socket set so a dead
        // dataplane recovers instead of reporting a permanent fallback.
        let retired = manager
            .af_xdp
            .lock()
            .as_ref()
            .and_then(|runtime| runtime.lease.as_ref().map(|lease| lease.is_retired()))
            .unwrap_or(false);
        if retired {
            *manager.af_xdp.lock() = None;
            if let Err(err) = manager.configure_af_xdp_runtime() {
                manager.set_proxy_fallback_reason(format!(
                    "AF_XDP dataplane rebuild after worker loss failed: {err}; traffic will PASS"
                ));
                return;
            }
            queue_handles = {
                let mut runtime = manager.af_xdp.lock();
                match runtime.as_mut() {
                    Some(runtime) => runtime.take_queues(),
                    None => Vec::new(),
                }
            };
        }
    }
    if queue_handles.is_empty() {
        // F1: an adopted runtime whose lease is still live means the
        // previous generation's workers own the dataplane — this manager
        // must not spawn duplicates or touch redirect state.
        let lease_live = manager
            .af_xdp
            .lock()
            .as_ref()
            .and_then(|runtime| runtime.lease.as_ref().map(|lease| !lease.is_retired()))
            .unwrap_or(false);
        if lease_live {
            tracing::debug!(
                "AF_XDP proxy bridge: dataplane adopted by this generation; workers still running"
            );
            return;
        }
        let message =
            "AF_XDP proxy bridge has no AF_XDP queues; proxy redirect disabled, traffic will PASS"
                .to_string();
        tracing::warn!("{message}");
        manager.disable_proxy_redirect_for_fallback(message);
        return;
    }
    // F1: the dataplane lease outlives the manager that spawned it —
    // workers gate on the lease, and a compatible reload repoints the
    // lease owner instead of stopping the polling loops.
    let lease = {
        let mut runtime = manager.af_xdp.lock();
        let lease = match runtime.as_mut() {
            Some(runtime) => match &runtime.lease {
                Some(lease) => lease.clone(),
                None => {
                    let lease = Arc::new(crate::xdp::AfXdpDataplaneLease::new(manager.clone()));
                    runtime.lease = Some(lease.clone());
                    lease
                }
            },
            None => Arc::new(crate::xdp::AfXdpDataplaneLease::new(manager.clone())),
        };
        lease
    };
    // EN-12 worker lease: prove every reactor is running *before* opening
    // redirect — a registered XSK is a socket, not a worker. Redirecting
    // into an XSK nobody drains would silently drop every proxied packet.
    spawn_queue_reactors(
        &manager,
        queue_handles,
        lease,
        quic_demux,
        tcp_manager,
        http_manager,
    )
    .await;
}

/// Spawn one pinned OS thread per AF_XDP queue, wait for every reactor to
/// signal it is processing-capable, and only then enable redirect. Any
/// reactor exiting while the bridge should still be alive disables proxy
/// redirect so traffic falls back to kernel listeners explicitly.
#[cfg(target_os = "linux")]
pub(crate) async fn spawn_queue_reactors(
    manager: &Arc<XdpManager>,
    queue_handles: Vec<linux::AfXdpQueueHandle>,
    lease: Arc<crate::xdp::AfXdpDataplaneLease>,
    quic_demux: Arc<crate::quic_udp_demux::QuicUdpDemuxManager>,
    tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
    http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
) {
    pub(crate) const AF_XDP_DOWNSTREAM_QUEUE: usize = 4096;
    pub(crate) const AF_XDP_WORKER_READY_TIMEOUT: Duration = Duration::from_secs(10);
    /// T4: per-queue dial/inject request channel depth — bounded like
    /// every other queue crossing so a dial burst or demux flood cannot
    /// grow memory unboundedly.
    pub(crate) const AF_XDP_REACTOR_REQUEST_QUEUE: usize = 1024;

    let online_cpus = num_cpus::get().max(1);
    let udp_routes = Arc::new(DashMap::new());
    // T4: one dial registry per bridge generation. Queues register their
    // request senders up-front so no dial window exists between redirect
    // opening and a queue becoming dialable.
    let dial_registry = Arc::new(AfXdpDialRegistry::new(manager.clone()));
    // One forwarding channel per queue; the first sender per interface is
    // the cross-interface forward target.
    let mut iface_fwd: HashMap<String, mpsc::Sender<AfXdpForward>> = HashMap::new();
    let mut contexts = Vec::with_capacity(queue_handles.len());
    for queue_handle in &queue_handles {
        let (downstream_tx, downstream_rx) =
            mpsc::channel::<crate::udp_proxy::DownstreamUdpDatagram>(
                AF_XDP_DOWNSTREAM_QUEUE,
            );
        let (fwd_tx, fwd_rx) = mpsc::channel::<AfXdpForward>(AF_XDP_DOWNSTREAM_QUEUE);
        let (request_tx, request_rx) =
            mpsc::channel::<AfXdpReactorRequest>(AF_XDP_REACTOR_REQUEST_QUEUE);
        dial_registry.register_queue(&queue_handle.interface, queue_handle.queue, request_tx);
        iface_fwd
            .entry(queue_handle.interface.clone())
            .or_insert(fwd_tx);
        contexts.push(AfXdpQueueCtx {
            downstream_tx,
            downstream_rx,
            fwd_rx,
            request_rx,
            dial_registry: dial_registry.clone(),
            udp_routes: udp_routes.clone(),
            iface_fwd: Arc::new(HashMap::new()),
            lease: lease.clone(),
            egress_rate_bps: None,
        });
    }
    // Publish only after every queue is registered — and only when the
    // upstream-dial feature is actually armed. `afxdp` mode requires the
    // T4-5 kernel guard to be installed first; a failed guard means the
    // registry is never published and `af_xdp_dial_tcp` errors explicitly
    // instead of dialing into an unguarded port span. `kernel` mode never
    // publishes — upstream dials keep the kernel connect() path.
    let dial_publishable =
        manager.config.upstream_mode() == crate::runtime_mode::XdpUpstreamMode::Afxdp;
    if dial_publishable {
        match manager.ensure_dial_guard().await {
            Ok(report) => {
                tracing::info!(
                    "AF_XDP dial guard installed: reserved ports {:?} pinned, nft DROP armed",
                    report.port_range
                );
                manager.set_dial_registry(Some(dial_registry.clone()));
            }
            Err(err) => {
                let detail = format!(
                    "xdp.upstream.mode=afxdp but dial guard install failed: {err}; \
                     AF_XDP upstream dials are disabled (kernel path is NOT used silently)"
                );
                tracing::error!("{detail}");
                manager.set_proxy_fallback_reason(detail);
            }
        }
    }
    let iface_fwd = Arc::new(iface_fwd);
    // T8 (D-G2): split the configured node egress budget evenly across
    // workers. Unconfigured → None → unshaped (无配置不整形).
    let egress_share = manager
        .config
        .egress_rate_bps
        .map(|rate| rate / contexts.len().max(1) as u64);
    for ctx in &mut contexts {
        ctx.iface_fwd = iface_fwd.clone();
        ctx.egress_rate_bps = egress_share;
    }
    // EN-12: the node-level TCP session budget is divided across queue
    // reactors — adding a queue must not multiply the whole-node session
    // quota. Floor of 1 keeps a degenerate config admitting at least one
    // session per reactor; the sum stays bounded by worker count.
    let per_queue_tcp_session_limit =
        af_xdp_tcp_session_limit_per_worker(af_xdp_tcp_session_limit(), queue_handles.len());
    let (ready_tx, mut ready_rx) = tokio::sync::mpsc::unbounded_channel::<(String, u32)>();
    manager.set_proxy_workers_starting(true);
    let mut joins: Vec<(String, u32, std::thread::JoinHandle<()>)> =
        Vec::with_capacity(queue_handles.len());
    for (ordinal, (queue_handle, ctx)) in queue_handles
        .into_iter()
        .zip(contexts.into_iter())
        .enumerate()
    {
        let cpu = af_xdp_queue_cpu(
            &manager.config,
            &queue_handle.interface,
            queue_handle.queue,
            ordinal,
            online_cpus,
        );
        let thread_name = format!("afxdp-{}-{}", queue_handle.interface, queue_handle.queue);
        let join_interface = queue_handle.interface.clone();
        let join_queue = queue_handle.queue;
        let reactor_manager = manager.clone();
        let quic_demux = quic_demux.clone();
        let tcp_manager = tcp_manager.clone();
        let http_manager = http_manager.clone();
        let ready = ready_tx.clone();
        let name = thread_name.clone();
        let worker_lease = ctx.lease.clone();
        worker_lease.worker_started();
        let join = match std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                if !pin_current_thread_to_cpu(cpu) {
                    tracing::warn!("{name}: failed to pin reactor thread to cpu {cpu}");
                }
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => {
                        // Worker lease: the reactor reports processing-capable
                        // only after its runtime exists and it is about to enter
                        // the poll loop. Redirect opens only after every queue
                        // has reported.
                        let _ = ready.send((queue_handle.interface.clone(), queue_handle.queue));
                        rt.block_on(run_queue_bridge_loop(
                            reactor_manager,
                            queue_handle,
                            ctx,
                            quic_demux,
                            tcp_manager,
                            http_manager,
                            per_queue_tcp_session_limit,
                        ));
                    }
                    Err(err) => {
                        tracing::error!("{name}: failed to build reactor runtime: {err}")
                    }
                }
                // Queue sockets drop with the ctx — bookkeeping for callers
                // that must not rebind the queue until it is provably free.
                worker_lease.worker_exited();
            }) {
            Ok(join) => join,
            Err(err) => {
                // The closure never ran — undo the worker_started above.
                lease.worker_exited();
                manager.disable_proxy_redirect_for_fallback(format!(
                    "AF_XDP proxy bridge failed to spawn reactor thread: {err}; proxy redirect disabled, traffic will PASS"
                ));
                for (_, _, join) in joins {
                    let _ = join.join();
                }
                return;
            }
        };
        joins.push((join_interface, join_queue, join));
    }
    drop(ready_tx);

    // Wait for every reactor to report ready before opening redirect.
    let expected = joins.len();
    let ready_wait = async {
        let mut seen = 0usize;
        while seen < expected {
            match ready_rx.recv().await {
                Some((interface, queue)) => {
                    seen += 1;
                    tracing::debug!(
                        "AF_XDP reactor ready interface={} queue={} ({seen}/{expected})",
                        interface,
                        queue
                    );
                }
                None => break,
            }
        }
        seen
    };
    match tokio::time::timeout(AF_XDP_WORKER_READY_TIMEOUT, ready_wait).await {
        Ok(seen) if seen == expected => {}
        Ok(seen) => {
            manager.disable_proxy_redirect_for_fallback(format!(
                "AF_XDP proxy bridge saw only {seen}/{expected} reactor workers ready; proxy redirect disabled, traffic will PASS"
            ));
            for (_, _, join) in joins {
                let _ = join.join();
            }
            return;
        }
        Err(_) => {
            manager.disable_proxy_redirect_for_fallback(format!(
                "AF_XDP reactor workers did not all report ready within {AF_XDP_WORKER_READY_TIMEOUT:?}; proxy redirect disabled, traffic will PASS"
            ));
            for (_, _, join) in joins {
                let _ = join.join();
            }
            return;
        }
    }
    // Keep the worker lease open until enable_proxy_redirect resolves:
    // clearing it first opens a window where should_continue sees
    // (starting=false, enabled=false) and freshly spawned workers exit
    // before redirect ever opens.
    match manager.enable_proxy_redirect("AF_XDP proxy bridge") {
        Ok(true) => {
            let message = format!(
                "AF_XDP proxy bridge enabled redirect for {} configured proxy ports across {} ready workers",
                manager.config.proxy.ports.len(),
                joins.len()
            );
            tracing::info!("{message}");
            crate::logging::report_node_log(
                "info".to_string(),
                "xdp_proxy".to_string(),
                message,
                0,
            );
            manager.set_proxy_workers_starting(false);
        }
        Ok(false) => {
            let message =
                "AF_XDP proxy bridge did not enable redirect; sockets are not ready or proxy ports are empty, traffic will PASS"
                    .to_string();
            tracing::warn!("{message}");
            crate::logging::report_node_log(
                "warn".to_string(),
                "xdp_proxy".to_string(),
                message.clone(),
                0,
            );
            manager.set_proxy_fallback_reason(&message);
            manager.persist_status_now();
            manager.set_proxy_workers_starting(false);
            for (_, _, join) in joins {
                let _ = join.join();
            }
            return;
        }
        Err(err) => {
            let message = format!(
                "AF_XDP proxy bridge failed to enable AF_XDP redirect: {err}; traffic will PASS"
            );
            tracing::warn!("{message}");
            crate::logging::report_node_log(
                "warn".to_string(),
                "xdp_proxy".to_string(),
                message.clone(),
                0,
            );
            manager.disable_proxy_redirect_for_fallback(message);
            manager.set_proxy_workers_starting(false);
            for (_, _, join) in joins {
                let _ = join.join();
            }
            return;
        }
    }
    tracing::info!(
        "AF_XDP proxy bridge running {} per-queue reactor threads",
        joins.len()
    );

    // EN-05 test hook (debug builds only): force one queue through the
    // queue-local fault path so e2e probes can observe slot withdrawal,
    // status marking, and sibling-queue survival without killing a worker.
    if let Some((interface, queue)) = crate::xdp::test_withdraw_queue_request() {
        manager.disable_queue_redirect_for_fault(
            &interface,
            queue,
            "test-only withdrawal via CLOUD_NODE_XDP_TEST_WITHDRAW_QUEUE".to_string(),
        );
    }

    let mut reported_dead: std::collections::HashSet<(String, u32)> =
        std::collections::HashSet::new();
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if joins.iter().all(|(_, _, join)| join.is_finished()) {
            // Every worker is gone — the socket generation is dead. Mark
            // the lease retired so the next manager generation rebuilds a
            // fresh dataplane instead of inheriting a husk.
            lease.retire();
            return;
        }
        if !lease.is_retired() {
            // EN-05: a dead reactor withdraws only its own queue — the
            // queue's XSK slots are removed so its traffic takes the
            // explicit dataplane fallback while sibling queues keep
            // serving. A queue's fault must not widen globally.
            // Fault bookkeeping always lands on the *current* owner of the
            // lease, which may be a newer manager generation after an
            // adopted reload.
            let owner = lease.owner();
            for (interface, queue, join) in &joins {
                // Skip queues the worker already withdrew itself — its
                // original fault detail is more precise than a generic
                // "thread exited" reason.
                if join.is_finished()
                    && reported_dead.insert((interface.clone(), *queue))
                    && !owner.xsk_queue_faulted(interface, *queue)
                {
                    owner.disable_queue_redirect_for_fault(
                        interface,
                        *queue,
                        "AF_XDP queue reactor thread exited unexpectedly".to_string(),
                    );
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) async fn run_queue_bridge_loop(
    // Kept for the spawn-site Arc lifetime; the loop itself gates and
    // reports through `ctx.lease` so a manager generation swap never
    // stops a polling worker that still owns sessions (F1).
    _manager: Arc<XdpManager>,
    mut queue_handle: linux::AfXdpQueueHandle,
    ctx: AfXdpQueueCtx,
    quic_demux: Arc<crate::quic_udp_demux::QuicUdpDemuxManager>,
    tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
    http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
    tcp_session_limit: usize,
) {
    pub(crate) const AF_XDP_DOWNSTREAM_DRAIN_BUDGET: usize = 1024;
    /// T4: per-round cap on dial/inject request processing so a burst
    /// cannot starve frame RX.
    pub(crate) const AF_XDP_REACTOR_REQUEST_BUDGET: usize = 256;
    pub(crate) const AF_XDP_ROUTE_CACHE_MAX: usize = 65_536;
    pub(crate) const AF_XDP_ROUTE_CACHE_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
    pub(crate) const AF_XDP_ROUTE_CACHE_EVICT_BATCH: usize = 1024;
    pub(crate) const AF_XDP_ROUTE_CACHE_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
    pub(crate) const AF_XDP_MAX_CONSECUTIVE_POLL_ERRORS: u32 = 3;
    pub(crate) const AF_XDP_MAX_CONSECUTIVE_TX_FAILURES: u32 = 256;
    pub(crate) const AF_XDP_MAX_CONSECUTIVE_UDP_INGRESS_FAILURES: u32 = 1024;
    pub(crate) const AF_XDP_MAX_CONSECUTIVE_TCP_ADMISSION_REFUSALS: u32 = 1024;
    // Idle backoff: busy-poll first, then exponentially back off to 1ms.
    pub(crate) const AF_XDP_IDLE_BACKOFF_MIN: Duration = Duration::from_micros(10);
    pub(crate) const AF_XDP_IDLE_BACKOFF_MAX: Duration = Duration::from_millis(1);
    pub(crate) const AF_XDP_STATUS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

    let AfXdpQueueCtx {
        downstream_tx,
        mut downstream_rx,
        mut fwd_rx,
        mut request_rx,
        dial_registry,
        udp_routes,
        iface_fwd,
        lease,
        egress_rate_bps,
    } = ctx;
    let own_interface: Arc<str> = Arc::from(queue_handle.interface.as_str());
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut idle_backoff = AF_XDP_IDLE_BACKOFF_MIN;
    let mut last_route_cache_sweep_ms = crate::udp_proxy::udp_activity_now_ms();
    let mut tcp_reactor =
        AfXdpTcpReactor::new_with_session_limit(tcp_manager, http_manager, tcp_session_limit);
    // T1: label the reactor so per-session /status snapshots are keyed by
    // the owning queue (the same 4-tuple may exist on multiple queues).
    tcp_reactor.set_label(format!("{own_interface}:{}", queue_handle.queue));
    // T4: the reactor releases demux/CT/port state itself when a dialed
    // session reaps — never leave it to the caller.
    tcp_reactor.set_dial_registry(dial_registry.clone());
    // T5/T6: transport policy comes from the lease owner — on an adopted
    // reload that is the live manager's config (the compatibility gate
    // already rejected any transport change, so old == new here).
    if let Some(policy) = lease.owner().config.transport.as_ref() {
        tcp_reactor.set_transport_policy(policy);
    }
    let mut consecutive_poll_errors = 0u32;
    let mut tx_failures = AfXdpTxFailureTracker::new(AF_XDP_MAX_CONSECUTIVE_TX_FAILURES);
    let mut udp_ingress_failures =
        AfXdpTxFailureTracker::new(AF_XDP_MAX_CONSECUTIVE_UDP_INGRESS_FAILURES);
    let mut tcp_admission_failures =
        AfXdpTcpAdmissionFailureTracker::new(AF_XDP_MAX_CONSECUTIVE_TCP_ADMISSION_REFUSALS);
    // EN-05 congestion gate: TX backpressure refuses *new* flow admission
    // (UDP route inserts, TCP session starts) while established flows keep
    // being served, so a congested queue sheds work at the boundary
    // instead of failing open or collapsing outright.
    let mut congested = false;
    let mut congested_drops = 0u64;
    // F2: TCP admission refusals are counted for status, never escalate to
    // queue teardown — the worker keeps serving existing sessions and new
    // admissions resume automatically when capacity frees.
    let mut admission_refusals = 0u64;
    let mut frames = Vec::with_capacity(64);
    // EN-17: reusable encode buffer for same-interface TCP egress — encodes
    // once per frame, no clone before `send_raw_frame`.
    let mut encode_scratch: Vec<u8> = Vec::with_capacity(2048);
    // T8 (D-G2/§4): production scheduler — hierarchical timing wheel +
    // tier DRR + this worker's static share of `xdp.egress_rate_bps` as
    // the bounded lease (workers' shares sum to the node budget; None =
    // unshaped, 无配置不整形). Deferred frames sit in per-flow queues
    // ordered by (deadline, tier, deficit); a full store sheds — counted.
    // T9 (D-AQM): CoDel runs on the deferred queue's real sojourn time;
    // ECT units are CE-marked, Not-ECT units dropped per the schedule.
    let mut sched = cloud_node_transport::sched::Scheduler::new(
        egress_rate_bps,
        AF_XDP_EGRESS_OVERHEAD_BYTES,
    );
    let mut pending_tx: std::collections::HashMap<u64, std::collections::VecDeque<PendingTx>> =
        std::collections::HashMap::new();
    let mut pending_tx_count = 0usize;
    let mut codel = cloud_node_transport::codel::Codel::new(
        cloud_node_transport::codel::DEFAULT_TARGET,
        cloud_node_transport::codel::DEFAULT_INTERVAL,
    );
    let mut aqm_drops = 0u64;
    let mut aqm_ce_marks = 0u64;
    let tx_clock = crate::transport_clock::TransportClock::real();
    let mut last_status_refresh = std::time::Instant::now();

    loop {
        // F1: the worker gates on the dataplane lease, not on manager
        // staleness — a compatible reload swaps the lease owner while
        // these sockets keep polling. The only exits are lease retire
        // (real teardown) or redirect disabled on the *current* owner.
        if lease.is_retired() || !proxy_bridge_should_continue(&lease) {
            // Explicit teardown contract: never leave peers on a silently
            // hung session. Abort every live smoltcp session and flush
            // the resulting RST frames before dropping the socket.
            let aborted = tcp_reactor.abort_all_sessions();
            let egress = tcp_reactor.poll();
            let mut sent = 0usize;
            for (route, ip_packet) in &egress {
                if encode_ip_reply_frame(&route.link, ip_packet, &mut encode_scratch).is_some()
                    && queue_handle
                        .send_raw_frame(&encode_scratch)
                        .unwrap_or(false)
                {
                    sent += 1;
                }
            }
            let message = format!(
                "AF_XDP proxy bridge exiting: dataplane retired={} aborted={aborted} rst_sent={sent}",
                lease.is_retired()
            );
            tracing::warn!("{message}");
            crate::logging::report_node_log(
                "warn".to_string(),
                "xdp_proxy".to_string(),
                message,
                0,
            );
            return;
        }
        // T8: deferred frames drain before any new work, ordered by the
        // scheduler (deadline → tier DRR → node budget). A token deficit
        // re-arms the flow at the budget's wait instant; a still-full
        // ring leaves the frame at its queue head for the next round.
        // T9: each dequeued head passes CoDel — ECT units get CE-marked,
        // Not-ECT units drop per the RFC 8289 control law.
        let tx_now = cloud_node_transport::TransportInstant::from_micros(
            tx_clock.now_micros().max(0) as u64,
        );
        while let Some(flow) = sched.next(tx_now) {
            let Some(mut head) = pending_tx
                .get_mut(&flow)
                .and_then(|q| q.pop_front())
            else {
                // Stale scheduler entry — flow's queue is already empty.
                sched.complete(flow);
                sched.remove_flow(flow);
                pending_tx.remove(&flow);
                continue;
            };
            match sched.charge(tx_now, flow, head.len()) {
                cloud_node_transport::sched::Admit::Wait(wait) => {
                    let tier = head.tier;
                    pending_tx
                        .get_mut(&flow)
                        .expect("flow queue exists")
                        .push_front(head);
                    sched.complete(flow);
                    sched.schedule(flow, tier, tx_now + wait);
                    // One shared budget — other flows hit the same wall.
                    break;
                }
                cloud_node_transport::sched::Admit::Now => {}
            }
            let stamp = cloud_node_transport::codel::Stamp {
                enqueued_at: cloud_node_transport::TransportInstant::from_micros(
                    head.enqueued_us,
                ),
                ecn: head.ecn,
            };
            let codel_action = codel.dequeue(tx_now, stamp, pending_tx_count <= 1);
            let codel_dropped = match codel_action {
                cloud_node_transport::codel::CodelAction::Drop => true,
                cloud_node_transport::codel::CodelAction::MarkCe => {
                    if head.mark_ce() {
                        aqm_ce_marks = aqm_ce_marks.saturating_add(1);
                        false
                    } else {
                        // Unmarkable despite an ECT stamp — treat as the
                        // scheduled drop rather than bypass the AQM.
                        true
                    }
                }
                cloud_node_transport::codel::CodelAction::Pass => false,
            };
            if codel_dropped {
                pending_tx_count -= 1;
                aqm_drops = aqm_drops.saturating_add(1);
                if pending_tx
                    .get(&flow)
                    .map(|q| q.is_empty())
                    .unwrap_or(true)
                {
                    sched.complete(flow);
                    sched.remove_flow(flow);
                    pending_tx.remove(&flow);
                }
                continue;
            }
            match send_pending_tx(&mut queue_handle, &mut head) {
                Ok(true) => {
                    pending_tx_count -= 1;
                    congested = false;
                    tx_failures.record(AfXdpTxStatus::Sent);
                }
                Ok(false) => {
                    // Ring full — return to the head; retried next round.
                    pending_tx
                        .get_mut(&flow)
                        .expect("flow queue exists")
                        .push_front(head);
                    break;
                }
                Err(err) => {
                    pending_tx_count -= 1;
                    tracing::debug!(
                        "AF_XDP deferred TX failed on {} queue {}: {}",
                        own_interface.as_ref(),
                        queue_handle.queue,
                        err
                    );
                    if tx_failures.record(AfXdpTxStatus::Failed) {
                        lease.owner().disable_queue_redirect_for_fault(
                            &own_interface,
                            queue_handle.queue,
                            format!(
                                "AF_XDP deferred TX failed repeatedly after {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} attempts: {err}"
                            ),
                        );
                        return;
                    }
                }
            }
            if pending_tx
                .get(&flow)
                .map(|q| q.is_empty())
                .unwrap_or(true)
            {
                sched.complete(flow);
                sched.remove_flow(flow);
                pending_tx.remove(&flow);
            }
        }
        if last_status_refresh.elapsed() >= AF_XDP_STATUS_REFRESH_INTERVAL {
            last_status_refresh = std::time::Instant::now();
            let stats = queue_handle.rx.fd().xdp_statistics().ok();
            let owner = lease.owner();
            owner.update_xsk_queue_status(
                &queue_handle.interface,
                queue_handle.queue,
                |status| {
                    if let Some(stats) = &stats {
                        status.rx_dropped = stats.rx_dropped();
                        status.rx_invalid_descs = stats.rx_invalid_descs();
                        status.rx_ring_full = stats.rx_ring_full();
                        status.tx_invalid_descs = stats.tx_invalid_descs();
                    }
                    status.congested_drops = congested_drops;
                    status.admission_refusals = admission_refusals;
                    status.aqm_drops = aqm_drops;
                    status.aqm_ce_marks = aqm_ce_marks;
                },
            );
        }
        frames.clear();
        // EN-17: `poll_raw_once` on a queue handle only ever yields frames
        // for this queue/interface — keep just the frame bytes instead of
        // allocating a `String` per packet on the RX path.
        let poll_result = queue_handle.poll_raw_once(&mut |_interface, _queue, frame| {
            frames.push(frame);
        });

        let polled_packets = match poll_result {
            Ok(stats) => {
                consecutive_poll_errors = 0;
                stats.packets
            }
            Err(err) => {
                frames.clear();
                consecutive_poll_errors = consecutive_poll_errors.saturating_add(1);
                let detail = format!(
                    "AF_XDP proxy bridge poll failed ({consecutive_poll_errors}/{AF_XDP_MAX_CONSECUTIVE_POLL_ERRORS}): {err}"
                );
                lease.owner().set_proxy_fallback_reason(detail.clone());
                tracing::warn!("{}", detail);
                if consecutive_poll_errors >= AF_XDP_MAX_CONSECUTIVE_POLL_ERRORS {
                    lease.owner().disable_queue_redirect_for_fault(
                        &own_interface,
                        queue_handle.queue,
                        format!("AF_XDP proxy bridge poll failed repeatedly: {err}"),
                    );
                    return;
                }
                std::thread::sleep(idle_backoff);
                continue;
            }
        };
        // T4: drain reactor requests before parsing frames so a queued
        // Dial lands before any same-round injects for its flow.
        for _ in 0..AF_XDP_REACTOR_REQUEST_BUDGET {
            match request_rx.try_recv() {
                Ok(AfXdpReactorRequest::Dial(req)) => tcp_reactor.dial(req),
                Ok(AfXdpReactorRequest::InjectTcp {
                    route,
                    flow,
                    ip_packet,
                }) => {
                    let status = tcp_reactor.ingest(route, flow, ip_packet);
                    if matches!(
                        status,
                        AfXdpTcpIngestStatus::RefusedAtCapacity
                            | AfXdpTcpIngestStatus::IngressQueueFull
                    ) {
                        admission_refusals = admission_refusals.saturating_add(1);
                    }
                }
                Ok(AfXdpReactorRequest::UdpEgress {
                    link,
                    local,
                    remote,
                    payload,
                    ecn,
                }) => {
                    // T8: QUIC/UDP egress honors the same shaping gate and
                    // bounded retry queue as TCP — UDP is lossy by
                    // contract, but a shed must be counted, never silent.
                    let tx_now = cloud_node_transport::TransportInstant::from_micros(
                        tx_clock.now_micros().max(0) as u64,
                    );
                    let mut pending =
                        PendingTx::udp(link, local, remote, payload, ecn, tx_now.micros());
                    if matches!(
                        sched.charge(tx_now, pending.flow, pending.len()),
                        cloud_node_transport::sched::Admit::Wait(_)
                    ) {
                        if !queue_deferred_tx(
                            &mut pending_tx,
                            &mut pending_tx_count,
                            &mut sched,
                            tx_now,
                            pending,
                        ) {
                            congested_drops = congested_drops.saturating_add(1);
                            tracing::debug!(
                                "AF_XDP TX retry queue full on {} queue {}; shedding UDP egress {} -> {}",
                                own_interface.as_ref(),
                                queue_handle.queue,
                                local,
                                remote
                            );
                        }
                        continue;
                    }
                    match send_pending_tx(&mut queue_handle, &mut pending) {
                        Ok(true) => {}
                        Ok(false) => {
                            if !queue_deferred_tx(
                                &mut pending_tx,
                                &mut pending_tx_count,
                                &mut sched,
                                tx_now,
                                pending,
                            ) {
                                congested_drops = congested_drops.saturating_add(1);
                                tracing::debug!(
                                    "AF_XDP TX retry queue full on {} queue {}; shedding UDP egress {} -> {}",
                                    own_interface.as_ref(),
                                    queue_handle.queue,
                                    local,
                                    remote
                                );
                            }
                        }
                        Err(err) => {
                            tracing::warn!(
                                "AF_XDP UDP egress failed for {} -> {}: {err}",
                                local,
                                remote
                            );
                        }
                    }
                }
                Ok(AfXdpReactorRequest::PmtuUpdate { flow, mtu }) => {
                    // T4-7: ICMP error quoting a dialed flow — clamp the
                    // session's send MSS to the reported next-hop MTU.
                    tcp_reactor.apply_pmtu(&flow, mtu);
                }
                Err(mpsc::error::TryRecvError::Empty)
                | Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        let parsed_frames = frames.len();
        let now_ms = crate::udp_proxy::udp_activity_now_ms();
        if udp_route_cache_sweep_due(
            now_ms,
            last_route_cache_sweep_ms,
            AF_XDP_ROUTE_CACHE_SWEEP_INTERVAL,
        ) {
            compact_udp_route_cache(
                &udp_routes,
                now_ms,
                AF_XDP_ROUTE_CACHE_IDLE_TIMEOUT,
                AF_XDP_ROUTE_CACHE_MAX,
                AF_XDP_ROUTE_CACHE_EVICT_BATCH,
            );
            last_route_cache_sweep_ms = now_ms;
        }

        for frame in frames.drain(..) {
            if let Some((flow, flags)) = parse_tcp_flow_flags_from_frame(&frame)
                && tcp_reactor.should_ignore_unknown_non_syn(&flow, flags)
                // T4: replies to node-dialed flows are demuxed below even
                // though this queue owns no session for them — never let
                // the unknown-flow filter drop them.
                && dial_registry.owner(&flow).is_none()
            {
                tcp_reactor.record_ignored_unknown_non_syn(flow, frame.len());
                continue;
            }
            match parse_proxy_frame(own_interface.clone(), queue_handle.queue, &frame) {
                Some(AfXdpProxyFrame::Udp { route, packet }) => {
                    // T4-6: replies to node-dialed UDP flows are owned by
                    // the dial registry — deliver the payload straight to
                    // the socket's channel regardless of which queue
                    // received it (XSK redirect is ingress-queue local).
                    let dialed_flow = AfXdpTcpFlowKey {
                        local_addr: packet.local_addr,
                        peer_addr: packet.peer_addr,
                    };
                    if let Some(owner) = dial_registry.owner(&dialed_flow)
                        && owner.proto == IP_PROTO_UDP
                    {
                        if let Some(tx) = &owner.udp_tx {
                            match tx.try_send(AfXdpUdpIngress::Datagram(AfXdpUdpDatagram {
                                payload: packet.payload.clone(),
                                ecn: packet.ecn,
                            })) {
                                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {
                                    // A full socket channel sheds the
                                    // datagram — UDP loss semantics, the
                                    // queue stays healthy.
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    dial_registry.release(&dialed_flow);
                                }
                            }
                        }
                        continue;
                    }
                    // Congestion gate: refuse new flow-route admission while
                    // this queue is TX-backpressured; known flows still get
                    // their route refreshed and packet demuxed.
                    if congested && !udp_routes.contains_key(&(packet.local_addr, packet.peer_addr))
                    {
                        congested_drops = congested_drops.saturating_add(1);
                        continue;
                    }
                    let now_ms = crate::udp_proxy::udp_activity_now_ms();
                    if udp_routes.len() >= AF_XDP_ROUTE_CACHE_MAX {
                        compact_udp_route_cache(
                            &udp_routes,
                            now_ms,
                            AF_XDP_ROUTE_CACHE_IDLE_TIMEOUT,
                            AF_XDP_ROUTE_CACHE_MAX,
                            AF_XDP_ROUTE_CACHE_EVICT_BATCH,
                        );
                    }
                    udp_routes.insert(
                        (packet.local_addr, packet.peer_addr),
                        AfXdpUdpRouteEntry {
                            route,
                            last_seen_ms: now_ms,
                        },
                    );
                    // F7: no eBPF DCID steering — an XSK redirect is only
                    // valid for the current ingress queue, so every packet
                    // arrives on this queue's socket and the shared
                    // userspace demux routes it to the CID's owning
                    // session regardless of which queue received it.
                    let Some(datagram) = packet.into_udp_datagram() else {
                        continue;
                    };
                    match quic_demux
                        .receive_af_xdp_datagram(
                            datagram,
                            downstream_tx.clone(),
                            shutdown_rx.clone(),
                        )
                        .await
                    {
                        Ok(crate::udp_proxy::UdpIngressDatagramStatus::Sent)
                        | Ok(crate::udp_proxy::UdpIngressDatagramStatus::Blocked)
                        | Ok(crate::udp_proxy::UdpIngressDatagramStatus::NoRoute) => {
                            udp_ingress_failures.record(AfXdpTxStatus::Sent);
                        }
                        Ok(crate::udp_proxy::UdpIngressDatagramStatus::Full) => {
                            // F2: upstream queue full is capacity pressure,
                            // not a fault — shed this datagram, keep the
                            // queue alive so existing sessions drain and new
                            // admissions resume when the queues free up.
                            congested = true;
                            congested_drops = congested_drops.saturating_add(1);
                            if udp_ingress_failures.record(AfXdpTxStatus::Backpressured) {
                                tracing::warn!(
                                    "AF_XDP UDP ingress queues stayed full for {AF_XDP_MAX_CONSECUTIVE_UDP_INGRESS_FAILURES} consecutive redirected datagrams; queue stays up and sheds new work until capacity frees"
                                );
                            }
                        }
                        Ok(crate::udp_proxy::UdpIngressDatagramStatus::Closed) => {
                            tracing::debug!("AF_XDP proxy bridge upstream session closed");
                            if udp_ingress_failures.record(AfXdpTxStatus::Failed) {
                                lease.owner().disable_queue_redirect_for_fault(
                                    &own_interface,
                                    queue_handle.queue,
                                    format!(
                                        "AF_XDP UDP ingress sessions stayed closed for {AF_XDP_MAX_CONSECUTIVE_UDP_INGRESS_FAILURES} redirected datagrams"
                                    ),
                                );
                                return;
                            }
                        }
                        Err(err) => {
                            tracing::debug!(
                                "AF_XDP proxy bridge failed to process datagram: {}",
                                err
                            );
                            if udp_ingress_failures.record(AfXdpTxStatus::Failed) {
                                lease.owner().disable_queue_redirect_for_fault(
                                    &own_interface,
                                    queue_handle.queue,
                                    format!(
                                        "AF_XDP UDP ingress failed repeatedly after {AF_XDP_MAX_CONSECUTIVE_UDP_INGRESS_FAILURES} redirected datagrams: {err}"
                                    ),
                                );
                                return;
                            }
                        }
                    }
                }
                Some(AfXdpProxyFrame::Tcp {
                    route,
                    flow,
                    ip_packet,
                }) => {
                    // T4 reply demux: the tuple is a registered outbound
                    // flow but this queue owns no session for it — the
                    // reply arrived on the wrong queue (or the dial is
                    // still queued on this one). Injecting through the
                    // owner channel preserves Dial→packet ordering; a
                    // failed inject means the flow is being torn down.
                    if !tcp_reactor.has_session(&flow)
                        && let Some(owner) = dial_registry.owner(&flow)
                    {
                        match dial_registry.inject(&owner, route, flow, ip_packet) {
                            Ok(()) => {}
                            Err(AfXdpDialInjectError::QueueFull) => {
                                // Owner channel full is backpressure — the
                                // sender retransmits; shed this packet.
                                congested_drops = congested_drops.saturating_add(1);
                            }
                            Err(AfXdpDialInjectError::OwnerGone) => {
                                tracing::debug!(
                                    "AF_XDP reply demux dropped packet for torn-down flow local={} peer={}",
                                    flow.local_addr,
                                    flow.peer_addr
                                );
                            }
                        }
                        continue;
                    }
                    // Congestion gate: unknown non-SYN packets were already
                    // dropped above, so reaching here without a session means
                    // a new SYN — refuse it while the queue is backpressured.
                    if congested && !tcp_reactor.has_session(&flow) {
                        congested_drops = congested_drops.saturating_add(1);
                        continue;
                    }
                    let status = tcp_reactor.ingest(route, flow, ip_packet);
                    if matches!(
                        status,
                        AfXdpTcpIngestStatus::RefusedAtCapacity
                            | AfXdpTcpIngestStatus::IngressQueueFull
                    ) {
                        admission_refusals = admission_refusals.saturating_add(1);
                    }
                    // F2: a refusal streak only sheds new SYNs — the queue
                    // keeps pumping existing sessions and recovers the
                    // moment capacity frees; no redirect withdrawal, no
                    // worker exit.
                    if tcp_admission_failures.record(status) {
                        tracing::warn!(
                            "AF_XDP TCP reactor refused {AF_XDP_MAX_CONSECUTIVE_TCP_ADMISSION_REFUSALS} new sessions consecutively on {} queue {}; queue stays up and resumes admitting when capacity frees",
                            own_interface.as_ref(),
                            queue_handle.queue
                        );
                    }
                }
                None => {
                    // T4-7: eBPF redirects ICMP errors whose quoted inner
                    // tuple matches XDP_OUT_CT — hand them to the dialed
                    // flow's owner (TCP: reactor PmtuUpdate; UDP: socket
                    // ingress channel). Non-matching frames stay unhandled.
                    if let Some(icmp) = parse_icmp_error_frame(&frame) {
                        dial_registry.notify_icmp(&icmp.flow, icmp.mtu);
                        continue;
                    }
                    tracing::debug!(
                        "AF_XDP proxy bridge received unparseable redirected frame interface={} queue={} bytes={}",
                        own_interface.as_ref(),
                        queue_handle.queue,
                        frame.len()
                    );
                }
            }
        }

        let mut downstream_datagrams = 0usize;
        let mut downstream_budget_exhausted = false;
        for _ in 0..AF_XDP_DOWNSTREAM_DRAIN_BUDGET {
            let datagram = match downstream_rx.try_recv() {
                Ok(datagram) => datagram,
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            };
            downstream_datagrams = downstream_datagrams.saturating_add(1);
            let now_ms = crate::udp_proxy::udp_activity_now_ms();
            let route = {
                let Some(mut entry) =
                    udp_routes.get_mut(&(datagram.listen_addr, datagram.peer_addr))
                else {
                    tracing::debug!(
                        "AF_XDP proxy bridge has no L2 route for downstream datagram listen={} peer={} bytes={}",
                        datagram.listen_addr,
                        datagram.peer_addr,
                        datagram.payload.len()
                    );
                    continue;
                };
                entry.last_seen_ms = now_ms;
                entry.route.clone()
            };
            if route.interface != own_interface {
                match iface_fwd.get(route.interface.as_ref()) {
                    Some(tx) => match tx.try_send(AfXdpForward::Udp(datagram)) {
                        Ok(()) => continue,
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            // F2: a full cross-interface channel is
                            // backpressure, not a fault — drop this
                            // datagram, stay congested, keep serving.
                            congested = true;
                            congested_drops = congested_drops.saturating_add(1);
                            if tx_failures.record(AfXdpTxStatus::Backpressured) {
                                tracing::warn!(
                                    "AF_XDP cross-interface forward channel to {} stayed full for {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} consecutive datagrams; queue stays up and sheds new work until the channel drains",
                                    route.interface.as_ref()
                                );
                            } else {
                                tracing::debug!(
                                    "AF_XDP proxy bridge forward channel to interface {} is full; dropping downstream datagram",
                                    route.interface.as_ref()
                                );
                            }
                            continue;
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            tracing::warn!(
                                "AF_XDP proxy bridge forward channel to interface {} is closed",
                                route.interface.as_ref()
                            );
                            continue;
                        }
                    },
                    None => {
                        tracing::warn!(
                            "AF_XDP proxy bridge has no reactor channel for route interface {}; dropping downstream datagram",
                            route.interface.as_ref()
                        );
                        continue;
                    }
                }
            }
            // T8 shaping gate (D-G2): token deficit defers the datagram
            // into the bounded retry queue — charged on actual send,
            // never dropped silently.
            let tx_now = cloud_node_transport::TransportInstant::from_micros(
                tx_clock.now_micros().max(0) as u64,
            );
            let make_pending = |now_us: u64| {
                PendingTx::udp(
                    route.link,
                    datagram.listen_addr,
                    datagram.peer_addr,
                    datagram.payload.clone(),
                    None,
                    now_us,
                )
            };
            let pending = make_pending(tx_now.micros());
            if matches!(
                sched.charge(tx_now, pending.flow, pending.len()),
                cloud_node_transport::sched::Admit::Wait(_)
            ) {
                if !queue_deferred_tx(
                    &mut pending_tx,
                    &mut pending_tx_count,
                    &mut sched,
                    tx_now,
                    pending,
                ) {
                    congested = true;
                    congested_drops = congested_drops.saturating_add(1);
                    tracing::debug!(
                        "AF_XDP TX retry queue full on {} queue {}; shedding downstream datagram peer={} bytes={}",
                        own_interface.as_ref(),
                        queue_handle.queue,
                        datagram.peer_addr,
                        datagram.payload.len()
                    );
                }
                continue;
            }
            let sent = queue_handle.send_udp_datagram(
                &route.link,
                datagram.listen_addr,
                datagram.peer_addr,
                datagram.payload.as_ref(),
                None,
            );
            match sent {
                Ok(true) => {
                    congested = false;
                    tx_failures.record(AfXdpTxStatus::Sent);
                }
                Ok(false) => {
                    // T8: ring full is backpressure — defer to the next
                    // round; only a full retry queue sheds (counted).
                    if queue_deferred_tx(
                        &mut pending_tx,
                        &mut pending_tx_count,
                        &mut sched,
                        tx_now,
                        make_pending(tx_now.micros()),
                    ) {
                        congested = true;
                        continue;
                    }
                    congested = true;
                    congested_drops = congested_drops.saturating_add(1);
                    if tx_failures.record(AfXdpTxStatus::Backpressured) {
                        tracing::warn!(
                            "AF_XDP proxy bridge TX backpressure on {} queue {} persisted for {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} consecutive datagrams; queue stays up and sheds new work until the ring drains",
                            own_interface.as_ref(),
                            queue_handle.queue
                        );
                    } else {
                        tracing::debug!(
                            "AF_XDP proxy bridge could not send downstream datagram listen={} peer={} bytes={}",
                            datagram.listen_addr,
                            datagram.peer_addr,
                            datagram.payload.len()
                        );
                    }
                }
                Err(err) => {
                    tracing::debug!(
                        "AF_XDP proxy bridge TX failed listen={} peer={} bytes={}: {}",
                        datagram.listen_addr,
                        datagram.peer_addr,
                        datagram.payload.len(),
                        err
                    );
                    if tx_failures.record(AfXdpTxStatus::Failed) {
                        lease.owner().disable_queue_redirect_for_fault(
                            &own_interface,
                            queue_handle.queue,
                            format!(
                                "AF_XDP proxy bridge TX failed repeatedly after {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} attempts: {err}"
                            ),
                        );
                        return;
                    }
                }
            }
        }
        if downstream_datagrams == AF_XDP_DOWNSTREAM_DRAIN_BUDGET {
            downstream_budget_exhausted = true;
        }

        // Forwarded traffic: datagrams/frames whose L2 route resolves to
        // this thread's interface but were drained by a reactor on another
        // interface.
        for _ in 0..AF_XDP_DOWNSTREAM_DRAIN_BUDGET {
            let fwd = match fwd_rx.try_recv() {
                Ok(fwd) => fwd,
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            };
            // T8: resolve to a sendable unit first so shaping and ring
            // backpressure defer the same object the live path sent.
            let tx_now = cloud_node_transport::TransportInstant::from_micros(
                tx_clock.now_micros().max(0) as u64,
            );
            let pending = match fwd {
                AfXdpForward::Udp(datagram) => {
                    let route = {
                        let Some(entry) = udp_routes
                            .get_mut(&(datagram.listen_addr, datagram.peer_addr))
                        else {
                            continue;
                        };
                        entry.route.clone()
                    };
                    if route.interface != own_interface {
                        continue;
                    }
                    PendingTx::udp(
                        route.link,
                        datagram.listen_addr,
                        datagram.peer_addr,
                        datagram.payload,
                        None,
                        tx_now.micros(),
                    )
                }
                AfXdpForward::TcpFrame(frame) => PendingTx::frame(frame, tx_now.micros()),
            };
            let pending_len = pending.len();
            if matches!(
                sched.charge(tx_now, pending.flow, pending_len),
                cloud_node_transport::sched::Admit::Wait(_)
            ) {
                // Token deficit: defer when the retry queue has room;
                // a full queue sheds (counted) — never bypass the shaper.
                if !queue_deferred_tx(
                    &mut pending_tx,
                    &mut pending_tx_count,
                    &mut sched,
                    tx_now,
                    pending,
                ) {
                    congested = true;
                    congested_drops = congested_drops.saturating_add(1);
                    tracing::debug!(
                        "AF_XDP TX retry queue full on {} queue {}; shedding forwarded frame bytes={}",
                        own_interface.as_ref(),
                        queue_handle.queue,
                        pending_len
                    );
                }
                continue;
            }
            let mut pending = pending;
            let sent = send_pending_tx(&mut queue_handle, &mut pending);
            match sent {
                Ok(true) => {
                    congested = false;
                    tx_failures.record(AfXdpTxStatus::Sent);
                }
                Ok(false) => {
                    if queue_deferred_tx(
                        &mut pending_tx,
                        &mut pending_tx_count,
                        &mut sched,
                        tx_now,
                        pending,
                    ) {
                        congested = true;
                        continue;
                    }
                    congested = true;
                    congested_drops = congested_drops.saturating_add(1);
                    if tx_failures.record(AfXdpTxStatus::Backpressured) {
                        tracing::warn!(
                            "AF_XDP forwarded TX backpressure on {} queue {} persisted for {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} consecutive frames; queue stays up and sheds new work until the ring drains",
                            own_interface.as_ref(),
                            queue_handle.queue
                        );
                    }
                }
                Err(err) => {
                    tracing::debug!("AF_XDP forwarded TX failed: {err}");
                    if tx_failures.record(AfXdpTxStatus::Failed) {
                        lease.owner().disable_queue_redirect_for_fault(
                            &own_interface,
                            queue_handle.queue,
                            format!(
                                "AF_XDP forwarded TX failed repeatedly after {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} attempts: {err}"
                            ),
                        );
                        return;
                    }
                }
            }
        }

        let tcp_egress = tcp_reactor.poll();
        let tcp_egress_frames = tcp_egress.len();
        #[cfg(target_os = "linux")]
        AF_XDP_TCP_DIAG_EGRESS_FRAMES.fetch_add(tcp_egress_frames as u64, Ordering::Relaxed);
        for (route, ip_packet) in tcp_egress {
            if route.interface != own_interface {
                // Cross-interface forwarding needs an owned frame; the
                // reactor-side scratch clone only happens on this path.
                match tcp_reactor.encode_egress_frame(&route, &ip_packet) {
                    Some(frame) => {
                        if let Some(tx) = iface_fwd.get(route.interface.as_ref()) {
                            // T8: the forward channel is bounded — a Full
                            // result is congestion shed and must be
                            // counted, never silently swallowed.
                            match tx.try_send(AfXdpForward::TcpFrame(frame)) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    congested = true;
                                    congested_drops =
                                        congested_drops.saturating_add(1);
                                    tracing::debug!(
                                        "AF_XDP forward channel to interface {} full; shedding TCP egress frame bytes={}",
                                        route.interface.as_ref(),
                                        ip_packet.len()
                                    );
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    tracing::warn!(
                                        "AF_XDP forward channel to interface {} closed; TCP egress frame lost bytes={}",
                                        route.interface.as_ref(),
                                        ip_packet.len()
                                    );
                                }
                            }
                        }
                    }
                    None => {
                        tracing::debug!(
                            "AF_XDP TCP reactor failed to encode egress frame interface={} queue={} bytes={}",
                            route.interface.as_ref(),
                            route.queue,
                            ip_packet.len()
                        );
                    }
                }
                continue;
            }
            // EN-17: encode straight into the bridge scratch — `send_raw_frame`
            // only borrows it, so no per-frame clone on the hot TX path.
            if encode_ip_reply_frame(&route.link, &ip_packet, &mut encode_scratch).is_none() {
                tracing::debug!(
                    "AF_XDP TCP reactor failed to encode egress frame interface={} queue={} bytes={}",
                    route.interface.as_ref(),
                    route.queue,
                    ip_packet.len()
                );
                continue;
            }
            // T8 shaping gate (D-G2): token deficit defers the encoded
            // frame; only a full retry queue sheds (counted).
            let tx_now = cloud_node_transport::TransportInstant::from_micros(
                tx_clock.now_micros().max(0) as u64,
            );
            if matches!(
                sched.charge(
                    tx_now,
                    frame_sched_meta(&encode_scratch).0,
                    encode_scratch.len() as u64,
                ),
                cloud_node_transport::sched::Admit::Wait(_)
            ) {
                if !queue_deferred_tx(
                    &mut pending_tx,
                    &mut pending_tx_count,
                    &mut sched,
                    tx_now,
                    PendingTx::frame(encode_scratch.clone(), tx_now.micros()),
                ) {
                    congested = true;
                    congested_drops = congested_drops.saturating_add(1);
                    tracing::debug!(
                        "AF_XDP TX retry queue full on {} queue {}; shedding TCP egress frame bytes={}",
                        own_interface.as_ref(),
                        queue_handle.queue,
                        encode_scratch.len()
                    );
                }
                continue;
            }
            let sent = queue_handle.send_raw_frame(&encode_scratch);
            match sent {
                Ok(true) => {
                    congested = false;
                    tx_failures.record(AfXdpTxStatus::Sent);
                }
                Ok(false) => {
                    // T8: ring full while flushing reactor egress is
                    // backpressure — defer to the next round; only a full
                    // retry queue sheds, and smoltcp retransmit covers
                    // real loss either way.
                    if queue_deferred_tx(
                        &mut pending_tx,
                        &mut pending_tx_count,
                        &mut sched,
                        tx_now,
                        PendingTx::frame(encode_scratch.clone(), tx_now.micros()),
                    ) {
                        congested = true;
                        continue;
                    }
                    congested = true;
                    congested_drops = congested_drops.saturating_add(1);
                    if tx_failures.record(AfXdpTxStatus::Backpressured) {
                        tracing::warn!(
                            "AF_XDP TCP egress TX backpressure on {} queue {} persisted for {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} consecutive frames; queue stays up and sheds new work until the ring drains",
                            own_interface.as_ref(),
                            queue_handle.queue
                        );
                    } else {
                        tracing::debug!(
                            "AF_XDP TCP reactor could not send frame interface={} queue={} bytes={}",
                            route.interface.as_ref(),
                            route.queue,
                            encode_scratch.len()
                        );
                    }
                }
                Err(err) => {
                    tracing::debug!(
                        "AF_XDP TCP reactor TX failed interface={} queue={} bytes={}: {}",
                        route.interface.as_ref(),
                        route.queue,
                        encode_scratch.len(),
                        err
                    );
                    if tx_failures.record(AfXdpTxStatus::Failed) {
                        lease.owner().disable_queue_redirect_for_fault(
                            &own_interface,
                            queue_handle.queue,
                            format!(
                                "AF_XDP TCP reactor TX failed repeatedly after {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} attempts: {err}"
                            ),
                        );
                        return;
                    }
                }
            }
        }

        if proxy_bridge_should_idle(
            polled_packets,
            parsed_frames,
            downstream_datagrams,
            tcp_egress_frames,
            downstream_budget_exhausted,
        ) {
            std::hint::spin_loop();
            // Async sleep, not std::thread::sleep: the timer yields to the
            // current-thread scheduler so spawned proxy tasks can run while
            // the reactor backs off.
            tokio::time::sleep(idle_backoff).await;
            idle_backoff = (idle_backoff.saturating_mul(2)).min(AF_XDP_IDLE_BACKOFF_MAX);
        } else {
            idle_backoff = AF_XDP_IDLE_BACKOFF_MIN;
        }
        // The busy path above never awaits; without an explicit yield the
        // current-thread runtime starves tokio::spawn'ed TCP/HTTP proxy
        // tasks (sessions get ACKed by the smoltcp stack but no relay task
        // is ever polled).
        tokio::task::yield_now().await;
    }
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn udp_route_cache_sweep_due(
    now_ms: u64,
    last_sweep_ms: u64,
    sweep_interval: Duration,
) -> bool {
    let interval_ms = sweep_interval.as_millis().min(u64::MAX as u128) as u64;
    now_ms.saturating_sub(last_sweep_ms) >= interval_ms
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn compact_udp_route_cache(
    routes: &DashMap<(SocketAddr, SocketAddr), AfXdpUdpRouteEntry>,
    now_ms: u64,
    idle_timeout: Duration,
    max_entries: usize,
    evict_batch: usize,
) {
    if routes.is_empty() {
        return;
    }
    let idle_timeout_ms = idle_timeout.as_millis().min(u64::MAX as u128) as u64;
    routes.retain(|_, entry| now_ms.saturating_sub(entry.last_seen_ms) < idle_timeout_ms);
    if routes.len() < max_entries {
        return;
    }
    let evict_count = routes
        .len()
        .saturating_sub(max_entries.saturating_sub(1))
        .max(evict_batch.min(routes.len()));
    let mut oldest = routes
        .iter()
        .map(|entry| {
            let (key, value) = entry.pair();
            (*key, value.last_seen_ms)
        })
        .collect::<Vec<_>>();
    oldest.select_nth_unstable_by(evict_count.saturating_sub(1), |left, right| {
        left.1.cmp(&right.1)
    });
    for (key, _) in oldest.into_iter().take(evict_count) {
        routes.remove(&key);
    }
    tracing::debug!(
        "AF_XDP proxy bridge evicted stale UDP route cache entries count={} remaining={}",
        evict_count,
        routes.len()
    );
}


#[cfg(all(test, target_os = "linux"))]
mod sched_aqm_tests {
    use super::*;
    use cloud_node_transport::codel::{Codel, CodelAction, Stamp, DEFAULT_INTERVAL, DEFAULT_TARGET};
    use cloud_node_transport::sched::Scheduler;
    use cloud_node_transport::TransportInstant;

    fn ipv4_frame(tos: u8, proto: u8, l4: &[u8], fix_checksum: bool) -> Vec<u8> {
        let mut f = Vec::with_capacity(14 + 20 + l4.len());
        f.extend_from_slice(&[0xaa; 6]); // dst mac
        f.extend_from_slice(&[0xbb; 6]); // src mac
        f.extend_from_slice(&[0x08, 0x00]); // IPv4
        let total = (20 + l4.len()) as u16;
        f.push(0x45); // v4, ihl 20
        f.push(tos);
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 64, proto]);
        f.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        f.extend_from_slice(&[192, 0, 2, 1]); // src
        f.extend_from_slice(&[203, 0, 113, 5]); // dst
        if fix_checksum {
            let mut sum = 0u32;
            for i in (14..34).step_by(2) {
                sum += u32::from(u16::from_be_bytes([f[i], f[i + 1]]));
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            let cksum = !(sum as u16);
            f[24..26].copy_from_slice(&cksum.to_be_bytes());
        }
        f.extend_from_slice(l4);
        f
    }

    fn ipv4_header_checksum_valid(frame: &[u8]) -> bool {
        let mut sum = 0u32;
        for i in (14..34).step_by(2) {
            sum += u32::from(u16::from_be_bytes([frame[i], frame[i + 1]]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum == 0xffff
    }

    fn tcp_segment(payload_len: usize, flags: u8) -> Vec<u8> {
        let mut s = Vec::with_capacity(20 + payload_len);
        s.extend_from_slice(&12345u16.to_be_bytes()); // sport
        s.extend_from_slice(&443u16.to_be_bytes()); // dport
        s.extend_from_slice(&[0; 8]); // seq+ack
        s.push(5 << 4); // data offset
        s.push(flags);
        s.extend_from_slice(&[0; 6]); // window/checksum/urg
        s.extend(std::iter::repeat(0x42).take(payload_len));
        s
    }

    #[test]
    fn frame_sched_meta_classifies_tcp_control_vs_data() {
        let data = ipv4_frame(0, 6, &tcp_segment(100, 0x18), false);
        let (flow_d, tier_d, _) = frame_sched_meta(&data);
        assert_eq!(tier_d, 1, "payload segment must be data tier");
        let ack = ipv4_frame(0, 6, &tcp_segment(0, 0x10), false);
        let (flow_a, tier_a, _) = frame_sched_meta(&ack);
        assert_eq!(tier_a, 0, "pure ACK must be control tier");
        assert_eq!(flow_a, flow_d, "same 4-tuple shares a flow");
    }

    #[test]
    fn frame_sched_meta_extracts_ecn_and_flow_distinctness() {
        let ect = ipv4_frame(0b10, 6, &tcp_segment(10, 0x18), false);
        let (f1, _, ecn) = frame_sched_meta(&ect);
        assert_eq!(ecn, 0b10);
        // Different peer port → different flow.
        let mut other_seg = tcp_segment(10, 0x18);
        other_seg[0..2].copy_from_slice(&54321u16.to_be_bytes());
        let other = ipv4_frame(0b10, 6, &other_seg, false);
        let (f2, _, _) = frame_sched_meta(&other);
        assert_ne!(f1, f2);
    }

    #[test]
    fn frame_mark_ce_sets_bits_and_keeps_ipv4_checksum_valid() {
        let mut f = ipv4_frame(0b10, 6, &tcp_segment(10, 0x18), true);
        assert!(ipv4_header_checksum_valid(&f));
        assert!(frame_mark_ce(&mut f));
        assert_eq!(f[14 + 1] & 0b11, 0b11);
        assert!(
            ipv4_header_checksum_valid(&f),
            "incremental update must keep header checksum valid"
        );
        // Already-CE and Not-ECT are not markable.
        assert!(!frame_mark_ce(&mut f));
        let mut notect = ipv4_frame(0, 6, &tcp_segment(10, 0x18), true);
        assert!(!frame_mark_ce(&mut notect));
    }

    #[test]
    fn pending_scheduler_prioritizes_control_over_data() {
        let mut sched = Scheduler::new(None, AF_XDP_EGRESS_OVERHEAD_BYTES);
        let mut pending: std::collections::HashMap<
            u64,
            std::collections::VecDeque<PendingTx>,
        > = std::collections::HashMap::new();
        let mut total = 0usize;
        let now = TransportInstant::from_micros(1_000);
        let link = AfXdpLinkMeta {
            destination_mac: [0xaa; 6],
            source_mac: [0xbb; 6],
            vlan_tags: [
                AfXdpVlanTag { tpid: 0, tci: 0 },
                AfXdpVlanTag { tpid: 0, tci: 0 },
            ],
            vlan_tag_count: 0,
            ethertype: 0x0800,
        };
        let data = PendingTx::udp(
            link,
            "10.0.0.1:443".parse().unwrap(),
            "10.0.0.2:1000".parse().unwrap(),
            bytes::Bytes::from_static(b"data"),
            None,
            now.micros(),
        );
        // Control-tier frame: pure TCP ACK.
        let ctrl = PendingTx::frame(
            ipv4_frame(0, 6, &tcp_segment(0, 0x10), false),
            now.micros(),
        );
        // Enqueue data first — scheduler must still pick control first.
        assert!(queue_deferred_tx(
            &mut pending, &mut total, &mut sched, now, data
        ));
        assert!(queue_deferred_tx(
            &mut pending, &mut total, &mut sched, now, ctrl
        ));
        let first = sched.next(now).expect("eligible flow");
        let head = pending[&first].front().expect("queued");
        assert_eq!(head.tier, 0, "control tier wins over earlier data");
    }

    #[test]
    fn codel_drops_sojourn_overdue_notect_and_marks_ect() {
        // Same sojourn profile, one instance per ECN policy: Not-ECT
        // must hit the drop schedule; ECT must be CE-marked instead.
        for (ecn, expect, forbidden) in [
            (0u8, CodelAction::Drop, CodelAction::MarkCe),
            (2u8, CodelAction::MarkCe, CodelAction::Drop),
        ] {
            let mut codel = Codel::new(DEFAULT_TARGET, DEFAULT_INTERVAL);
            let mut saw = false;
            for i in 0..60u64 {
                let t = i * 10_000; // 10ms dequeue cadence
                let action = codel.dequeue(
                    TransportInstant::from_micros(t),
                    Stamp {
                        enqueued_at: TransportInstant::from_micros(
                            t.saturating_sub(20_000),
                        ),
                        ecn,
                    },
                    false,
                );
                assert_ne!(
                    action, forbidden,
                    "AQM policy must never cross (ecn={ecn} i={i})"
                );
                saw |= action == expect;
            }
            assert!(saw, "ecn={ecn}: sustained >target sojourn never triggered the AQM");
        }
    }

    #[test]
    fn pending_queue_sheds_at_cap_and_counts() {
        let mut sched = Scheduler::new(None, AF_XDP_EGRESS_OVERHEAD_BYTES);
        let mut pending: std::collections::HashMap<
            u64,
            std::collections::VecDeque<PendingTx>,
        > = std::collections::HashMap::new();
        let mut total = 0usize;
        let now = TransportInstant::from_micros(1_000);
        let link = AfXdpLinkMeta {
            destination_mac: [0xaa; 6],
            source_mac: [0xbb; 6],
            vlan_tags: [
                AfXdpVlanTag { tpid: 0, tci: 0 },
                AfXdpVlanTag { tpid: 0, tci: 0 },
            ],
            vlan_tag_count: 0,
            ethertype: 0x0800,
        };
        for i in 0..AF_XDP_TX_RETRY_CAP {
            let peer: SocketAddr = format!("10.0.0.2:{}", 1000 + i).parse().unwrap();
            let p = PendingTx::udp(
                link,
                "10.0.0.1:443".parse().unwrap(),
                peer,
                bytes::Bytes::from_static(b"x"),
                None,
                now.micros(),
            );
            assert!(queue_deferred_tx(
                &mut pending, &mut total, &mut sched, now, p
            ));
        }
        let overflow = PendingTx::udp(
            link,
            "10.0.0.1:443".parse().unwrap(),
            "10.0.0.2:9999".parse().unwrap(),
            bytes::Bytes::from_static(b"x"),
            None,
            now.micros(),
        );
        assert!(
            !queue_deferred_tx(&mut pending, &mut total, &mut sched, now, overflow),
            "cap must shed — counted by caller"
        );
        assert_eq!(total, AF_XDP_TX_RETRY_CAP);
    }
}
