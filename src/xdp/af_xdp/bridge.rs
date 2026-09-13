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

/// Per-queue reactor context shared at spawn time.
#[cfg(target_os = "linux")]
pub(crate) struct AfXdpQueueCtx {
    pub(crate) downstream_tx: mpsc::Sender<crate::udp_proxy::DownstreamUdpDatagram>,
    pub(crate) downstream_rx: mpsc::Receiver<crate::udp_proxy::DownstreamUdpDatagram>,
    pub(crate) fwd_rx: mpsc::Receiver<AfXdpForward>,
    /// Route cache shared by all queue threads: ingress on queue A may be
    /// answered by the demux/H3 endpoint on queue B's channel, so lookups
    /// must see every queue's learned L2 routes.
    pub(crate) udp_routes: Arc<DashMap<(SocketAddr, SocketAddr), AfXdpUdpRouteEntry>>,
    /// QUIC DCIDs this bridge has pinned to an XSK queue, mirrored from the
    /// eBPF XDP_QUIC_DCID map for idle-expiry sweeping.
    pub(crate) quic_dcid_steers:
        Arc<DashMap<cloud_node_xdp_common::XdpQuicDcidKey, u64>>,
    /// First channel per interface for cross-interface forwarding.
    pub(crate) iface_fwd: Arc<HashMap<String, mpsc::Sender<AfXdpForward>>>,
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
    if !manager.config.enabled {
        return;
    }
    if !XDP_PROXY_DATAPLANE_ACTIVE {
        manager.set_proxy_fallback_reason(
            "AF_XDP UDP bridge is compiled but TX dataplane is not active; traffic will PASS",
        );
        return;
    }
    #[cfg(target_os = "linux")]
    run_proxy_bridge(manager, quic_demux, tcp_manager, http_manager).await;
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
    match manager.enable_proxy_redirect("AF_XDP proxy bridge") {
        Ok(true) => {
            let message = format!(
                "AF_XDP proxy bridge enabled redirect for {} configured proxy ports",
                manager.config.proxy.ports.len()
            );
            tracing::info!("{message}");
            crate::logging::report_node_log(
                "info".to_string(),
                "xdp_proxy".to_string(),
                message,
                0,
            );
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
            return;
        }
    }

    // Per-queue reactor threads: each AF_XDP queue is owned by a dedicated
    // CPU-pinned OS thread running an isolated smoltcp reactor. The shared
    // af_xdp mutex and single poll loop are removed from the dataplane;
    // RSS flow-to-queue affinity keeps flows on one reactor.
    let queue_handles = {
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
        let message =
            "AF_XDP proxy bridge has no AF_XDP queues; proxy redirect disabled, traffic will PASS"
                .to_string();
        tracing::warn!("{message}");
        manager.disable_proxy_redirect_for_fallback(message);
        return;
    }
    spawn_queue_reactors(&manager, queue_handles, quic_demux, tcp_manager, http_manager).await;
}

/// Spawn one pinned OS thread per AF_XDP queue and watch them: any reactor
/// exiting while the bridge should still be alive disables proxy redirect
/// so traffic falls back to kernel listeners explicitly.
#[cfg(target_os = "linux")]
pub(crate) async fn spawn_queue_reactors(
    manager: &Arc<XdpManager>,
    queue_handles: Vec<linux::AfXdpQueueHandle>,
    quic_demux: Arc<crate::quic_udp_demux::QuicUdpDemuxManager>,
    tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
    http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
) {
    pub(crate) const AF_XDP_DOWNSTREAM_QUEUE: usize = 4096;

    let online_cpus = num_cpus::get().max(1);
    let udp_routes = Arc::new(DashMap::new());
    let quic_dcid_steers = Arc::new(DashMap::new());
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
        iface_fwd
            .entry(queue_handle.interface.clone())
            .or_insert(fwd_tx);
        contexts.push(AfXdpQueueCtx {
            downstream_tx,
            downstream_rx,
            fwd_rx,
            udp_routes: udp_routes.clone(),
            quic_dcid_steers: quic_dcid_steers.clone(),
            iface_fwd: Arc::new(HashMap::new()),
        });
    }
    let iface_fwd = Arc::new(iface_fwd);
    for ctx in &mut contexts {
        ctx.iface_fwd = iface_fwd.clone();
    }
    let mut joins: Vec<std::thread::JoinHandle<()>> =
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
        let reactor_manager = manager.clone();
        let quic_demux = quic_demux.clone();
        let tcp_manager = tcp_manager.clone();
        let http_manager = http_manager.clone();
        let name = thread_name.clone();
        let join = match std::thread::Builder::new().name(thread_name).spawn(move || {
            if !pin_current_thread_to_cpu(cpu) {
                tracing::warn!("{name}: failed to pin reactor thread to cpu {cpu}");
            }
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt.block_on(run_queue_bridge_loop(
                    reactor_manager,
                    queue_handle,
                    ctx,
                    quic_demux,
                    tcp_manager,
                    http_manager,
                )),
                Err(err) => {
                    tracing::error!("{name}: failed to build reactor runtime: {err}")
                }
            }
        }) {
            Ok(join) => join,
            Err(err) => {
                manager.disable_proxy_redirect_for_fallback(format!(
                    "AF_XDP proxy bridge failed to spawn reactor thread: {err}; proxy redirect disabled, traffic will PASS"
                ));
                for join in joins {
                    let _ = join.join();
                }
                return;
            }
        };
        joins.push(join);
    }
    tracing::info!(
        "AF_XDP proxy bridge running {} per-queue reactor threads",
        joins.len()
    );

    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if joins.iter().all(|join| join.is_finished()) {
            return;
        }
        if joins.iter().any(|join| join.is_finished())
            && proxy_bridge_should_continue(manager)
        {
            manager.disable_proxy_redirect_for_fallback(
                "AF_XDP queue reactor thread exited unexpectedly; proxy redirect disabled, traffic will PASS"
                    .to_string(),
            );
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) async fn run_queue_bridge_loop(
    manager: Arc<XdpManager>,
    mut queue_handle: linux::AfXdpQueueHandle,
    ctx: AfXdpQueueCtx,
    quic_demux: Arc<crate::quic_udp_demux::QuicUdpDemuxManager>,
    tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
    http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
) {
    pub(crate) const AF_XDP_DOWNSTREAM_DRAIN_BUDGET: usize = 1024;
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
        udp_routes,
        quic_dcid_steers,
        iface_fwd,
    } = ctx;
    let own_interface = queue_handle.interface.clone();
    let own_ifindex = linux::ifindex_from_name(&own_interface).unwrap_or(0);
    let mut quic_dcid_map_unavailable = false;
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut idle_backoff = AF_XDP_IDLE_BACKOFF_MIN;
    let mut last_route_cache_sweep_ms = crate::udp_proxy::udp_activity_now_ms();
    let mut tcp_reactor = AfXdpTcpReactor::new(tcp_manager, http_manager);
    let mut consecutive_poll_errors = 0u32;
    let mut tx_failures = AfXdpTxFailureTracker::new(AF_XDP_MAX_CONSECUTIVE_TX_FAILURES);
    let mut udp_ingress_failures =
        AfXdpTxFailureTracker::new(AF_XDP_MAX_CONSECUTIVE_UDP_INGRESS_FAILURES);
    let mut tcp_admission_failures =
        AfXdpTcpAdmissionFailureTracker::new(AF_XDP_MAX_CONSECUTIVE_TCP_ADMISSION_REFUSALS);
    let mut frames = Vec::with_capacity(64);
    let mut last_status_refresh = std::time::Instant::now();

    loop {
        if !proxy_bridge_should_continue(&manager) {
            let message =
                "AF_XDP proxy bridge exiting because XDP manager is stale or redirect is disabled"
                    .to_string();
            tracing::warn!("{message}");
            crate::logging::report_node_log(
                "warn".to_string(),
                "xdp_proxy".to_string(),
                message,
                0,
            );
            return;
        }
        if last_status_refresh.elapsed() >= AF_XDP_STATUS_REFRESH_INTERVAL {
            last_status_refresh = std::time::Instant::now();
            if let Ok(stats) = queue_handle.rx.fd().xdp_statistics() {
                manager.update_xsk_queue_status(
                    &queue_handle.interface,
                    queue_handle.queue,
                    |status| {
                        status.rx_dropped = stats.rx_dropped();
                        status.rx_invalid_descs = stats.rx_invalid_descs();
                        status.rx_ring_full = stats.rx_ring_full();
                        status.tx_invalid_descs = stats.tx_invalid_descs();
                    },
                );
            }
        }
        frames.clear();
        let poll_result = queue_handle.poll_raw_once(&mut |interface, queue, frame| {
            frames.push((interface.to_string(), queue, frame));
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
                manager.set_proxy_fallback_reason(detail.clone());
                tracing::warn!("{}", detail);
                if consecutive_poll_errors >= AF_XDP_MAX_CONSECUTIVE_POLL_ERRORS {
                    manager.disable_proxy_redirect_for_fallback(format!(
                        "AF_XDP proxy bridge poll failed repeatedly: {err}; proxy redirect disabled, traffic will PASS"
                    ));
                    return;
                }
                std::thread::sleep(idle_backoff);
                continue;
            }
        };
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
            let mut expired_dcids = Vec::new();
            quic_dcid_steers.retain(|key, last_seen_ms| {
                if now_ms.saturating_sub(*last_seen_ms)
                    >= AF_XDP_ROUTE_CACHE_IDLE_TIMEOUT.as_millis() as u64
                {
                    expired_dcids.push(*key);
                    return false;
                }
                true
            });
            for key in expired_dcids {
                manager.remove_quic_dcid(&key);
            }
            last_route_cache_sweep_ms = now_ms;
        }

        for (interface, queue, frame) in frames.drain(..) {
            if let Some((flow, flags)) = parse_tcp_flow_flags_from_frame(&frame)
                && tcp_reactor.should_ignore_unknown_non_syn(&flow, flags)
            {
                tcp_reactor.record_ignored_unknown_non_syn(flow, frame.len());
                continue;
            }
            match parse_proxy_frame(&interface, queue, &frame) {
                Some(AfXdpProxyFrame::Udp { route, packet }) => {
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
                    // Long-header QUIC packets encode their DCID length,
                    // so the eBPF program can steer them. Pin this flow's
                    // DCID to this queue's XSK so retransmissions and
                    // handshake traffic stay on the owning reactor.
                    if own_ifindex != 0
                        && packet.payload.first().is_some_and(|b| b & 0x80 != 0)
                        && let Some(cids) =
                            crate::quic_probe::quic_packet_cids(&packet.payload, 0)
                        && let Some(dkey) =
                            cloud_node_xdp_common::XdpQuicDcidKey::new(&cids.dcid)
                    {
                        match quic_dcid_steers.get_mut(&dkey) {
                            Some(mut seen) => *seen = now_ms,
                            None => {
                                if manager.upsert_quic_dcid(
                                    &cids.dcid,
                                    own_ifindex,
                                    queue_handle.queue,
                                ) {
                                    quic_dcid_steers.insert(dkey, now_ms);
                                } else if !quic_dcid_map_unavailable {
                                    quic_dcid_map_unavailable = true;
                                    tracing::warn!(
                                        "AF_XDP QUIC DCID steering unavailable (eBPF object lacks XDP_QUIC_DCID or XSK index for {} queue {}); RSS queue affinity remains the fallback",
                                        own_interface,
                                        queue_handle.queue
                                    );
                                }
                            }
                        }
                    }
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
                            tracing::debug!("AF_XDP proxy bridge upstream session queue full");
                            if udp_ingress_failures.record(AfXdpTxStatus::Backpressured) {
                                manager.disable_proxy_redirect_for_fallback(format!(
                                    "AF_XDP UDP ingress queues stayed full for {AF_XDP_MAX_CONSECUTIVE_UDP_INGRESS_FAILURES} redirected datagrams; proxy redirect disabled, traffic will PASS"
                                ));
                                return;
                            }
                        }
                        Ok(crate::udp_proxy::UdpIngressDatagramStatus::Closed) => {
                            tracing::debug!("AF_XDP proxy bridge upstream session closed");
                            if udp_ingress_failures.record(AfXdpTxStatus::Failed) {
                                manager.disable_proxy_redirect_for_fallback(format!(
                                    "AF_XDP UDP ingress sessions stayed closed for {AF_XDP_MAX_CONSECUTIVE_UDP_INGRESS_FAILURES} redirected datagrams; proxy redirect disabled, traffic will PASS"
                                ));
                                return;
                            }
                        }
                        Err(err) => {
                            tracing::debug!(
                                "AF_XDP proxy bridge failed to process datagram: {}",
                                err
                            );
                            if udp_ingress_failures.record(AfXdpTxStatus::Failed) {
                                manager.disable_proxy_redirect_for_fallback(format!(
                                    "AF_XDP UDP ingress failed repeatedly after {AF_XDP_MAX_CONSECUTIVE_UDP_INGRESS_FAILURES} redirected datagrams: {err}; proxy redirect disabled, traffic will PASS"
                                ));
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
                    let status = tcp_reactor.ingest(route, flow, ip_packet);
                    if tcp_admission_failures.record(status) {
                        manager.disable_proxy_redirect_for_fallback(format!(
                            "AF_XDP TCP reactor refused {AF_XDP_MAX_CONSECUTIVE_TCP_ADMISSION_REFUSALS} new sessions consecutively; proxy redirect disabled, traffic will PASS"
                        ));
                        return;
                    }
                }
                None => {
                    tracing::debug!(
                        "AF_XDP proxy bridge received unparseable redirected frame interface={} queue={} bytes={}",
                        interface,
                        queue,
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
                match iface_fwd.get(&route.interface) {
                    Some(tx) => match tx.try_send(AfXdpForward::Udp(datagram)) {
                        Ok(()) => continue,
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            tracing::warn!(
                                "AF_XDP proxy bridge forward channel to interface {} is full; dropping downstream datagram",
                                route.interface
                            );
                            if tx_failures.record(AfXdpTxStatus::Backpressured) {
                                manager.disable_proxy_redirect_for_fallback(format!(
                                    "AF_XDP cross-interface forward channel stayed full for {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} datagrams; proxy redirect disabled, traffic will PASS"
                                ));
                                return;
                            }
                            continue;
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            tracing::warn!(
                                "AF_XDP proxy bridge forward channel to interface {} is closed",
                                route.interface
                            );
                            continue;
                        }
                    },
                    None => {
                        tracing::warn!(
                            "AF_XDP proxy bridge has no reactor channel for route interface {}; dropping downstream datagram",
                            route.interface
                        );
                        continue;
                    }
                }
            }
            let sent = queue_handle.send_udp_datagram(
                &route.link,
                datagram.listen_addr,
                datagram.peer_addr,
                datagram.payload.as_ref(),
            );
            match sent {
                Ok(true) => {
                    tx_failures.record(AfXdpTxStatus::Sent);
                }
                Ok(false) => {
                    tracing::debug!(
                        "AF_XDP proxy bridge could not send downstream datagram listen={} peer={} bytes={}",
                        datagram.listen_addr,
                        datagram.peer_addr,
                        datagram.payload.len()
                    );
                    if tx_failures.record(AfXdpTxStatus::Backpressured) {
                        manager.disable_proxy_redirect_for_fallback(format!(
                            "AF_XDP proxy bridge TX backpressure repeated {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} times; proxy redirect disabled, traffic will PASS"
                        ));
                        return;
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
                        manager.disable_proxy_redirect_for_fallback(format!(
                            "AF_XDP proxy bridge TX failed repeatedly after {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} attempts: {err}; proxy redirect disabled, traffic will PASS"
                        ));
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
            let sent = match fwd {
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
                    queue_handle.send_udp_datagram(
                        &route.link,
                        datagram.listen_addr,
                        datagram.peer_addr,
                        datagram.payload.as_ref(),
                    )
                }
                AfXdpForward::TcpFrame(frame) => queue_handle.send_raw_frame(&frame),
            };
            match sent {
                Ok(true) => {
                    tx_failures.record(AfXdpTxStatus::Sent);
                }
                Ok(false) => {
                    if tx_failures.record(AfXdpTxStatus::Backpressured) {
                        manager.disable_proxy_redirect_for_fallback(format!(
                            "AF_XDP forwarded TX backpressure repeated {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} times; proxy redirect disabled, traffic will PASS"
                        ));
                        return;
                    }
                }
                Err(err) => {
                    tracing::debug!("AF_XDP forwarded TX failed: {err}");
                    if tx_failures.record(AfXdpTxStatus::Failed) {
                        manager.disable_proxy_redirect_for_fallback(format!(
                            "AF_XDP forwarded TX failed repeatedly after {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} attempts: {err}; proxy redirect disabled, traffic will PASS"
                        ));
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
            let Some(frame) = tcp_reactor.encode_egress_frame(&route, &ip_packet) else {
                tracing::debug!(
                    "AF_XDP TCP reactor failed to encode egress frame interface={} queue={} bytes={}",
                    route.interface,
                    route.queue,
                    ip_packet.len()
                );
                continue;
            };
            if route.interface != own_interface {
                if let Some(tx) = iface_fwd.get(&route.interface) {
                    let _ = tx.try_send(AfXdpForward::TcpFrame(frame));
                }
                continue;
            }
            let sent = queue_handle.send_raw_frame(&frame);
            match sent {
                Ok(true) => {
                    tx_failures.record(AfXdpTxStatus::Sent);
                }
                Ok(false) => {
                    tracing::debug!(
                        "AF_XDP TCP reactor could not send frame interface={} queue={} bytes={}",
                        route.interface,
                        route.queue,
                        frame.len()
                    );
                    if tx_failures.record(AfXdpTxStatus::Backpressured) {
                        manager.disable_proxy_redirect_for_fallback(format!(
                            "AF_XDP TCP reactor TX backpressure repeated {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} times; proxy redirect disabled, traffic will PASS"
                        ));
                        return;
                    }
                }
                Err(err) => {
                    tracing::debug!(
                        "AF_XDP TCP reactor TX failed interface={} queue={} bytes={}: {}",
                        route.interface,
                        route.queue,
                        frame.len(),
                        err
                    );
                    if tx_failures.record(AfXdpTxStatus::Failed) {
                        manager.disable_proxy_redirect_for_fallback(format!(
                            "AF_XDP TCP reactor TX failed repeatedly after {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} attempts: {err}; proxy redirect disabled, traffic will PASS"
                        ));
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

