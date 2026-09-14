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
    // EN-12 worker lease: prove every reactor is running *before* opening
    // redirect — a registered XSK is a socket, not a worker. Redirecting
    // into an XSK nobody drains would silently drop every proxied packet.
    spawn_queue_reactors(
        &manager,
        queue_handles,
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
    quic_demux: Arc<crate::quic_udp_demux::QuicUdpDemuxManager>,
    tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
    http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
) {
    pub(crate) const AF_XDP_DOWNSTREAM_QUEUE: usize = 4096;
    pub(crate) const AF_XDP_WORKER_READY_TIMEOUT: Duration = Duration::from_secs(10);

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
                        ))
                    }
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
            return;
        }
        if proxy_bridge_should_continue(manager) {
            // EN-05: a dead reactor withdraws only its own queue — the
            // queue's XSK slots are removed so its traffic takes the
            // explicit dataplane fallback while sibling queues keep
            // serving. A queue's fault must not widen globally.
            for (interface, queue, join) in &joins {
                // Skip queues the worker already withdrew itself — its
                // original fault detail is more precise than a generic
                // "thread exited" reason.
                if join.is_finished()
                    && reported_dead.insert((interface.clone(), *queue))
                    && !manager.xsk_queue_faulted(interface, *queue)
                {
                    manager.disable_queue_redirect_for_fault(
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
    manager: Arc<XdpManager>,
    mut queue_handle: linux::AfXdpQueueHandle,
    ctx: AfXdpQueueCtx,
    quic_demux: Arc<crate::quic_udp_demux::QuicUdpDemuxManager>,
    tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
    http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
    tcp_session_limit: usize,
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
    let mut tcp_reactor =
        AfXdpTcpReactor::new_with_session_limit(tcp_manager, http_manager, tcp_session_limit);
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
            let stats = queue_handle.rx.fd().xdp_statistics().ok();
            manager.update_xsk_queue_status(
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
                },
            );
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
                    manager.disable_queue_redirect_for_fault(
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
                            congested = true;
                            if udp_ingress_failures.record(AfXdpTxStatus::Backpressured) {
                                manager.disable_queue_redirect_for_fault(
                                    &own_interface,
                                    queue_handle.queue,
                                    format!(
                                        "AF_XDP UDP ingress queues stayed full for {AF_XDP_MAX_CONSECUTIVE_UDP_INGRESS_FAILURES} redirected datagrams"
                                    ),
                                );
                                return;
                            }
                        }
                        Ok(crate::udp_proxy::UdpIngressDatagramStatus::Closed) => {
                            tracing::debug!("AF_XDP proxy bridge upstream session closed");
                            if udp_ingress_failures.record(AfXdpTxStatus::Failed) {
                                manager.disable_queue_redirect_for_fault(
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
                                manager.disable_queue_redirect_for_fault(
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
                    // Congestion gate: unknown non-SYN packets were already
                    // dropped above, so reaching here without a session means
                    // a new SYN — refuse it while the queue is backpressured.
                    if congested && !tcp_reactor.has_session(&flow) {
                        congested_drops = congested_drops.saturating_add(1);
                        continue;
                    }
                    let status = tcp_reactor.ingest(route, flow, ip_packet);
                    if tcp_admission_failures.record(status) {
                        manager.disable_queue_redirect_for_fault(
                            &own_interface,
                            queue_handle.queue,
                            format!(
                                "AF_XDP TCP reactor refused {AF_XDP_MAX_CONSECUTIVE_TCP_ADMISSION_REFUSALS} new sessions consecutively"
                            ),
                        );
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
                            congested = true;
                            if tx_failures.record(AfXdpTxStatus::Backpressured) {
                                manager.disable_queue_redirect_for_fault(
                                    &own_interface,
                                    queue_handle.queue,
                                    format!(
                                        "AF_XDP cross-interface forward channel stayed full for {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} datagrams"
                                    ),
                                );
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
                    congested = false;
                    tx_failures.record(AfXdpTxStatus::Sent);
                }
                Ok(false) => {
                    tracing::debug!(
                        "AF_XDP proxy bridge could not send downstream datagram listen={} peer={} bytes={}",
                        datagram.listen_addr,
                        datagram.peer_addr,
                        datagram.payload.len()
                    );
                    congested = true;
                    if tx_failures.record(AfXdpTxStatus::Backpressured) {
                        manager.disable_queue_redirect_for_fault(
                            &own_interface,
                            queue_handle.queue,
                            format!(
                                "AF_XDP proxy bridge TX backpressure repeated {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} times"
                            ),
                        );
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
                        manager.disable_queue_redirect_for_fault(
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
                    congested = false;
                    tx_failures.record(AfXdpTxStatus::Sent);
                }
                Ok(false) => {
                    congested = true;
                    if tx_failures.record(AfXdpTxStatus::Backpressured) {
                        manager.disable_queue_redirect_for_fault(
                            &own_interface,
                            queue_handle.queue,
                            format!(
                                "AF_XDP forwarded TX backpressure repeated {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} times"
                            ),
                        );
                        return;
                    }
                }
                Err(err) => {
                    tracing::debug!("AF_XDP forwarded TX failed: {err}");
                    if tx_failures.record(AfXdpTxStatus::Failed) {
                        manager.disable_queue_redirect_for_fault(
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
                    congested = false;
                    tx_failures.record(AfXdpTxStatus::Sent);
                }
                Ok(false) => {
                    tracing::debug!(
                        "AF_XDP TCP reactor could not send frame interface={} queue={} bytes={}",
                        route.interface,
                        route.queue,
                        frame.len()
                    );
                    congested = true;
                    if tx_failures.record(AfXdpTxStatus::Backpressured) {
                        manager.disable_queue_redirect_for_fault(
                            &own_interface,
                            queue_handle.queue,
                            format!(
                                "AF_XDP TCP reactor TX backpressure repeated {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} times"
                            ),
                        );
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
                        manager.disable_queue_redirect_for_fault(
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

