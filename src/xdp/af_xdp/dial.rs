use super::*;
use std::sync::atomic::{AtomicU32, AtomicUsize};

/// T4: requests delivered to a queue reactor on its bounded channel.
/// `Dial` carries a fully prepared outbound connect (route, source port,
/// XDP_OUT_CT row and demux ownership already registered); `InjectTcp`
/// carries a reply packet that arrived on a different queue than the
/// flow's owner — eBPF can only redirect into the ingress queue's XSK,
/// so cross-queue delivery is a userspace concern.
#[cfg(target_os = "linux")]
pub(crate) enum AfXdpReactorRequest {
    Dial(AfXdpTcpDialRequest),
    InjectTcp {
        route: AfXdpRouteMeta,
        flow: AfXdpTcpFlowKey,
        ip_packet: Bytes,
    },
    /// T4-6: node-dialed UDP egress — the socket crafts L3-less output by
    /// handing (link, endpoints, payload) to the owning queue, which
    /// emits a full frame through its XSK TX ring.
    UdpEgress {
        link: AfXdpLinkMeta,
        local: SocketAddr,
        remote: SocketAddr,
        payload: Bytes,
        /// ECN codepoint bits (0–3) requested by the sender — QUIC marks
        /// packets; plain UDP proxy traffic passes `None`.
        ecn: Option<u8>,
        /// Monotonic enqueue timestamp (`udp_activity_now_ms`) — the
        /// bridge reports channel age when it drains the request.
        enqueued_ms: u64,
    },
    /// T4-7: an ICMP error quoting this flow arrived on some queue's
    /// XSK — deliver the reported next-hop MTU to the owning session's
    /// smoltcp socket (`None` for error kinds without an MTU field).
    PmtuUpdate {
        flow: AfXdpTcpFlowKey,
        mtu: Option<u32>,
    },
}

/// T4: owner record for a node-dialed flow — the queue reactor holding
/// its smoltcp socket and the protocol the flow registered in
/// XDP_OUT_CT (needed so `release` removes the right map row).
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub(crate) struct AfXdpDialOwner {
    pub(crate) interface: Arc<str>,
    pub(crate) queue: u32,
    pub(crate) proto: u8,
    /// UDP dialed flows deliver reply payloads and quoted ICMP errors
    /// straight into the owning socket's channel — no reactor session
    /// exists for them.
    pub(crate) udp_tx: Option<mpsc::Sender<AfXdpUdpIngress>>,
}

/// T4: bridge between async upstream dialers and the per-queue AF_XDP
/// reactors. Owns the flow→owner demux table, the per-queue request
/// senders, and the reserved source-port span. Registration order in
/// `dial_tcp` is transactional: owner claim → XDP_OUT_CT insert →
/// reactor request; every failure path rolls back what it created, and
/// `release` (called on session reap) unwinds the rest.
#[cfg(target_os = "linux")]
pub(crate) struct AfXdpDialRegistry {
    /// F1: the manager generation that owns the live eBPF handle — used
    /// for out-CT map writes. Repointed at dataplane adoption so a reload
    /// never leaves dials writing through a detached generation.
    manager: parking_lot::RwLock<Arc<XdpManager>>,
    owners: DashMap<AfXdpTcpFlowKey, AfXdpDialOwner>,
    queues: DashMap<(String, u32), mpsc::Sender<AfXdpReactorRequest>>,
    port_cursor: AtomicU32,
    /// T4: resolved outbound routes (interface/source/MACs) keyed by
    /// target IP. `resolve_outbound_route` shells out to `ip` three
    /// times per call — tens of milliseconds — so each dial would pay
    /// ~100ms of pure process-spawn latency on top of the ~4ms wire RTT.
    /// Entries expire quickly and a dial timeout evicts the entry so a
    /// stale neighbor MAC self-heals on the next connect.
    route_cache: DashMap<IpAddr, AfXdpCachedRoute>,
    /// D-B1: reserved source-port span from `xdp.upstream.dialPortRange`
    /// (default 40000-49999), pinned in `ip_local_reserved_ports` by the
    /// dial guard before this registry is published.
    pub(crate) port_base: u16,
    pub(crate) port_span: u16,
}

/// T4: cached `resolve_outbound_route` result — the kernel answer is
/// reused across dials until the TTL lapses.
#[cfg(target_os = "linux")]
struct AfXdpCachedRoute {
    route: Arc<linux::XdpOutboundRoute>,
    expires_at: std::time::Instant,
}

/// T4: route-resolution freshness window — short enough that a neighbor
/// change surfaces quickly, long enough to collapse a connect burst to
/// one `ip`-tool resolution per target.
#[cfg(target_os = "linux")]
const AF_XDP_DIAL_ROUTE_CACHE_TTL: Duration = Duration::from_secs(5);

/// T4: hard bound on cached targets — a dial sweep across many backends
/// can never grow the map without limit.
#[cfg(target_os = "linux")]
const AF_XDP_DIAL_ROUTE_CACHE_MAX: usize = 4_096;

#[cfg(target_os = "linux")]
impl AfXdpDialRegistry {
    pub(crate) fn new(manager: Arc<XdpManager>) -> Self {
        let (port_base, port_end) = manager
            .config
            .upstream
            .as_ref()
            .map(|upstream| upstream.dial_port_range())
            .unwrap_or((AF_XDP_DIAL_PORT_BASE, 49_999));
        Self {
            manager: parking_lot::RwLock::new(manager),
            port_base,
            port_span: port_end.saturating_sub(port_base).saturating_add(1),
            owners: DashMap::new(),
            queues: DashMap::new(),
            route_cache: DashMap::new(),
            // Randomized start spreads the probe cursor so back-to-back
            // dials do not serialize on the same port order.
            port_cursor: AtomicU32::new(
                (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0))
                    .max(1),
            ),
        }
    }

    /// F1: repoint bookkeeping to the successor manager after dataplane
    /// adoption. Queue senders and owner entries are untouched — the
    /// workers sharing this registry never stopped.
    pub(crate) fn repoint(&self, manager: Arc<XdpManager>) {
        *self.manager.write() = manager;
    }

    /// Called once per queue reactor at spawn time. Stale senders are
    /// tolerated between reactor death and the next send attempt — a
    /// `Closed` send error self-cleans the entry, so the table stays
    /// bounded by the queue count.
    pub(crate) fn register_queue(
        &self,
        interface: &str,
        queue: u32,
        tx: mpsc::Sender<AfXdpReactorRequest>,
    ) {
        self.queues.insert((interface.to_string(), queue), tx);
    }

    /// Flow→owner lookup for the reply demux: `None` means the tuple was
    /// never dialed through AF_XDP and takes the normal accept path.
    pub(crate) fn owner(&self, flow: &AfXdpTcpFlowKey) -> Option<AfXdpDialOwner> {
        self.owners.get(flow).map(|entry| entry.clone())
    }

    /// Hand a reply packet to the owning reactor's request channel. The
    /// inject lands after the pending `Dial` on the same channel, so the
    /// session is guaranteed to exist when it is processed.
    pub(crate) fn inject(
        &self,
        owner: &AfXdpDialOwner,
        route: AfXdpRouteMeta,
        flow: AfXdpTcpFlowKey,
        ip_packet: Bytes,
    ) -> Result<(), AfXdpDialInjectError> {
        let key = (owner.interface.to_string(), owner.queue);
        let Some(tx) = self.queues.get(&key) else {
            // Owner reactor is gone — drop the entry so the flow reaps
            // instead of accumulating undeliverable replies.
            self.owners.remove(&flow);
            return Err(AfXdpDialInjectError::OwnerGone);
        };
        tx.try_send(AfXdpReactorRequest::InjectTcp {
            route,
            flow,
            ip_packet,
        })
        .map_err(|err| match err {
            mpsc::error::TrySendError::Full(_) => AfXdpDialInjectError::QueueFull,
            mpsc::error::TrySendError::Closed(_) => {
                self.queues.remove(&key);
                self.owners.remove(&flow);
                AfXdpDialInjectError::OwnerGone
            }
        })
    }

    /// T4-7: deliver a quoted ICMP error to a dialed flow's owner. TCP
    /// owners get a `PmtuUpdate` on the reactor channel; UDP owners get
    /// the error on the socket's ingress channel. A full channel sheds
    /// the report (the next RTO/timeout retries the path anyway);
    /// a closed channel tears the owner down like `inject`.
    pub(crate) fn notify_icmp(&self, flow: &AfXdpTcpFlowKey, mtu: Option<u32>) {
        let Some(owner) = self.owner(flow) else {
            return;
        };
        if owner.proto == IP_PROTO_UDP {
            if let Some(tx) = &owner.udp_tx {
                match tx.try_send(AfXdpUdpIngress::IcmpError { mtu }) {
                    Ok(()) => {}
                    // Bounded channel full — the socket is already
                    // overloaded; the error is dropped but stays
                    // observable instead of vanishing silently.
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        tracing::warn!(
                            "AF_XDP UDP ingress queue full; ICMP error (mtu={mtu:?}) dropped for {} -> {}",
                            flow.local_addr,
                            flow.peer_addr
                        );
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => self.release(flow),
                }
            }
            return;
        }
        let key = (owner.interface.to_string(), owner.queue);
        let Some(tx) = self.queues.get(&key) else {
            self.owners.remove(flow);
            return;
        };
        match tx.try_send(AfXdpReactorRequest::PmtuUpdate {
            flow: *flow,
            mtu,
        }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(
                    "AF_XDP reactor queue full; PmtuUpdate (mtu={mtu:?}) dropped for {} -> {}",
                    flow.local_addr,
                    flow.peer_addr
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.queues.remove(&key);
                self.owners.remove(flow);
            }
        }
    }

    /// Pick the owning queue for a new flow on `interface`: stable hash
    /// of the remote endpoint over the live queue set. Returns the queue
    /// id and its request sender.
    fn pick_queue(
        &self,
        interface: &str,
        remote: SocketAddr,
    ) -> Option<(u32, mpsc::Sender<AfXdpReactorRequest>)> {
        let mut ids: Vec<u32> = self
            .queues
            .iter()
            .filter(|entry| entry.key().0 == interface)
            .map(|entry| entry.key().1)
            .collect();
        if ids.is_empty() {
            return None;
        }
        ids.sort_unstable();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(&remote, &mut hasher);
        let queue = ids[(std::hash::Hasher::finish(&hasher) as usize) % ids.len()];
        self.queues
            .get(&(interface.to_string(), queue))
            .map(|entry| (queue, entry.value().clone()))
    }

    /// Claim a source port in the reserved span by inserting the flow
    /// into the owner table — the claim is the allocation, so a tuple can
    /// never be handed out twice. `preferred_port` (in-span) is tried
    /// first: UDP callers use it to preserve the kernel path's
    /// recent-upstream-port pinning semantics.
    pub(crate) fn claim_flow(
        &self,
        source: IpAddr,
        remote: SocketAddr,
        owner: &AfXdpDialOwner,
        preferred_port: Option<u16>,
    ) -> Option<AfXdpTcpFlowKey> {
        if let Some(port) = preferred_port
            && port >= self.port_base
            && port < self.port_base + self.port_span
        {
            let flow = AfXdpTcpFlowKey {
                local_addr: SocketAddr::new(source, port),
                peer_addr: remote,
            };
            if let dashmap::mapref::entry::Entry::Vacant(vacant) = self.owners.entry(flow) {
                vacant.insert(owner.clone());
                return Some(flow);
            }
        }
        let span = u32::from(self.port_span);
        let start = self.port_cursor.fetch_add(1, Ordering::Relaxed) % span;
        for i in 0..span {
            let port = self.port_base + ((start + i) % span) as u16;
            let flow = AfXdpTcpFlowKey {
                local_addr: SocketAddr::new(source, port),
                peer_addr: remote,
            };
            match self.owners.entry(flow) {
                dashmap::mapref::entry::Entry::Occupied(_) => continue,
                dashmap::mapref::entry::Entry::Vacant(vacant) => {
                    vacant.insert(owner.clone());
                    return Some(flow);
                }
            }
        }
        None
    }

    /// T4: route+neighbor resolution shared by TCP/UDP dials. Each
    /// uncached lookup spawns three `ip`-tool processes (route/neigh/link)
    /// — tens of milliseconds — which dominated the measured ~99ms dial
    /// latency over a ~4ms RTT. Fresh entries are served for
    /// AF_XDP_DIAL_ROUTE_CACHE_TTL; a dial timeout evicts the entry so a
    /// stale next-hop MAC re-resolves on the next connect.
    async fn resolve_route_cached(
        &self,
        target: IpAddr,
        remote: SocketAddr,
    ) -> io::Result<Arc<linux::XdpOutboundRoute>> {
        let now = std::time::Instant::now();
        if let Some(entry) = self.route_cache.get(&target)
            && entry.expires_at > now
        {
            return Ok(entry.route.clone());
        }
        let route = tokio::task::spawn_blocking(move || linux::resolve_outbound_route(target))
            .await
            .map_err(|err| {
                io::Error::other(format!("AF_XDP route resolution task failed: {err}"))
            })?
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("AF_XDP dial to {remote}: route resolution failed: {err}"),
                )
            })?;
        let route = Arc::new(route);
        if self.route_cache.len() >= AF_XDP_DIAL_ROUTE_CACHE_MAX {
            self.route_cache
                .retain(|_, entry| entry.expires_at > now);
            if self.route_cache.len() >= AF_XDP_DIAL_ROUTE_CACHE_MAX
                && let Some(oldest) = self
                    .route_cache
                    .iter()
                    .min_by_key(|entry| entry.expires_at)
                    .map(|entry| *entry.key())
            {
                self.route_cache.remove(&oldest);
            }
        }
        self.route_cache.insert(
            target,
            AfXdpCachedRoute {
                route: route.clone(),
                expires_at: now + AF_XDP_DIAL_ROUTE_CACHE_TTL,
            },
        );
        Ok(route)
    }

    /// Node-originated TCP connect through the AF_XDP dataplane. Fails
    /// explicitly on route/neighbor failure, missing reactor, port-span
    /// exhaustion, map insert failure, or a full request queue — there is
    /// no silent kernel-path fallback.
    pub(crate) async fn dial_tcp(
        &self,
        remote: SocketAddr,
        syn_extra_options: Vec<u8>,
    ) -> io::Result<AfXdpTcpStream> {
        let target = remote.ip();
        let route = self.resolve_route_cached(target, remote).await?;
        if route.source.is_ipv4() != remote.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "AF_XDP dial to {remote}: resolved source {} has a different address family",
                    route.source
                ),
            ));
        }
        let interface: Arc<str> = Arc::from(route.interface.as_str());
        let (queue, request_tx) = self.pick_queue(&interface, remote).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                format!(
                    "AF_XDP dial to {remote}: no live reactor queue on interface {interface}"
                ),
            )
        })?;
        let owner = AfXdpDialOwner {
            interface: interface.clone(),
            queue,
            proto: IP_PROTO_TCP,
            udp_tx: None,
        };
        let Some(flow) = self.claim_flow(route.source, remote, &owner, None) else {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!(
                    "AF_XDP dial to {remote}: reserved source-port span {}..{} exhausted",
                    self.port_base,
                    self.port_base + self.port_span - 1
                ),
            ));
        };
        // Rollback helper: every failure past this point must release the
        // flow claim (and the XDP_OUT_CT row once it exists) so failed
        // dials leak no state.
        macro_rules! bail {
            ($kind:expr, $($arg:tt)*) => {{
                self.rollback(&flow);
                return Err(io::Error::new($kind, format!($($arg)*)));
            }};
        }
        let Some(ct_key) = linux::out_ct_key(flow.local_addr, flow.peer_addr, IP_PROTO_TCP) else {
            bail!(
                io::ErrorKind::InvalidInput,
                "AF_XDP dial {} -> {}: address-family mismatch",
                flow.local_addr,
                flow.peer_addr
            );
        };
        if let Err(err) = self.manager.read().upsert_out_ct(ct_key) {
            bail!(
                io::ErrorKind::Other,
                "AF_XDP dial {} -> {}: XDP_OUT_CT insert failed: {err}",
                flow.local_addr,
                flow.peer_addr
            );
        }
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let request = AfXdpTcpDialRequest {
            remote,
            local: flow.local_addr,
            route: AfXdpRouteMeta {
                interface,
                queue,
                link: AfXdpLinkMeta {
                    // Link-meta fields follow the inbound-wire convention
                    // (`encode_reply_eth_header` emits source_mac as the
                    // frame destination): for a dialed flow the next hop
                    // is our "peer", our own MAC is the "destination".
                    destination_mac: route.source_mac,
                    source_mac: route.destination_mac,
                    vlan_tags: [AfXdpVlanTag { tpid: 0, tci: 0 }; 2],
                    vlan_tag_count: 0,
                    ethertype: if remote.is_ipv4() {
                        ETHERTYPE_IPV4
                    } else {
                        ETHERTYPE_IPV6
                    },
                },
            },
            syn_extra_options,
            reply: reply_tx,
        };
        if let Err(err) = request_tx.try_send(AfXdpReactorRequest::Dial(request)) {
            bail!(
                io::ErrorKind::WouldBlock,
                "AF_XDP dial {} -> {}: reactor request queue {}:{} unavailable: {err}",
                flow.local_addr,
                flow.peer_addr,
                owner.interface,
                owner.queue
            );
        }
        match reply_rx.await {
            Ok(Ok(stream)) => Ok(stream),
            // Reactor refused admission (duplicate/session limit/SYN
            // options/connect error) — the claim and CT row unwind here;
            // once the dial succeeds, reap-time `release` owns cleanup.
            Ok(Err(err)) => {
                self.rollback(&flow);
                // A connect timeout is the one failure consistent with a
                // stale cached next-hop MAC (frames black-holed at L2) —
                // drop the entry so the next dial re-resolves. Refusals
                // prove the L2 path works (the RST arrived) and keep it.
                if err.kind() == io::ErrorKind::TimedOut {
                    self.route_cache.remove(&target);
                }
                Err(err)
            }
            Err(_) => {
                self.rollback(&flow);
                Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!(
                        "AF_XDP dial {} -> {}: reactor dropped the request",
                        flow.local_addr, flow.peer_addr
                    ),
                ))
            }
        }
    }

    /// T4-6: node-originated UDP "connect" through the AF_XDP dataplane.
    /// No handshake exists, so the returned socket is live immediately:
    /// egress frames are emitted by the owning queue via `UdpEgress`
    /// requests, and replies are delivered through `udp_tx` on the owner
    /// record by whichever queue received them. Same explicit-failure
    /// contract as `dial_tcp` — no silent kernel fallback.
    pub(crate) async fn dial_udp(
        self: &std::sync::Arc<Self>,
        remote: SocketAddr,
        preferred_port: Option<u16>,
    ) -> io::Result<AfXdpUdpSocket> {
        let target = remote.ip();
        let route = self.resolve_route_cached(target, remote).await?;
        if route.source.is_ipv4() != remote.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "AF_XDP UDP dial to {remote}: resolved source {} has a different address family",
                    route.source
                ),
            ));
        }
        let interface: Arc<str> = Arc::from(route.interface.as_str());
        let (queue, egress_tx) = self.pick_queue(&interface, remote).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                format!(
                    "AF_XDP UDP dial to {remote}: no live reactor queue on interface {interface}"
                ),
            )
        })?;
        let (udp_tx, ingress_rx) = mpsc::channel(AF_XDP_UDP_DIAL_INGRESS_QUEUE);
        let owner = AfXdpDialOwner {
            interface,
            queue,
            proto: IP_PROTO_UDP,
            udp_tx: Some(udp_tx),
        };
        let Some(flow) = self.claim_flow(route.source, remote, &owner, preferred_port) else {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!(
                    "AF_XDP UDP dial to {remote}: reserved source-port span {}..{} exhausted",
                    self.port_base,
                    self.port_base + self.port_span - 1
                ),
            ));
        };
        let Some(ct_key) = linux::out_ct_key(flow.local_addr, flow.peer_addr, IP_PROTO_UDP) else {
            self.rollback(&flow);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "AF_XDP UDP dial {} -> {}: address-family mismatch",
                    flow.local_addr, flow.peer_addr
                ),
            ));
        };
        if let Err(err) = self.manager.read().upsert_out_ct(ct_key) {
            self.rollback(&flow);
            return Err(io::Error::other(format!(
                "AF_XDP UDP dial {} -> {}: XDP_OUT_CT insert failed: {err}",
                flow.local_addr, flow.peer_addr
            )));
        }
        Ok(AfXdpUdpSocket {
            flow,
            link: AfXdpLinkMeta {
                // Same wire-direction convention as the TCP dial path.
                destination_mac: route.source_mac,
                source_mac: route.destination_mac,
                vlan_tags: [AfXdpVlanTag { tpid: 0, tci: 0 }; 2],
                vlan_tag_count: 0,
                ethertype: if remote.is_ipv4() {
                    ETHERTYPE_IPV4
                } else {
                    ETHERTYPE_IPV6
                },
            },
            egress_tx,
            ingress_rx: std::sync::Mutex::new(ingress_rx),
            registry: self.clone(),
            path_mtu: AtomicUsize::new(0),
        })
    }

    /// Reap-time cleanup: drop the owner claim and the XDP_OUT_CT row so
    /// post-close replies fall back to the kernel path. Removal failure
    /// is logged — the row expires with the map, and replies to it simply
    /// reach a closed socket.
    pub(crate) fn release(&self, flow: &AfXdpTcpFlowKey) {
        let Some((_, owner)) = self.owners.remove(flow) else {
            return;
        };
        if let Some(key) = linux::out_ct_key(flow.local_addr, flow.peer_addr, owner.proto)
            && let Err(err) = self.manager.read().remove_out_ct(&key)
        {
            tracing::warn!(
                "AF_XDP dial release failed to remove XDP_OUT_CT row local={} peer={}: {err}",
                flow.local_addr,
                flow.peer_addr
            );
        }
    }

    /// Transactional rollback for `dial_tcp`: `release` drops the owner
    /// claim and the XDP_OUT_CT row; both are idempotent so pre- and
    /// post-insert failures share the same unwind.
    fn rollback(&self, flow: &AfXdpTcpFlowKey) {
        self.release(flow);
    }

    /// Generation teardown: remove every registered flow's XDP_OUT_CT
    /// row and pending owner so a withdrawn bridge leaves no rows
    /// steering replies into dead XSK queues. Removal errors are logged,
    /// never swallowed silently.
    pub(crate) fn drain(&self) {
        let flows: Vec<AfXdpTcpFlowKey> =
            self.owners.iter().map(|entry| *entry.key()).collect();
        for flow in &flows {
            self.release(flow);
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for AfXdpDialRegistry {
    fn drop(&mut self) {
        // Last-resort cleanup — explicit `drain` via set_dial_registry is
        // the normal path; Drop catches a registry dropped without swap.
        self.drain();
    }
}

/// T4: why a demux inject failed — both cases drop the packet; the owner
/// being gone also tears down the registration.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AfXdpDialInjectError {
    OwnerGone,
    QueueFull,
}

#[cfg(target_os = "linux")]
impl std::fmt::Debug for AfXdpDialRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AfXdpDialRegistry")
            .field("flows", &self.owners.len())
            .field("queues", &self.queues.len())
            .finish()
    }
}

/// T4-6: bounded per-socket reply channel for node-dialed UDP flows.
#[cfg(target_os = "linux")]
pub(crate) const AF_XDP_UDP_DIAL_INGRESS_QUEUE: usize = 256;

/// T4-6: inbound datagram delivered to a node-dialed UDP socket —
/// payload plus the IP-header ECN bits so QUIC consumers keep their
/// congestion-feedback marks instead of silently losing them.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct AfXdpUdpDatagram {
    pub payload: Bytes,
    pub ecn: Option<u8>,
    /// Monotonic enqueue timestamp (`udp_activity_now_ms`) set by the
    /// demuxing bridge — the socket reports channel age on recv.
    pub enqueued_ms: u64,
}

/// T4-7: one message on a dialed UDP socket's ingress channel. ICMP
/// errors quoting the flow's outbound datagrams arrive here (eBPF
/// `XDP_OUT_CT` redirect); they surface as one-shot transient receive
/// errors — kernel error-queue semantics — and a PTB's MTU is cached
/// on the socket so oversized sends fail `MessageTooLarge`.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) enum AfXdpUdpIngress {
    Datagram(AfXdpUdpDatagram),
    IcmpError { mtu: Option<u32> },
}

/// T4-6: node-dialed UDP socket over the AF_XDP dataplane. UDP has no
/// handshake — the reserved source port, XDP_OUT_CT row and demux
/// ownership are established by `dial_udp` before this handle exists,
/// and `Drop` releases them through the registry.
#[cfg(target_os = "linux")]
pub struct AfXdpUdpSocket {
    flow: AfXdpTcpFlowKey,
    link: AfXdpLinkMeta,
    egress_tx: mpsc::Sender<AfXdpReactorRequest>,
    // `Mutex` (not `&mut self` access) so quinn's `AsyncUdpSocket`
    // adapter can poll receives through `&self`.
    ingress_rx: std::sync::Mutex<mpsc::Receiver<AfXdpUdpIngress>>,
    registry: Arc<AfXdpDialRegistry>,
    /// T4-7: path-MTU learned from ICMP PTB errors — max IP datagram
    /// size, 0 = uncapped. Mirroring a kernel connected-socket's cached
    /// PMTU, oversized sends fail `MessageTooLarge` instead of being
    /// fragmented (the dataplane never emits fragments).
    path_mtu: AtomicUsize,
}

#[cfg(target_os = "linux")]
impl AfXdpUdpSocket {
    pub fn local_addr(&self) -> SocketAddr {
        self.flow.local_addr
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.flow.peer_addr
    }

    fn egress_request(&self, payload: &[u8], ecn: Option<u8>) -> AfXdpReactorRequest {
        AfXdpReactorRequest::UdpEgress {
            link: self.link,
            local: self.flow.local_addr,
            remote: self.flow.peer_addr,
            payload: Bytes::copy_from_slice(payload),
            ecn,
            enqueued_ms: crate::udp_proxy::udp_activity_now_ms(),
        }
    }

    /// Payload cap from the learned path MTU — `None` while uncapped.
    fn payload_cap(&self) -> Option<usize> {
        let mtu = self.path_mtu.load(Ordering::Relaxed);
        if mtu == 0 {
            return None;
        }
        let ip_header = if self.flow.local_addr.is_ipv4() {
            20
        } else {
            40
        };
        Some(mtu.saturating_sub(ip_header + 8))
    }

    /// Kernel-equivalent send check: beyond the learned path MTU the
    /// datagram would have to be fragmented, which the dataplane never
    /// does — report `MessageTooLarge` so callers (QUIC DPLPMTUD)
    /// shrink and retry.
    fn check_payload_cap(&self, len: usize) -> io::Result<()> {
        if let Some(cap) = self.payload_cap()
            && len > cap
        {
            // EMSGSIZE — the same errno a kernel socket returns past the
            // cached PMTU; quinn's DPLPMTUD keys on this raw code.
            return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
        }
        Ok(())
    }

    /// Queue a datagram for egress through the owning queue's XSK TX
    /// ring. The bounded request channel applies backpressure — a full
    /// queue awaits instead of shedding silently.
    pub async fn send(&self, payload: &[u8]) -> io::Result<usize> {
        self.send_with_ecn(payload, None).await
    }

    /// Same as `send`, with an explicit ECN codepoint (QUIC marking).
    pub async fn send_with_ecn(&self, payload: &[u8], ecn: Option<u8>) -> io::Result<usize> {
        let len = payload.len();
        self.check_payload_cap(len)?;
        self.egress_tx
            .send(self.egress_request(payload, ecn))
            .await
            .map_err(|_| self.egress_closed_error())?;
        Ok(len)
    }

    /// Non-blocking variant for poll-style consumers (quinn). A full
    /// bounded queue reports `WouldBlock`; the caller must await
    /// writability via the poller before retrying.
    pub fn try_send(&self, payload: &[u8], ecn: Option<u8>) -> io::Result<usize> {
        let len = payload.len();
        self.check_payload_cap(len)?;
        match self.egress_tx.try_send(self.egress_request(payload, ecn)) {
            Ok(()) => Ok(len),
            Err(mpsc::error::TrySendError::Full(_)) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "AF_XDP UDP egress queue full for {} -> {}",
                    self.flow.local_addr, self.flow.peer_addr
                ),
            )),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(self.egress_closed_error()),
        }
    }

    /// Clone of the egress channel for the writable poller — callers
    /// `poll_reserve` on it to await queue capacity after a
    /// `WouldBlock`.
    pub(crate) fn egress_sender(&self) -> mpsc::Sender<AfXdpReactorRequest> {
        self.egress_tx.clone()
    }

    /// Poll-style receive for `&self` consumers (quinn). The bounded
    /// channel registers `cx` for wake-up; a closed channel reports
    /// `UnexpectedEof` because AF_XDP flows never recover. Returns the
    /// copied length and the datagram's ECN bits.
    pub fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<io::Result<(usize, Option<u8>)>> {
        let mut rx = self
            .ingress_rx
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        match rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(AfXdpUdpIngress::Datagram(datagram))) => {
                crate::udp_proxy::note_udp_sock_ingress_age_ms(
                    crate::udp_proxy::udp_activity_now_ms()
                        .saturating_sub(datagram.enqueued_ms),
                );
                let len = datagram.payload.len().min(buf.len());
                buf[..len].copy_from_slice(&datagram.payload[..len]);
                std::task::Poll::Ready(Ok((len, datagram.ecn)))
            }
            std::task::Poll::Ready(Some(AfXdpUdpIngress::IcmpError { mtu })) => {
                std::task::Poll::Ready(Err(self.icmp_error(mtu)))
            }
            std::task::Poll::Ready(None) => {
                std::task::Poll::Ready(Err(self.ingress_closed_error()))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    /// Next reply payload from the upstream peer. The channel closes
    /// when the owning demux entry is torn down (registry release,
    /// generation drain), which surfaces as `UnexpectedEof`.
    pub async fn recv(&mut self) -> io::Result<Bytes> {
        match self
            .ingress_rx
            .get_mut()
            .unwrap_or_else(|err| err.into_inner())
            .recv()
            .await
        {
            // ICMP errors surface once, kernel error-queue style;
            // the loop continues so the next item is the payload.
            Some(AfXdpUdpIngress::IcmpError { mtu }) => Err(self.icmp_error(mtu)),
            Some(AfXdpUdpIngress::Datagram(datagram)) => {
                crate::udp_proxy::note_udp_sock_ingress_age_ms(
                    crate::udp_proxy::udp_activity_now_ms()
                        .saturating_sub(datagram.enqueued_ms),
                );
                Ok(datagram.payload)
            }
            None => Err(self.ingress_closed_error()),
        }
    }

    /// True once either direction's channel is closed — the flow can
    /// never deliver again (unlike kernel UDP, where errors are
    /// transient).
    pub fn defunct(&self) -> bool {
        self.ingress_rx
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .is_closed()
            || self.egress_tx.is_closed()
    }

    /// Kernel error-queue semantics: a PTB updates the cached path MTU
    /// and reports `MessageTooLarge` once; other ICMP errors report
    /// `HostUnreachable` once. Both are transient — the socket lives on.
    /// The reported MTU is clamped to the protocol floor (576 v4 /
    /// 1280 v6, the minimums every path must carry) so a bogus small
    /// PTB cannot wedge the flow below the guaranteed size.
    fn icmp_error(&self, mtu: Option<u32>) -> io::Error {
        if let Some(mtu) = mtu {
            let floor: u32 = if self.flow.local_addr.is_ipv4() {
                576
            } else {
                1280
            };
            let mtu = mtu.max(floor);
            self.path_mtu
                .store(mtu as usize, Ordering::Relaxed);
            // EMSGSIZE once, kernel error-queue style.
            return io::Error::from_raw_os_error(libc::EMSGSIZE);
        }
        io::Error::new(
            io::ErrorKind::HostUnreachable,
            format!(
                "AF_XDP UDP ICMP error for {} -> {}",
                self.flow.local_addr, self.flow.peer_addr
            ),
        )
    }

    fn egress_closed_error(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!(
                "AF_XDP UDP egress queue closed for {} -> {}",
                self.flow.local_addr, self.flow.peer_addr
            ),
        )
    }

    fn ingress_closed_error(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "AF_XDP UDP ingress closed for {} -> {}",
                self.flow.local_addr, self.flow.peer_addr
            ),
        )
    }
}

#[cfg(target_os = "linux")]
impl std::fmt::Debug for AfXdpUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AfXdpUdpSocket")
            .field("flow", &self.flow)
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl Drop for AfXdpUdpSocket {
    fn drop(&mut self) {
        self.registry.release(&self.flow);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn test_registry() -> Arc<AfXdpDialRegistry> {
        Arc::new(AfXdpDialRegistry::new(Arc::new(XdpManager::new(
            crate::runtime_mode::XdpConfig::default(),
        ))))
    }

    fn test_flow() -> AfXdpTcpFlowKey {
        AfXdpTcpFlowKey {
            local_addr: "203.0.113.7:42001".parse().unwrap(),
            peer_addr: "198.51.100.5:443".parse().unwrap(),
        }
    }

    fn test_socket(
        registry: &Arc<AfXdpDialRegistry>,
    ) -> (
        AfXdpUdpSocket,
        mpsc::Sender<AfXdpUdpIngress>,
        mpsc::Receiver<AfXdpReactorRequest>,
    ) {
        let (egress_tx, egress_rx) = mpsc::channel(8);
        let (udp_tx, ingress_rx) = mpsc::channel(AF_XDP_UDP_DIAL_INGRESS_QUEUE);
        (
            AfXdpUdpSocket {
                flow: test_flow(),
                link: AfXdpLinkMeta {
                    destination_mac: [0x02, 0, 0, 0, 0, 1],
                    source_mac: [0x02, 0, 0, 0, 0, 2],
                    vlan_tags: [AfXdpVlanTag { tpid: 0, tci: 0 }; 2],
                    vlan_tag_count: 0,
                    ethertype: ETHERTYPE_IPV4,
                },
                egress_tx,
                ingress_rx: std::sync::Mutex::new(ingress_rx),
                registry: registry.clone(),
                path_mtu: AtomicUsize::new(0),
            },
            udp_tx,
            egress_rx,
        )
    }

    #[tokio::test]
    async fn udp_socket_ptb_caches_mtu_and_caps_sends() {
        let registry = test_registry();
        let (mut socket, udp_tx, mut egress_rx) = test_socket(&registry);
        assert_eq!(socket.path_mtu.load(Ordering::Relaxed), 0);

        udp_tx
            .try_send(AfXdpUdpIngress::IcmpError { mtu: Some(1400) })
            .unwrap();
        let err = socket.recv().await.expect_err("PTB surfaces once");
        assert_eq!(err.raw_os_error(), Some(libc::EMSGSIZE));
        assert_eq!(socket.path_mtu.load(Ordering::Relaxed), 1400);

        // Payload beyond the learned cap is rejected before queueing.
        let cap = 1400 - 20 - 8;
        let err = socket
            .try_send(&vec![0u8; cap + 1], None)
            .expect_err("oversized datagram");
        assert_eq!(err.raw_os_error(), Some(libc::EMSGSIZE));
        assert!(egress_rx.try_recv().is_err(), "rejected send never queued");

        // Within cap queues the egress request.
        socket.try_send(&vec![0u8; cap], None).expect("in-cap send");
        assert!(matches!(
            egress_rx.try_recv(),
            Ok(AfXdpReactorRequest::UdpEgress { .. })
        ));
    }

    #[tokio::test]
    async fn udp_socket_tiny_ptb_clamps_to_family_floor() {
        let registry = test_registry();
        let (mut socket, udp_tx, _egress_rx) = test_socket(&registry);
        udp_tx
            .try_send(AfXdpUdpIngress::IcmpError { mtu: Some(64) })
            .unwrap();
        let _ = socket.recv().await;
        assert_eq!(socket.path_mtu.load(Ordering::Relaxed), 576);
    }

    #[tokio::test]
    async fn udp_socket_icmp_error_is_one_shot_and_flow_stays_live() {
        let registry = test_registry();
        let (mut socket, udp_tx, _egress_rx) = test_socket(&registry);
        udp_tx
            .try_send(AfXdpUdpIngress::IcmpError { mtu: None })
            .unwrap();
        udp_tx
            .try_send(AfXdpUdpIngress::Datagram(AfXdpUdpDatagram {
                payload: Bytes::from_static(b"pong"),
                ecn: Some(0b10),
                enqueued_ms: crate::udp_proxy::udp_activity_now_ms(),
            }))
            .unwrap();
        let err = socket.recv().await.expect_err("ICMP error surfaces");
        assert_eq!(err.kind(), io::ErrorKind::HostUnreachable);
        let payload = socket.recv().await.expect("next datagram still arrives");
        assert_eq!(&payload[..], b"pong");
    }

    #[tokio::test]
    async fn udp_socket_closed_channels_are_explicit() {
        let registry = test_registry();
        let (mut socket, udp_tx, egress_rx) = test_socket(&registry);
        drop(udp_tx);
        let err = socket.recv().await.expect_err("closed ingress");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(socket.defunct());
        drop(egress_rx);
        assert!(socket.try_send(b"x", None).is_err());
        assert!(socket.send(b"x").await.is_err());
    }

    #[test]
    fn notify_icmp_routes_udp_error_to_socket_and_tcp_to_reactor() {
        let registry = test_registry();
        let (queue_tx, mut queue_rx) = mpsc::channel(8);
        registry.register_queue("eth0", 0, queue_tx);
        let remote: SocketAddr = "198.51.100.5:443".parse().unwrap();
        let source: IpAddr = "203.0.113.7".parse().unwrap();

        // UDP owner: ICMP lands on the socket's ingress channel.
        let (udp_tx, mut udp_rx) = mpsc::channel(AF_XDP_UDP_DIAL_INGRESS_QUEUE);
        let udp_owner = AfXdpDialOwner {
            interface: Arc::from("eth0"),
            queue: 0,
            proto: IP_PROTO_UDP,
            udp_tx: Some(udp_tx),
        };
        let udp_flow = registry
            .claim_flow(source, remote, &udp_owner, None)
            .expect("udp claim");
        registry.notify_icmp(&udp_flow, Some(1400));
        assert!(matches!(
            udp_rx.try_recv(),
            Ok(AfXdpUdpIngress::IcmpError { mtu: Some(1400) })
        ));

        // TCP owner: ICMP becomes a PmtuUpdate on the reactor channel.
        let tcp_owner = AfXdpDialOwner {
            interface: Arc::from("eth0"),
            queue: 0,
            proto: IP_PROTO_TCP,
            udp_tx: None,
        };
        let tcp_flow = registry
            .claim_flow(source, "198.51.100.6:443".parse().unwrap(), &tcp_owner, None)
            .expect("tcp claim");
        registry.notify_icmp(&tcp_flow, Some(1280));
        assert!(matches!(
            queue_rx.try_recv(),
            Ok(AfXdpReactorRequest::PmtuUpdate { flow, mtu: Some(1280) }) if flow == tcp_flow
        ));

        // Unknown tuple is a no-op (ICMP stays on the kernel path).
        registry.notify_icmp(
            &AfXdpTcpFlowKey {
                local_addr: "203.0.113.7:9".parse().unwrap(),
                peer_addr: remote,
            },
            Some(1400),
        );
        assert!(udp_rx.try_recv().is_err());
        assert!(queue_rx.try_recv().is_err());
    }
}
