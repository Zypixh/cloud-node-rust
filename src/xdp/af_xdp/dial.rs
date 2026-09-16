use super::*;
use std::sync::atomic::AtomicU32;

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
}

/// T4: bridge between async upstream dialers and the per-queue AF_XDP
/// reactors. Owns the flow→owner demux table, the per-queue request
/// senders, and the reserved source-port span. Registration order in
/// `dial_tcp` is transactional: owner claim → XDP_OUT_CT insert →
/// reactor request; every failure path rolls back what it created, and
/// `release` (called on session reap) unwinds the rest.
#[cfg(target_os = "linux")]
pub(crate) struct AfXdpDialRegistry {
    manager: Arc<XdpManager>,
    owners: DashMap<AfXdpTcpFlowKey, AfXdpDialOwner>,
    queues: DashMap<(String, u32), mpsc::Sender<AfXdpReactorRequest>>,
    port_cursor: AtomicU32,
    /// D-B1: reserved source-port span from `xdp.upstream.dialPortRange`
    /// (default 40000-49999), pinned in `ip_local_reserved_ports` by the
    /// dial guard before this registry is published.
    pub(crate) port_base: u16,
    pub(crate) port_span: u16,
}

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
            manager,
            port_base,
            port_span: port_end.saturating_sub(port_base).saturating_add(1),
            owners: DashMap::new(),
            queues: DashMap::new(),
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
    /// never be handed out twice.
    pub(crate) fn claim_flow(
        &self,
        source: IpAddr,
        remote: SocketAddr,
        owner: &AfXdpDialOwner,
    ) -> Option<AfXdpTcpFlowKey> {
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
        };
        let Some(flow) = self.claim_flow(route.source, remote, &owner) else {
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
        if let Err(err) = self.manager.upsert_out_ct(ct_key) {
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

    /// Reap-time cleanup: drop the owner claim and the XDP_OUT_CT row so
    /// post-close replies fall back to the kernel path. Removal failure
    /// is logged — the row expires with the map, and replies to it simply
    /// reach a closed socket.
    pub(crate) fn release(&self, flow: &AfXdpTcpFlowKey) {
        let Some((_, owner)) = self.owners.remove(flow) else {
            return;
        };
        if let Some(key) = linux::out_ct_key(flow.local_addr, flow.peer_addr, owner.proto)
            && let Err(err) = self.manager.remove_out_ct(&key)
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
