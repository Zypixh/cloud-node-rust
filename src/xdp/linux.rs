use super::*;
use crate::runtime_mode::{
    XdpAttachMode, XdpInterfaceConfig, XdpRuntimeMode, XdpStateTables,
};
use aya::maps::lpm_trie::Key as LpmKey;
use aya::maps::{Array, HashMap as AyaHashMap, LpmTrie, PerCpuArray, XskMap};
use aya::programs::links::PinnedLink;
use cloud_node_xdp_common::{
    XdpBudgetConfig, XdpCounters, XdpFlowAcct, XdpInterfacePolicy, XdpIpv4Key,
    XdpIpv6Key, XdpLocalIpv4Key, XdpLocalIpv6Key, XdpPendingCap, XdpPortProtoKey, XdpQueueKey,
    XdpRateBucket, XdpRateLimitConfig, XdpRuleValue, XdpSnatRevKey, XdpSnatRevValue, XdpUdpCtKey,
    XdpUdpCtValue, XdpUdpFwdKey, XdpUdpFwdRule,
};
use ipnet::IpNet;
use std::collections::BTreeSet;
use std::ffi::CString;
use std::io::Write;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::{Path, PathBuf};
use xsk_rs::config::{
    BindFlags, FrameSize, Interface, LibxdpFlags, QueueSize, SocketConfig, UmemConfig,
};
use xsk_rs::{CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem};

const AF_XDP_FRAME_COUNT: u32 = 4096;
const AF_XDP_RING_SIZE: u32 = 2048;
const AF_XDP_RX_BATCH: usize = 64;
const AF_XDP_MAX_SOCKETS: usize = 4096;
const AF_XDP_SOCKET_CREATE_ATTEMPTS: usize = 80;
const AF_XDP_SOCKET_CREATE_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

pub struct AttachedProgram {
    pub interfaces: BTreeSet<String>,
    pub ebpf: aya::Ebpf,
    /// EN-10 owner epoch written to XDP_OWNER_EPOCH for this attach. Events
    /// stamped with a smaller epoch were published by an older generation.
    pub owner_epoch: u64,
    /// EN-10 flow records adopted from pinned state maps (reload/restart
    /// continuity) — TCP CT + UDP CT + pending admissions still resident.
    pub imported_flows: u64,
    /// State-table sizes actually applied. When the operator gave no
    /// explicit `xdp.stateTables` this is the budget-scaled result;
    /// callers record it so status reports and later reloads see the real
    /// map sizes rather than the unsized defaults.
    pub effective_state_tables: Option<XdpStateTables>,
}

#[derive(Debug)]
pub struct AfXdpRuntimeHandle {
    queues: Vec<AfXdpQueueHandle>,
    pub statuses: Vec<XdpQueueStatus>,
    last_status_refresh_at: Option<std::time::Instant>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AfXdpPollStats {
    pub packets: usize,
    pub parsed: usize,
    pub parse_errors: usize,
    pub refilled: usize,
}

impl AfXdpRuntimeHandle {
    pub fn poll_raw_once<F>(&mut self, mut on_packet: F) -> anyhow::Result<AfXdpPollStats>
    where
        F: FnMut(&str, u32, Vec<u8>),
    {
        let mut stats = AfXdpPollStats::default();
        for queue in &mut self.queues {
            let queue_stats = queue.poll_raw_once(&mut on_packet)?;
            stats.packets += queue_stats.packets;
            stats.parsed += queue_stats.parsed;
            stats.parse_errors += queue_stats.parse_errors;
            stats.refilled += queue_stats.refilled;
        }
        self.refresh_statuses(false);
        Ok(stats)
    }

    pub fn refresh_statuses(&mut self, force: bool) {
        let now = std::time::Instant::now();
        if !super::xsk_status_refresh_due(self.last_status_refresh_at, now, force) {
            return;
        }
        self.last_status_refresh_at = Some(now);
        for queue in &self.queues {
            let Some(status) = self
                .statuses
                .iter_mut()
                .find(|status| status.interface == queue.interface && status.queue == queue.queue)
            else {
                continue;
            };
            if let Ok(stats) = queue.rx.fd().xdp_statistics() {
                status.rx_dropped = stats.rx_dropped();
                status.rx_invalid_descs = stats.rx_invalid_descs();
                status.rx_ring_full = stats.rx_ring_full();
                status.tx_invalid_descs = stats.tx_invalid_descs();
            }
        }
    }

    /// Move queue handles out so each can be owned by a dedicated pinned
    /// reactor thread. After this call `poll_raw_once` is a no-op.
    pub fn take_queues(&mut self) -> Vec<AfXdpQueueHandle> {
        std::mem::take(&mut self.queues)
    }
}

#[derive(Debug)]
pub(super) struct AfXdpQueueHandle {
    pub(super) interface: String,
    pub(super) queue: u32,
    tx: TxQueue,
    pub(super) rx: RxQueue,
    fill: Option<FillQueue>,
    comp: Option<CompQueue>,
    umem: Umem,
    free_frames: Vec<FrameDesc>,
    rx_batch: Vec<FrameDesc>,
    tx_completion_batch: Vec<FrameDesc>,
    tx_scratch: Vec<u8>,
}

impl AfXdpQueueHandle {
    pub(super) fn poll_raw_once<F>(&mut self, on_packet: &mut F) -> anyhow::Result<AfXdpPollStats>
    where
        F: FnMut(&str, u32, Vec<u8>),
    {
        let mut stats = AfXdpPollStats {
            refilled: self.replenish_fill()?,
            ..AfXdpPollStats::default()
        };
        let limit = self.rx_batch.len();
        if limit == 0 {
            return Ok(stats);
        }
        // SAFETY: `rx_batch` only contains descriptors for this queue's UMEM. The
        // kernel owns any descriptors returned by RX until this method returns them
        // to the fill ring or `free_frames`.
        let received = unsafe { self.rx.poll_and_consume(&mut self.rx_batch[..limit], 0)? };
        stats.packets += received;
        for desc in &self.rx_batch[..received] {
            // SAFETY: RX populated `desc` from this queue's UMEM, and we copy the
            // frame before returning ownership to the fill ring.
            let (_, data) = unsafe { self.umem.frame(desc) };
            let frame = data.contents();
            if super::af_xdp::parse_l4_packet(frame).is_some() {
                stats.parsed += 1;
            } else {
                stats.parse_errors += 1;
            }
            on_packet(&self.interface, self.queue, frame.to_vec());
        }
        stats.refilled += self.return_rx_frames(received)?;
        Ok(stats)
    }

    // EN-12: the socket is bound with XDP_USE_NEED_WAKEUP — after the fill
    // ring drains empty the driver sleeps and will not consume newly
    // produced descriptors until userspace wakes it. `produce` alone would
    // leave RX starved forever; `produce_and_wakeup` keeps fill starvation
    // recoverable.
    fn replenish_fill(&mut self) -> anyhow::Result<usize> {
        let Some(fill) = self.fill.as_mut() else {
            return Ok(0);
        };
        let count = self.free_frames.len().min(AF_XDP_RX_BATCH);
        if count == 0 {
            return Ok(0);
        }
        let split_at = self.free_frames.len() - count;
        let frames = self.free_frames.split_off(split_at);
        // SAFETY: `frames` came from this queue's UMEM free list and have not been
        // submitted to TX or fill while in `free_frames`. `fd` is this queue's
        // socket descriptor used only to wake the kernel when it sleeps on an
        // empty fill ring.
        let produced = unsafe { fill.produce_and_wakeup(&frames, self.rx.fd_mut(), 0)? };
        if produced < frames.len() {
            self.free_frames.extend_from_slice(&frames[produced..]);
        }
        Ok(produced)
    }

    fn return_rx_frames(&mut self, count: usize) -> anyhow::Result<usize> {
        if count == 0 {
            return Ok(0);
        }
        let frames = &self.rx_batch[..count];
        let Some(fill) = self.fill.as_mut() else {
            self.free_frames.extend_from_slice(frames);
            return Ok(0);
        };
        // SAFETY: RX returned these descriptors from the same UMEM and userspace no
        // longer holds packet data references when they are handed back to fill.
        // Wakeup keeps RX alive after fill-ring starvation (see replenish_fill).
        let produced = unsafe { fill.produce_and_wakeup(frames, self.rx.fd_mut(), 0)? };
        if produced < frames.len() {
            self.free_frames.extend_from_slice(&frames[produced..]);
        }
        Ok(produced)
    }

    fn reclaim_tx_completions(&mut self) -> usize {
        let Some(comp) = self.comp.as_mut() else {
            return 0;
        };
        // SAFETY: `tx_completion_batch` descriptors belong to this queue's UMEM and
        // are only used here to receive TX completion ownership from the kernel.
        let completed = unsafe { comp.consume(&mut self.tx_completion_batch) };
        self.free_frames
            .extend_from_slice(&self.tx_completion_batch[..completed]);
        completed
    }

    pub(super) fn send_udp_datagram(
        &mut self,
        link: &super::af_xdp::AfXdpLinkMeta,
        listen_addr: std::net::SocketAddr,
        peer_addr: std::net::SocketAddr,
        payload: &[u8],
    ) -> anyhow::Result<bool> {
        self.reclaim_tx_completions();
        let Some(mut desc) = self.free_frames.pop() else {
            return Ok(false);
        };
        desc.set_options(0);
        if super::af_xdp::encode_udp_reply_frame(
            link,
            listen_addr,
            peer_addr,
            payload,
            &mut self.tx_scratch,
        )
        .is_none()
        {
            self.free_frames.push(desc);
            return Ok(false);
        }
        let frame = std::mem::take(&mut self.tx_scratch);
        let result = self.submit_raw_frame(desc, &frame);
        self.tx_scratch = frame;
        result
    }

    pub(super) fn send_raw_frame(&mut self, frame: &[u8]) -> anyhow::Result<bool> {
        self.reclaim_tx_completions();
        let Some(desc) = self.free_frames.pop() else {
            return Ok(false);
        };
        self.submit_raw_frame(desc, frame)
    }

    fn submit_raw_frame(&mut self, mut desc: FrameDesc, frame: &[u8]) -> anyhow::Result<bool> {
        desc.set_options(0);
        {
            // SAFETY: `desc` was taken from this queue's free list and therefore
            // belongs to this UMEM. It is not submitted to any ring while we hold
            // this mutable frame view.
            let (_, mut data) = unsafe { self.umem.frame_mut(&mut desc) };
            let mut cursor = data.cursor();
            cursor.zero_out();
            if let Err(err) = cursor.write_all(frame) {
                self.free_frames.push(desc);
                return Err(err.into());
            }
        }
        // SAFETY: `desc` describes a frame from this queue's UMEM. After successful
        // submission it is not reused until returned by the completion queue.
        match unsafe { self.tx.produce_one_and_wakeup(&desc) } {
            Ok(1) => Ok(true),
            Ok(_) => {
                self.free_frames.push(desc);
                Ok(false)
            }
            Err(err) => {
                self.free_frames.push(desc);
                Err(err.into())
            }
        }
    }
}

#[derive(Clone, Debug)]
struct XskMapEntry {
    interface: String,
    ifindex: u32,
    queue: u32,
    index: u32,
}

pub fn prepare_af_xdp_sockets(config: &XdpConfig) -> anyhow::Result<AfXdpRuntimeHandle> {
    let socket_count = config
        .interfaces
        .iter()
        .filter(|interface| interface.mode == XdpRuntimeMode::Proxy)
        .try_fold(0usize, |count, interface| {
            count.checked_add(interface.queues.len())
        })
        .ok_or_else(|| anyhow::anyhow!("AF_XDP queue count overflow"))?;
    if socket_count > AF_XDP_MAX_SOCKETS {
        anyhow::bail!(
            "AF_XDP proxy queue count {} exceeds XSK map capacity {}",
            socket_count,
            AF_XDP_MAX_SOCKETS
        );
    }
    let mut seen = std::collections::HashSet::with_capacity(socket_count);
    let mut projected_bytes = 0u64;
    for interface in config
        .interfaces
        .iter()
        .filter(|interface| interface.mode == XdpRuntimeMode::Proxy)
    {
        for queue in &interface.queues {
            anyhow::ensure!(
                seen.insert((interface.name.as_str(), *queue)),
                "duplicate AF_XDP queue {}:{}",
                interface.name,
                queue
            );
            let frames = u64::from(AF_XDP_FRAME_COUNT)
                .checked_mul(u64::from(interface.frame_size))
                .ok_or_else(|| anyhow::anyhow!("AF_XDP UMEM byte count overflow"))?;
            let rings = u64::from(AF_XDP_RING_SIZE)
                .checked_mul(std::mem::size_of::<FrameDesc>() as u64)
                .and_then(|bytes| bytes.checked_mul(4))
                .ok_or_else(|| anyhow::anyhow!("AF_XDP ring byte count overflow"))?;
            projected_bytes = projected_bytes
                .checked_add(frames.saturating_add(rings))
                .ok_or_else(|| anyhow::anyhow!("AF_XDP total byte count overflow"))?;
        }
    }
    let budget = crate::memory_governor::MEMORY_GOVERNOR
        .snapshot(crate::memory_governor::MEMORY_GOVERNOR.pingora_worker_threads())
        .af_xdp_budget_bytes;
    anyhow::ensure!(
        projected_bytes <= budget,
        "AF_XDP projected memory {} exceeds node budget {}",
        projected_bytes,
        budget
    );
    let mut queues = Vec::with_capacity(socket_count);
    let mut statuses = Vec::with_capacity(socket_count);
    for interface in config
        .interfaces
        .iter()
        .filter(|interface| interface.mode == XdpRuntimeMode::Proxy)
    {
        for queue in &interface.queues {
            match create_af_xdp_queue_with_retry(interface, *queue) {
                Ok((handle, status)) => {
                    queues.push(handle);
                    statuses.push(status);
                }
                Err(err) => {
                    statuses.push(XdpQueueStatus {
                        interface: interface.name.clone(),
                        queue: *queue,
                        configured: true,
                        detail: format!("AF_XDP socket setup failed: {err}"),
                        ..XdpQueueStatus::default()
                    });
                }
            }
        }
    }
    Ok(AfXdpRuntimeHandle {
        queues,
        statuses,
        last_status_refresh_at: None,
    })
}

fn create_af_xdp_queue_with_retry(
    interface: &crate::runtime_mode::XdpInterfaceConfig,
    queue: u32,
) -> anyhow::Result<(AfXdpQueueHandle, XdpQueueStatus)> {
    let mut last_error = None;
    for attempt in 1..=AF_XDP_SOCKET_CREATE_ATTEMPTS {
        match create_af_xdp_queue(interface, queue) {
            Ok(queue) => return Ok(queue),
            Err(err) => {
                last_error = Some(err);
                if attempt < AF_XDP_SOCKET_CREATE_ATTEMPTS {
                    std::thread::sleep(AF_XDP_SOCKET_CREATE_RETRY_DELAY);
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("AF_XDP socket setup failed")))
}

pub fn register_af_xdp_sockets(
    ebpf: &mut aya::Ebpf,
    config: &XdpConfig,
    runtime: &mut AfXdpRuntimeHandle,
    enable_redirect: bool,
) -> anyhow::Result<()> {
    sync_proxy_ports(ebpf, config, false)?;
    sync_xsk_indices(ebpf, config, false, &Default::default())?;
    clear_xsk_map(ebpf)?;
    sync_xsk_indices(ebpf, config, true, &Default::default())?;

    let entries = xsk_map_entries(config)?;
    let map = ebpf
        .map_mut("XDP_XSKS")
        .ok_or_else(|| anyhow::anyhow!("missing map XDP_XSKS"))?;
    let mut xsk_map = XskMap::try_from(map)?;

    for entry in entries {
        let Some(queue) = runtime
            .queues
            .iter()
            .find(|queue| queue.interface == entry.interface && queue.queue == entry.queue)
        else {
            mark_queue_status(
                &mut runtime.statuses,
                &entry.interface,
                entry.queue,
                false,
                false,
                "AF_XDP socket not available for configured queue",
            );
            continue;
        };
        // SAFETY: the AF_XDP socket is owned by `runtime.queues` and remains alive
        // while its fd is registered in the XSK map. BorrowedFd does not take ownership.
        let socket_fd = unsafe { BorrowedFd::borrow_raw(queue.rx.fd().as_raw_fd()) };
        xsk_map.set(entry.index, socket_fd, 0)?;
        mark_queue_status(
            &mut runtime.statuses,
            &entry.interface,
            entry.queue,
            true,
            true,
            format!(
                "AF_XDP socket registered in XSK map index {} for ifindex {} queue {}",
                entry.index, entry.ifindex, entry.queue
            ),
        );
    }

    sync_proxy_ports(ebpf, config, enable_redirect)?;
    Ok(())
}

fn create_af_xdp_queue(
    interface: &crate::runtime_mode::XdpInterfaceConfig,
    queue: u32,
) -> anyhow::Result<(AfXdpQueueHandle, XdpQueueStatus)> {
    let frame_size = FrameSize::new(interface.frame_size)?;
    let ring_size = QueueSize::new(AF_XDP_RING_SIZE)?;
    let mut umem_config = UmemConfig::builder();
    umem_config
        .frame_size(frame_size)
        .fill_queue_size(ring_size)
        .comp_queue_size(ring_size);
    let umem_config = umem_config.build()?;
    let frame_count = NonZeroU32::new(AF_XDP_FRAME_COUNT)
        .ok_or_else(|| anyhow::anyhow!("AF_XDP frame count must be non-zero"))?;
    let (umem, mut frames) = Umem::new(umem_config, frame_count, false)?;

    let if_name: Interface = interface.name.parse()?;
    let build_socket = |bind_flags: BindFlags| {
        let mut socket_config = SocketConfig::builder();
        socket_config
            .libxdp_flags(LibxdpFlags::XSK_LIBXDP_FLAGS_INHIBIT_PROG_LOAD)
            .bind_flags(bind_flags);
        let socket_config = socket_config.build();
        // SAFETY: The UMEM, queues, and socket-backed rings are owned by the
        // returned handle for the full socket lifetime. INHIBIT_PROG_LOAD
        // prevents libxdp from replacing the Aya-managed XDP program on this
        // interface.
        unsafe { Socket::new(socket_config, &umem, &if_name, queue) }.map_err(|err| {
            let mut detail = err.to_string();
            let mut source = std::error::Error::source(&err);
            while let Some(err) = source {
                detail.push_str(": ");
                detail.push_str(&err.to_string());
                source = err.source();
            }
            anyhow::anyhow!(detail)
        })
    };
    // EN-12 real bind-mode probing: `auto` asks the kernel for zero-copy and
    // falls back to copy explicitly when the driver rejects it; the landed
    // mode is recorded in queue status. `zero-copy` fails queue setup when
    // unsupported — a configured hard requirement, not a silent downgrade.
    use crate::runtime_mode::XdpXskMode;
    let mut socket_probe = None;
    let bind_attempts: &[(&str, BindFlags)] = match interface.xsk_mode {
        XdpXskMode::Auto => &[
            (
                "zero-copy",
                BindFlags::XDP_USE_NEED_WAKEUP | BindFlags::XDP_ZEROCOPY,
            ),
            ("copy", BindFlags::XDP_USE_NEED_WAKEUP | BindFlags::XDP_COPY),
        ],
        XdpXskMode::Copy => &[("copy", BindFlags::XDP_USE_NEED_WAKEUP | BindFlags::XDP_COPY)],
        XdpXskMode::ZeroCopy => &[(
            "zero-copy",
            BindFlags::XDP_USE_NEED_WAKEUP | BindFlags::XDP_ZEROCOPY,
        )],
    };
    let mut last_bind_error: Option<(&str, anyhow::Error)> = None;
    let mut landed_mode = "";
    let mut socket_parts = None;
    for (mode, flags) in bind_attempts {
        match build_socket(*flags) {
            Ok(parts) => {
                landed_mode = mode;
                socket_parts = Some(parts);
                break;
            }
            Err(err) => {
                socket_probe = Some(format!("{mode} bind failed: {err}"));
                last_bind_error = Some((mode, err));
            }
        }
    }
    let (tx, mut rx, fill_and_comp) = socket_parts.ok_or_else(|| {
        last_bind_error
            .map(|(mode, err)| anyhow::anyhow!("AF_XDP {mode} bind failed: {err}"))
            .unwrap_or_else(|| anyhow::anyhow!("AF_XDP bind failed"))
    })?;
    let (fill, comp, primed_frames) = match fill_and_comp {
        Some((mut fill, comp)) => {
            let fill_count = frames.len().min(AF_XDP_RING_SIZE as usize);
            let initial_fill = frames.drain(..fill_count).collect::<Vec<_>>();
            // SAFETY: `initial_fill` contains descriptors returned by the same UMEM
            // that owns this fill queue. Submitted descriptors are not reused until
            // the kernel returns them on RX.
            let produced = unsafe { fill.produce_and_wakeup(&initial_fill, rx.fd_mut(), 0)? };
            if produced < initial_fill.len() {
                frames.extend_from_slice(&initial_fill[produced..]);
            }
            (Some(fill), Some(comp), produced)
        }
        None => (None, None, 0),
    };
    let stats = rx.fd().xdp_statistics().ok();
    let status = XdpQueueStatus {
        interface: interface.name.clone(),
        queue,
        configured: true,
        socket_created: true,
        registered: false,
        ready: false,
        detail: format!(
            "AF_XDP socket created in {landed_mode} mode and fill ring primed with {} frames; awaiting XSK map registration{}",
            primed_frames,
            socket_probe
                .as_ref()
                .map(|probe| format!("; probe: {probe}"))
                .unwrap_or_default()
        ),
        rx_dropped: stats.map(|stats| stats.rx_dropped()).unwrap_or_default(),
        rx_invalid_descs: stats
            .map(|stats| stats.rx_invalid_descs())
            .unwrap_or_default(),
        rx_ring_full: stats.map(|stats| stats.rx_ring_full()).unwrap_or_default(),
        tx_invalid_descs: stats
            .map(|stats| stats.tx_invalid_descs())
            .unwrap_or_default(),
        xsk_mode: landed_mode.to_string(),
        faulted: false,
        congested_drops: 0,
    };
    Ok((
        AfXdpQueueHandle {
            interface: interface.name.clone(),
            queue,
            tx,
            rx,
            fill,
            comp,
            umem,
            free_frames: frames,
            rx_batch: vec![FrameDesc::default(); AF_XDP_RX_BATCH],
            tx_completion_batch: vec![FrameDesc::default(); AF_XDP_RX_BATCH],
            tx_scratch: Vec::with_capacity(interface.frame_size as usize),
        },
        status,
    ))
}

/// Prepare-before-commit attach (R5): the previous dataplane keeps
/// running until the new generation is fully verified. Phase 1 (no side
/// effects on the live dataplane): budget check, stale-pin gate, object
/// load with pin reuse, map-spec audit, and verifier loads of the root
/// program plus every dispatch subprogram. Phase 2 (commit): detach the
/// old links/subprogram pins/dispatch pin, pin the verified subprograms,
/// populate the dispatch table, adopt flow state, sync maps, then attach
/// and pin the new links. A failure anywhere in phase 1 leaves the old
/// program running; a failure in phase 2 surfaces as an attach error with
/// the dataplane on the kernel path (bounded commit window, ms-scale).
pub async fn attach(
    config: &XdpConfig,
    object_path: Option<&Path>,
    purge_stale_state: bool,
    commit_started: Option<&std::sync::atomic::AtomicBool>,
) -> anyhow::Result<AttachedProgram> {
    std::fs::create_dir_all(xdp_bpf_pin_dir())
        .map_err(|err| {
            anyhow::anyhow!("create bpffs pin dir {}: {err}", xdp_bpf_pin_dir())
        })?;
    // When the operator gave no explicit stateTables, size the scalable
    // state maps to this node's kernel-BPF budget — default tables can
    // exceed the budget on small nodes and would otherwise fail attach.
    // Explicit operator sizes are never silently shrunk: they either fit
    // or fail the budget check below.
    let bpf_budget = crate::memory_governor::MEMORY_GOVERNOR
        .snapshot(crate::memory_governor::MEMORY_GOVERNOR.pingora_worker_threads())
        .kernel_bpf_budget_bytes;
    let mut effective_config = config.clone();
    if effective_config.state_tables.is_none() {
        effective_config.state_tables = auto_scale_state_tables(config, bpf_budget)?;
    }
    let config = &effective_config;
    ensure_bpf_map_budget(config, bpf_budget)?;
    // State-pin gate runs before any load attempt: an ABI-incompatible
    // pinned state map is a migration boundary, not an attach side effect.
    // Refusing keeps the live dataplane running and reports exactly which
    // maps block the upgrade; the operator opts into state loss with an
    // explicit purge.
    let stale_state: Vec<String> = stale_pinned_maps(config)
        .into_iter()
        .filter(|name| is_state_map_pin(name))
        .collect();
    if !stale_state.is_empty() && !purge_stale_state {
        anyhow::bail!(
            "pinned eBPF state maps are ABI-incompatible with this object: {stale_state:?}; \
             the live dataplane was left running and no state was destroyed. \
             Flow-state migration across this change is not implemented — \
             to accept the loss run `cloud-node xdp detach --purge-state`, then attach again"
        );
    }
    drop_stale_pinned_maps(config, purge_stale_state);
    let mut attached = BTreeSet::new();
    let mut loader = aya::EbpfLoader::new();
    loader.default_map_pin_directory(xdp_bpf_pin_dir());
    // EN-16: apply operator-sized state tables before load; the ledger above
    // already rejected the attach when the configured total exceeds the node
    // budget, so these sizes are guaranteed to fit.
    for spec in &bpf_map_specs(config) {
        if let Some(max) = state_table_override(spec.0, config) {
            loader.map_max_entries(spec.0, max);
        }
    }
    // The dispatch table must outlive the process: aya-ebpf maps default
    // to PinningType::None so default_map_pin_directory alone does not pin
    // it, and without a pin the tail-call targets die with the process.
    loader.map_pin_path(
        "XDP_DISPATCH",
        Path::new(xdp_bpf_pin_dir()).join("XDP_DISPATCH"),
    );
    // Counters are pinned so verdict accounting stays readable by other
    // processes (`xdp dump-maps` while a daemon owns the attachment) and
    // survives process exit. The spec check above still guards layout.
    loader.map_pin_path(
        "XDP_COUNTERS",
        Path::new(xdp_bpf_pin_dir()).join("XDP_COUNTERS"),
    );
    // EN-10 takeover contract: flow state and the lifecycle feedback channel
    // are pinned so a reload/restart adopts existing flows instead of
    // severing them. aya reuses a compatible pin purely by name; the spec
    // table check and post-load audit reject ABI-mismatched pins, and the
    // stale-pin gate above already refused or purged those.
    for name in [
        "XDP_TCP_CT",
        "XDP_UDP_CT",
        "XDP_PENDING",
        "XDP_SNAT_REV",
        "XDP_FLOW_ACCT",
        "XDP_FLOW_EVENTS",
        "XDP_OWNER_EPOCH",
        "XDP_FLOW_SEQ",
        "XDP_COOKIE_KEY",
    ] {
        loader.map_pin_path(name, Path::new(xdp_bpf_pin_dir()).join(name));
    }
    let mut ebpf = match object_path {
        Some(path) => loader.load_file(path)?,
        None => loader.load(XDP_EBPF_EMBEDDED)?,
    };
    audit_loaded_map_specs(&ebpf, config)?;
    let mode = match config.attach_mode {
        XdpAttachMode::Auto => aya::programs::XdpMode::default(),
        XdpAttachMode::Drv => aya::programs::XdpMode::Driver,
        XdpAttachMode::Skb => aya::programs::XdpMode::Skb,
    };
    {
        let program: &mut aya::programs::Xdp = ebpf
            .program_mut("cloud_node_xdp")
            .ok_or_else(|| anyhow::anyhow!("missing eBPF program cloud_node_xdp"))?
            .try_into()?;
        program.load()?;
    }
    // Verify every dispatch subprogram while the previous dataplane is
    // still live. Slots are per (family, proto) pairs because a single
    // SNAT-capable NAT handler is already ~10KiB of BPF: slot 0 =
    // UDP/IPv4, 2 = TCP/IPv4, 3 = UDP/IPv6 replies, 4 = TCP/IPv6 replies,
    // and the IPv6 forward halves each get their own program (5 = UDPv6
    // fwd, 6 = TCPv6 fwd) to stay under older kernels' verifier state
    // budget. Slot 1 is reserved (was SNI blocklist). An older object
    // without a symbol leaves that slot empty; the tail call then returns
    // and the dispatcher falls back to the redirect/PASS path explicitly.
    // Pinned programs keep a kernel reference independent of our fds, so
    // the tail-call chain stays live after a one-shot `xdp attach` exits.
    let mut dispatch_fds: Vec<(u32, Option<aya::programs::ProgramFd>)> = Vec::new();
    for (slot, name) in [
        (0u32, "xdp_nat_dispatch"),
        (2, "xdp_nat_tcp_dispatch"),
        (3, "xdp_nat_udp6_dispatch"),
        (4, "xdp_nat_tcp6_dispatch"),
        (5, "xdp_nat_udp6_fwd"),
        (6, "xdp_nat_tcp6_fwd"),
        (7, "xdp_nat_udp4_work"),
        (8, "xdp_nat_tcp4_work"),
        (9, "xdp_nat_udp6_work"),
        (10, "xdp_nat_tcp6_work"),
        // EN-14: challenge/splice worker — the stateless-cookie forge
        // chain exceeds the 512B combined-stack budget inside the TCP4
        // work program, so it runs behind its own tail call. A stale
        // object without this program leaves the slot empty; the callers
        // fail closed (counted drop) rather than forwarding unverified
        // challenge traffic.
        (11, "xdp_tcp4_challenge"),
    ] {
        let fd = match ebpf.program_mut(name) {
            Some(sub_program) => {
                let sub: &mut aya::programs::Xdp = sub_program.try_into()?;
                sub.load()?;
                Some(
                    sub.fd()?
                        .try_clone()
                        .map_err(|err| anyhow::anyhow!("clone {name} fd: {err}"))?,
                )
            }
            None => None,
        };
        dispatch_fds.push((slot, fd));
    }

    // ---- commit: everything below may change the live dataplane ----
    if let Some(flag) = commit_started {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    detach(config).await?;
    // detach() removed the XDP_DISPATCH pin; our object still holds the
    // map fd (reused during load), so re-pin it — pinned links must keep a
    // live tail-call table after a one-shot `xdp attach` exits.
    if let Some(map) = ebpf.map("XDP_DISPATCH") {
        let dispatch_pin = Path::new(xdp_bpf_pin_dir()).join("XDP_DISPATCH");
        map.pin(&dispatch_pin).map_err(|err| {
            anyhow::anyhow!("re-pin XDP_DISPATCH to {}: {err}", dispatch_pin.display())
        })?;
    }
    let prog_pin_dir = Path::new(xdp_bpf_pin_dir()).join("progs");
    std::fs::create_dir_all(&prog_pin_dir)
        .map_err(|err| anyhow::anyhow!("create prog pin dir {}: {err}", prog_pin_dir.display()))?;
    // Pin the already-verified subprograms; the dispatch table is then
    // populated from the cloned fds captured during prepare.
    for (slot, name) in [
        (0u32, "xdp_nat_dispatch"),
        (2, "xdp_nat_tcp_dispatch"),
        (3, "xdp_nat_udp6_dispatch"),
        (4, "xdp_nat_tcp6_dispatch"),
        (5, "xdp_nat_udp6_fwd"),
        (6, "xdp_nat_tcp6_fwd"),
        (7, "xdp_nat_udp4_work"),
        (8, "xdp_nat_tcp4_work"),
        (9, "xdp_nat_udp6_work"),
        (10, "xdp_nat_tcp6_work"),
        (11, "xdp_tcp4_challenge"),
    ] {
        let Some(sub_program) = ebpf.program_mut(name) else {
            continue;
        };
        debug_assert!(dispatch_fds
            .iter()
            .any(|(s, fd)| *s == slot && fd.is_some()));
        let sub: &mut aya::programs::Xdp = sub_program.try_into()?;
        let pin_path = prog_pin_dir.join(name);
        if pin_path.exists() {
            std::fs::remove_file(&pin_path)?;
        }
        sub.pin(&pin_path).map_err(|err| {
            anyhow::anyhow!("pin {name} to {}: {err}", pin_path.display())
        })?;
    }
    match ebpf.map_mut("XDP_DISPATCH") {
        Some(map) => {
            let mut table = aya::maps::ProgramArray::try_from(map)?;
            let mut missing = false;
            for (slot, fd) in &dispatch_fds {
                match fd {
                    Some(fd) => table.set(*slot, fd, 0)?,
                    None => missing = true,
                }
            }
            if missing {
                tracing::warn!(
                    "eBPF object lacks a dispatch subprogram; affected direct-forward features stay on the normal dataplane"
                );
            }
        }
        None => {
            let configured: usize = config
                .interfaces
                .iter()
                .map(|iface| iface.udp_forwards.len() + iface.tcp_forwards.len())
                .sum();
            if configured > 0 {
                tracing::warn!(
                    "eBPF object lacks XDP_DISPATCH; {configured} configured forwards are not active (stale object, rebuild cloud-node-xdp-ebpf.o)"
                );
            }
        }
    }
    let (owner_epoch, imported_flows) = adopt_flow_state(&mut ebpf)?;
    sync_interface_policy(&mut ebpf, config)?;
    sync_local_ip_maps(&mut ebpf, config)?;
    sync_proxy_ports(&mut ebpf, config, false)?;
    sync_xsk_indices(&mut ebpf, config, false, &Default::default())?;
    zero_counters(&mut ebpf)?;
    let program: &mut aya::programs::Xdp = ebpf
        .program_mut("cloud_node_xdp")
        .ok_or_else(|| anyhow::anyhow!("missing eBPF program cloud_node_xdp"))?
        .try_into()?;
    for interface in &config.interfaces {
        // The commit-phase detach just released the previous link; kernel
        // link teardown can lag the pin removal by an RCU grace period, so
        // retry EBUSY briefly rather than racing bpf_link_create once.
        let mut attach_err = None;
        let mut link_id = None;
        for _ in 0..20 {
            match program.attach(&interface.name, mode) {
                Ok(id) => {
                    link_id = Some(id);
                    break;
                }
                Err(err) => {
                    let busy = match &err {
                        aya::programs::ProgramError::SyscallError(e) => {
                            e.io_error.raw_os_error() == Some(libc::EBUSY)
                        }
                        _ => false,
                    };
                    attach_err = Some(err);
                    if !busy {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        }
        let link_id = link_id.ok_or_else(|| {
            anyhow::anyhow!(
                "attach XDP to {} after bounded EBUSY wait: {}",
                interface.name,
                attach_err.map(|e| e.to_string()).unwrap_or_default()
            )
        })?;
        let link = program.take_link(link_id)?;
        let fd_link: aya::programs::links::FdLink = link.try_into().map_err(|err| {
            anyhow::anyhow!(
                "kernel attached {} through a legacy XDP link that cannot be pinned: {err}",
                interface.name
            )
        })?;
        let pin_path = link_pin_path(&interface.name);
        if pin_path.exists() {
            std::fs::remove_file(&pin_path)?;
        }
        fd_link.pin(&pin_path)?;
        attached.insert(interface.name.clone());
    }
    Ok(AttachedProgram {
        interfaces: attached,
        ebpf,
        owner_epoch,
        imported_flows,
        effective_state_tables: effective_config.state_tables,
    })
}

pub async fn detach(config: &XdpConfig) -> anyhow::Result<()> {
    detach_blocking(config)
}

/// Remove every remaining pinned map under the bpffs pin dir —
/// conntrack, SNAT, pending, accounting, cookie keys, counters and XSK
/// slots are all destroyed. Destructive and explicit: callers must only
/// reach this through the operator-facing `--purge-state` flag, after
/// `detach` has already removed links/programs.
pub fn purge_pinned_state() -> usize {
    let mut removed = 0usize;
    let Ok(dir) = std::fs::read_dir(xdp_bpf_pin_dir()) else {
        return removed;
    };
    for entry in dir.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {
                removed += 1;
                tracing::warn!(
                    "purged pinned eBPF state {} (explicit --purge-state)",
                    path.display()
                );
            }
            Err(err) => {
                tracing::warn!("failed to purge pinned map {}: {err}", path.display());
            }
        }
    }
    removed
}

pub fn detach_blocking(config: &XdpConfig) -> anyhow::Result<()> {
    if let Err(err) = clear_pinned_xsk_map() {
        tracing::warn!("failed to clear pinned AF_XDP socket map: {}", err);
    }
    // Detach every pinned link this process owns — including links for
    // interfaces that were removed from the config since they were pinned.
    // Iterating config.interfaces alone would leak those links (the old
    // program would keep running on an unmanaged interface).
    let mut link_pins: Vec<PathBuf> = config
        .interfaces
        .iter()
        .map(|interface| link_pin_path(&interface.name))
        .collect();
    if let Ok(dir) = std::fs::read_dir(xdp_bpf_pin_dir()) {
        for entry in dir.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            if name.starts_with("link-") && !link_pins.iter().any(|p| *p == path) {
                link_pins.push(path);
            }
        }
    }
    for pin_path in link_pins {
        match PinnedLink::from_pin(&pin_path) {
            Ok(pinned) => {
                if let Err(err) = pinned.unpin() {
                    tracing::warn!("failed to unpin XDP link {}: {}", pin_path.display(), err);
                }
            }
            Err(err) if !pin_path.exists() => {
                let _ = err;
            }
            Err(err) => {
                tracing::warn!(
                    "failed to open pinned XDP link {}: {}",
                    pin_path.display(),
                    err
                );
            }
        }
    }
    // Drop the extra kernel references taken at attach: pinned tail-call
    // subprograms and the pinned dispatch table. Unlink order is
    // irrelevant — each pin only removes one reference.
    let prog_pin_dir = Path::new(xdp_bpf_pin_dir()).join("progs");
    if let Ok(entries) = std::fs::read_dir(&prog_pin_dir) {
        for entry in entries.flatten() {
            if let Err(err) = std::fs::remove_file(entry.path()) {
                tracing::warn!(
                    "failed to unpin eBPF program {}: {}",
                    entry.path().display(),
                    err
                );
            }
        }
        let _ = std::fs::remove_dir(&prog_pin_dir);
    }
    let dispatch_pin = Path::new(xdp_bpf_pin_dir()).join("XDP_DISPATCH");
    if dispatch_pin.exists() {
        if let Err(err) = std::fs::remove_file(&dispatch_pin) {
            tracing::warn!("failed to unpin XDP_DISPATCH map: {err}");
        }
    }
    Ok(())
}

pub fn sync_maps(
    ebpf: &mut aya::Ebpf,
    config: &XdpConfig,
    state: &RuleState,
    proxy_dataplane_active: bool,
    xsk_withdrawn: &std::collections::HashSet<(u32, u32)>,
) -> anyhow::Result<()> {
    sync_interface_policy(ebpf, config)?;
    sync_local_ip_maps(ebpf, config)?;
    sync_proxy_ports(ebpf, config, proxy_dataplane_active)?;
    sync_xsk_indices(ebpf, config, proxy_dataplane_active, xsk_withdrawn)?;
    sync_udp_forwards(ebpf, config, proxy_dataplane_active)?;
    sync_tcp_forwards(ebpf, config, proxy_dataplane_active)?;
    clear_rule_maps(ebpf)?;
    let empty = RuleState::default();
    apply_rule_diff(ebpf, &empty, state)?;
    Ok(())
}

fn clear_rule_maps(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    for name in ["XDP_ALLOWED_V4", "XDP_BLOCKED_V4"] {
        let map = ebpf
            .map_mut(name)
            .ok_or_else(|| anyhow::anyhow!("missing map {name}"))?;
        let mut map = AyaHashMap::<_, XdpIpv4Key, XdpRuleValue>::try_from(map)?;
        clear_hash_map(&mut map)?;
    }
    for name in ["XDP_ALLOWED_V6", "XDP_BLOCKED_V6"] {
        let map = ebpf
            .map_mut(name)
            .ok_or_else(|| anyhow::anyhow!("missing map {name}"))?;
        let mut map = AyaHashMap::<_, XdpIpv6Key, XdpRuleValue>::try_from(map)?;
        clear_hash_map(&mut map)?;
    }
    for name in ["XDP_ALLOWED_V4_LPM", "XDP_BLOCKED_V4_LPM"] {
        let map = ebpf
            .map_mut(name)
            .ok_or_else(|| anyhow::anyhow!("missing map {name}"))?;
        let mut map = LpmTrie::<_, u32, XdpRuleValue>::try_from(map)?;
        clear_lpm_map(&mut map)?;
    }
    for name in ["XDP_ALLOWED_V6_LPM", "XDP_BLOCKED_V6_LPM"] {
        let map = ebpf
            .map_mut(name)
            .ok_or_else(|| anyhow::anyhow!("missing map {name}"))?;
        let mut map = LpmTrie::<_, [u8; 16], XdpRuleValue>::try_from(map)?;
        clear_lpm_map(&mut map)?;
    }
    Ok(())
}

/// EN-08 bounded GC for the per-source rate buckets: entries whose window
/// has been idle for `gc_after_windows` windows are reaped so randomized
/// source churn cannot permanently exhaust the table. Work is capped at
/// `max_reap` removals per pass per map — the remainder is picked up by the
/// next sweep tick, keeping a single GC run's latency bounded.
pub(super) fn sweep_rate_maps(
    ebpf: &mut aya::Ebpf,
    window_ns: u64,
    gc_after_windows: u64,
    max_reap: usize,
) -> anyhow::Result<()> {
    if window_ns == 0 || gc_after_windows == 0 {
        return Ok(());
    }
    let horizon = window_ns.saturating_mul(gc_after_windows);
    let now_ns = monotonic_now_ns();
    let mut reaped = 0usize;

    if let Some(map) = ebpf.map_mut("XDP_RATE_V4") {
        let mut map = AyaHashMap::<_, XdpIpv4Key, XdpRateBucket>::try_from(map)?;
        let mut stale = Vec::new();
        for item in map.iter() {
            let (key, value) = item?;
            if now_ns.saturating_sub(value.window_start_ns) >= horizon {
                stale.push(key);
                if stale.len() >= max_reap {
                    break;
                }
            }
        }
        for key in &stale {
            let _ = map.remove(key);
        }
        reaped += stale.len();
    }
    if let Some(map) = ebpf.map_mut("XDP_RATE_V6") {
        let mut map = AyaHashMap::<_, XdpIpv6Key, XdpRateBucket>::try_from(map)?;
        let mut stale = Vec::new();
        for item in map.iter() {
            let (key, value) = item?;
            if now_ns.saturating_sub(value.window_start_ns) >= horizon {
                stale.push(key);
                if stale.len() >= max_reap {
                    break;
                }
            }
        }
        for key in &stale {
            let _ = map.remove(key);
        }
        reaped += stale.len();
    }
    if reaped > 0 {
        tracing::debug!("XDP rate-map GC reaped {reaped} stale buckets");
    }
    Ok(())
}

pub fn disable_proxy_redirect(ebpf: &mut aya::Ebpf, config: &XdpConfig) -> anyhow::Result<()> {
    sync_proxy_ports(ebpf, config, false)?;
    sync_xsk_indices(ebpf, config, false, &Default::default())?;
    clear_xsk_map(ebpf)?;
    Ok(())
}

/// Aggregate the per-CPU counter slots into a single snapshot. The map is
/// a PerCpuArray so concurrent RX on different cores never loses updates;
/// summing here keeps the status schema unchanged for consumers.
pub(crate) fn sum_percpu_counters<'a>(
    values: impl Iterator<Item = &'a XdpCounters>,
) -> XdpCounters {
    let mut total = XdpCounters::default();
    for v in values {
        macro_rules! sum {
            ($($field:ident),+) => {
                $(total.$field = total.$field.saturating_add(v.$field);)+
            };
        }
        sum!(
            packets,
            pass,
            drop,
            redirect,
            parse_errors,
            map_miss,
            xsk_drops,
            rate_limited,
            ratelimit_map_full,
            udp_fwd_tx,
            udp_fwd_map_full,
            tcp_fwd_tx,
            tcp_fwd_map_full,
            snat_bound,
            snat_alloc_fail,
            snat_reply_tx,
            tx,
            acl_blocked,
            malformed,
            unsupported,
            fragmented,
            control,
            acl_would_block,
            nonlocal_pass,
            unverified_limited,
            admission_limited,
            pending_limited,
            flow_event_lost,
            nat_conflict,
            verified_limited,
            control_limited,
            nat_seq_rejected,
            service_limited,
            svc_budget_full,
            challenge_sent,
            challenge_rejected,
            challenge_worker_err
        );
    }
    total
}

pub fn read_counters(ebpf: &aya::Ebpf) -> anyhow::Result<XdpCounters> {
    let map = ebpf
        .map("XDP_COUNTERS")
        .ok_or_else(|| anyhow::anyhow!("missing map XDP_COUNTERS"))?;
    let counters = PerCpuArray::<_, XdpCounters>::try_from(map)?.get(&0, 0)?;
    Ok(sum_percpu_counters(counters.iter()))
}

/// Read the dataplane counters straight from the pinned XDP_COUNTERS map
/// without requiring this process to own the loaded program. Used by
/// `xdp dump-maps` so test tooling can observe fresh verdict counters
/// while a separate daemon/smoke process owns the attachment.
pub fn read_pinned_counters() -> anyhow::Result<XdpCounters> {
    let path = std::path::Path::new(xdp_bpf_pin_dir()).join("XDP_COUNTERS");
    let data = aya::maps::MapData::from_pin(&path)
        .map_err(|err| anyhow::anyhow!("open pinned XDP_COUNTERS {}: {err}", path.display()))?;
    let map = aya::maps::Map::PerCpuArray(data);
    let counters = PerCpuArray::<_, XdpCounters>::try_from(&map)?.get(&0, 0)?;
    Ok(sum_percpu_counters(counters.iter()))
}

/// Write the per-IP rate limiter config. Returns an explicit error when the
/// loaded eBPF object predates the limiter so callers can report the
/// unsupported feature instead of silently degrading.
pub fn sync_rate_limit(ebpf: &mut aya::Ebpf, config: &XdpRateLimitConfig) -> anyhow::Result<()> {
    let map = ebpf.map_mut("XDP_RATE_CFG").ok_or_else(|| {
        anyhow::anyhow!(
            "missing map XDP_RATE_CFG; eBPF object predates rate limiter (rebuild cloud-node-xdp-ebpf.o)"
        )
    })?;
    let mut array = Array::<_, XdpRateLimitConfig>::try_from(map)?;
    array.set(0, *config, 0)?;
    Ok(())
}

/// Push the resolved aggregate budget (EN-07) into XDP_BUDGET_CFG. The
/// per-CPU bucket map needs no writes — each CPU's fixed-window state lives
/// only in eBPF.
pub fn sync_budget(ebpf: &mut aya::Ebpf, config: &XdpBudgetConfig) -> anyhow::Result<()> {
    let map = ebpf.map_mut("XDP_BUDGET_CFG").ok_or_else(|| {
        anyhow::anyhow!(
            "missing map XDP_BUDGET_CFG; eBPF object predates budget gate (rebuild cloud-node-xdp-ebpf.o)"
        )
    })?;
    let mut array = Array::<_, XdpBudgetConfig>::try_from(map)?;
    array.set(0, *config, 0)?;
    Ok(())
}

/// Push the EN-09 pending admission contract. `max_pending` mirrors the
/// pending table's map bound (the actual hard limit); `pending_ttl_ns` is
/// the absolute half-open deadline enforced in the dataplane.
/// EN-14: install the cookie key ring on first attach. The map is pinned so
/// in-flight challenges survive a reload; an all-zero `cur` means "no key
/// installed" and the dataplane fails challenged SYNs closed (counted).
/// Rotation (cur->prev, fresh cur) is an explicit later API.
pub fn sync_cookie_key(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let map = ebpf.map_mut("XDP_COOKIE_KEY").ok_or_else(|| {
        anyhow::anyhow!(
            "missing map XDP_COOKIE_KEY; eBPF object predates EN-14 cookie key ring (rebuild cloud-node-xdp-ebpf.o)"
        )
    })?;
    let mut array = Array::<_, cloud_node_xdp_common::XdpCookieKey>::try_from(map)?;
    let cur = array.get(&0, 0)?;
    if cur.cur != [0u8; 16] {
        return Ok(());
    }
    let mut key = cloud_node_xdp_common::XdpCookieKey::default();
    key.cur = rand::random::<[u8; 16]>();
    array.set(0, key, 0)?;
    Ok(())
}

pub fn sync_pending_cap(
    ebpf: &mut aya::Ebpf,
    pending_ttl_ns: u64,
    flags: u64,
    max_pending: u32,
) -> anyhow::Result<()> {
    let map = ebpf.map_mut("XDP_PENDING_CAP").ok_or_else(|| {
        anyhow::anyhow!(
            "missing map XDP_PENDING_CAP; eBPF object predates EN-09 pending table (rebuild cloud-node-xdp-ebpf.o)"
        )
    })?;
    let mut array = Array::<_, XdpPendingCap>::try_from(map)?;
    array.set(
        0,
        XdpPendingCap {
            max_pending: u64::from(max_pending),
            pending_ttl_ns,
            flags,
        },
        0,
    )?;
    Ok(())
}

fn zero_counters(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let map = ebpf
        .map_mut("XDP_COUNTERS")
        .ok_or_else(|| anyhow::anyhow!("missing map XDP_COUNTERS"))?;
    let mut counters = PerCpuArray::<_, XdpCounters>::try_from(map)?;
    let ncpu = aya::util::nr_cpus().map_err(|(_, err)| err)?;
    let values = aya::maps::PerCpuValues::try_from(vec![XdpCounters::default(); ncpu])
        .map_err(|err| anyhow::anyhow!("per-cpu counter reset buffer: {err}"))?;
    counters.set(0, values, 0)?;
    Ok(())
}

fn sync_interface_policy(ebpf: &mut aya::Ebpf, config: &XdpConfig) -> anyhow::Result<()> {
    let map = ebpf
        .map_mut("XDP_INTERFACE_POLICY")
        .ok_or_else(|| anyhow::anyhow!("missing map XDP_INTERFACE_POLICY"))?;
    let mut policies = AyaHashMap::<_, u32, XdpInterfacePolicy>::try_from(map)?;
    clear_hash_map(&mut policies)?;
    for interface in &config.interfaces {
        let ifindex = ifindex_from_name(&interface.name)?;
        let policy = XdpInterfacePolicy {
            mode: match interface.mode {
                XdpRuntimeMode::Observe => 0,
                XdpRuntimeMode::Protect => 1,
                XdpRuntimeMode::Proxy => 2,
            },
            fallback_pass: u8::from(!config.fallback.fail_start()),
            local_ip_filter: u8::from(!interface.local_ips.is_empty()),
            fragment_action: match interface.fragment_action {
                crate::runtime_mode::XdpFragmentAction::Pass => {
                    cloud_node_xdp_common::XDP_FRAGMENT_PASS
                }
                crate::runtime_mode::XdpFragmentAction::Drop => {
                    cloud_node_xdp_common::XDP_FRAGMENT_DROP
                }
            },
            frame_size: interface.frame_size,
        };
        policies.insert(ifindex, policy, 0)?;
    }
    Ok(())
}

/// XDP_LOCAL_* value: bit0 marks presence; bits[2:1] carry the per-VIP
/// fragment override resolved from `protectedServices[].fragmentAction`
/// (0 = inherit the interface policy); bit3 marks the VIP redirect-eligible
/// — `protectedServices[].redirect: false` clears it so protection stays on
/// while the VIP's ports keep their kernel path.
fn local_ip_flags(interface: &XdpInterfaceConfig, ip: &IpAddr) -> u32 {
    let mut flags =
        cloud_node_xdp_common::XDP_LOCAL_PRESENT | cloud_node_xdp_common::XDP_LOCAL_REDIRECT;
    for entry in &interface.protected_services {
        if &entry.ip == ip {
            if !entry.redirect {
                flags &= !cloud_node_xdp_common::XDP_LOCAL_REDIRECT;
            }
            flags |= match entry.fragment_action {
                Some(crate::runtime_mode::XdpFragmentAction::Pass) => {
                    cloud_node_xdp_common::XDP_LOCAL_FRAG_PASS
                }
                Some(crate::runtime_mode::XdpFragmentAction::Drop) => {
                    cloud_node_xdp_common::XDP_LOCAL_FRAG_DROP
                }
                None => 0,
            };
        }
    }
    flags
}

fn sync_local_ip_maps(ebpf: &mut aya::Ebpf, config: &XdpConfig) -> anyhow::Result<()> {
    {
        let map = ebpf
            .map_mut("XDP_LOCAL_V4")
            .ok_or_else(|| anyhow::anyhow!("missing map XDP_LOCAL_V4"))?;
        let mut map = AyaHashMap::<_, XdpLocalIpv4Key, u32>::try_from(map)?;
        clear_hash_map(&mut map)?;
        for interface in &config.interfaces {
            let ifindex = ifindex_from_name(&interface.name)?;
            for ip in &interface.local_ips {
                if let IpAddr::V4(addr) = ip {
                    map.insert(
                        XdpLocalIpv4Key::new(ifindex, u32::from_be_bytes(addr.octets())),
                        local_ip_flags(interface, ip),
                        0,
                    )?;
                }
            }
        }
    }

    {
        let map = ebpf
            .map_mut("XDP_LOCAL_V6")
            .ok_or_else(|| anyhow::anyhow!("missing map XDP_LOCAL_V6"))?;
        let mut map = AyaHashMap::<_, XdpLocalIpv6Key, u32>::try_from(map)?;
        clear_hash_map(&mut map)?;
        for interface in &config.interfaces {
            let ifindex = ifindex_from_name(&interface.name)?;
            for ip in &interface.local_ips {
                if let IpAddr::V6(addr) = ip {
                    map.insert(
                        XdpLocalIpv6Key::new(ifindex, addr.octets()),
                        local_ip_flags(interface, ip),
                        0,
                    )?;
                }
            }
        }
    }

    Ok(())
}

fn sync_proxy_ports(
    ebpf: &mut aya::Ebpf,
    config: &XdpConfig,
    dataplane_active: bool,
) -> anyhow::Result<()> {
    let map = ebpf
        .map_mut("XDP_PROXY_PORTS")
        .ok_or_else(|| anyhow::anyhow!("missing map XDP_PROXY_PORTS"))?;
    let mut map = AyaHashMap::<_, XdpPortProtoKey, u32>::try_from(map)?;
    clear_hash_map(&mut map)?;
    if !dataplane_active {
        return Ok(());
    }
    for port in &config.proxy.ports {
        if !xdp_protocol_dataplane_supported(&port.protocol) {
            continue;
        }
        map.insert(
            XdpPortProtoKey {
                port_be: port.port.to_be(),
                proto: xdp_ip_proto(&port.protocol),
                _pad: 0,
            },
            1,
            0,
        )?;
    }
    Ok(())
}

fn sync_xsk_indices(
    ebpf: &mut aya::Ebpf,
    config: &XdpConfig,
    dataplane_active: bool,
    withdrawn: &std::collections::HashSet<(u32, u32)>,
) -> anyhow::Result<()> {
    let map = ebpf
        .map_mut("XDP_XSK_INDEX")
        .ok_or_else(|| anyhow::anyhow!("missing map XDP_XSK_INDEX"))?;
    let mut map = AyaHashMap::<_, XdpQueueKey, u32>::try_from(map)?;
    clear_hash_map(&mut map)?;
    if !dataplane_active {
        return Ok(());
    }
    for entry in xsk_map_entries(config)? {
        // EN-05: never resurrect a queue-scoped withdrawal — the faulted
        // queue's traffic must keep taking the explicit dataplane fallback.
        if withdrawn.contains(&(entry.ifindex, entry.queue)) {
            continue;
        }
        map.insert(XdpQueueKey::new(entry.ifindex, entry.queue), entry.index, 0)?;
    }
    Ok(())
}

/// EN-05 queue-scoped withdrawal: remove one queue's XSK_INDEX entry and
/// unset its XSKS socket slot. Redirect for that queue then resolves to
/// the explicit dataplane fallback instead of a dead socket; sibling
/// queues keep serving. Returns true when an index entry existed.
pub fn disable_queue_redirect(
    ebpf: &mut aya::Ebpf,
    interface: &str,
    queue: u32,
) -> anyhow::Result<bool> {
    let ifindex = ifindex_from_name(interface)?;
    let map = ebpf
        .map_mut("XDP_XSK_INDEX")
        .ok_or_else(|| anyhow::anyhow!("missing map XDP_XSK_INDEX"))?;
    let mut index_map = AyaHashMap::<_, XdpQueueKey, u32>::try_from(map)?;
    let key = XdpQueueKey::new(ifindex, queue);
    let slot = index_map.get(&key, 0).ok();
    index_map.remove(&key)?;
    let Some(slot) = slot else {
        return Ok(false);
    };
    let map = ebpf
        .map_mut("XDP_XSKS")
        .ok_or_else(|| anyhow::anyhow!("missing map XDP_XSKS"))?;
    let mut xsks = XskMap::try_from(map)?;
    xsks.unset(slot)?;
    Ok(true)
}

/// Program explicit UDP direct-forward rules. Each entry needs a resolved
/// backend address and a next-hop MAC (from config or the neighbor table).
/// Unresolvable entries are skipped with a warning so the listen tuple
/// keeps its normal XSK/kernel path instead of being silently forwarded
/// with a bogus route.
fn sync_udp_forwards(
    ebpf: &mut aya::Ebpf,
    config: &XdpConfig,
    dataplane_active: bool,
) -> anyhow::Result<()> {
    sync_forward_map(
        ebpf,
        "XDP_UDP_FWD",
        "UDP",
        false,
        config,
        dataplane_active,
        |iface| &iface.udp_forwards,
    )
}

/// Program explicit TCP direct-forward rules; same contract as
/// `sync_udp_forwards`.
fn sync_tcp_forwards(
    ebpf: &mut aya::Ebpf,
    config: &XdpConfig,
    dataplane_active: bool,
) -> anyhow::Result<()> {
    sync_forward_map(
        ebpf,
        "XDP_TCP_FWD",
        "TCP",
        true,
        config,
        dataplane_active,
        |iface| &iface.tcp_forwards,
    )
}

fn sync_forward_map(
    ebpf: &mut aya::Ebpf,
    map_name: &str,
    proto: &str,
    is_tcp: bool,
    config: &XdpConfig,
    dataplane_active: bool,
    forwards: impl Fn(
        &crate::runtime_mode::XdpInterfaceConfig,
    ) -> &Vec<crate::runtime_mode::XdpUdpForwardConfig>,
) -> anyhow::Result<()> {
    let Some(map) = ebpf.map_mut(map_name) else {
        let configured: usize = config.interfaces.iter().map(|i| forwards(i).len()).sum();
        if configured > 0 {
            tracing::warn!(
                "eBPF object lacks {map_name}; {configured} configured {proto} forwards are not active (stale object, rebuild cloud-node-xdp-ebpf.o)"
            );
        }
        return Ok(());
    };
    let mut map = AyaHashMap::<_, XdpUdpFwdKey, XdpUdpFwdRule>::try_from(map)?;
    clear_hash_map(&mut map)?;
    if !dataplane_active {
        return Ok(());
    }
    for iface in &config.interfaces {
        for fwd in forwards(iface) {
            match udp_forward_entry(fwd, is_tcp) {
                Ok((key, rule)) => {
                    if let Err(err) = map.insert(key, rule, 0) {
                        tracing::warn!(
                            "XDP {proto} forward {} -> {} on {} failed to install: {err}",
                            fwd.listen,
                            fwd.backend,
                            iface.name
                        );
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        "XDP {proto} forward {} -> {} on {} is not active: {err}; traffic keeps the normal dataplane",
                        fwd.listen,
                        fwd.backend,
                        iface.name
                    );
                }
            }
        }
    }
    Ok(())
}

pub(super) fn udp_forward_entry(
    fwd: &crate::runtime_mode::XdpUdpForwardConfig,
    is_tcp: bool,
) -> anyhow::Result<(XdpUdpFwdKey, XdpUdpFwdRule)> {
    use std::net::ToSocketAddrs;
    let backend = fwd
        .backend
        .to_socket_addrs()
        .map_err(|err| anyhow::anyhow!("backend {} resolve failed: {err}", fwd.backend))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("backend {} resolved no addresses", fwd.backend))?;
    if backend.is_ipv4() != fwd.listen.is_ipv4() {
        anyhow::bail!(
            "address family mismatch: listen {} vs backend {}",
            fwd.listen,
            backend
        );
    }
    let next_hop_mac = if fwd.next_hop_mac.is_empty() {
        resolve_next_hop_mac(backend.ip())
            .map_err(|err| anyhow::anyhow!("next-hop MAC for {}: {err}", backend.ip()))?
    } else {
        parse_mac(&fwd.next_hop_mac)
            .map_err(|err| anyhow::anyhow!("invalid nextHopMac {}: {err}", fwd.next_hop_mac))?
    };
    let (key, backend_addr) = match (fwd.listen.ip(), backend.ip()) {
        (IpAddr::V4(listen), IpAddr::V4(backend)) => (
            XdpUdpFwdKey::new_v4(
                u32::from_be_bytes(listen.octets()),
                fwd.listen.port().to_be(),
            ),
            v4_embed(backend),
        ),
        (IpAddr::V6(listen), IpAddr::V6(backend)) => (
            XdpUdpFwdKey::new_v6(listen.octets(), fwd.listen.port().to_be()),
            backend.octets(),
        ),
        _ => unreachable!(),
    };
    // EN-14 challenge gating is explicit: unsupported combinations fail the
    // rule with a logged reason instead of silently downgrading to bounded
    // admission on a service the operator believes is strongly validated.
    if fwd.challenge {
        anyhow::ensure!(is_tcp, "challenge is TCP-only (UDP rules ignore it)");
        anyhow::ensure!(fwd.snat, "challenge requires snat (the splice needs observable backend replies)");
        anyhow::ensure!(key.family == 4, "challenge is IPv4-only in this slice (IPv6 keeps bounded admission)");
    }
    Ok((
        key,
        XdpUdpFwdRule {
            backend_addr,
            next_hop_mac,
            backend_port_be: backend.port().to_be(),
            family: key.family,
            snat: u8::from(fwd.snat),
            server_id: fwd.server_id,
            challenge: u8::from(fwd.challenge && is_tcp),
            ..Default::default()
        },
    ))
}

fn v4_embed(addr: std::net::Ipv4Addr) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&addr.octets());
    out
}

pub(super) fn parse_mac(text: &str) -> anyhow::Result<[u8; 6]> {
    let parts: Vec<&str> = text.split(':').collect();
    if parts.len() != 6 {
        anyhow::bail!("expected 6 octets");
    }
    let mut mac = [0u8; 6];
    for (idx, part) in parts.iter().enumerate() {
        mac[idx] = u8::from_str_radix(part, 16)?;
    }
    Ok(mac)
}

/// Resolve the neighbor MAC for a backend address: `ip -j route get`
/// yields the next hop (gateway, or the target itself when on-link), then
/// `ip -j neigh show` yields its link-layer address.
fn resolve_next_hop_mac(target: IpAddr) -> anyhow::Result<[u8; 6]> {
    let route = run_ip_json(&["route", "get", &target.to_string()])?;
    let entry = route
        .first()
        .ok_or_else(|| anyhow::anyhow!("no route to {target}"))?;
    let next_hop = entry
        .get("gateway")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| target.to_string());
    let neigh = run_ip_json(&["neigh", "show", "to", &next_hop])?;
    for entry in &neigh {
        let Some(lladdr) = entry.get("lladdr").and_then(|v| v.as_str()) else {
            continue;
        };
        let usable = entry
            .get("state")
            .and_then(|v| v.as_array())
            .map(|states| {
                states.iter().any(|s| {
                    matches!(
                        s.as_str(),
                        Some("REACHABLE") | Some("STALE") | Some("DELAY") | Some("PERMANENT")
                    )
                })
            })
            .unwrap_or(true);
        if usable {
            return parse_mac(lladdr)
                .map_err(|err| anyhow::anyhow!("neighbor {next_hop} lladdr {lladdr}: {err}"));
        }
    }
    anyhow::bail!("no usable neighbor entry for {next_hop} (route to {target})")
}

fn run_ip_json(args: &[&str]) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut argv = vec!["-j"];
    argv.extend_from_slice(args);
    let output = std::process::Command::new("ip")
        .args(&argv)
        .output()
        .map_err(|err| anyhow::anyhow!("ip command failed to start: {err}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "ip {} exited {}: {}",
            argv.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|err| anyhow::anyhow!("ip -j output parse failed: {err}"))
}

/// GC stale conntrack entries and fold per-CPU flow accounting into the
/// billing pipeline. Accounting is folded first (final deltas included)
/// and only then are stale conntrack/accounting/shadow entries removed, so
/// a reaped flow's last bytes are billed exactly once. TCP entries in
/// CLOSING state are reaped after `tcp_closing_grace`; all others use the
/// protocol's idle timeout.
/// EN-11 sweep budget: caps the syscall-bound removals each map performs
/// per round (see sweep_nat_maps). Bulk scans stay bounded by the map's
/// max_entries; stale entries past the cap are collected first next round.
const SWEEP_MAX_REAP_PER_MAP: usize = 4096;

pub(super) fn sweep_nat_maps(
    ebpf: &mut aya::Ebpf,
    shadow: &mut std::collections::HashMap<XdpUdpCtKey, XdpFlowAcct>,
    udp_idle: std::time::Duration,
    tcp_idle: std::time::Duration,
    tcp_closing_grace: std::time::Duration,
    tcp_pending: std::time::Duration,
) -> anyhow::Result<()> {
    use cloud_node_xdp_common::XDP_CT_STATE_CLOSING;
    let now_ns = monotonic_now_ns();
    let udp_idle_ns = udp_idle.as_nanos().min(u64::MAX as u128) as u64;
    let tcp_idle_ns = tcp_idle.as_nanos().min(u64::MAX as u128) as u64;
    let closing_ns = tcp_closing_grace.as_nanos().min(u64::MAX as u128) as u64;
    let pending_ns = tcp_pending.as_nanos().min(u64::MAX as u128) as u64;

    // Per-round work budget: map removals are one syscall each, so every
    // map reaps at most SWEEP_MAX_REAP_PER_MAP stale entries per round.
    // Stale entries past the cap stay in the live set — they still exist
    // in the kernel map and may own SNAT bindings — and are collected
    // first next round, so reaping progresses regardless of churn. The
    // bulk iteration itself is bounded by the map's max_entries.
    let mut stale: std::collections::HashSet<XdpUdpCtKey> = Default::default();
    // EN-11: live sets record each live entry's claimed SNAT port, so the
    // orphan check can distinguish a binding whose flow was re-admitted on
    // a new port (orphan — reap it) from the binding the live flow owns.
    let mut udp_live: std::collections::HashMap<XdpUdpCtKey, u16> = Default::default();
    let mut tcp_live: std::collections::HashMap<XdpUdpCtKey, u16> = Default::default();
    if let Some(map) = ebpf.map_mut("XDP_UDP_CT") {
        let mut map = AyaHashMap::<_, XdpUdpCtKey, XdpUdpCtValue>::try_from(map)?;
        // (key, last_seen snapshot): the entry is only removed when the
        // value is unchanged — a concurrent refresh or tuple re-admission
        // between scan and removal must not delete the newer record.
        let mut reap: Vec<(XdpUdpCtKey, u64)> = Vec::new();
        for item in map.iter() {
            let (key, value) = item?;
            if now_ns.saturating_sub(value.last_seen_ns) >= udp_idle_ns
                && reap.len() < SWEEP_MAX_REAP_PER_MAP
            {
                reap.push((key, value.last_seen_ns));
                stale.insert(key);
            } else {
                udp_live.insert(key, value.snat_port_be);
            }
        }
        for (key, seen) in &reap {
            let still_stale = map
                .get(key, 0)
                .map(|v| v.last_seen_ns == *seen)
                .unwrap_or(false);
            if still_stale {
                let _ = map.remove(key);
            }
        }
    }
    if let Some(map) = ebpf.map_mut("XDP_TCP_CT") {
        let mut map = AyaHashMap::<_, XdpUdpCtKey, XdpUdpCtValue>::try_from(map)?;
        let mut reap: Vec<(XdpUdpCtKey, u64)> = Vec::new();
        for item in map.iter() {
            let (key, value) = item?;
            let idle = now_ns.saturating_sub(value.last_seen_ns);
            let limit = if value.state == XDP_CT_STATE_CLOSING {
                closing_ns
            } else {
                tcp_idle_ns
            };
            if idle >= limit && reap.len() < SWEEP_MAX_REAP_PER_MAP {
                reap.push((key, value.last_seen_ns));
                stale.insert(key);
            } else {
                tcp_live.insert(key, value.snat_port_be);
            }
        }
        for (key, seen) in &reap {
            let still_stale = map
                .get(key, 0)
                .map(|v| v.last_seen_ns == *seen)
                .unwrap_or(false);
            if still_stale {
                let _ = map.remove(key);
            }
        }
    }

    // EN-09: reap half-open entries whose absolute deadline has passed.
    // Pending last_seen_ns is frozen at admission, so this cannot be held
    // open by retransmits. Live pending entries count as owning conntrack
    // for the SNAT orphan check below.
    if let Some(map) = ebpf.map_mut("XDP_PENDING") {
        let mut map = AyaHashMap::<_, XdpUdpCtKey, XdpUdpCtValue>::try_from(map)?;
        let mut reap: Vec<(XdpUdpCtKey, u64)> = Vec::new();
        for item in map.iter() {
            let (key, value) = item?;
            if now_ns.saturating_sub(value.last_seen_ns) >= pending_ns
                && reap.len() < SWEEP_MAX_REAP_PER_MAP
            {
                reap.push((key, value.last_seen_ns));
                stale.insert(key);
            } else {
                tcp_live.insert(key, value.snat_port_be);
            }
        }
        for (key, seen) in &reap {
            // A pending entry re-admitted after the scan carries a new
            // last_seen (and incarnation); skip removal in that case.
            let still_stale = map
                .get(key, 0)
                .map(|v| v.last_seen_ns == *seen)
                .unwrap_or(false);
            if still_stale {
                let _ = map.remove(key);
            }
        }
    }

    // Reap SNAT reverse bindings whose owning conntrack entry is gone.
    if let Some(map) = ebpf.map_mut("XDP_SNAT_REV") {
        let mut map = AyaHashMap::<_, XdpSnatRevKey, XdpSnatRevValue>::try_from(map)?;
        let mut orphan = Vec::new();
        for item in map.iter() {
            let (key, value) = item?;
            let ct_key = XdpUdpCtKey {
                client_addr: value.client_addr,
                backend_addr: value.backend_addr,
                client_port_be: value.client_port_be,
                backend_port_be: value.backend_port_be,
                family: value.family,
                proto: value.proto,
                ..Default::default()
            };
            // A binding is live only while its owning conntrack entry both
            // exists and still claims THIS port — a re-admitted tuple on a
            // new port leaves the old binding an orphan to reap, and a
            // re-claimed port stays protected because the live entry's
            // claim matches the key.
            let alive = match value.proto {
                6 => tcp_live.get(&ct_key),
                _ => udp_live.get(&ct_key),
            }
            .is_some_and(|port| *port == key.snat_port_be);
            if !alive {
                orphan.push(key);
            }
        }
        for key in &orphan {
            let _ = map.remove(key);
        }
    }

    let mut bill: std::collections::HashMap<i64, (u64, u64)> = Default::default();
    if let Some(map) = ebpf.map_mut("XDP_FLOW_ACCT") {
        let mut map = aya::maps::PerCpuHashMap::<_, XdpUdpCtKey, XdpFlowAcct>::try_from(map)?;
        let mut acct_remove = Vec::new();
        for item in map.iter() {
            let (key, per_cpu) = item?;
            let mut total = XdpFlowAcct::default();
            for value in per_cpu.iter() {
                total.rx_bytes = total.rx_bytes.saturating_add(value.rx_bytes);
                total.tx_bytes = total.tx_bytes.saturating_add(value.tx_bytes);
                total.rx_pkts = total.rx_pkts.saturating_add(value.rx_pkts);
                total.tx_pkts = total.tx_pkts.saturating_add(value.tx_pkts);
                total.last_seen_ns = total.last_seen_ns.max(value.last_seen_ns);
                total.server_id = value.server_id;
            }
            let previous = shadow.get(&key).copied().unwrap_or_default();
            let delta_rx = total.rx_bytes.saturating_sub(previous.rx_bytes);
            let delta_tx = total.tx_bytes.saturating_sub(previous.tx_bytes);
            if delta_rx > 0 || delta_tx > 0 {
                // Aggregate deltas per server_id: billing calls per round
                // are bounded by the number of distinct servers (itself
                // bounded by the forward-rule count) instead of the flow
                // count, and no delta is ever dropped or deferred.
                let entry = bill.entry(total.server_id).or_insert((0, 0));
                entry.0 = entry.0.saturating_add(delta_tx);
                entry.1 = entry.1.saturating_add(delta_rx);
            }
            if stale.contains(&key) {
                acct_remove.push(key);
                shadow.remove(&key);
            } else {
                shadow.insert(key, total);
            }
        }
        for key in acct_remove {
            let _ = map.remove(&key);
        }
        for (server_id, (tx, rx)) in bill {
            crate::metrics::record::record_transfer(server_id, tx, rx, None);
        }
    }
    // Shadow entries whose flow was already reaped stay; they are dropped
    // once their acct entry is observed above, so nothing accumulates.
    Ok(())
}

fn clear_xsk_map(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let map = ebpf
        .map_mut("XDP_XSKS")
        .ok_or_else(|| anyhow::anyhow!("missing map XDP_XSKS"))?;
    let mut map = XskMap::try_from(map)?;
    clear_xsk_map_entries(&mut map);
    Ok(())
}

fn clear_pinned_xsk_map() -> anyhow::Result<()> {
    let path = Path::new(xdp_bpf_pin_dir()).join("XDP_XSKS");
    if !path.exists() {
        return Ok(());
    }
    let map = aya::maps::Map::XskMap(aya::maps::MapData::from_pin(path)?);
    let mut map = XskMap::try_from(map)?;
    clear_xsk_map_entries(&mut map);
    Ok(())
}

/// Removes pinned maps whose kernel-reported spec no longer matches the
/// eBPF object's definition. aya adopts an existing pin purely by name
/// (`bpf_get_object` succeeds => reuse), so a pin left over from an older
/// build — a 4-slot XDP_DISPATCH, a pre-SNAT XDP_COUNTERS value, etc. —
/// would otherwise be silently reused and then fail deep inside attach
/// with an opaque index/size error. Mismatched maps only lose runtime
/// state that is resynced right after load (CT/acct entries are rebuilt
/// by traffic); the removal is logged, never silent.
/// (name, map type, key size, value size, max_entries). Must stay
/// aligned with the #[map] definitions in
/// crates/cloud-node-xdp-ebpf/src/main.rs. LPM trie keys carry a
/// 4-byte prefix length in front of the address.
/// EN-16: `xdp.stateTables` overrides for the sizeable state maps. Returns
/// the configured max_entries or `None` to keep the object's default.
fn state_table_override(name: &str, config: &XdpConfig) -> Option<u32> {
    let t = config.state_tables.as_ref()?;
    match name {
        "XDP_TCP_CT" | "XDP_UDP_CT" => t.ct_max_entries,
        "XDP_PENDING" => t.pending_max_entries,
        "XDP_SNAT_REV" => t.snat_rev_max_entries,
        "XDP_FLOW_ACCT" => t.flow_acct_max_entries,
        "XDP_RATE_V6" => t.rate_v6_max_entries,
        "XDP_QUIC_DCID" => t.quic_dcid_max_entries,
        "XDP_BLOCKED_V4" | "XDP_BLOCKED_V6" | "XDP_BLOCKED_V4_LPM"
        | "XDP_BLOCKED_V6_LPM" => t.acl_blocked_max_entries,
        "XDP_ALLOWED_V4" | "XDP_ALLOWED_V6" | "XDP_ALLOWED_V4_LPM"
        | "XDP_ALLOWED_V6_LPM" => t.acl_allowed_max_entries,
        "XDP_RATE_V4" => t.rate_v4_max_entries,
        _ => None,
    }
}

fn bpf_map_specs(
    config: &XdpConfig,
) -> [(&'static str, aya::maps::MapType, u32, u32, u32); 37] {
    use aya::maps::MapType;
    use cloud_node_xdp_common::*;
    use core::mem::size_of;

    let u = size_of::<u32>() as u32;
    let v4 = size_of::<XdpIpv4Key>() as u32;
    let v6 = size_of::<XdpIpv6Key>() as u32;
    let rule = size_of::<XdpRuleValue>() as u32;
    let fwd_key = size_of::<XdpUdpFwdKey>() as u32;
    let fwd_rule = size_of::<XdpUdpFwdRule>() as u32;
    let ct_key = size_of::<XdpUdpCtKey>() as u32;
    let ct_value = size_of::<XdpUdpCtValue>() as u32;
    let mut specs = [
        ("XDP_BLOCKED_V4", MapType::Hash, v4, rule, 262_144),
        ("XDP_BLOCKED_V6", MapType::Hash, v6, rule, 262_144),
        ("XDP_ALLOWED_V4", MapType::Hash, v4, rule, 65_536),
        ("XDP_ALLOWED_V6", MapType::Hash, v6, rule, 65_536),
        ("XDP_BLOCKED_V4_LPM", MapType::LpmTrie, u + 4, rule, 65_536),
        ("XDP_BLOCKED_V6_LPM", MapType::LpmTrie, u + 16, rule, 65_536),
        ("XDP_ALLOWED_V4_LPM", MapType::LpmTrie, u + 4, rule, 65_536),
        ("XDP_ALLOWED_V6_LPM", MapType::LpmTrie, u + 16, rule, 65_536),
        (
            "XDP_INTERFACE_POLICY",
            MapType::Hash,
            u,
            size_of::<XdpInterfacePolicy>() as u32,
            64,
        ),
        (
            "XDP_LOCAL_V4",
            MapType::Hash,
            size_of::<XdpLocalIpv4Key>() as u32,
            u,
            4_096,
        ),
        (
            "XDP_LOCAL_V6",
            MapType::Hash,
            size_of::<XdpLocalIpv6Key>() as u32,
            u,
            4_096,
        ),
        (
            "XDP_PROXY_PORTS",
            MapType::Hash,
            size_of::<XdpPortProtoKey>() as u32,
            u,
            4_096,
        ),
        (
            "XDP_COUNTERS",
            MapType::PerCpuArray,
            u,
            size_of::<XdpCounters>() as u32,
            1,
        ),
        ("XDP_XSKS", MapType::XskMap, u, u, 4_096),
        (
            "XDP_XSK_INDEX",
            MapType::Hash,
            size_of::<XdpQueueKey>() as u32,
            u,
            4_096,
        ),
        (
            "XDP_RATE_CFG",
            MapType::Array,
            u,
            size_of::<XdpRateLimitConfig>() as u32,
            1,
        ),
        (
            "XDP_BUDGET_CFG",
            MapType::Array,
            u,
            size_of::<XdpBudgetConfig>() as u32,
            1,
        ),
        (
            "XDP_BUDGET",
            MapType::PerCpuArray,
            u,
            size_of::<XdpBudgetBucket>() as u32,
            1,
        ),
        (
            "XDP_SVC_BUDGET",
            MapType::PerCpuHash,
            u,
            size_of::<cloud_node_xdp_common::XdpSvcBucket>() as u32,
            256,
        ),
        (
            "XDP_RATE_V4",
            MapType::Hash,
            v4,
            size_of::<XdpRateBucket>() as u32,
            262_144,
        ),
        (
            "XDP_RATE_V6",
            MapType::Hash,
            v6,
            size_of::<XdpRateBucket>() as u32,
            262_144,
        ),
        (
            "XDP_QUIC_DCID",
            MapType::Hash,
            size_of::<XdpQuicDcidKey>() as u32,
            u,
            131_072,
        ),
        ("XDP_UDP_FWD", MapType::Hash, fwd_key, fwd_rule, 4_096),
        ("XDP_TCP_FWD", MapType::Hash, fwd_key, fwd_rule, 4_096),
        ("XDP_UDP_CT", MapType::Hash, ct_key, ct_value, 262_144),
        ("XDP_TCP_CT", MapType::Hash, ct_key, ct_value, 262_144),
        ("XDP_PENDING", MapType::Hash, ct_key, ct_value, 65_536),
        (
            "XDP_PENDING_CAP",
            MapType::Array,
            u,
            size_of::<XdpPendingCap>() as u32,
            1,
        ),
        (
            "XDP_COOKIE_KEY",
            MapType::Array,
            u,
            size_of::<cloud_node_xdp_common::XdpCookieKey>() as u32,
            1,
        ),
        (
            "XDP_SNAT_REV",
            MapType::Hash,
            size_of::<XdpSnatRevKey>() as u32,
            size_of::<XdpSnatRevValue>() as u32,
            65_536,
        ),
        (
            "XDP_NAT_SCRATCH",
            MapType::PerCpuArray,
            u,
            size_of::<NatScratch>() as u32,
            1,
        ),
        ("XDP_DISPATCH", MapType::ProgramArray, u, u, 16),
        // Compiler-generated constant pool (EN-14 cookie compare/MSS table):
        // counted like every other map — it is kernel memory too.
        (".rodata.cst16", MapType::Array, u, 16, 1),
        (
            "XDP_FLOW_ACCT",
            MapType::PerCpuHash,
            ct_key,
            size_of::<XdpFlowAcct>() as u32,
            262_144,
        ),
        // EN-10 lifecycle feedback channel: kernel reports ring buffers with
        // zero key/value sizes and max_entries == byte size.
        ("XDP_FLOW_EVENTS", MapType::RingBuf, 0, 0, 256 * 1024),
        (
            "XDP_OWNER_EPOCH",
            MapType::Array,
            u,
            size_of::<u64>() as u32,
            1,
        ),
        (
            "XDP_FLOW_SEQ",
            MapType::PerCpuArray,
            u,
            size_of::<u64>() as u32,
            1,
        ),
    ];
    for spec in specs.iter_mut() {
        if let Some(max) = state_table_override(spec.0, config) {
            spec.4 = max;
        }
    }
    specs
}

/// Worst-case pinned kernel memory for one spec-table entry set.
fn map_spec_bytes(ty: aya::maps::MapType, key: u32, value: u32, max_entries: u32) -> u64 {
    const HASH_ENTRY_OVERHEAD: u64 = 64;
    const LPM_ENTRY_OVERHEAD: u64 = 48;
    const ARRAY_ENTRY_OVERHEAD: u64 = 8;
    let ncpu = aya::util::nr_cpus().unwrap_or(1).max(1) as u64;
    let (k, v, n) = (u64::from(key), u64::from(value), u64::from(max_entries));
    match ty {
        aya::maps::MapType::PerCpuArray | aya::maps::MapType::PerCpuHash => {
            n.saturating_mul(k + v.saturating_mul(ncpu) + HASH_ENTRY_OVERHEAD)
        }
        aya::maps::MapType::Hash => n.saturating_mul(k + v + HASH_ENTRY_OVERHEAD),
        aya::maps::MapType::LpmTrie => n.saturating_mul(k + v + LPM_ENTRY_OVERHEAD),
        // Ring buffers reserve their declared byte size plus a couple of
        // bookkeeping pages; key/value sizes are zero.
        aya::maps::MapType::RingBuf => n.saturating_add(2 * 4096),
        _ => n.saturating_mul(k + v + ARRAY_ENTRY_OVERHEAD),
    }
}

/// EN-16 kernel-BPF ledger: worst-case pinned kernel memory for every map in
/// the object. Hash entries are charged `key + value + 64B` of htab
/// bookkeeping (measured on kernel 7.0 within ~10% of memlock); per-CPU maps
/// multiply the value by the possible-CPU count; LPM tries allocate lazily
/// but are still bounded at their worst case.
pub(crate) fn projected_bpf_map_bytes(config: &XdpConfig) -> u64 {
    let mut total = 0u64;
    for (_name, ty, key, value, max_entries) in bpf_map_specs(config) {
        total = total.saturating_add(map_spec_bytes(ty, key, value, max_entries));
    }
    total
}

/// Auto-size the sizeable state tables to the kernel-BPF budget when the
/// operator gave no explicit `xdp.stateTables`. Without this a default
/// configuration exceeds the budget on small nodes (e.g. 2 GiB VPS) and
/// attach would fail outright. The scale-down is proportional across the
/// scalable tables with a per-table floor; if even floored tables do not
/// fit, the node is too small and attach fails explicitly.
fn auto_scale_state_tables(config: &XdpConfig, budget: u64) -> anyhow::Result<Option<XdpStateTables>> {
    let projected = projected_bpf_map_bytes(config);
    if projected <= budget {
        return Ok(None);
    }
    const STATE_TABLE_FLOOR: u32 = 1_024;
    // Fixed cost = maps not covered by state_table_override. `config` here
    // always carries the default table sizes (this runs only when the
    // operator left `stateTables` unset).
    let mut fixed = 0u64;
    let mut scalable: Vec<(&'static str, u64, u32, aya::maps::MapType, u32, u32)> = Vec::new();
    for (name, ty, key, value, max) in bpf_map_specs(config) {
        let bytes = map_spec_bytes(ty, key, value, max);
        if state_table_override_scalable(name) {
            scalable.push((name, bytes / u64::from(max).max(1), max, ty, key, value));
        } else {
            fixed = fixed.saturating_add(bytes);
        }
    }
    let headroom = budget.saturating_sub(fixed);
    // Scale factor in milli-units to keep integer math.
    let scalable_total: u64 = scalable
        .iter()
        .map(|(_, per_entry, max, ..)| per_entry.saturating_mul(u64::from(*max)))
        .sum();
    if scalable_total == 0 {
        return Ok(None);
    }
    let scale_milli = headroom.saturating_mul(1000) / scalable_total;
    // Per-map candidate sizes. Prefer an existing spec-compatible pin: the
    // stale-pin gate refuses any max mismatch, so adopting the pinned size
    // keeps restarts stable when this boot's scale factor drifts. Pins that
    // no longer fit the headroom fail the capacity check below explicitly.
    let mut candidates: Vec<(&'static str, &'static str, u64, u32)> =
        Vec::with_capacity(scalable.len());
    for (name, per_entry, default_max, ty, key, value) in &scalable {
        let pinned_max = pinned_map_max_entries(name, *ty, *key, *value);
        let scaled_max = u64::from(*default_max)
            .saturating_mul(scale_milli)
            / 1000;
        let candidate = match pinned_max {
            Some(pin_max) => pin_max.min(*default_max),
            None => (scaled_max as u32).max(STATE_TABLE_FLOOR).min(*default_max),
        };
        candidates.push((state_table_knob(name), name, *per_entry, candidate));
    }
    // A stateTables knob covers every map in its group with ONE value, so
    // the charged size must be the group minimum — a member charged at its
    // own larger candidate would make the real projection exceed the
    // accounted total. Members whose pin exceeds the chosen value trip the
    // stale-pin gate later: an explicit refusal, not silent state loss.
    let mut knob_values: Vec<(&'static str, u32)> = Vec::new();
    for (knob, _name, _per_entry, candidate) in &candidates {
        match knob_values.iter_mut().find(|(k, _)| k == knob) {
            Some((_, v)) => *v = (*v).min(*candidate),
            None => knob_values.push((knob, *candidate)),
        }
    }
    let mut scaled_total = 0u64;
    for (knob, _name, per_entry, candidate) in &candidates {
        let chosen = knob_values
            .iter()
            .find(|(k, _)| k == knob)
            .map(|(_, v)| *v)
            .unwrap_or(*candidate);
        scaled_total =
            scaled_total.saturating_add(per_entry.saturating_mul(u64::from(chosen)));
    }
    anyhow::ensure!(
        scaled_total <= headroom,
        "eBPF state tables cannot fit kernel-bpf budget {budget} even at the {STATE_TABLE_FLOOR}-entry floor (fixed={fixed}, need={scaled_total})"
    );
    let get = |knob: &str| -> Option<u32> {
        knob_values
            .iter()
            .find(|(k, _)| *k == knob)
            .map(|(_, m)| *m)
    };
    let ct = get("ct");
    let pending = get("pending");
    let snat_rev = get("snat_rev");
    let flow_acct = get("flow_acct");
    let rate_v6 = get("rate_v6");
    let quic_dcid = get("quic_dcid");
    let acl_blocked = get("acl_blocked");
    let acl_allowed = get("acl_allowed");
    let rate_v4 = get("rate_v4");
    tracing::warn!(
        "eBPF state tables auto-scaled to fit kernel-bpf budget {budget}B (projected {projected}B): ct={ct:?} pending={pending:?} snatRev={snat_rev:?} flowAcct={flow_acct:?} rateV4={rate_v4:?} rateV6={rate_v6:?} quicDcid={quic_dcid:?} aclBlocked={acl_blocked:?} aclAllowed={acl_allowed:?}"
    );
    Ok(Some(XdpStateTables {
        ct_max_entries: ct,
        pending_max_entries: pending,
        snat_rev_max_entries: snat_rev,
        flow_acct_max_entries: flow_acct,
        rate_v6_max_entries: rate_v6,
        quic_dcid_max_entries: quic_dcid,
        acl_blocked_max_entries: acl_blocked,
        acl_allowed_max_entries: acl_allowed,
        rate_v4_max_entries: rate_v4,
    }))
}

/// True for maps whose max_entries `xdp.stateTables` can size.
fn state_table_override_scalable(name: &str) -> bool {
    state_table_knob(name) != "fixed"
}

/// The `xdp.stateTables` field that sizes a given map. One knob covers a
/// whole group (e.g. `aclBlocked` sizes all four block-list maps), so the
/// auto-scaler must pick a single value per group, not per map.
fn state_table_knob(name: &str) -> &'static str {
    match name {
        "XDP_TCP_CT" | "XDP_UDP_CT" => "ct",
        "XDP_PENDING" => "pending",
        "XDP_SNAT_REV" => "snat_rev",
        "XDP_FLOW_ACCT" => "flow_acct",
        "XDP_RATE_V6" => "rate_v6",
        "XDP_QUIC_DCID" => "quic_dcid",
        "XDP_BLOCKED_V4" | "XDP_BLOCKED_V6" | "XDP_BLOCKED_V4_LPM"
        | "XDP_BLOCKED_V6_LPM" => "acl_blocked",
        "XDP_ALLOWED_V4" | "XDP_ALLOWED_V6" | "XDP_ALLOWED_V4_LPM"
        | "XDP_ALLOWED_V6_LPM" => "acl_allowed",
        "XDP_RATE_V4" => "rate_v4",
        _ => "fixed",
    }
}

/// Ensure the object's projected map memory fits the kernel-BPF ledger.
/// Called before load: map memory is preallocated and non-reclaimable, so
/// over-budget objects must fail attach explicitly rather than silently
/// pinning unbounded kernel memory. `budget` is a single caller-supplied
/// snapshot — the governor's budget moves with live free memory, and
/// sizing against one snapshot while enforcing another races (a shrinking
/// snapshot can reject tables that were scaled to fit the earlier one).
fn ensure_bpf_map_budget(config: &XdpConfig, budget: u64) -> anyhow::Result<()> {
    let projected = projected_bpf_map_bytes(config);
    anyhow::ensure!(
        projected <= budget,
        "eBPF map projected memory {projected} exceeds kernel-bpf budget {budget}"
    );
    Ok(())
}

/// EN-16 post-load audit: every map the object actually declares must be
/// covered by the ledger spec table. A map added to the eBPF object without a
/// matching spec entry would silently pin kernel memory outside the budget —
/// refuse to attach instead.
fn audit_loaded_map_specs(ebpf: &aya::Ebpf, config: &XdpConfig) -> anyhow::Result<()> {
    let specs = bpf_map_specs(config);
    for (name, map) in ebpf.maps() {
        let data = match map {
            aya::maps::Map::Array(d)
            | aya::maps::Map::ArrayOfMaps(d)
            | aya::maps::Map::BloomFilter(d)
            | aya::maps::Map::CgroupArray(d)
            | aya::maps::Map::CgroupStorage(d)
            | aya::maps::Map::CgrpStorage(d)
            | aya::maps::Map::CpuMap(d)
            | aya::maps::Map::DevMap(d)
            | aya::maps::Map::DevMapHash(d)
            | aya::maps::Map::HashMap(d)
            | aya::maps::Map::HashOfMaps(d)
            | aya::maps::Map::InodeStorage(d)
            | aya::maps::Map::LpmTrie(d)
            | aya::maps::Map::LruHashMap(d)
            | aya::maps::Map::PerCpuArray(d)
            | aya::maps::Map::PerCpuCgroupStorage(d)
            | aya::maps::Map::PerCpuHashMap(d)
            | aya::maps::Map::PerCpuLruHashMap(d)
            | aya::maps::Map::PerfEventArray(d)
            | aya::maps::Map::ProgramArray(d)
            | aya::maps::Map::Queue(d)
            | aya::maps::Map::ReusePortSockArray(d)
            | aya::maps::Map::RingBuf(d)
            | aya::maps::Map::SockHash(d)
            | aya::maps::Map::SockMap(d)
            | aya::maps::Map::SkStorage(d)
            | aya::maps::Map::Stack(d)
            | aya::maps::Map::StackTraceMap(d)
            | aya::maps::Map::Unsupported(d)
            | aya::maps::Map::XskMap(d) => d,
        };
        let info = data
            .info()
            .map_err(|err| anyhow::anyhow!("read map info for {name}: {err}"))?;
        let spec = specs.iter().find(|(n, ..)| *n == name);
        anyhow::ensure!(
            spec.is_some_and(|(_, ty, key, value, max)| {
                info.map_type().ok() == Some(*ty)
                    && info.key_size() == *key
                    && info.value_size() == *value
                    && info.max_entries() == *max
            }),
            "eBPF map {name} (type {:?}, key {}B, value {}B, max {}) is not covered by the kernel-bpf ledger spec table",
            info.map_type().ok(),
            info.key_size(),
            info.value_size(),
            info.max_entries(),
        );
    }
    Ok(())
}

/// EN-10 takeover: claim ownership of the pinned flow-state maps.
/// `XDP_OWNER_EPOCH` persists across attach (it is pinned), so bumping the
/// stored value yields a strictly increasing generation sequence across
/// reloads *and* process restarts — consumers can then order or drop
/// feedback emitted by older generations. Returns the new epoch and the
/// number of flow records still resident in the adopted maps.
fn adopt_flow_state(ebpf: &mut aya::Ebpf) -> anyhow::Result<(u64, u64)> {
    let epoch_map = ebpf.map_mut("XDP_OWNER_EPOCH").ok_or_else(|| {
        anyhow::anyhow!(
            "missing map XDP_OWNER_EPOCH; eBPF object predates EN-10 ownership epochs (rebuild cloud-node-xdp-ebpf.o)"
        )
    })?;
    let mut epochs = Array::<_, u64>::try_from(epoch_map)?;
    let previous = epochs.get(&0, 0).unwrap_or(0);
    let epoch = previous.saturating_add(1).max(1);
    epochs.set(0, epoch, 0)?;

    let mut imported = 0u64;
    for name in ["XDP_TCP_CT", "XDP_UDP_CT", "XDP_PENDING"] {
        let Some(map) = ebpf.map(name) else {
            continue;
        };
        let ct_map = AyaHashMap::<_, XdpUdpCtKey, XdpUdpCtValue>::try_from(map)
            .map_err(|err| anyhow::anyhow!("open adopted state map {name}: {err}"))?;
        let mut count = 0u64;
        for item in ct_map.keys() {
            item.map_err(|err| anyhow::anyhow!("iterate adopted state map {name}: {err}"))?;
            count = count.saturating_add(1);
        }
        imported = imported.saturating_add(count);
    }
    if imported > 0 {
        tracing::info!(
            "XDP flow-state takeover: epoch {} adopted {} resident flow records",
            epoch,
            imported
        );
    }
    Ok((epoch, imported))
}

/// Read the pinned owner epoch without owning the attachment — the value
/// survives across generations, so `xdp dump-maps` can report which
/// generation currently owns emitted feedback even from a CLI process.
pub fn read_pinned_owner_epoch() -> Option<u64> {
    let path = Path::new(xdp_bpf_pin_dir()).join("XDP_OWNER_EPOCH");
    if !path.exists() {
        return None;
    }
    let data = aya::maps::MapData::from_pin(&path).ok()?;
    let map = aya::maps::Map::Array(data);
    let array = Array::<_, u64>::try_from(&map).ok()?;
    array.get(&0, 0).ok()
}

/// Open the pinned lifecycle ring buffer on its own fd so the consumer task
/// never holds the manager's eBPF lock. Returns `None` when the pinned map
/// is absent (older object or attach failed before pinning) — callers treat
/// that as an explicit "feedback channel unavailable" state, not success.
pub fn open_pinned_flow_events() -> anyhow::Result<Option<aya::maps::RingBuf<aya::maps::MapData>>> {
    let path = Path::new(xdp_bpf_pin_dir()).join("XDP_FLOW_EVENTS");
    if !path.exists() {
        return Ok(None);
    }
    let data = aya::maps::MapData::from_pin(&path)
        .map_err(|err| anyhow::anyhow!("open pinned XDP_FLOW_EVENTS {}: {err}", path.display()))?;
    let map = aya::maps::Map::RingBuf(data);
    aya::maps::RingBuf::try_from(map)
        .map(Some)
        .map_err(|err| anyhow::anyhow!("pinned XDP_FLOW_EVENTS is not a ring buffer: {err}"))
}

/// Max entries of a pinned map whose type/key/value match the object spec —
/// used by auto-scaling to prefer the live pinned size so restart sizing is
/// stable. Returns `None` when the pin is absent, unreadable, or has an
/// ABI-different layout (in which case the stale-pin gate still applies).
fn pinned_map_max_entries(
    name: &str,
    spec_ty: aya::maps::MapType,
    spec_key: u32,
    spec_value: u32,
) -> Option<u32> {
    let path = Path::new(xdp_bpf_pin_dir()).join(name);
    let info = aya::maps::MapInfo::from_pin(&path).ok()?;
    (info.map_type().ok() == Some(spec_ty)
        && info.key_size() == spec_key
        && info.value_size() == spec_value)
        .then(|| info.max_entries())
}

/// Pinned maps whose kernel-reported spec differs from the object's spec
/// table. Detect-only: callers decide whether dropping the pin is safe —
/// state maps carry conntrack/SNAT/pending data whose loss must be an
/// explicit operator decision, never a silent attach side effect.
fn stale_pinned_maps(config: &XdpConfig) -> Vec<String> {
    let specs = bpf_map_specs(config);
    let mut stale = Vec::new();

    let Ok(dir) = std::fs::read_dir(xdp_bpf_pin_dir()) else {
        return stale;
    };
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(spec) = specs.iter().find(|(n, ..)| *n == name) else {
            continue;
        };
        let Ok(info) = aya::maps::MapInfo::from_pin(entry.path()) else {
            continue;
        };
        let matches = info.map_type().ok() == Some(spec.1)
            && info.key_size() == spec.2
            && info.value_size() == spec.3
            && info.max_entries() == spec.4;
        if matches {
            continue;
        }
        tracing::warn!(
            "stale pinned eBPF map {name}: kernel spec (type {:?}, key {}B, value {}B, max {}) != object spec (type {:?}, key {}B, value {}B, max {})",
            info.map_type().ok(),
            info.key_size(),
            info.value_size(),
            info.max_entries(),
            spec.1,
            spec.2,
            spec.3,
            spec.4,
        );
        stale.push(name);
    }
    stale
}

/// State maps whose contents are irreplaceable flow/billing/cookie state.
/// A spec-incompatible pin of one of these is a migration boundary:
/// attach refuses rather than silently destroying the data. Plumbing maps
/// (dispatch table, counters, XSK slots) are rebuilt empty at every
/// attach and may be dropped without consent.
fn is_state_map_pin(name: &str) -> bool {
    matches!(
        name,
        "XDP_TCP_CT"
            | "XDP_UDP_CT"
            | "XDP_PENDING"
            | "XDP_SNAT_REV"
            | "XDP_FLOW_ACCT"
            | "XDP_FLOW_EVENTS"
            | "XDP_OWNER_EPOCH"
            | "XDP_FLOW_SEQ"
            | "XDP_COOKIE_KEY"
    )
}

/// Remove stale plumbing pins and — only with `purge_state` — stale state
/// pins. Returns the names actually removed.
fn drop_stale_pinned_maps(config: &XdpConfig, purge_state: bool) -> Vec<String> {
    let mut dropped = Vec::new();
    for name in stale_pinned_maps(config) {
        if !purge_state && is_state_map_pin(&name) {
            continue;
        }
        let path = Path::new(xdp_bpf_pin_dir()).join(&name);
        if let Err(err) = std::fs::remove_file(&path) {
            tracing::warn!(
                "failed to remove stale pinned eBPF map {name}: {err}; attach may fail on the stale definition"
            );
            continue;
        }
        dropped.push(name);
    }
    dropped
}

fn clear_xsk_map_entries<T>(map: &mut XskMap<T>)
where
    T: std::borrow::BorrowMut<aya::maps::MapData>,
{
    for index in 0..map.len() {
        let _ = map.unset(index);
    }
}

fn xsk_map_entries(config: &XdpConfig) -> anyhow::Result<Vec<XskMapEntry>> {
    let mut entries = Vec::new();
    for interface in config
        .interfaces
        .iter()
        .filter(|interface| interface.mode == XdpRuntimeMode::Proxy)
    {
        let ifindex = ifindex_from_name(&interface.name)?;
        for queue in &interface.queues {
            let index = u32::try_from(entries.len())
                .map_err(|_| anyhow::anyhow!("too many AF_XDP queues configured"))?;
            if index >= AF_XDP_MAX_SOCKETS as u32 {
                anyhow::bail!(
                    "too many AF_XDP queues configured; XDP_XSKS max is {}",
                    AF_XDP_MAX_SOCKETS
                );
            }
            entries.push(XskMapEntry {
                interface: interface.name.clone(),
                ifindex,
                queue: *queue,
                index,
            });
        }
    }
    Ok(entries)
}

fn mark_queue_status(
    statuses: &mut [XdpQueueStatus],
    interface: &str,
    queue: u32,
    registered: bool,
    ready: bool,
    detail: impl Into<String>,
) {
    let detail = detail.into();
    for status in statuses
        .iter_mut()
        .filter(|status| status.interface == interface && status.queue == queue)
    {
        status.registered = registered;
        status.ready = ready;
        status.detail = detail.clone();
    }
}

// Desired-contents "images" of the rule maps, keyed so that an unchanged
// entry (same expiry) is never rewritten. Keeping the diff keyed on the unix
// expiry preserves each entry's original monotonic deadline in the eBPF map.
type ExactV4Image = std::collections::BTreeMap<u32, i64>;
type ExactV6Image = std::collections::BTreeMap<[u8; 16], i64>;
type LpmV4Image = std::collections::BTreeMap<(u32, u32), i64>;
type LpmV6Image = std::collections::BTreeMap<(u32, [u8; 16]), i64>;

pub(crate) struct RuleMapImages {
    pub(crate) allowed_v4: ExactV4Image,
    pub(crate) allowed_v6: ExactV6Image,
    pub(crate) blocked_v4: ExactV4Image,
    pub(crate) blocked_v6: ExactV6Image,
    pub(crate) allowed_v4_lpm: LpmV4Image,
    pub(crate) allowed_v6_lpm: LpmV6Image,
    pub(crate) blocked_v4_lpm: LpmV4Image,
    pub(crate) blocked_v6_lpm: LpmV6Image,
}

// Must stay aligned with crates/cloud-node-xdp-ebpf map max_entries.
const XDP_BLOCKED_EXACT_MAP_MAX_ENTRIES: u64 = 262_144;
const XDP_ALLOWED_EXACT_MAP_MAX_ENTRIES: u64 = 65_536;
const XDP_RULE_LPM_MAP_MAX_ENTRIES: u64 = 65_536;
const XDP_RULE_MAP_ENTRY_ESTIMATED_BYTES: u64 = 64;
const XDP_RULE_MAP_BUDGET_DIVISOR: u64 = 512;

#[derive(Clone, Copy, Debug, Default)]
struct RuleMapEntryCounts {
    allowed_v4: u64,
    allowed_v6: u64,
    blocked_v4: u64,
    blocked_v6: u64,
    allowed_v4_lpm: u64,
    allowed_v6_lpm: u64,
    blocked_v4_lpm: u64,
    blocked_v6_lpm: u64,
}

impl RuleMapImages {
    fn projected_high_water(&self, next: &Self) -> RuleMapEntryCounts {
        fn high_water<K: Ord, V>(
            old: &std::collections::BTreeMap<K, V>,
            new: &std::collections::BTreeMap<K, V>,
        ) -> u64 {
            let additions = new.keys().filter(|key| !old.contains_key(*key)).count() as u64;
            (old.len() as u64).saturating_add(additions)
        }

        RuleMapEntryCounts {
            allowed_v4: high_water(&self.allowed_v4, &next.allowed_v4),
            allowed_v6: high_water(&self.allowed_v6, &next.allowed_v6),
            blocked_v4: high_water(&self.blocked_v4, &next.blocked_v4),
            blocked_v6: high_water(&self.blocked_v6, &next.blocked_v6),
            allowed_v4_lpm: high_water(&self.allowed_v4_lpm, &next.allowed_v4_lpm),
            allowed_v6_lpm: high_water(&self.allowed_v6_lpm, &next.allowed_v6_lpm),
            blocked_v4_lpm: high_water(&self.blocked_v4_lpm, &next.blocked_v4_lpm),
            blocked_v6_lpm: high_water(&self.blocked_v6_lpm, &next.blocked_v6_lpm),
        }
    }
}

fn rule_map_entry_budget() -> u64 {
    let snapshot = crate::memory_governor::MEMORY_GOVERNOR
        .snapshot(crate::memory_governor::MEMORY_GOVERNOR.pingora_worker_threads());
    snapshot
        .af_xdp_budget_bytes
        .max(snapshot.connection_budget_bytes)
        .saturating_div(XDP_RULE_MAP_BUDGET_DIVISOR)
        .saturating_div(XDP_RULE_MAP_ENTRY_ESTIMATED_BYTES.max(1))
        .max(1)
}

fn ensure_rule_map_capacity(old: &RuleMapImages, new: &RuleMapImages) -> anyhow::Result<()> {
    let projected = old.projected_high_water(new);
    anyhow::ensure!(
        projected.allowed_v4 <= XDP_ALLOWED_EXACT_MAP_MAX_ENTRIES
            && projected.allowed_v6 <= XDP_ALLOWED_EXACT_MAP_MAX_ENTRIES
            && projected.blocked_v4 <= XDP_BLOCKED_EXACT_MAP_MAX_ENTRIES
            && projected.blocked_v6 <= XDP_BLOCKED_EXACT_MAP_MAX_ENTRIES
            && projected.allowed_v4_lpm <= XDP_RULE_LPM_MAP_MAX_ENTRIES
            && projected.allowed_v6_lpm <= XDP_RULE_LPM_MAP_MAX_ENTRIES
            && projected.blocked_v4_lpm <= XDP_RULE_LPM_MAP_MAX_ENTRIES
            && projected.blocked_v6_lpm <= XDP_RULE_LPM_MAP_MAX_ENTRIES,
        "XDP rule map projected high-water exceeds static eBPF map maxima"
    );

    let budget = rule_map_entry_budget();
    let allow_total = projected
        .allowed_v4
        .saturating_add(projected.allowed_v6)
        .saturating_add(projected.allowed_v4_lpm)
        .saturating_add(projected.allowed_v6_lpm);
    anyhow::ensure!(
        allow_total <= budget,
        "XDP allow-map projected entries {} exceed node budget {}",
        allow_total,
        budget
    );
    let block_budget = budget.saturating_sub(allow_total);
    let block_total = projected
        .blocked_v4
        .saturating_add(projected.blocked_v6)
        .saturating_add(projected.blocked_v4_lpm)
        .saturating_add(projected.blocked_v6_lpm);
    anyhow::ensure!(
        block_total <= block_budget,
        "XDP block-map projected entries {} exceed remaining node budget {}",
        block_total,
        block_budget
    );
    Ok(())
}

fn exact_image(ips: &std::collections::BTreeMap<IpAddr, i64>) -> (ExactV4Image, ExactV6Image) {
    let mut v4 = ExactV4Image::new();
    let mut v6 = ExactV6Image::new();
    for (ip, expiry) in ips {
        match ip {
            IpAddr::V4(addr) => {
                v4.insert(u32::from_be_bytes(addr.octets()), *expiry);
            }
            IpAddr::V6(addr) => {
                v6.insert(addr.octets(), *expiry);
            }
        }
    }
    (v4, v6)
}

fn lpm_image(
    nets: &std::collections::BTreeMap<String, (IpNet, i64)>,
    ranges: &std::collections::BTreeMap<RangeKey, i64>,
) -> (LpmV4Image, LpmV6Image) {
    let mut v4 = LpmV4Image::new();
    let mut v6 = LpmV6Image::new();
    // Networks first, then range decomposition, matching the full-sync order.
    for (net, expiry) in nets.values() {
        insert_net_image(&mut v4, &mut v6, net, *expiry);
    }
    for (range, expiry) in ranges {
        for net in range_to_nets(range) {
            insert_net_image(&mut v4, &mut v6, &net, *expiry);
        }
    }
    (v4, v6)
}

fn insert_net_image(v4: &mut LpmV4Image, v6: &mut LpmV6Image, net: &IpNet, expiry: i64) {
    match net {
        IpNet::V4(net) => {
            let key = (
                net.prefix_len() as u32,
                u32::from_be_bytes(net.network().octets()),
            );
            // Keep the latest-seen expiry deterministically (max wins).
            let slot = v4.entry(key).or_insert(expiry);
            if expiry > *slot {
                *slot = expiry;
            }
        }
        IpNet::V6(net) => {
            let key = (net.prefix_len() as u32, net.network().octets());
            let slot = v6.entry(key).or_insert(expiry);
            if expiry > *slot {
                *slot = expiry;
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn rule_map_images(state: &RuleState) -> RuleMapImages {
    let (allowed_v4, allowed_v6) = exact_image(&state.allowed_ips);
    let (blocked_v4, blocked_v6) = exact_image(&state.blocked_ips);
    let (allowed_v4_lpm, allowed_v6_lpm) =
        lpm_image(&state.allowed_networks, &state.allowed_ranges);
    let (blocked_v4_lpm, blocked_v6_lpm) =
        lpm_image(&state.blocked_networks, &state.blocked_ranges);
    RuleMapImages {
        allowed_v4,
        allowed_v6,
        blocked_v4,
        blocked_v6,
        allowed_v4_lpm,
        allowed_v6_lpm,
        blocked_v4_lpm,
        blocked_v6_lpm,
    }
}

/// Incrementally reconcile the six rule maps from `old` to `new` without ever
/// clearing a whole map. Only changed/added keys are inserted and only removed
/// keys are deleted, so the data plane never observes an empty-map window.
pub fn apply_rule_diff(
    ebpf: &mut aya::Ebpf,
    old: &RuleState,
    new: &RuleState,
) -> anyhow::Result<()> {
    let old = rule_map_images(old);
    let new = rule_map_images(new);
    ensure_rule_map_capacity(&old, &new)?;
    diff_exact_v4(
        ebpf,
        "XDP_ALLOWED_V4",
        &old.allowed_v4,
        &new.allowed_v4,
        true,
    )?;
    diff_exact_v6(
        ebpf,
        "XDP_ALLOWED_V6",
        &old.allowed_v6,
        &new.allowed_v6,
        true,
    )?;
    diff_exact_v4(
        ebpf,
        "XDP_BLOCKED_V4",
        &old.blocked_v4,
        &new.blocked_v4,
        false,
    )?;
    diff_exact_v6(
        ebpf,
        "XDP_BLOCKED_V6",
        &old.blocked_v6,
        &new.blocked_v6,
        false,
    )?;
    diff_lpm_v4(
        ebpf,
        "XDP_ALLOWED_V4_LPM",
        &old.allowed_v4_lpm,
        &new.allowed_v4_lpm,
        true,
    )?;
    diff_lpm_v6(
        ebpf,
        "XDP_ALLOWED_V6_LPM",
        &old.allowed_v6_lpm,
        &new.allowed_v6_lpm,
        true,
    )?;
    diff_lpm_v4(
        ebpf,
        "XDP_BLOCKED_V4_LPM",
        &old.blocked_v4_lpm,
        &new.blocked_v4_lpm,
        false,
    )?;
    diff_lpm_v6(
        ebpf,
        "XDP_BLOCKED_V6_LPM",
        &old.blocked_v6_lpm,
        &new.blocked_v6_lpm,
        false,
    )?;
    Ok(())
}

fn diff_exact_v4(
    ebpf: &mut aya::Ebpf,
    name: &str,
    old: &ExactV4Image,
    new: &ExactV4Image,
    allow: bool,
) -> anyhow::Result<()> {
    if old == new {
        return Ok(());
    }
    let map = ebpf
        .map_mut(name)
        .ok_or_else(|| anyhow::anyhow!("missing map {name}"))?;
    let mut map = AyaHashMap::<_, XdpIpv4Key, XdpRuleValue>::try_from(map)?;
    for (addr_be, expiry) in new {
        if old.get(addr_be) != Some(expiry) {
            map.insert(
                XdpIpv4Key { addr_be: *addr_be },
                rule_value(*expiry, allow),
                0,
            )?;
        }
    }
    for addr_be in old.keys() {
        if !new.contains_key(addr_be) {
            let _ = map.remove(&XdpIpv4Key { addr_be: *addr_be });
        }
    }
    Ok(())
}

fn diff_exact_v6(
    ebpf: &mut aya::Ebpf,
    name: &str,
    old: &ExactV6Image,
    new: &ExactV6Image,
    allow: bool,
) -> anyhow::Result<()> {
    if old == new {
        return Ok(());
    }
    let map = ebpf
        .map_mut(name)
        .ok_or_else(|| anyhow::anyhow!("missing map {name}"))?;
    let mut map = AyaHashMap::<_, XdpIpv6Key, XdpRuleValue>::try_from(map)?;
    for (addr, expiry) in new {
        if old.get(addr) != Some(expiry) {
            map.insert(XdpIpv6Key { addr: *addr }, rule_value(*expiry, allow), 0)?;
        }
    }
    for addr in old.keys() {
        if !new.contains_key(addr) {
            let _ = map.remove(&XdpIpv6Key { addr: *addr });
        }
    }
    Ok(())
}

fn diff_lpm_v4(
    ebpf: &mut aya::Ebpf,
    name: &str,
    old: &LpmV4Image,
    new: &LpmV4Image,
    allow: bool,
) -> anyhow::Result<()> {
    if old == new {
        return Ok(());
    }
    let map = ebpf
        .map_mut(name)
        .ok_or_else(|| anyhow::anyhow!("missing map {name}"))?;
    let mut map = LpmTrie::<_, u32, XdpRuleValue>::try_from(map)?;
    for ((prefix_len, addr_be), expiry) in new {
        if old.get(&(*prefix_len, *addr_be)) != Some(expiry) {
            let key = LpmKey::new(*prefix_len, *addr_be);
            map.insert(&key, rule_value(*expiry, allow), 0)?;
        }
    }
    for (prefix_len, addr_be) in old.keys() {
        if !new.contains_key(&(*prefix_len, *addr_be)) {
            let key = LpmKey::new(*prefix_len, *addr_be);
            let _ = map.remove(&key);
        }
    }
    Ok(())
}

fn diff_lpm_v6(
    ebpf: &mut aya::Ebpf,
    name: &str,
    old: &LpmV6Image,
    new: &LpmV6Image,
    allow: bool,
) -> anyhow::Result<()> {
    if old == new {
        return Ok(());
    }
    let map = ebpf
        .map_mut(name)
        .ok_or_else(|| anyhow::anyhow!("missing map {name}"))?;
    let mut map = LpmTrie::<_, [u8; 16], XdpRuleValue>::try_from(map)?;
    for ((prefix_len, addr), expiry) in new {
        if old.get(&(*prefix_len, *addr)) != Some(expiry) {
            let key = LpmKey::new(*prefix_len, *addr);
            map.insert(&key, rule_value(*expiry, allow), 0)?;
        }
    }
    for (prefix_len, addr) in old.keys() {
        if !new.contains_key(&(*prefix_len, *addr)) {
            let key = LpmKey::new(*prefix_len, *addr);
            let _ = map.remove(&key);
        }
    }
    Ok(())
}

fn rule_value(expires_at: i64, allow: bool) -> XdpRuleValue {
    let flags = if allow {
        XdpRuleValue::FLAG_WHITELIST
    } else {
        XdpRuleValue::FLAG_BLOCK
    } | XdpRuleValue::FLAG_RUNTIME;
    XdpRuleValue::with_monotonic_deadline(
        expires_at.max(1) as u64,
        monotonic_deadline_ns(expires_at),
        0,
        flags,
    )
}

fn monotonic_deadline_ns(expires_at: i64) -> u64 {
    let now_mono_ns = monotonic_now_ns();
    if now_mono_ns == 0 {
        static LAST_WARN_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let now_ms = crate::utils::time::now_timestamp_millis() as u64;
        let last = LAST_WARN_MS.load(std::sync::atomic::Ordering::Relaxed);
        if now_ms.saturating_sub(last) > 60_000 {
            LAST_WARN_MS.store(now_ms, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                "XDP monotonic clock read failed; rules will rely on 5s shadow sweeper for expiry"
            );
        }
        return 0;
    }
    let ttl_secs = expires_at
        .saturating_sub(crate::utils::time::now_timestamp())
        .max(0) as u64;
    now_mono_ns.saturating_add(ttl_secs.saturating_mul(1_000_000_000))
}

fn monotonic_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` points to valid writable memory for the duration of the
    // call, and CLOCK_MONOTONIC does not require any additional ownership.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

fn clear_hash_map<K, V>(map: &mut AyaHashMap<&mut aya::maps::MapData, K, V>) -> anyhow::Result<()>
where
    K: aya::Pod,
    V: aya::Pod,
{
    let keys = map.keys().collect::<Result<Vec<_>, _>>()?;
    for key in keys {
        let _ = map.remove(&key);
    }
    Ok(())
}

fn clear_lpm_map<K, V>(map: &mut LpmTrie<&mut aya::maps::MapData, K, V>) -> anyhow::Result<()>
where
    K: aya::Pod,
    V: aya::Pod,
{
    let keys = map.keys().collect::<Result<Vec<_>, _>>()?;
    for key in keys {
        let _ = map.remove(&key);
    }
    Ok(())
}

pub(super) fn ifindex_from_name(name: &str) -> anyhow::Result<u32> {
    let c_name = CString::new(name)?;
    let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if ifindex == 0 {
        anyhow::bail!("unknown interface {name}");
    }
    Ok(ifindex)
}

fn link_pin_path(interface: &str) -> PathBuf {
    let safe_name = interface
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    Path::new(xdp_bpf_pin_dir()).join(format!("link-{safe_name}"))
}
