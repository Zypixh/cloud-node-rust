use super::*;
use crate::runtime_mode::{XdpAttachMode, XdpInterfaceConfig, XdpRuntimeMode};
use aya::maps::lpm_trie::Key as LpmKey;
use aya::maps::{Array, HashMap as AyaHashMap, LpmTrie, PerCpuArray, XskMap};
use aya::programs::links::PinnedLink;
use cloud_node_xdp_common::{
    XdpBudgetBucket, XdpBudgetConfig, XdpCounters, XdpFlowAcct, XdpInterfacePolicy, XdpIpv4Key,
    XdpIpv6Key, XdpLocalIpv4Key, XdpLocalIpv6Key, XdpPortProtoKey, XdpQueueKey, XdpRateBucket,
    XdpRateLimitConfig, XdpRuleValue, XdpSnatRevKey, XdpSnatRevValue, XdpUdpCtKey, XdpUdpCtValue,
    XdpUdpFwdKey, XdpUdpFwdRule,
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
            refilled: self.replenish_fill(),
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
        stats.refilled += self.return_rx_frames(received);
        Ok(stats)
    }

    fn replenish_fill(&mut self) -> usize {
        let Some(fill) = self.fill.as_mut() else {
            return 0;
        };
        let count = self.free_frames.len().min(AF_XDP_RX_BATCH);
        if count == 0 {
            return 0;
        }
        let split_at = self.free_frames.len() - count;
        let frames = self.free_frames.split_off(split_at);
        // SAFETY: `frames` came from this queue's UMEM free list and have not been
        // submitted to TX or fill while in `free_frames`.
        let produced = unsafe { fill.produce(&frames) };
        if produced < frames.len() {
            self.free_frames.extend_from_slice(&frames[produced..]);
        }
        produced
    }

    fn return_rx_frames(&mut self, count: usize) -> usize {
        if count == 0 {
            return 0;
        }
        let frames = &self.rx_batch[..count];
        let Some(fill) = self.fill.as_mut() else {
            self.free_frames.extend_from_slice(frames);
            return 0;
        };
        // SAFETY: RX returned these descriptors from the same UMEM and userspace no
        // longer holds packet data references when they are handed back to fill.
        let produced = unsafe { fill.produce(frames) };
        if produced < frames.len() {
            self.free_frames.extend_from_slice(&frames[produced..]);
        }
        produced
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
    sync_xsk_indices(ebpf, config, false)?;
    clear_xsk_map(ebpf)?;
    sync_xsk_indices(ebpf, config, true)?;

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
    let mut socket_config = SocketConfig::builder();
    socket_config
        .libxdp_flags(LibxdpFlags::XSK_LIBXDP_FLAGS_INHIBIT_PROG_LOAD)
        .bind_flags(BindFlags::XDP_USE_NEED_WAKEUP);
    let socket_config = socket_config.build();

    // SAFETY: The UMEM, queues, and socket-backed rings are owned by the returned
    // handle for the full socket lifetime. INHIBIT_PROG_LOAD prevents libxdp
    // from replacing the Aya-managed XDP program on this interface.
    let (tx, rx, fill_and_comp) = unsafe { Socket::new(socket_config, &umem, &if_name, queue) }
        .map_err(|err| {
            let mut detail = err.to_string();
            let mut source = std::error::Error::source(&err);
            while let Some(err) = source {
                detail.push_str(": ");
                detail.push_str(&err.to_string());
                source = err.source();
            }
            anyhow::anyhow!(detail)
        })?;
    let (fill, comp, primed_frames) = match fill_and_comp {
        Some((mut fill, comp)) => {
            let fill_count = frames.len().min(AF_XDP_RING_SIZE as usize);
            let initial_fill = frames.drain(..fill_count).collect::<Vec<_>>();
            // SAFETY: `initial_fill` contains descriptors returned by the same UMEM
            // that owns this fill queue. Submitted descriptors are not reused until
            // the kernel returns them on RX.
            let produced = unsafe { fill.produce(&initial_fill) };
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
            "AF_XDP socket created and fill ring primed with {} frames; awaiting XSK map registration",
            primed_frames
        ),
        rx_dropped: stats.map(|stats| stats.rx_dropped()).unwrap_or_default(),
        rx_invalid_descs: stats
            .map(|stats| stats.rx_invalid_descs())
            .unwrap_or_default(),
        rx_ring_full: stats.map(|stats| stats.rx_ring_full()).unwrap_or_default(),
        tx_invalid_descs: stats
            .map(|stats| stats.tx_invalid_descs())
            .unwrap_or_default(),
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

pub async fn attach(
    config: &XdpConfig,
    object_path: Option<&Path>,
) -> anyhow::Result<AttachedProgram> {
    std::fs::create_dir_all(XDP_BPF_PIN_DIR)
        .map_err(|err| anyhow::anyhow!("create bpffs pin dir {XDP_BPF_PIN_DIR}: {err}"))?;
    detach(config).await?;
    drop_stale_pinned_maps();
    let mut attached = BTreeSet::new();
    let mut loader = aya::EbpfLoader::new();
    loader.default_map_pin_directory(XDP_BPF_PIN_DIR);
    // The dispatch table must outlive the process: aya-ebpf maps default
    // to PinningType::None so default_map_pin_directory alone does not pin
    // it, and without a pin the tail-call targets die with the process.
    loader.map_pin_path(
        "XDP_DISPATCH",
        Path::new(XDP_BPF_PIN_DIR).join("XDP_DISPATCH"),
    );
    // Counters are pinned so verdict accounting stays readable by other
    // processes (`xdp dump-maps` while a daemon owns the attachment) and
    // survives process exit. The spec check above still guards layout.
    loader.map_pin_path(
        "XDP_COUNTERS",
        Path::new(XDP_BPF_PIN_DIR).join("XDP_COUNTERS"),
    );
    let mut ebpf = match object_path {
        Some(path) => loader.load_file(path)?,
        None => loader.load(XDP_EBPF_EMBEDDED)?,
    };
    sync_interface_policy(&mut ebpf, config)?;
    sync_local_ip_maps(&mut ebpf, config)?;
    sync_proxy_ports(&mut ebpf, config, false)?;
    sync_xsk_indices(&mut ebpf, config, false)?;
    zero_counters(&mut ebpf)?;
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
    // Populate the tail-call dispatch table. Slots are per (family, proto)
    // pairs because a single SNAT-capable NAT handler is already ~10KiB of
    // BPF: slot 0 = UDP/IPv4, 2 = TCP/IPv4, 3 = UDP/IPv6 replies,
    // 4 = TCP/IPv6 replies, and the IPv6 forward halves each get their own
    // program (5 = UDPv6 fwd, 6 = TCPv6 fwd) to stay under older kernels'
    // verifier state budget. Slot 1 is reserved (was SNI blocklist).
    // An older object without a symbol leaves that slot empty; the tail
    // call then returns and the dispatcher falls back to the
    // redirect/PASS path explicitly.
    // Pinned programs keep a kernel reference independent of our fds, so
    // the tail-call chain stays live after a one-shot `xdp attach` exits.
    let prog_pin_dir = Path::new(XDP_BPF_PIN_DIR).join("progs");
    std::fs::create_dir_all(&prog_pin_dir)
        .map_err(|err| anyhow::anyhow!("create prog pin dir {}: {err}", prog_pin_dir.display()))?;
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
    ] {
        let fd = match ebpf.program_mut(name) {
            Some(sub_program) => {
                let sub: &mut aya::programs::Xdp = sub_program.try_into()?;
                sub.load()?;
                let pin_path = prog_pin_dir.join(name);
                if pin_path.exists() {
                    std::fs::remove_file(&pin_path)?;
                }
                sub.pin(&pin_path).map_err(|err| {
                    anyhow::anyhow!("pin {name} to {}: {err}", pin_path.display())
                })?;
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
    let program: &mut aya::programs::Xdp = ebpf
        .program_mut("cloud_node_xdp")
        .ok_or_else(|| anyhow::anyhow!("missing eBPF program cloud_node_xdp"))?
        .try_into()?;
    for interface in &config.interfaces {
        let link_id = program.attach(&interface.name, mode)?;
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
    })
}

pub async fn detach(config: &XdpConfig) -> anyhow::Result<()> {
    detach_blocking(config)
}

pub fn detach_blocking(config: &XdpConfig) -> anyhow::Result<()> {
    if let Err(err) = clear_pinned_xsk_map() {
        tracing::warn!("failed to clear pinned AF_XDP socket map: {}", err);
    }
    for interface in &config.interfaces {
        let pin_path = link_pin_path(&interface.name);
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
    let prog_pin_dir = Path::new(XDP_BPF_PIN_DIR).join("progs");
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
    let dispatch_pin = Path::new(XDP_BPF_PIN_DIR).join("XDP_DISPATCH");
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
) -> anyhow::Result<()> {
    sync_interface_policy(ebpf, config)?;
    sync_local_ip_maps(ebpf, config)?;
    sync_proxy_ports(ebpf, config, proxy_dataplane_active)?;
    sync_xsk_indices(ebpf, config, proxy_dataplane_active)?;
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
    sync_xsk_indices(ebpf, config, false)?;
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
            admission_limited
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
    let path = std::path::Path::new(XDP_BPF_PIN_DIR).join("XDP_COUNTERS");
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
        map.insert(XdpQueueKey::new(entry.ifindex, entry.queue), entry.index, 0)?;
    }
    Ok(())
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
        config,
        dataplane_active,
        |iface| &iface.tcp_forwards,
    )
}

fn sync_forward_map(
    ebpf: &mut aya::Ebpf,
    map_name: &str,
    proto: &str,
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
            match udp_forward_entry(fwd) {
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
    Ok((
        key,
        XdpUdpFwdRule {
            backend_addr,
            next_hop_mac,
            backend_port_be: backend.port().to_be(),
            family: key.family,
            snat: u8::from(fwd.snat),
            server_id: fwd.server_id,
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
pub(super) fn sweep_nat_maps(
    ebpf: &mut aya::Ebpf,
    shadow: &mut std::collections::HashMap<XdpUdpCtKey, XdpFlowAcct>,
    udp_idle: std::time::Duration,
    tcp_idle: std::time::Duration,
    tcp_closing_grace: std::time::Duration,
) -> anyhow::Result<()> {
    use cloud_node_xdp_common::XDP_CT_STATE_CLOSING;
    let now_ns = monotonic_now_ns();
    let udp_idle_ns = udp_idle.as_nanos().min(u64::MAX as u128) as u64;
    let tcp_idle_ns = tcp_idle.as_nanos().min(u64::MAX as u128) as u64;
    let closing_ns = tcp_closing_grace.as_nanos().min(u64::MAX as u128) as u64;

    let mut stale: Vec<XdpUdpCtKey> = Vec::new();
    let mut udp_live: std::collections::HashSet<XdpUdpCtKey> = Default::default();
    let mut tcp_live: std::collections::HashSet<XdpUdpCtKey> = Default::default();
    if let Some(map) = ebpf.map_mut("XDP_UDP_CT") {
        let mut map = AyaHashMap::<_, XdpUdpCtKey, XdpUdpCtValue>::try_from(map)?;
        for item in map.iter() {
            let (key, value) = item?;
            if now_ns.saturating_sub(value.last_seen_ns) >= udp_idle_ns {
                stale.push(key);
            } else {
                udp_live.insert(key);
            }
        }
        for key in &stale {
            let _ = map.remove(key);
        }
    }
    if let Some(map) = ebpf.map_mut("XDP_TCP_CT") {
        let mut map = AyaHashMap::<_, XdpUdpCtKey, XdpUdpCtValue>::try_from(map)?;
        let mut tcp_stale = Vec::new();
        for item in map.iter() {
            let (key, value) = item?;
            let idle = now_ns.saturating_sub(value.last_seen_ns);
            let limit = if value.state == XDP_CT_STATE_CLOSING {
                closing_ns
            } else {
                tcp_idle_ns
            };
            if idle >= limit {
                tcp_stale.push(key);
            } else {
                tcp_live.insert(key);
            }
        }
        for key in &tcp_stale {
            let _ = map.remove(key);
        }
        stale.extend(tcp_stale);
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
            let alive = match value.proto {
                6 => tcp_live.contains(&ct_key),
                _ => udp_live.contains(&ct_key),
            };
            if !alive {
                orphan.push(key);
            }
        }
        for key in &orphan {
            let _ = map.remove(key);
        }
    }

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
                crate::metrics::record::record_transfer(total.server_id, delta_tx, delta_rx, None);
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
    let path = Path::new(XDP_BPF_PIN_DIR).join("XDP_XSKS");
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
fn drop_stale_pinned_maps() {
    use aya::maps::MapType;
    use cloud_node_xdp_common::*;
    use core::mem::size_of;

    // (name, map type, key size, value size, max_entries). Must stay
    // aligned with the #[map] definitions in
    // crates/cloud-node-xdp-ebpf/src/main.rs. LPM trie keys carry a
    // 4-byte prefix length in front of the address.
    let u = size_of::<u32>() as u32;
    let v4 = size_of::<XdpIpv4Key>() as u32;
    let v6 = size_of::<XdpIpv6Key>() as u32;
    let rule = size_of::<XdpRuleValue>() as u32;
    let fwd_key = size_of::<XdpUdpFwdKey>() as u32;
    let fwd_rule = size_of::<XdpUdpFwdRule>() as u32;
    let ct_key = size_of::<XdpUdpCtKey>() as u32;
    let ct_value = size_of::<XdpUdpCtValue>() as u32;
    let specs: [(&str, MapType, u32, u32, u32); 29] = [
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
        (
            "XDP_FLOW_ACCT",
            MapType::PerCpuHash,
            ct_key,
            size_of::<XdpFlowAcct>() as u32,
            262_144,
        ),
    ];

    let Ok(dir) = std::fs::read_dir(XDP_BPF_PIN_DIR) else {
        return;
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
            "removing stale pinned eBPF map {name}: kernel spec (type {:?}, key {}B, value {}B, max {}) != object spec (type {:?}, key {}B, value {}B, max {}); it is recreated on load and its previous contents are lost",
            info.map_type().ok(),
            info.key_size(),
            info.value_size(),
            info.max_entries(),
            spec.1,
            spec.2,
            spec.3,
            spec.4,
        );
        if let Err(err) = std::fs::remove_file(entry.path()) {
            tracing::warn!(
                "failed to remove stale pinned eBPF map {name}: {err}; attach may fail on the stale definition"
            );
        }
    }
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
    Path::new(XDP_BPF_PIN_DIR).join(format!("link-{safe_name}"))
}
