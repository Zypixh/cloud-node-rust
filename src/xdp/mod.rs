use crate::firewall::kernel::{KernelFilter, KernelFilterSnapshot, KernelFilterStatus};
use crate::runtime_mode::{
    RuntimeConfig, XdpConfig, XdpProxyProtocol, XdpRuntimeMode, XdpUpstreamMode,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// eBPF program embedded at build time (see build.rs). The kernel only accepts
/// verified eBPF bytecode at the XDP hook, so the program must ship as an ELF
/// object — embedding it keeps binary and program versioned atomically.
#[cfg(target_os = "linux")]
const XDP_EBPF_EMBEDDED: &[u8] = aya::include_bytes_aligned!(env!("CLOUD_NODE_XDP_EBPF_OBJECT"));
#[cfg(target_os = "linux")]
const XDP_BPF_PIN_DIR: &str = "/sys/fs/bpf/cloud-node-xdp";

/// Resolved bpffs pin root. `CLOUD_NODE_XDP_PIN_DIR` gives an isolated
/// task/probe its own pin space; unset keeps the production default.
#[cfg(target_os = "linux")]
fn xdp_bpf_pin_dir() -> &'static str {
    static DIR: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        std::env::var("CLOUD_NODE_XDP_PIN_DIR")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| XDP_BPF_PIN_DIR.to_string())
    })
    .as_str()
}
const XDP_STATE_WRITE_INTERVAL_SECS: u64 = 10;
const XDP_RULE_SWEEP_INTERVAL_SECS: u64 = 5;
// Coalescing window for rule-map writes: bursts of block/unblock events under an
// attack collapse into a single incremental eBPF map update. Off-round to avoid
// whole-second resonance with the rule sweeper.
const XDP_MAP_SYNC_DEBOUNCE_MS: u64 = 47;
const XDP_PROXY_DATAPLANE_ACTIVE: bool = true;
// Status-file writes are last-writer-wins by claim order: `persist_status`
// spawns one async writer per call and they can complete out of order, so
// each claim carries a sequence and a stale claim drops its write instead
// of clobbering a newer snapshot.
static XDP_STATUS_WRITE_SEQ: AtomicU64 = AtomicU64::new(0);
static XDP_STATUS_WRITE_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
#[cfg(any(test, target_os = "linux"))]
const XDP_XSK_STATUS_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct XdpQueueStatus {
    pub interface: String,
    pub queue: u32,
    pub configured: bool,
    pub socket_created: bool,
    pub registered: bool,
    pub ready: bool,
    pub detail: String,
    pub rx_dropped: u64,
    pub rx_invalid_descs: u64,
    pub rx_ring_full: u64,
    pub tx_invalid_descs: u64,
    /// AF_XDP bind mode the kernel granted this queue: "zero-copy", "copy",
    /// or empty when the socket was never bound (EN-12).
    pub xsk_mode: String,
    /// True once the queue's XSK_INDEX/XSKS slots were withdrawn after a
    /// queue-scoped fault. The queue's redirected traffic takes the explicit
    /// dataplane fallback; other queues keep serving (EN-05).
    #[serde(default)]
    pub faulted: bool,
    /// New-flow admissions dropped while this queue was TX-backpressured.
    /// Existing sessions stay admitted; only new work is refused so the
    /// queue can drain instead of collapsing (EN-05).
    #[serde(default)]
    pub congested_drops: u64,
    /// TCP sessions refused at the reactor session/ingress limits. These
    /// are capacity refusals, not faults: the worker keeps serving existing
    /// sessions and new admissions resume automatically once capacity is
    /// released (F2 — refusal must never escalate to queue teardown).
    #[serde(default)]
    pub admission_refusals: u64,
    /// T9/D-AQM: CoDel drops on the deferred TX queue (Not-ECT units only).
    #[serde(default)]
    pub aqm_drops: u64,
    /// T9/D-AQM: CE marks applied to ECT-capable deferred units (RFC 3168).
    #[serde(default)]
    pub aqm_ce_marks: u64,
    /// TX descriptors currently held by the kernel (produced minus
    /// completed), bounded by the in-flight cap — observability for
    /// bufferbloat at the xsk TX ring.
    #[serde(default)]
    pub tx_inflight: u64,
    /// Frames that crossed the dataplane dwell bound before reaching the
    /// wire (emit→send > 100 ms). Measurement only — they were still
    /// sent. Nonzero under load means emit backpressure isn't bounding
    /// queue latency and RTT samples can fold in internal queueing.
    #[serde(default)]
    pub stale_dwells: u64,
    /// TCP frames handed off to a sibling worker (flow-ownership
    /// steering). High values relative to RX mean the NIC's RSS spread
    /// disagrees with the worker assignment — normal on asymmetric RSS.
    #[serde(default)]
    pub steered_frames: u64,
    /// Steered frames shed because the target worker's channel was full.
    /// TCP retransmits cover the loss; nonzero means a worker is behind.
    #[serde(default)]
    pub steer_sheds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XdpInterfaceStatus {
    pub name: String,
    pub mode: String,
    pub queues: Vec<u32>,
    pub local_ips: Vec<IpAddr>,
    pub frame_size: u32,
    pub attached: bool,
    pub xsk_ready: bool,
    pub xsk_queues: Vec<XdpQueueStatus>,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct XdpStatusSnapshot {
    pub enabled: bool,
    pub available: bool,
    pub attached: bool,
    pub attach_mode: String,
    pub fallback: String,
    pub fallback_reason: String,
    pub ebpf_object: String,
    pub interfaces: Vec<XdpInterfaceStatus>,
    pub exact_blocked_v4: usize,
    pub exact_blocked_v6: usize,
    pub exact_allowed_v4: usize,
    pub exact_allowed_v6: usize,
    pub blocked_networks: usize,
    pub allowed_networks: usize,
    pub blocked_ranges: usize,
    pub allowed_ranges: usize,
    pub proxy_ports: usize,
    #[serde(default)]
    pub proxy_supported_ports: usize,
    #[serde(default)]
    pub proxy_unsupported_ports: usize,
    pub proxy_ready: bool,
    #[serde(default)]
    pub proxy_redirect_enabled: bool,
    /// Proxy bridge/AF_XDP workers are mid-spawn — attach or reload is in
    /// progress and "redirect not enabled yet" is a transient state, not a
    /// fault. Health checks must not count failures while this is set.
    #[serde(default)]
    pub warming: bool,
    pub proxy_fallback_reason: String,
    pub tcp_dataplane_ready: bool,
    pub tcp_dataplane_detail: String,
    /// F8: congestion controller the AF_XDP TCP dataplane runs ("cubic"),
    /// empty when the TCP dataplane is not supported/configured.
    #[serde(default)]
    pub tcp_congestion_control: String,
    pub xsk_configured_queues: usize,
    pub xsk_ready_queues: usize,
    pub packets: u64,
    pub pass: u64,
    pub drop: u64,
    pub redirect: u64,
    pub parse_errors: u64,
    pub map_miss: u64,
    pub xsk_drops: u64,
    #[serde(default)]
    pub rate_limited: u64,
    #[serde(default)]
    pub ratelimit_map_full: u64,
    #[serde(default)]
    pub udp_fwd_tx: u64,
    #[serde(default)]
    pub udp_fwd_map_full: u64,
    #[serde(default)]
    pub tcp_fwd_tx: u64,
    #[serde(default)]
    pub tcp_fwd_map_full: u64,
    /// SNAT source-port bindings successfully claimed.
    #[serde(default)]
    pub snat_bound: u64,
    /// SNAT port allocation failures; those packets take the userspace path.
    #[serde(default)]
    pub snat_alloc_fail: u64,
    /// Backend replies restored to clients via SNAT reverse bindings.
    #[serde(default)]
    pub snat_reply_tx: u64,
    /// Terminal XDP_TX actions (kernel-bypassed forwards).
    #[serde(default)]
    pub tx: u64,
    /// Terminal drops caused by ACL block rules.
    #[serde(default)]
    pub acl_blocked: u64,
    /// Deterministic-illegal packets dropped at parse (XDP_CLASS_MALFORMED).
    #[serde(default)]
    pub malformed: u64,
    /// Legal-but-unparseable traffic passed to the kernel (deep ext chains,
    /// >2 VLAN tags, non-TCP/UDP/ICMP).
    #[serde(default)]
    pub unsupported: u64,
    /// IP fragments classified before L4 handling.
    #[serde(default)]
    pub fragmented: u64,
    /// Observe-mode ACL hits that would have dropped in enforce modes.
    #[serde(default)]
    pub acl_would_block: u64,
    /// Packets passed because the destination is outside the protected
    /// VIP set (direction gate).
    #[serde(default)]
    pub nonlocal_pass: u64,
    /// EN-07: packets dropped at the aggregate unverified-packet budget.
    pub unverified_limited: u64,
    /// EN-07: new-state admissions rejected by the new-flow budget.
    pub admission_limited: u64,
    /// EN-09: SYN admissions rejected because the bounded half-open table
    /// XDP_PENDING is full.
    pub pending_limited: u64,
    /// EN-11: packets rejected because their flow tuple is already bound
    /// to a different listen (VIP) tuple.
    #[serde(default)]
    pub nat_conflict: u64,
    /// Verified-state packets dropped by the verified-packet budget (dim4).
    pub verified_limited: u64,
    /// Necessary-control packets dropped by the control budget (dim5).
    pub control_limited: u64,
    /// TCP packets rejected by the admission sequence anchors (EN-13/14).
    pub nat_seq_rejected: u64,
    /// EN-07: new-flow admissions rejected by the per-service (listen port)
    /// budget — a flood on one service is contained without draining
    /// siblings' share.
    #[serde(default)]
    pub service_limited: u64,
    /// EN-07: per-service buckets that could not be created because
    /// XDP_SVC_BUDGET is at capacity (aggregate dim1 envelope still applies).
    #[serde(default)]
    pub svc_budget_full: u64,
    /// EN-14: stateless challenge SYN-ACKs emitted (dim3-gated).
    #[serde(default)]
    pub challenge_sent: u64,
    /// EN-14: challenge responses/cookie ACKs rejected (budget, no key,
    /// bad cookie) — explicit fail-closed accounting.
    #[serde(default)]
    pub challenge_rejected: u64,
    /// EN-14: challenge/splice worker faults — the frame was dropped,
    /// never passed half-forged. Distinct from policy rejections.
    #[serde(default)]
    pub challenge_worker_err: u64,
    /// T4: replies claimed by XDP_OUT_CT (node-dialed outbound flows)
    /// and redirected to the ingress queue's XSK for the userspace
    /// dial-flow demux.
    #[serde(default)]
    pub out_ct_hit: u64,
    /// T4-7: ICMP errors claimed by XDP_OUT_CT on the quoted inner
    /// tuple — the PMTU/error delivery path to dialed flows.
    #[serde(default)]
    pub out_ct_icmp: u64,
    /// T4 (D-B1): configured upstream dataplane ("kernel" / "afxdp").
    #[serde(default)]
    pub upstream_mode: String,
    /// T4-5: reserved AF_XDP dial source-port span ("40000-49999"),
    /// empty when upstream mode is not afxdp.
    #[serde(default)]
    pub dial_port_range: String,
    /// T4-5: kernel guard installed (reserved-ports pin + nft DROP).
    #[serde(default)]
    pub dial_guard_installed: bool,
    /// T4-5: packets the guard's nft counter has dropped.
    #[serde(default)]
    pub dial_guard_hits: u64,
    /// T4-5: last guard install failure, empty when healthy/absent.
    #[serde(default)]
    pub dial_guard_detail: String,
    /// EN-10: lifecycle events dropped in-kernel because XDP_FLOW_EVENTS was
    /// full (consumer too slow). Feedback is advisory — loss never blocks or
    /// alters the dataplane, but is always accounted.
    #[serde(default)]
    pub flow_event_lost: u64,
    /// EN-10: lifecycle events applied to the userspace feedback ledger.
    #[serde(default)]
    pub flow_events_received: u64,
    /// EN-10: events dropped by the ordering contract — a stale
    /// (incarnation, owner_epoch, seq) triple or a record for a tuple whose
    /// ledger entry is newer. Old-generation feedback can never renew
    /// state owned by a newer generation.
    #[serde(default)]
    pub flow_events_stale: u64,
    /// EN-10: ledger entries evicted at capacity (bounded feedback state).
    #[serde(default)]
    pub flow_events_evicted: u64,
    /// EN-10: flow records adopted from pinned state maps at attach —
    /// evidence a reload/restart did not sever imported connections.
    #[serde(default)]
    pub imported_flows: u64,
    /// EN-10: owner generation stamped on emitted lifecycle events.
    #[serde(default)]
    pub owner_epoch: u64,
    /// F1: this manager adopted a live AF_XDP dataplane from its
    /// predecessor — sockets/workers/sessions carried over a reload.
    #[serde(default)]
    pub dataplane_adopted: bool,
    /// F1: adoptions the current dataplane lease has survived (0 = the
    /// running socket generation was created by this manager).
    #[serde(default)]
    pub dataplane_lease_adoptions: u64,
    /// ICMP/ICMPv6 control traffic handed to the kernel stack.
    #[serde(default)]
    pub control: u64,
    #[serde(default)]
    pub rate_limit_active: bool,
    #[serde(default)]
    pub rate_limit_detail: String,
    pub updated_at: i64,
}

fn write_status_snapshot_blocking(
    path: &std::path::Path,
    status: &XdpStatusSnapshot,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_vec_pretty(status)?;
    std::fs::write(path, body)?;
    Ok(())
}

#[cfg(any(test, target_os = "linux"))]
fn xsk_status_refresh_due(
    last_refresh_at: Option<std::time::Instant>,
    now: std::time::Instant,
    force: bool,
) -> bool {
    if force {
        return true;
    }
    match last_refresh_at {
        Some(last_refresh_at) => {
            now.saturating_duration_since(last_refresh_at) >= XDP_XSK_STATUS_REFRESH_INTERVAL
        }
        None => true,
    }
}

/// F1: generation-independent handle for one AF_XDP socket generation.
/// The lease is created when the proxy bridge spawns its per-queue
/// reactor threads and is adopted wholesale by the next manager when a
/// reload is dataplane-compatible — workers keep polling the same
/// sockets and their smoltcp sessions are never dropped.
///
/// Workers gate on this lease, not on the manager Arc they were spawned
/// with: `manager_is_current` must never stop a polling loop that still
/// owns live sessions.
#[cfg(any(test, target_os = "linux"))]
pub(crate) struct AfXdpDataplaneLease {
    /// Set when this socket generation is truly decommissioned — runtime
    /// stop, `xdp.enabled=false`, or dataplane teardown. A compatible
    /// reload never touches this flag; workers only exit on it.
    pub(crate) retired: AtomicBool,
    /// Manager generation that currently owns status/fault reporting and
    /// the eBPF handle. Repointed once at adoption handover, after the
    /// new owner's redirect bookkeeping is already armed — workers never
    /// observe a not-ready owner.
    owner: parking_lot::RwLock<std::sync::Arc<XdpManager>>,
    /// Number of times this dataplane has been adopted by a newer
    /// manager generation (0 = original owner still attached).
    adoptions: AtomicU64,
    /// Live reactor workers gating on this lease — incremented at
    /// spawn, decremented when the worker loop returns. Retirement
    /// callers that rebind the queues wait for this to drain so a new
    /// socket generation never races a dying worker's still-open fd.
    live_workers: AtomicU64,
}

#[cfg(any(test, target_os = "linux"))]
impl AfXdpDataplaneLease {
    pub(crate) fn new(owner: std::sync::Arc<XdpManager>) -> Self {
        Self {
            retired: AtomicBool::new(false),
            owner: parking_lot::RwLock::new(owner),
            adoptions: AtomicU64::new(0),
            live_workers: AtomicU64::new(0),
        }
    }

    pub(crate) fn owner(&self) -> std::sync::Arc<XdpManager> {
        self.owner.read().clone()
    }

    /// Adoption handover — caller must arm the new manager's redirect
    /// bookkeeping *before* this repoint.
    pub(crate) fn adopt(&self, new_owner: std::sync::Arc<XdpManager>) {
        *self.owner.write() = new_owner;
        self.adoptions.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn retire(&self) {
        self.retired.store(true, Ordering::Relaxed);
    }

    pub(crate) fn is_retired(&self) -> bool {
        self.retired.load(Ordering::Relaxed)
    }

    pub(crate) fn adoptions(&self) -> u64 {
        self.adoptions.load(Ordering::Relaxed)
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(crate) fn worker_started(&self) {
        self.live_workers.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(crate) fn worker_exited(&self) {
        self.live_workers.fetch_sub(1, Ordering::Relaxed);
    }

    /// Bounded wait for every retired worker to drop its queue sockets —
    /// used before rebinding the same queues on a rebuilt dataplane.
    /// Returns false when the deadline expired with workers still alive;
    /// the caller reports that explicitly rather than assuming.
    #[cfg(target_os = "linux")]
    pub(crate) async fn wait_workers_drained(&self, deadline: std::time::Duration) -> bool {
        let start = std::time::Instant::now();
        while self.live_workers.load(Ordering::Relaxed) > 0 {
            if start.elapsed() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        true
    }
}

#[cfg(any(test, target_os = "linux"))]
impl std::fmt::Debug for AfXdpDataplaneLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately shallow — `owner` is an Arc<XdpManager> and
        // XdpManager::fmt would recurse back into this lease.
        f.debug_struct("AfXdpDataplaneLease")
            .field("retired", &self.retired.load(Ordering::Relaxed))
            .field("adoptions", &self.adoptions.load(Ordering::Relaxed))
            .finish()
    }
}

/// F1 reload gate: fields that determine the AF_XDP socket/queue/link
/// shape. A reload changing any of these cannot keep the running
/// dataplane's sessions and is rejected before the new generation
/// commits — the old dataplane keeps serving untouched. Map-content
/// settings (local IPs, forwards, rules, proxy ports, rate limits) are
/// deliberately absent: they are re-synced gap-free into the pinned
/// maps and take effect on the running program.
#[cfg(any(test, target_os = "linux"))]
fn dataplane_shape_compatible(old: &XdpManager, new: &XdpConfig) -> Result<(), String> {
    let old_cfg = &old.config;
    if old_cfg.attach_mode != new.attach_mode {
        return Err(format!(
            "attachMode changed {} -> {}",
            old_cfg.attach_mode.as_str(),
            new.attach_mode.as_str()
        ));
    }
    if old_cfg.ebpf_object != new.ebpf_object {
        return Err("ebpfObject override changed".to_string());
    }
    // Compare *resolved* table sizes: `None` means auto-scale, which is
    // deterministic for an identical socket shape on the same node — so
    // a reload pinning the previously auto-scaled values stays
    // compatible, while a genuinely different sizing is rejected.
    if let Some(new_tables) = &new.state_tables
        && old.effective_state_tables.read().as_ref() != Some(new_tables)
    {
        return Err("stateTables changed (pinned eBPF map sizes are fixed)".to_string());
    }
    if old_cfg.upstream != new.upstream {
        return Err("upstream dataplane settings changed".to_string());
    }
    if old_cfg.transport != new.transport {
        // Controller/ECN-trust changes mid-generation would silently
        // diverge the congestion semantics of adopted flows.
        return Err("transport policy changed (controller/ECN trust)".to_string());
    }
    let shape = |interfaces: &[crate::runtime_mode::XdpInterfaceConfig]| {
        interfaces
            .iter()
            .map(|i| (i.name.clone(), i.mode, i.queues.clone(), i.cpus.clone()))
            .collect::<Vec<_>>()
    };
    let old_shape = shape(&old_cfg.interfaces);
    let new_shape = shape(&new.interfaces);
    if old_shape != new_shape {
        return Err(format!(
            "interface socket shape changed ({old_shape:?} -> {new_shape:?})"
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct XdpManager {
    /// F1/T5: `pub(crate)` — the lease owner hands the resolved transport
    /// policy to adopted workers; same-generation mutation never happens
    /// (the struct is behind `Arc` once live).
    pub(crate) config: XdpConfig,
    /// State-table sizes actually loaded — set by attach when no explicit
    /// `xdp.stateTables` was configured and the defaults were auto-scaled
    /// to fit this node's kernel-BPF budget. Status reports the real
    /// footprint, not the unsized defaults.
    #[cfg(any(test, target_os = "linux"))]
    effective_state_tables: parking_lot::RwLock<Option<crate::runtime_mode::XdpStateTables>>,
    state: parking_lot::RwLock<RuleState>,
    fallback_reason: parking_lot::RwLock<String>,
    proxy_fallback_reason: parking_lot::RwLock<String>,
    tcp_dataplane_detail: parking_lot::RwLock<String>,
    xsk_status: parking_lot::RwLock<Vec<XdpQueueStatus>>,
    attached: parking_lot::RwLock<BTreeSet<String>>,
    #[cfg(target_os = "linux")]
    ebpf: parking_lot::Mutex<Option<aya::Ebpf>>,
    /// Shared-account credential covering this generation's new pinned
    /// map bytes — held for the dataplane's lifetime, released on
    /// teardown/manager drop. Kept beside `ebpf` so ownership tracks the
    /// same lifecycle.
    #[cfg(target_os = "linux")]
    attach_permit: parking_lot::Mutex<Option<crate::memory_governor::StaticSharedPermit>>,
    #[cfg(target_os = "linux")]
    af_xdp: parking_lot::Mutex<Option<linux::AfXdpRuntimeHandle>>,
    /// T4: outbound dial registry for the current bridge generation —
    /// populated by `spawn_queue_reactors`, replaced wholesale on manager
    /// swap so stale generations cannot admit new dials.
    #[cfg(target_os = "linux")]
    dial_registry: parking_lot::Mutex<Option<std::sync::Arc<af_xdp::AfXdpDialRegistry>>>,
    /// T4-5 (D-B1): kernel guard state — set once the reserved-port
    /// sysctl pin and netfilter DROP rules are confirmed installed. The
    /// registry is only published while a guard report exists.
    #[cfg(target_os = "linux")]
    dial_guard: parking_lot::Mutex<Option<std::sync::Arc<dial_guard::DialGuardReport>>>,
    /// T4-5: packets dropped by the guard's named nft counter (cached —
    /// refreshed by the rule sweeper tick, not per status read).
    #[cfg(target_os = "linux")]
    dial_guard_hits: AtomicU64,
    /// T4-5: last guard install failure — keeps a refused registry
    /// explainable in /status.
    #[cfg(target_os = "linux")]
    dial_guard_detail: parking_lot::Mutex<String>,
    packets: AtomicU64,
    pass: AtomicU64,
    drop: AtomicU64,
    redirect: AtomicU64,
    parse_errors: AtomicU64,
    map_miss: AtomicU64,
    xsk_drops: AtomicU64,
    rate_limited: AtomicU64,
    ratelimit_map_full: AtomicU64,
    udp_fwd_tx: AtomicU64,
    udp_fwd_map_full: AtomicU64,
    tcp_fwd_tx: AtomicU64,
    tcp_fwd_map_full: AtomicU64,
    snat_bound: AtomicU64,
    snat_alloc_fail: AtomicU64,
    snat_reply_tx: AtomicU64,
    tx: AtomicU64,
    acl_blocked: AtomicU64,
    malformed: AtomicU64,
    unsupported: AtomicU64,
    fragmented: AtomicU64,
    control: AtomicU64,
    acl_would_block: AtomicU64,
    nonlocal_pass: AtomicU64,
    unverified_limited: AtomicU64,
    admission_limited: AtomicU64,
    pending_limited: AtomicU64,
    /// EN-11: cross-VIP flow-tuple conflicts rejected in-kernel.
    nat_conflict: AtomicU64,
    verified_limited: AtomicU64,
    control_limited: AtomicU64,
    nat_seq_rejected: AtomicU64,
    service_limited: AtomicU64,
    svc_budget_full: AtomicU64,
    challenge_sent: AtomicU64,
    challenge_rejected: AtomicU64,
    challenge_worker_err: AtomicU64,
    out_ct_hit: AtomicU64,
    out_ct_icmp: AtomicU64,
    rate_limit_active: AtomicU64,
    rate_limit_detail: parking_lot::Mutex<String>,
    /// EN-10: owner generation written to XDP_OWNER_EPOCH at attach.
    owner_epoch: AtomicU64,
    /// EN-10: flow records adopted from pinned maps at the last attach.
    imported_flows: AtomicU64,
    /// EN-10: kernel-side lifecycle events lost to a full ring.
    flow_event_lost: AtomicU64,
    /// EN-10: events applied / rejected / evicted by the feedback consumer.
    flow_events_received: AtomicU64,
    flow_events_stale: AtomicU64,
    flow_events_evicted: AtomicU64,
    /// EN-10 bounded advisory mirror of dataplane lifecycle transitions.
    /// Kernel maps are the sole authority; this ledger never admits trust.
    #[cfg(target_os = "linux")]
    flow_event_ledger: parking_lot::Mutex<FlowEventLedger>,
    flow_event_consumer_started: AtomicBool,
    flow_event_consumer_generation: AtomicU64,
    proxy_redirect_enabled: AtomicBool,
    /// R5: set by `linux::attach` once it passes verification and enters
    /// the commit phase (where the previous generation's links are
    /// detached). Rollback distinguishes prepare failures (old links
    /// still live — never detach) from partial commits (must re-attach
    /// the previous generation).
    attach_committed: AtomicBool,
    /// EN-12 worker lease: true between reactor-thread spawn and the
    /// redirect enable attempt, so queue workers stay alive while the
    /// bridge proves they can actually process before opening redirect.
    /// Socket registration alone is not proof a worker is running.
    proxy_workers_starting: AtomicBool,
    /// F1: this generation adopted the predecessor's live AF_XDP
    /// dataplane instead of creating fresh sockets — observability for
    /// /status and reload diagnostics.
    #[cfg(target_os = "linux")]
    dataplane_adopted: AtomicBool,
    /// F1: set by the atomic link swap when a mid-commit failure reverted
    /// every swapped link cleanly — the predecessor's dataplane is then
    /// intact and reload rollback keeps it serving instead of rebuilding.
    #[cfg(target_os = "linux")]
    attach_dataplane_restored: std::sync::Arc<AtomicBool>,
    /// EN-05: (ifindex, queue) pairs whose XSK_INDEX/XSKS slots were
    /// withdrawn after a queue-scoped fault. Periodic map syncs consult
    /// this so they never resurrect a dead queue's redirect entry; cleared
    /// when a new attach generation registers fresh sockets.
    #[cfg(target_os = "linux")]
    xsk_withdrawn: parking_lot::Mutex<std::collections::HashSet<(u32, u32)>>,
    last_state_write_at: AtomicU64,
    rule_sweeper_started: AtomicBool,
    rule_sweeper_generation: AtomicU64,
    /// Image of the rule state last successfully written to the eBPF maps. The
    /// incremental sync diffs the live shadow `state` against this to compute the
    /// minimal set of map inserts/removes.
    #[cfg(target_os = "linux")]
    synced: parking_lot::Mutex<RuleState>,
    /// Last-aggregated per-flow totals for XDP UDP direct-forward accounting;
    /// sweeps emit deltas against this image so nothing is double-counted.
    #[cfg(target_os = "linux")]
    udp_flow_shadow: parking_lot::Mutex<
        std::collections::HashMap<
            cloud_node_xdp_common::XdpUdpCtKey,
            cloud_node_xdp_common::XdpFlowAcct,
        >,
    >,
    map_sync_started: AtomicBool,
    map_sync_generation: AtomicU64,
    map_sync_notify: tokio::sync::Notify,
}

impl XdpManager {
    fn new(config: XdpConfig) -> Self {
        Self {
            config,
            #[cfg(any(test, target_os = "linux"))]
            effective_state_tables: parking_lot::RwLock::new(None),
            state: parking_lot::RwLock::new(RuleState::default()),
            fallback_reason: parking_lot::RwLock::new(String::new()),
            proxy_fallback_reason: parking_lot::RwLock::new(String::new()),
            tcp_dataplane_detail: parking_lot::RwLock::new(String::new()),
            xsk_status: parking_lot::RwLock::new(Vec::new()),
            attached: parking_lot::RwLock::new(BTreeSet::new()),
            #[cfg(target_os = "linux")]
            ebpf: parking_lot::Mutex::new(None),
            #[cfg(target_os = "linux")]
            attach_permit: parking_lot::Mutex::new(None),
            #[cfg(target_os = "linux")]
            af_xdp: parking_lot::Mutex::new(None),
            #[cfg(target_os = "linux")]
            dial_registry: parking_lot::Mutex::new(None),
            #[cfg(target_os = "linux")]
            dial_guard: parking_lot::Mutex::new(None),
            #[cfg(target_os = "linux")]
            dial_guard_hits: AtomicU64::new(0),
            #[cfg(target_os = "linux")]
            dial_guard_detail: parking_lot::Mutex::new(String::new()),
            packets: AtomicU64::new(0),
            pass: AtomicU64::new(0),
            drop: AtomicU64::new(0),
            redirect: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            map_miss: AtomicU64::new(0),
            xsk_drops: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            ratelimit_map_full: AtomicU64::new(0),
            udp_fwd_tx: AtomicU64::new(0),
            udp_fwd_map_full: AtomicU64::new(0),
            tcp_fwd_tx: AtomicU64::new(0),
            tcp_fwd_map_full: AtomicU64::new(0),
            snat_bound: AtomicU64::new(0),
            snat_alloc_fail: AtomicU64::new(0),
            snat_reply_tx: AtomicU64::new(0),
            tx: AtomicU64::new(0),
            acl_blocked: AtomicU64::new(0),
            malformed: AtomicU64::new(0),
            unsupported: AtomicU64::new(0),
            fragmented: AtomicU64::new(0),
            control: AtomicU64::new(0),
            acl_would_block: AtomicU64::new(0),
            nonlocal_pass: AtomicU64::new(0),
            unverified_limited: AtomicU64::new(0),
            admission_limited: AtomicU64::new(0),
            pending_limited: AtomicU64::new(0),
            nat_conflict: AtomicU64::new(0),
            verified_limited: AtomicU64::new(0),
            control_limited: AtomicU64::new(0),
            nat_seq_rejected: AtomicU64::new(0),
            service_limited: AtomicU64::new(0),
            svc_budget_full: AtomicU64::new(0),
            challenge_sent: AtomicU64::new(0),
            challenge_rejected: AtomicU64::new(0),
            challenge_worker_err: AtomicU64::new(0),
            out_ct_hit: AtomicU64::new(0),
            out_ct_icmp: AtomicU64::new(0),
            rate_limit_active: AtomicU64::new(0),
            rate_limit_detail: parking_lot::Mutex::new(String::new()),
            owner_epoch: AtomicU64::new(0),
            imported_flows: AtomicU64::new(0),
            flow_event_lost: AtomicU64::new(0),
            flow_events_received: AtomicU64::new(0),
            flow_events_stale: AtomicU64::new(0),
            flow_events_evicted: AtomicU64::new(0),
            #[cfg(target_os = "linux")]
            flow_event_ledger: parking_lot::Mutex::new(FlowEventLedger::default()),
            flow_event_consumer_started: AtomicBool::new(false),
            flow_event_consumer_generation: AtomicU64::new(0),
            proxy_redirect_enabled: AtomicBool::new(false),
            attach_committed: AtomicBool::new(false),
            proxy_workers_starting: AtomicBool::new(false),
            #[cfg(target_os = "linux")]
            dataplane_adopted: AtomicBool::new(false),
            #[cfg(target_os = "linux")]
            attach_dataplane_restored: std::sync::Arc::new(AtomicBool::new(false)),
            #[cfg(target_os = "linux")]
            xsk_withdrawn: parking_lot::Mutex::new(std::collections::HashSet::new()),
            last_state_write_at: AtomicU64::new(0),
            rule_sweeper_started: AtomicBool::new(false),
            rule_sweeper_generation: AtomicU64::new(0),
            #[cfg(target_os = "linux")]
            synced: parking_lot::Mutex::new(RuleState::default()),
            #[cfg(target_os = "linux")]
            udp_flow_shadow: parking_lot::Mutex::new(std::collections::HashMap::new()),
            map_sync_started: AtomicBool::new(false),
            map_sync_generation: AtomicU64::new(0),
            map_sync_notify: tokio::sync::Notify::new(),
        }
    }

    async fn initialize(&self) -> anyhow::Result<()> {
        self.initialize_inner(None, None).await
    }

    /// `predecessor` is set during an owner-respecting reload: the old
    /// generation keeps its kernel links and AF_XDP sockets until the new
    /// attach commits, then releases them so the new sockets can bind the
    /// same queues. `self_arc` is the Arc of `self` — required when the
    /// reload adopts the predecessor's live dataplane so the lease owner
    /// can be repointed at this generation.
    async fn initialize_inner(
        &self,
        predecessor: Option<&std::sync::Arc<XdpManager>>,
        self_arc: Option<&std::sync::Arc<XdpManager>>,
    ) -> anyhow::Result<()> {
        #[cfg(not(target_os = "linux"))]
        let _ = (predecessor, self_arc);
        if !self.config.enabled {
            // F1: disabling XDP decommissions the predecessor's dataplane
            // for real — retire the lease so workers abort their sessions
            // with wire-visible RSTs instead of polling dead rings.
            #[cfg(target_os = "linux")]
            if let Some(old) = predecessor {
                old.retire_dataplane_lease();
            }
            self.ensure_detached_when_disabled().await;
            return Ok(());
        }
        if self.config.interfaces.is_empty() {
            self.set_fallback_reason("runtime xdp.interfaces is empty");
            // A reload must never publish a generation that cannot attach:
            // rejecting keeps the predecessor's dataplane serving. The
            // fallback=pass contract only covers cold start.
            if self.config.fallback.fail_start() || predecessor.is_some() {
                anyhow::bail!("xdp enabled but no interfaces configured");
            }
            return Ok(());
        }
        let proxy_frame_size_detail = xdp_proxy_frame_size_detail(&self.config);
        if !proxy_frame_size_detail.is_empty() {
            self.set_fallback_reason(format!("{proxy_frame_size_detail}; traffic will PASS"));
            if self.config.fallback.fail_start() || predecessor.is_some() {
                anyhow::bail!("{proxy_frame_size_detail}");
            }
            self.persist_status();
            return Ok(());
        }
        if !self.attached.read().is_empty() {
            self.persist_status();
            return Ok(());
        }

        let object_override = ebpf_object_override(&self.config);
        if let Some(path) = &object_override
            && !path.exists()
        {
            self.set_fallback_reason(format!(
                "configured eBPF object {} is missing",
                path.display()
            ));
            if self.config.fallback.fail_start() || predecessor.is_some() {
                anyhow::bail!("xdp eBPF object is missing: {}", path.display());
            }
            self.persist_status();
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        {
            // F1: decide dataplane adoption before attach. A predecessor
            // with a live (non-retired) dataplane lease can only be
            // replaced by a dataplane-compatible config — anything else
            // would orphan the AF_XDP sessions the workers still own, so
            // the reload is rejected before any commit damage.
            let adopt_lease = predecessor.and_then(|old| old.live_dataplane_lease());
            if let Some(old) = predecessor
                && adopt_lease.is_some()
                && let Err(detail) = dataplane_shape_compatible(old, &self.config)
            {
                let reason = format!(
                    "XDP reload rejected — dataplane-incompatible change ({detail}); \
                     the live AF_XDP dataplane keeps serving under the previous generation; \
                     restart the node to apply this config"
                );
                self.set_fallback_reason(reason.clone());
                anyhow::bail!("{reason}");
            }
            // The daemon never purges pinned state implicitly: an
            // ABI-incompatible state map is a migration boundary and must
            // surface as an explicit fallback reason, not silent state loss.
            let atomic_reattach = predecessor
                .filter(|_| adopt_lease.is_some())
                .map(|old| linux::AtomicReattach {
                    xsk_withdrawn: old.xsk_withdrawn.lock().clone(),
                    dataplane_restored: self.attach_dataplane_restored.clone(),
                });
            self.attach_committed.store(false, Ordering::Relaxed);
            self.attach_dataplane_restored
                .store(false, Ordering::Relaxed);
            // Reload keeps the resolved footprint: when the operator left
            // `stateTables` unset, inherit the predecessor's effective
            // sizes so attach never re-derives them from the moving
            // `available` watermark. Restart recovery (no predecessor)
            // happens inside attach via the pin survey.
            let mut attach_config = self.config.clone();
            if attach_config.state_tables.is_none() {
                attach_config.state_tables =
                    predecessor.and_then(|old| old.effective_state_tables.read().clone());
            }
            match linux::attach(
                &attach_config,
                object_override.as_deref(),
                false,
                Some(&self.attach_committed),
                atomic_reattach.as_ref(),
            )
            .await
            {
                Ok(attached_program) => {
                    self.owner_epoch
                        .store(attached_program.owner_epoch, Ordering::Relaxed);
                    self.imported_flows
                        .store(attached_program.imported_flows, Ordering::Relaxed);
                    *self.effective_state_tables.write() =
                        attached_program.effective_state_tables;
                    // The committed map-memory credential lives as long as
                    // this generation's dataplane — dropping it here would
                    // free ledger bytes the kernel still pins.
                    *self.attach_permit.lock() = attached_program.resource_permit;
                    *self.ebpf.lock() = Some(attached_program.ebpf);
                    let attached = attached_program.interfaces;
                    *self.attached.write() = attached;
                    self.set_fallback_reason(String::new());
                    // Admission contract is config-derived and the map is
                    // pinned — write it once at attach rather than every
                    // sweep tick, so test-only fault flags written through
                    // the map are not clobbered between sweeps.
                    self.sync_pending_cap();
                    // EN-14: populate the pinned cookie key ring on first
                    // attach (no-op when a generation already holds a key).
                    self.sync_cookie_key();
                    if let Some(old) = predecessor {
                        if let Some(lease) = &adopt_lease {
                            // F1: adopt the predecessor's live dataplane —
                            // sockets, workers, sessions, dial registry and
                            // guard all carry over; the atomic link swap
                            // already pointed the kernel at this object's
                            // program. Redirect bookkeeping is armed here
                            // *before* the lease owner repoint inside.
                            self.adopt_af_xdp_runtime(old, lease, self_arc);
                            old.release_bookkeeping_for_adoption();
                        } else {
                            // The attach commit already swapped the kernel
                            // links. Release the previous generation's
                            // AF_XDP sockets and eBPF handle so this
                            // generation can bind the same queues.
                            old.release_for_handover();
                        }
                    } else {
                        // Fresh attach: queue withdrawals applied to a
                        // previous socket set must not leak into this
                        // generation's index sync.
                        self.xsk_withdrawn.lock().clear();
                    }
                    self.flush_maps_full_blocking(self.proxy_redirect_ready());
                    self.configure_af_xdp_runtime()?;
                }
                Err(err) => {
                    self.set_fallback_reason(format!("attach failed: {err}"));
                    // On reload the failed generation must not stay
                    // published — `fallback=pass` would silently drop the
                    // predecessor's dataplane with it. Reject the change
                    // and let the rollback restore the serving manager.
                    if self.config.fallback.fail_start() || predecessor.is_some() {
                        return Err(err);
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.set_fallback_reason("XDP attach is supported on Linux only");
            if self.config.fallback.fail_start() || predecessor.is_some() {
                anyhow::bail!("XDP attach is supported on Linux only");
            }
        }

        self.persist_status();
        Ok(())
    }

    async fn ensure_detached_when_disabled(&self) {
        if self.config.enabled {
            return;
        }
        self.stop_rule_sweeper();
        self.stop_map_sync_worker();
        self.stop_flow_event_consumer();
        self.proxy_redirect_enabled.store(false, Ordering::Relaxed);
        #[cfg(target_os = "linux")]
        {
            // F1: retire the lease first so workers abort live sessions
            // with wire RSTs instead of polling dead rings.
            self.retire_dataplane_lease();
            self.release_dial_guard().await;
            *self.af_xdp.lock() = None;
            *self.ebpf.lock() = None;
            *self.attach_permit.lock() = None;
            if !self.config.interfaces.is_empty()
                && let Err(err) = linux::detach(&self.config).await
            {
                let detail = format!("runtime xdp.enabled=false; detach failed: {err}");
                self.set_fallback_reason(detail.clone());
                tracing::warn!("{detail}");
                crate::logging::report_node_log(
                    "warn".to_string(),
                    "xdp".to_string(),
                    detail,
                    0,
                );
                self.persist_status_blocking();
                return;
            }
        }
        self.attached.write().clear();
        self.xsk_status.write().clear();
        self.set_fallback_reason(String::new());
        self.set_proxy_fallback_reason(String::new());
        self.persist_status_blocking();
    }

    fn set_fallback_reason(&self, reason: impl Into<String>) {
        *self.fallback_reason.write() = reason.into();
    }

    fn set_proxy_fallback_reason(&self, reason: impl Into<String>) {
        *self.proxy_fallback_reason.write() = reason.into();
    }

    #[cfg(target_os = "linux")]
    fn set_tcp_dataplane_detail(&self, detail: impl Into<String>) {
        *self.tcp_dataplane_detail.write() = detail.into();
    }

    fn tcp_dataplane_detail(&self) -> String {
        let detail = self.tcp_dataplane_detail.read().clone();
        if !detail.is_empty() {
            return detail;
        }
        xdp_tcp_dataplane_detail(&self.config)
    }

    fn proxy_xsk_ready(&self) -> bool {
        if !XDP_PROXY_DATAPLANE_ACTIVE
            || self.config.proxy.ports.is_empty()
            || xdp_supported_proxy_port_count(&self.config) == 0
        {
            return false;
        }
        let statuses = self.xsk_status.read();
        let proxy_interfaces = self
            .config
            .interfaces
            .iter()
            .filter(|interface| interface.mode == XdpRuntimeMode::Proxy)
            .collect::<Vec<_>>();
        !proxy_interfaces.is_empty()
            && proxy_interfaces.iter().all(|interface| {
                !interface.queues.is_empty()
                    && interface.queues.iter().all(|queue| {
                        statuses.iter().any(|status| {
                            status.interface == interface.name
                                && status.queue == *queue
                                // A faulted queue is deliberately withdrawn:
                                // its slots are gone and its traffic takes the
                                // explicit dataplane fallback, so it must not
                                // stall readiness for surviving queues.
                                && (status.ready || status.faulted)
                        })
                    })
            })
    }

    fn proxy_redirect_ready(&self) -> bool {
        self.proxy_redirect_enabled.load(Ordering::Relaxed) && self.proxy_xsk_ready()
    }

    /// Worker lease gate: true while the bridge is proving reactor workers
    /// can run, before redirect opens. Keeps `should_continue` alive during
    /// startup without treating a registered socket as a working dataplane.
    #[cfg(any(test, target_os = "linux"))]
    pub(crate) fn proxy_workers_starting(&self) -> bool {
        self.proxy_workers_starting.load(Ordering::Relaxed)
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(crate) fn set_proxy_workers_starting(&self, starting: bool) {
        self.proxy_workers_starting
            .store(starting, Ordering::Relaxed);
    }

    #[cfg(any(test, target_os = "linux"))]
    fn mark_proxy_dataplane_degraded(&self, detail: impl Into<String>) {
        let detail = detail.into();
        self.proxy_redirect_enabled.store(false, Ordering::Relaxed);
        self.proxy_workers_starting.store(false, Ordering::Relaxed);
        self.set_proxy_fallback_reason(detail.clone());
        let mut statuses = self.xsk_status.write();
        for status in statuses.iter_mut() {
            let was_registered = status.registered;
            let was_ready = status.ready;
            status.registered = false;
            status.ready = false;
            if was_registered || was_ready || status.detail.is_empty() {
                status.detail = detail.clone();
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn disable_proxy_redirect_for_fallback(&self, detail: impl Into<String>) {
        let detail = detail.into();
        self.proxy_redirect_enabled.store(false, Ordering::Relaxed);
        self.mark_proxy_dataplane_degraded(detail.clone());
        let result = {
            let mut ebpf = self.ebpf.lock();
            match ebpf.as_mut() {
                Some(ebpf) => linux::disable_proxy_redirect(ebpf, &self.config),
                None => Ok(()),
            }
        };
        if let Err(err) = result {
            self.set_proxy_fallback_reason(format!(
                "{detail}; failed to disable AF_XDP proxy redirect maps: {err}"
            ));
            tracing::warn!("failed to disable AF_XDP proxy redirect maps: {}", err);
        }
        self.persist_status_now();
    }

    /// True when the queue already went through queue-scoped withdrawal —
    /// the supervisor uses it to avoid overwriting the original fault
    /// detail with a generic "worker exited" reason.
    #[cfg(target_os = "linux")]
    fn xsk_queue_faulted(&self, interface: &str, queue: u32) -> bool {
        self.xsk_status
            .read()
            .iter()
            .any(|status| status.interface == interface && status.queue == queue && status.faulted)
    }

    /// EN-05 queue-scoped fault containment: withdraw one queue's
    /// XSK_INDEX/XSKS slots so its redirected traffic takes the explicit
    /// dataplane fallback (map_miss → PASS/DROP per policy) while sibling
    /// queues keep serving. The withdrawal is recorded in `xsk_withdrawn`
    /// so periodic map syncs cannot resurrect the slot. If the map update
    /// itself fails, containment is impossible — escalate honestly to the
    /// global disable rather than leaving a half-withdrawn queue.
    #[cfg(target_os = "linux")]
    fn disable_queue_redirect_for_fault(
        &self,
        interface: &str,
        queue: u32,
        detail: impl Into<String>,
    ) {
        let detail = format!(
            "{}; queue {}/{} withdrawn — remaining queues unaffected, this queue's traffic falls back explicitly",
            detail.into(),
            interface,
            queue
        );
        tracing::warn!("{detail}");
        let ifindex = linux::ifindex_from_name(interface).unwrap_or(0);
        if ifindex != 0 {
            self.xsk_withdrawn.lock().insert((ifindex, queue));
        }
        self.update_xsk_queue_status(interface, queue, |status| {
            status.registered = false;
            status.ready = false;
            status.faulted = true;
            status.detail = detail.clone();
        });
        self.set_proxy_fallback_reason(detail.clone());
        let result = {
            let mut ebpf = self.ebpf.lock();
            match ebpf.as_mut() {
                Some(ebpf) => linux::disable_queue_redirect(ebpf, interface, queue),
                None => Ok(false),
            }
        };
        if let Err(err) = result {
            self.disable_proxy_redirect_for_fallback(format!(
                "{detail}; queue-local withdrawal failed ({err}); widening to global redirect disable"
            ));
            return;
        }
        self.persist_status_now();
    }

    /// T4: register a node-dialed outbound flow in XDP_OUT_CT so its
    /// replies redirect into AF_XDP instead of passing to the kernel
    #[cfg(target_os = "linux")]
    fn configure_af_xdp_runtime(&self) -> anyhow::Result<()> {
        if !self
            .config
            .interfaces
            .iter()
            .any(|interface| interface.mode == XdpRuntimeMode::Proxy)
        {
            self.xsk_status.write().clear();
            self.set_proxy_fallback_reason(String::new());
            return Ok(());
        }
        if self.config.proxy.ports.is_empty() {
            self.xsk_status.write().clear();
            self.set_proxy_fallback_reason("xdp.proxy.ports is empty; proxy traffic will PASS");
            return Ok(());
        }
        if xdp_supported_proxy_port_count(&self.config) == 0 {
            self.xsk_status.write().clear();
            self.set_proxy_fallback_reason(
                "xdp.proxy.ports has no AF_XDP-supported protocols; traffic will PASS",
            );
            self.set_tcp_dataplane_detail(xdp_tcp_dataplane_detail(&self.config));
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        {
            // F1: an adopted dataplane already carries the runtime handle
            // (sockets + workers + sessions) — do not bind fresh sockets.
            if self.af_xdp.lock().is_some() {
                self.set_proxy_fallback_reason(xdp_proxy_partial_detail(&self.config));
                self.set_tcp_dataplane_detail(xdp_tcp_dataplane_detail(&self.config));
                return Ok(());
            }
            match linux::prepare_af_xdp_sockets(&self.config) {
                Ok(mut runtime) => {
                    let mut registration_failed = false;
                    let mut registration_failure_detail = None;
                    if XDP_PROXY_DATAPLANE_ACTIVE
                        && runtime.statuses.iter().all(|status| status.socket_created)
                    {
                        let register_result = {
                            let mut ebpf = self.ebpf.lock();
                            match ebpf.as_mut() {
                                Some(ebpf) => linux::register_af_xdp_sockets(
                                    ebpf,
                                    &self.config,
                                    &mut runtime,
                                    false,
                                ),
                                None => Err(anyhow::anyhow!(
                                    "eBPF program is not loaded; cannot register AF_XDP sockets"
                                )),
                            }
                        };
                        if let Err(err) = register_result {
                            registration_failed = true;
                            registration_failure_detail = Some(format!(
                                "AF_XDP socket registration failed: {err}; proxy redirect disabled, traffic will PASS"
                            ));
                        }
                    }
                    let statuses = runtime.statuses.clone();
                    let failed = statuses.iter().any(|status| !status.socket_created);
                    let failure_detail = if failed {
                        Some(xdp_queue_failure_detail(
                            &statuses,
                            "one or more AF_XDP sockets failed to start",
                        ))
                    } else {
                        None
                    };
                    *self.xsk_status.write() = statuses;
                    if failed || registration_failed {
                        drop(runtime);
                    } else {
                        *self.af_xdp.lock() = Some(runtime);
                    }
                    if failed {
                        let detail = failure_detail.unwrap_or_else(|| {
                            "one or more AF_XDP sockets failed to start".to_string()
                        });
                        self.disable_proxy_redirect_for_fallback(format!(
                            "{detail}; proxy redirect disabled, traffic will PASS"
                        ));
                        if self.config.fallback.fail_start() {
                            anyhow::bail!("{detail}");
                        }
                    } else if registration_failed {
                        let detail = registration_failure_detail.unwrap_or_else(|| {
                            "AF_XDP socket registration failed; proxy redirect disabled, traffic will PASS"
                                .to_string()
                        });
                        self.disable_proxy_redirect_for_fallback(detail);
                        if self.config.fallback.fail_start() {
                            anyhow::bail!("one or more AF_XDP sockets failed to register");
                        }
                    } else if XDP_PROXY_DATAPLANE_ACTIVE {
                        self.proxy_redirect_enabled.store(false, Ordering::Relaxed);
                        let partial = xdp_proxy_partial_detail(&self.config);
                        let detail = if partial.is_empty() {
                            "AF_XDP sockets registered; proxy bridge has not enabled redirect yet, traffic will PASS".to_string()
                        } else {
                            format!(
                                "AF_XDP sockets registered; proxy bridge has not enabled redirect yet, traffic will PASS; {partial}"
                            )
                        };
                        self.set_proxy_fallback_reason(detail);
                        self.set_tcp_dataplane_detail(
                            "AF_XDP TCP sockets registered; proxy bridge has not enabled redirect yet",
                        );
                    } else {
                        self.set_proxy_fallback_reason(
                            "AF_XDP sockets staged; userspace proxy dataplane is not active, traffic will PASS",
                        );
                        if self.config.fallback.fail_start() {
                            anyhow::bail!(
                                "xdp proxy requested but AF_XDP userspace proxy dataplane is not active"
                            );
                        }
                    }
                }
                Err(err) => {
                    *self.xsk_status.write() = configured_queue_statuses(
                        &self.config,
                        format!("AF_XDP socket setup failed: {err}"),
                    );
                    self.disable_proxy_redirect_for_fallback(format!(
                        "AF_XDP socket setup failed: {err}; proxy redirect disabled, traffic will PASS"
                    ));
                    if self.config.fallback.fail_start() {
                        return Err(err);
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            *self.xsk_status.write() = configured_queue_statuses(
                &self.config,
                "AF_XDP sockets are supported on Linux only",
            );
            self.set_proxy_fallback_reason("AF_XDP sockets are supported on Linux only");
            if self.config.fallback.fail_start() {
                anyhow::bail!("AF_XDP sockets are supported on Linux only");
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn enable_proxy_redirect(&self, source: &'static str) -> anyhow::Result<bool> {
        if !self.config.enabled
            || !XDP_PROXY_DATAPLANE_ACTIVE
            || self.config.proxy.ports.is_empty()
            || xdp_supported_proxy_port_count(&self.config) == 0
            || !self.proxy_xsk_ready()
        {
            return Ok(false);
        }

        self.flush_maps_full_blocking(true);

        // Check if still attached after flush (detach_after_runtime_failure may have been called)
        if self.attached.read().is_empty() {
            return Err(anyhow::anyhow!(
                "{source} failed to enable AF_XDP redirect: map sync failed"
            ));
        }

        self.proxy_redirect_enabled.store(true, Ordering::Relaxed);
        self.set_proxy_fallback_reason(xdp_proxy_partial_detail(&self.config));
        self.set_tcp_dataplane_detail(xdp_tcp_dataplane_detail(&self.config));
        self.persist_status_now();
        Ok(true)
    }

    fn queue_statuses_for_config(&self) -> Vec<XdpQueueStatus> {
        let statuses = self.xsk_status.read().clone();
        if !statuses.is_empty() {
            return statuses;
        }
        self.config
            .interfaces
            .iter()
            .filter(|interface| interface.mode == XdpRuntimeMode::Proxy)
            .flat_map(|interface| {
                interface.queues.iter().map(|queue| XdpQueueStatus {
                    interface: interface.name.clone(),
                    queue: *queue,
                    configured: true,
                    socket_created: false,
                    registered: false,
                    ready: false,
                    detail: if self.config.proxy.ports.is_empty() {
                        "proxy ports not configured; traffic will PASS".to_string()
                    } else if xdp_supported_proxy_port_count(&self.config) == 0 {
                        "no AF_XDP-supported proxy ports configured; traffic will PASS".to_string()
                    } else {
                        "AF_XDP runtime not started".to_string()
                    },
                    ..XdpQueueStatus::default()
                })
            })
            .collect()
    }

    fn status(&self) -> XdpStatusSnapshot {
        #[cfg(target_os = "linux")]
        self.refresh_af_xdp_statuses(true);
        self.refresh_counters();
        let state = self.state.read();
        let attached = self.attached.read();
        let fallback_reason = self.fallback_reason.read().clone();
        let proxy_fallback_reason = self.proxy_fallback_reason.read().clone();
        let tcp_dataplane_detail = self.tcp_dataplane_detail();
        let queue_statuses = self.queue_statuses_for_config();
        let interfaces = self
            .config
            .interfaces
            .iter()
            .map(|interface| {
                let is_attached = attached.contains(&interface.name);
                let xsk_queues = queue_statuses
                    .iter()
                    .filter(|status| status.interface == interface.name)
                    .cloned()
                    .collect::<Vec<_>>();
                let xsk_ready = interface.mode == XdpRuntimeMode::Proxy
                    && !xsk_queues.is_empty()
                    && xsk_queues.iter().all(|status| status.ready);
                XdpInterfaceStatus {
                    name: interface.name.clone(),
                    mode: interface.mode.as_str().to_string(),
                    queues: interface.queues.clone(),
                    local_ips: interface.local_ips.clone(),
                    frame_size: interface.frame_size,
                    attached: is_attached,
                    xsk_ready,
                    xsk_queues,
                    detail: if is_attached {
                        if interface.mode == XdpRuntimeMode::Proxy {
                            if self.config.proxy.ports.is_empty() {
                                "attached; proxy port map is empty; passing traffic".to_string()
                            } else if !XDP_PROXY_DATAPLANE_ACTIVE {
                                "attached; AF_XDP sockets staged but proxy dataplane is not active"
                                    .to_string()
                            } else if xdp_supported_proxy_port_count(&self.config) == 0 {
                                "attached; no AF_XDP-supported proxy ports; passing traffic"
                                    .to_string()
                            } else if xsk_ready {
                                if !self.proxy_redirect_enabled.load(Ordering::Relaxed) {
                                    "attached; AF_XDP sockets ready; redirect disabled until proxy bridge starts; passing traffic".to_string()
                                } else {
                                    let detail = xdp_proxy_partial_detail(&self.config);
                                    if detail.is_empty() {
                                        "attached; AF_XDP redirect ready".to_string()
                                    } else {
                                        format!("attached; AF_XDP redirect ready; {detail}")
                                    }
                                }
                            } else {
                                "attached; AF_XDP sockets not ready".to_string()
                            }
                        } else {
                            "attached".to_string()
                        }
                    } else if fallback_reason.is_empty() {
                        "not attached".to_string()
                    } else {
                        fallback_reason.clone()
                    },
                }
            })
            .collect::<Vec<_>>();
        let attached_any = !attached.is_empty();
        let xsk_configured_queues = queue_statuses
            .iter()
            .filter(|status| status.configured)
            .count();
        let xsk_ready_queues = queue_statuses.iter().filter(|status| status.ready).count();
        let proxy_supported_ports = xdp_supported_proxy_port_count(&self.config);
        let proxy_unsupported_ports = self
            .config
            .proxy
            .ports
            .len()
            .saturating_sub(proxy_supported_ports);
        let proxy_interfaces = self
            .config
            .interfaces
            .iter()
            .filter(|interface| interface.mode == XdpRuntimeMode::Proxy)
            .collect::<Vec<_>>();
        let proxy_ready = self.proxy_redirect_enabled.load(Ordering::Relaxed)
            && !proxy_interfaces.is_empty()
            && proxy_interfaces.iter().all(|interface| {
                !interface.queues.is_empty()
                    && interface.queues.iter().all(|queue| {
                        queue_statuses.iter().any(|status| {
                            status.interface == interface.name
                                && status.queue == *queue
                                && status.ready
                        })
                    })
            });
        XdpStatusSnapshot {
            enabled: self.config.enabled,
            available: self.config.enabled && attached_any && fallback_reason.is_empty(),
            attached: attached_any,
            attach_mode: self.config.attach_mode.as_str().to_string(),
            fallback: self.config.fallback.as_str().to_string(),
            fallback_reason,
            ebpf_object: ebpf_object_source_label(&self.config),
            interfaces,
            exact_blocked_v4: state.blocked_ips.keys().filter(|ip| ip.is_ipv4()).count(),
            exact_blocked_v6: state.blocked_ips.keys().filter(|ip| ip.is_ipv6()).count(),
            exact_allowed_v4: state.allowed_ips.keys().filter(|ip| ip.is_ipv4()).count(),
            exact_allowed_v6: state.allowed_ips.keys().filter(|ip| ip.is_ipv6()).count(),
            blocked_networks: state.blocked_networks.len(),
            allowed_networks: state.allowed_networks.len(),
            blocked_ranges: state.blocked_ranges.len(),
            allowed_ranges: state.allowed_ranges.len(),
            proxy_ports: self.config.proxy.ports.len(),
            proxy_supported_ports,
            proxy_unsupported_ports,
            proxy_ready,
            proxy_redirect_enabled: self.proxy_redirect_enabled.load(Ordering::Relaxed),
            warming: self.proxy_workers_starting.load(Ordering::Relaxed),
            proxy_fallback_reason,
            tcp_dataplane_ready: xdp_proxy_has_tcp_like_ports(&self.config)
                && xdp_tcp_dataplane_supported()
                && proxy_ready
                && tcp_dataplane_detail.is_empty(),
            tcp_dataplane_detail,
            // F8: the AF_XDP TCP dataplane always runs an explicit smoltcp
            // congestion controller — expose which one so `xdp status` can
            // prove no session silently runs NoControl.
            tcp_congestion_control: if xdp_proxy_has_tcp_like_ports(&self.config)
                && xdp_tcp_dataplane_supported()
            {
                crate::runtime_mode::XdpTransportController::Edgecc
                    .as_str()
                    .to_string()
            } else {
                String::new()
            },
            xsk_configured_queues,
            xsk_ready_queues,
            packets: self.packets.load(Ordering::Relaxed),
            pass: self.pass.load(Ordering::Relaxed),
            drop: self.drop.load(Ordering::Relaxed),
            redirect: self.redirect.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            map_miss: self.map_miss.load(Ordering::Relaxed),
            xsk_drops: self.xsk_drops.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            ratelimit_map_full: self.ratelimit_map_full.load(Ordering::Relaxed),
            udp_fwd_tx: self.udp_fwd_tx.load(Ordering::Relaxed),
            udp_fwd_map_full: self.udp_fwd_map_full.load(Ordering::Relaxed),
            tcp_fwd_tx: self.tcp_fwd_tx.load(Ordering::Relaxed),
            tcp_fwd_map_full: self.tcp_fwd_map_full.load(Ordering::Relaxed),
            snat_bound: self.snat_bound.load(Ordering::Relaxed),
            snat_alloc_fail: self.snat_alloc_fail.load(Ordering::Relaxed),
            snat_reply_tx: self.snat_reply_tx.load(Ordering::Relaxed),
            tx: self.tx.load(Ordering::Relaxed),
            acl_blocked: self.acl_blocked.load(Ordering::Relaxed),
            malformed: self.malformed.load(Ordering::Relaxed),
            unsupported: self.unsupported.load(Ordering::Relaxed),
            fragmented: self.fragmented.load(Ordering::Relaxed),
            control: self.control.load(Ordering::Relaxed),
            acl_would_block: self.acl_would_block.load(Ordering::Relaxed),
            nonlocal_pass: self.nonlocal_pass.load(Ordering::Relaxed),
            unverified_limited: self.unverified_limited.load(Ordering::Relaxed),
            admission_limited: self.admission_limited.load(Ordering::Relaxed),
            pending_limited: self.pending_limited.load(Ordering::Relaxed),
            nat_conflict: self.nat_conflict.load(Ordering::Relaxed),
            verified_limited: self.verified_limited.load(Ordering::Relaxed),
            control_limited: self.control_limited.load(Ordering::Relaxed),
            nat_seq_rejected: self.nat_seq_rejected.load(Ordering::Relaxed),
            service_limited: self.service_limited.load(Ordering::Relaxed),
            svc_budget_full: self.svc_budget_full.load(Ordering::Relaxed),
            challenge_sent: self.challenge_sent.load(Ordering::Relaxed),
            challenge_rejected: self.challenge_rejected.load(Ordering::Relaxed),
            challenge_worker_err: self.challenge_worker_err.load(Ordering::Relaxed),
            out_ct_hit: self.out_ct_hit.load(Ordering::Relaxed),
            out_ct_icmp: self.out_ct_icmp.load(Ordering::Relaxed),
            upstream_mode: match self.config.upstream_mode() {
                XdpUpstreamMode::Kernel => "kernel".to_string(),
                XdpUpstreamMode::Afxdp => "afxdp".to_string(),
            },
            #[cfg(target_os = "linux")]
            dial_port_range: {
                let (start, end) = self.config.dial_port_range();
                format!("{start}-{end}")
            },
            #[cfg(not(target_os = "linux"))]
            dial_port_range: String::new(),
            #[cfg(target_os = "linux")]
            dial_guard_installed: self.dial_guard.lock().is_some(),
            #[cfg(not(target_os = "linux"))]
            dial_guard_installed: false,
            #[cfg(target_os = "linux")]
            dial_guard_hits: self.dial_guard_hits.load(Ordering::Relaxed),
            #[cfg(not(target_os = "linux"))]
            dial_guard_hits: 0,
            #[cfg(target_os = "linux")]
            dial_guard_detail: self.dial_guard_detail.lock().clone(),
            #[cfg(not(target_os = "linux"))]
            dial_guard_detail: String::new(),
            flow_event_lost: self.flow_event_lost.load(Ordering::Relaxed),
            flow_events_received: self.flow_events_received.load(Ordering::Relaxed),
            flow_events_stale: self.flow_events_stale.load(Ordering::Relaxed),
            flow_events_evicted: self.flow_events_evicted.load(Ordering::Relaxed),
            imported_flows: self.imported_flows.load(Ordering::Relaxed),
            owner_epoch: self.owner_epoch.load(Ordering::Relaxed),
            #[cfg(target_os = "linux")]
            dataplane_adopted: self.dataplane_adopted.load(Ordering::Relaxed),
            #[cfg(not(target_os = "linux"))]
            dataplane_adopted: false,
            #[cfg(target_os = "linux")]
            dataplane_lease_adoptions: self
                .af_xdp
                .lock()
                .as_ref()
                .and_then(|runtime| runtime.lease.as_ref().map(|lease| lease.adoptions()))
                .unwrap_or(0),
            #[cfg(not(target_os = "linux"))]
            dataplane_lease_adoptions: 0,
            rate_limit_active: self.rate_limit_active.load(Ordering::Relaxed) != 0,
            rate_limit_detail: self.rate_limit_detail.lock().clone(),
            updated_at: crate::utils::time::now_timestamp(),
        }
    }

    fn persist_status(&self) {
        let now = crate::utils::time::now_timestamp() as u64;
        if !self.claim_status_write_slot(now, false) {
            return;
        }
        self.write_status_snapshot();
    }

    #[cfg(target_os = "linux")]
    fn persist_status_now(&self) {
        let now = crate::utils::time::now_timestamp() as u64;
        self.claim_status_write_slot(now, true);
        self.write_status_snapshot();
    }

    fn claim_status_write_slot(&self, now: u64, force: bool) -> bool {
        let last = self.last_state_write_at.load(Ordering::Relaxed);
        if !force && now.saturating_sub(last) < XDP_STATE_WRITE_INTERVAL_SECS {
            return false;
        }
        if force {
            self.last_state_write_at.store(now, Ordering::Relaxed);
            return true;
        }
        if self
            .last_state_write_at
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        true
    }

    fn write_status_snapshot(&self) {
        let paths = crate::paths::NodePaths::current();
        let path = paths.xdp_state_file();
        let status = self.status();
        let seq = XDP_STATUS_WRITE_SEQ.fetch_add(1, Ordering::Relaxed) + 1;
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    if seq != XDP_STATUS_WRITE_SEQ.load(Ordering::Relaxed) {
                        return;
                    }
                    let _guard = XDP_STATUS_WRITE_LOCK.lock();
                    if seq != XDP_STATUS_WRITE_SEQ.load(Ordering::Relaxed) {
                        return;
                    }
                    if let Some(parent) = path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    match serde_json::to_vec_pretty(&status) {
                        Ok(body) => {
                            let _ = std::fs::write(&path, body);
                        }
                        Err(err) => tracing::warn!("failed to encode XDP status: {}", err),
                    }
                });
            }
            Err(_) => {
                let _guard = XDP_STATUS_WRITE_LOCK.lock();
                if seq != XDP_STATUS_WRITE_SEQ.load(Ordering::Relaxed) {
                    return;
                }
                if let Err(err) = write_status_snapshot_blocking(&path, &status) {
                    tracing::warn!("failed to write XDP status: {}", err);
                }
            }
        }
    }

    fn persist_status_blocking(&self) {
        self.last_state_write_at.store(
            crate::utils::time::now_timestamp() as u64,
            Ordering::Relaxed,
        );
        let path = crate::paths::NodePaths::current().xdp_state_file();
        let status = self.status();
        let seq = XDP_STATUS_WRITE_SEQ.fetch_add(1, Ordering::Relaxed) + 1;
        let _guard = XDP_STATUS_WRITE_LOCK.lock();
        if seq != XDP_STATUS_WRITE_SEQ.load(Ordering::Relaxed) {
            return;
        }
        if let Err(err) = write_status_snapshot_blocking(&path, &status) {
            tracing::warn!("failed to write XDP status: {}", err);
        }
    }

    #[cfg(target_os = "linux")]
    fn update_xsk_queue_status(
        &self,
        interface: &str,
        queue: u32,
        update: impl FnOnce(&mut XdpQueueStatus),
    ) {
        let mut statuses = self.xsk_status.write();
        if let Some(status) = statuses
            .iter_mut()
            .find(|status| status.interface == interface && status.queue == queue)
        {
            update(status);
        }
    }

    #[cfg(target_os = "linux")]
    fn refresh_af_xdp_statuses(&self, force: bool) {
        let mut statuses = {
            let mut runtime = self.af_xdp.lock();
            let Some(runtime) = runtime.as_mut() else {
                return;
            };
            runtime.refresh_statuses(force);
            runtime.statuses.clone()
        };
        // The runtime image only knows socket registration state; preserve
        // queue-scoped fault/withdrawal and congestion marks applied since.
        let previous = self.xsk_status.read().clone();
        for status in statuses.iter_mut() {
            if let Some(prev) = previous
                .iter()
                .find(|prev| prev.interface == status.interface && prev.queue == status.queue)
            {
                status.congested_drops = prev.congested_drops;
                status.aqm_drops = prev.aqm_drops;
                status.aqm_ce_marks = prev.aqm_ce_marks;
                status.admission_refusals = prev.admission_refusals;
                status.stale_dwells = prev.stale_dwells;
                status.steered_frames = prev.steered_frames;
                status.steer_sheds = prev.steer_sheds;
                if prev.faulted {
                    status.faulted = true;
                    status.registered = false;
                    status.ready = false;
                    status.detail = prev.detail.clone();
                }
            }
        }
        *self.xsk_status.write() = statuses;
    }

    fn update_block_ip(&self, ip: IpAddr, ttl_secs: i64) {
        let expiry = crate::utils::time::now_timestamp() + ttl_secs.max(1);
        self.state.write().blocked_ips.insert(ip, expiry);
        self.request_map_sync();
        self.persist_status();
    }

    fn remove_block_ip(&self, ip: IpAddr) {
        self.state.write().blocked_ips.remove(&ip);
        self.request_map_sync();
        self.persist_status();
    }

    fn update_block_network(&self, net: IpNet, ttl_secs: i64) {
        let expiry = crate::utils::time::now_timestamp() + ttl_secs.max(1);
        self.state
            .write()
            .blocked_networks
            .insert(net.to_string(), (net, expiry));
        self.request_map_sync();
        self.persist_status();
    }

    fn remove_block_network(&self, net: IpNet) {
        self.state.write().blocked_networks.remove(&net.to_string());
        self.request_map_sync();
        self.persist_status();
    }

    fn update_block_range(&self, from: u128, to: u128, v6: bool, ttl_secs: i64) {
        if from > to {
            return;
        }
        let expiry = crate::utils::time::now_timestamp() + ttl_secs.max(1);
        self.state
            .write()
            .blocked_ranges
            .insert(RangeKey { from, to, v6 }, expiry);
        self.request_map_sync();
        self.persist_status();
    }

    fn remove_block_range(&self, from: u128, to: u128, v6: bool) {
        self.state
            .write()
            .blocked_ranges
            .remove(&RangeKey { from, to, v6 });
        self.request_map_sync();
        self.persist_status();
    }

    fn update_allowed_ip(&self, ip: IpAddr, ttl_secs: i64) {
        let expiry = crate::utils::time::now_timestamp() + ttl_secs.max(1);
        self.state.write().allowed_ips.insert(ip, expiry);
        self.request_map_sync();
        self.persist_status();
    }

    fn remove_allowed_ip(&self, ip: IpAddr) {
        self.state.write().allowed_ips.remove(&ip);
        self.request_map_sync();
        self.persist_status();
    }

    fn update_allowed_network(&self, net: IpNet, ttl_secs: i64) {
        let expiry = crate::utils::time::now_timestamp() + ttl_secs.max(1);
        self.state
            .write()
            .allowed_networks
            .insert(net.to_string(), (net, expiry));
        self.request_map_sync();
        self.persist_status();
    }

    fn remove_allowed_network(&self, net: IpNet) {
        self.state.write().allowed_networks.remove(&net.to_string());
        self.request_map_sync();
        self.persist_status();
    }

    fn update_allowed_range(&self, from: u128, to: u128, v6: bool, ttl_secs: i64) {
        if from > to {
            return;
        }
        let expiry = crate::utils::time::now_timestamp() + ttl_secs.max(1);
        self.state
            .write()
            .allowed_ranges
            .insert(RangeKey { from, to, v6 }, expiry);
        self.request_map_sync();
        self.persist_status();
    }

    fn remove_allowed_range(&self, from: u128, to: u128, v6: bool) {
        self.state
            .write()
            .allowed_ranges
            .remove(&RangeKey { from, to, v6 });
        self.request_map_sync();
        self.persist_status();
    }

    fn sync_snapshot(&self, snapshot: &KernelFilterSnapshot) {
        let mut state = self.state.write();
        state.sync_from_snapshot(snapshot);
        state.retain_active(crate::utils::time::now_timestamp());
        drop(state);
        self.request_map_sync();
        self.persist_status();
    }

    fn sweep_expired_rules(&self) -> bool {
        let changed = self
            .state
            .write()
            .retain_active(crate::utils::time::now_timestamp());
        if changed {
            self.request_map_sync();
            self.persist_status();
        }
        changed
    }

    #[cfg(test)]
    fn rule_verdict_for_ip(&self, ip: IpAddr) -> XdpRuleVerdict {
        self.state
            .read()
            .ip_verdict(ip, crate::utils::time::now_timestamp())
    }

    /// Signal the background worker that the shadow rule state changed. Multiple
    /// signals during a burst coalesce into one debounced incremental map write,
    /// so a flood that blocks thousands of distinct IPs no longer triggers a full
    /// map rebuild per block. The userspace `is_l4_blocked` check still applies
    /// immediately; XDP enforcement follows within the debounce window.
    fn request_map_sync(&self) {
        self.map_sync_notify.notify_one();
    }

    /// Synchronous full reconciliation of every map (interface policy, local IPs,
    /// proxy ports, XSK indices and all rule maps). Used on cold start / reload /
    /// proxy-redirect enable where we want the maps populated before returning.
    #[cfg(target_os = "linux")]
    fn flush_maps_full_blocking(&self, proxy_dataplane_active: bool) {
        if self.attached.read().is_empty() {
            return;
        }
        let state = self.state.read().clone();
        let withdrawn = self.xsk_withdrawn.lock().clone();
        let result = {
            let mut ebpf = self.ebpf.lock();
            match ebpf.as_mut() {
                Some(ebpf) => linux::sync_maps(
                    ebpf,
                    &self.config,
                    &state,
                    proxy_dataplane_active,
                    &withdrawn,
                ),
                None => Ok(()),
            }
        };
        match result {
            Ok(()) => *self.synced.lock() = state,
            Err(err) => {
                let reason = format!("map sync failed: {err}");
                self.detach_after_runtime_failure(reason);
                tracing::warn!("XDP map sync failed; detached and falling back: {}", err);
            }
        }
    }

    /// Incremental reconciliation of just the rule maps, diffing the live shadow
    /// state against the last-applied image. Run by the background worker.
    #[cfg(target_os = "linux")]
    fn flush_maps_diff(&self) {
        if self.attached.read().is_empty() {
            return;
        }
        let new_state = self.state.read().clone();
        let old_state = self.synced.lock().clone();
        let result = {
            let mut ebpf = self.ebpf.lock();
            match ebpf.as_mut() {
                Some(ebpf) => linux::apply_rule_diff(ebpf, &old_state, &new_state),
                None => Ok(()),
            }
        };
        match result {
            Ok(()) => *self.synced.lock() = new_state,
            Err(err) => {
                let reason = format!("map diff sync failed: {err}");
                self.detach_after_runtime_failure(reason);
                tracing::warn!(
                    "XDP map diff sync failed; detached and falling back: {}",
                    err
                );
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn flush_maps_diff(&self) {}

    /// Effective per-IP rate limit for the current pressure level: base
    /// settings apply at Elevated, halve at High, quarter at Critical, and the
    /// limiter is fully disabled at Normal (zero pps = off in eBPF).
    fn effective_rate_limit_config(&self) -> cloud_node_xdp_common::XdpRateLimitConfig {
        let config = cloud_node_xdp_common::XdpRateLimitConfig::default();
        let Some(base) = &self.config.rate_limit else {
            return config;
        };
        let divisor: u64 = match xdp_rate_limit_pressure_level() {
            crate::l4_defense::L4PressureLevel::Normal => return config,
            crate::l4_defense::L4PressureLevel::Elevated => 1,
            crate::l4_defense::L4PressureLevel::High => 2,
            crate::l4_defense::L4PressureLevel::Critical => 4,
        };
        scaled_rate_limit_config(base, divisor)
    }

    /// Effective aggregate budget (EN-07). Node-wide totals from
    /// `xdp.budget` (or the built-in baseline) are divided by the
    /// possible-CPU count into per-CPU shares — the sum of shares never
    /// exceeds the configured total, so CPU/queue changes cannot multiply
    /// the quota (I09). Pressure scaling narrows the elastic allowance
    /// (Elevated x1, High /2, Critical /4) but clamps each share at >=1:
    /// "divide to zero" never disables a dimension. `enabled: false` in
    /// config is the only off switch and writes flag=0 explicitly.
    fn effective_budget_config(&self) -> cloud_node_xdp_common::XdpBudgetConfig {
        use crate::l4_defense::L4PressureLevel;
        let base = self.config.budget.clone().unwrap_or_default();
        if !base.enabled {
            return cloud_node_xdp_common::XdpBudgetConfig::default();
        }
        let divisor: u64 = match crate::l4_defense::current_pressure_level() {
            L4PressureLevel::Normal | L4PressureLevel::Elevated => 1,
            L4PressureLevel::High => 2,
            L4PressureLevel::Critical => 4,
        };
        #[cfg(target_os = "linux")]
        let ncpu = aya::util::nr_cpus().map(|n| n as u64).unwrap_or(1).max(1);
        #[cfg(not(target_os = "linux"))]
        let ncpu: u64 = num_cpus::get() as u64;
        let share = |total: u64| -> u64 {
            // ceil(total / (ncpu * divisor)), floored at 1 so a share can
            // never collapse to "disabled" through integer division.
            let denom = ncpu.saturating_mul(divisor).max(1);
            let per = total.saturating_add(denom - 1) / denom;
            per.max(1)
        };
        // Per-service ceiling defaults to the aggregate new-flow cap: a
        // single service may fill the envelope (status quo), while
        // multi-service nodes get a fairness floor operators can tighten.
        let service_flow_pps = base.service_flow_pps.unwrap_or(base.new_flow_per_sec);
        cloud_node_xdp_common::XdpBudgetConfig {
            unverified_pps: share(base.unverified_pps),
            new_flow_per_sec: share(base.new_flow_per_sec),
            xsk_redirect_pps: share(base.xsk_redirect_pps),
            // dim3 challenge responses: bounded like the new-flow
            // envelope (default) — forged-packet egress stays capped
            // under SYN flood; override via budget.challengePps.
            challenge_pps: share(base.challenge_pps.unwrap_or(base.new_flow_per_sec)),
            verified_pps: share(base.verified_pps),
            control_pps: share(base.control_pps),
            service_flow_pps: share(service_flow_pps),
            window_ns: base.window_ms.saturating_mul(1_000_000),
            // dim0 unverified | dim1 new-flow | dim2 xsk-redirect |
            // dim3 challenge | dim4 verified | dim5 control |
            // dim6 per-service — all fail-closed counted.
            flags: 0b111_1111,
        }
    }

    /// EN-14: install the cookie key ring if the pinned map has none.
    #[cfg(target_os = "linux")]
    fn sync_cookie_key(&self) {
        let result = {
            let mut ebpf = self.ebpf.lock();
            match ebpf.as_mut() {
                Some(ebpf) => linux::sync_cookie_key(ebpf),
                None => return,
            }
        };
        if let Err(err) = result {
            tracing::warn!("XDP cookie key install unavailable: {err}");
        }
    }

    /// Push the effective budget into the eBPF config map; failures are
    /// logged and surfaced through the status detail, never silent.
    fn sync_budget_config(&self) {
        #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
        let config = self.effective_budget_config();
        #[cfg(target_os = "linux")]
        let result = {
            let mut ebpf = self.ebpf.lock();
            match ebpf.as_mut() {
                Some(ebpf) => linux::sync_budget(ebpf, &config),
                None => return,
            }
        };
        #[cfg(not(target_os = "linux"))]
        let result: anyhow::Result<()> = Ok(());
        if let Err(err) = result {
            tracing::warn!("XDP budget map sync unavailable: {err}");
        }
    }

    /// Push the EN-09 absolute pending deadline into XDP_PENDING_CAP.
    #[cfg(target_os = "linux")]
    fn sync_pending_cap(&self) {
        let ttl_ns = self
            .config
            .admission
            .as_ref()
            .map(|a| a.tcp_pending_ms)
            .unwrap_or_else(crate::runtime_mode::default_tcp_pending_ms)
            .saturating_mul(1_000_000);
        let flags = self
            .config
            .admission
            .as_ref()
            .map(|a| a.debug_fail_flags)
            .unwrap_or(0);
        // EN-16: the admission cap tracks the configured pending-table size
        // so the eBPF bound and the pinned map never disagree.
        let max_pending = self
            .config
            .state_tables
            .as_ref()
            .and_then(|t| t.pending_max_entries)
            .unwrap_or(65_536);
        let result = {
            let mut ebpf = self.ebpf.lock();
            match ebpf.as_mut() {
                Some(ebpf) => linux::sync_pending_cap(ebpf, ttl_ns, flags, max_pending),
                None => return,
            }
        };
        if let Err(err) = result {
            tracing::warn!("XDP pending-cap map sync unavailable: {err}");
        }
    }

    /// Push the effective rate limit into the eBPF config map and record the
    /// outcome in the status snapshot. An object without XDP_RATE_CFG (built
    /// before the limiter existed) is reported, never silently ignored.
    fn sync_rate_limit_config(&self) {
        let config = self.effective_rate_limit_config();
        let active = config.window_ns != 0 && (config.udp_pps != 0 || config.tcp_syn_pps != 0);
        let detail = format!(
            "udp_pps={} tcp_syn_pps={} window_ns={}",
            config.udp_pps, config.tcp_syn_pps, config.window_ns
        );
        #[cfg(target_os = "linux")]
        let result = {
            let mut ebpf = self.ebpf.lock();
            match ebpf.as_mut() {
                Some(ebpf) => linux::sync_rate_limit(ebpf, &config),
                None => return,
            }
        };
        #[cfg(not(target_os = "linux"))]
        let result: anyhow::Result<()> = Ok(());
        match result {
            Ok(()) => {
                self.rate_limit_active
                    .store(u64::from(active), Ordering::Relaxed);
                *self.rate_limit_detail.lock() = detail;
            }
            Err(err) => {
                let detail = format!("rate limit map sync unavailable: {err}");
                if *self.rate_limit_detail.lock() != detail {
                    tracing::warn!("{detail}");
                    *self.rate_limit_detail.lock() = detail;
                }
                self.rate_limit_active.store(0, Ordering::Relaxed);
                crate::pipeline_metrics::add(
                    crate::pipeline_metrics::PipelineCounter::XdpMapSyncFailed,
                    1,
                );
            }
        }
    }

    /// GC direct-forward conntrack entries and fold per-CPU flow accounting
    /// into billing. No-op unless the dataplane is attached and forwards are
    /// configured.
    #[cfg(target_os = "linux")]
    fn sweep_nat_maps(&self) {
        let configured = self
            .config
            .interfaces
            .iter()
            .any(|iface| !iface.udp_forwards.is_empty() || !iface.tcp_forwards.is_empty());
        if !configured || self.attached.read().is_empty() {
            return;
        }
        let pending_ttl = std::time::Duration::from_millis(
            self.config
                .admission
                .as_ref()
                .map(|a| a.tcp_pending_ms)
                .unwrap_or_else(crate::runtime_mode::default_tcp_pending_ms),
        );
        let result = {
            let mut guard = self.ebpf.lock();
            let mut shadow = self.udp_flow_shadow.lock();
            match guard.as_mut() {
                Some(ebpf) => linux::sweep_nat_maps(
                    ebpf,
                    &mut shadow,
                    std::time::Duration::from_secs(180),
                    std::time::Duration::from_secs(7200),
                    std::time::Duration::from_secs(120),
                    pending_ttl,
                ),
                None => Ok(()),
            }
        };
        if let Err(err) = result {
            tracing::warn!("XDP NAT map sweep failed: {err}");
            crate::pipeline_metrics::add(
                crate::pipeline_metrics::PipelineCounter::XdpMapSyncFailed,
                1,
            );
        }
    }

    /// EN-08: reap idle per-source rate buckets (bounded per pass).
    #[cfg(target_os = "linux")]
    fn sweep_rate_buckets(&self) {
        const MAX_REAP_PER_PASS: usize = 8192;
        let base = self.config.rate_limit.clone().unwrap_or_default();
        if base.window_ms == 0 || self.attached.read().is_empty() {
            return;
        }
        let result = {
            let mut guard = self.ebpf.lock();
            match guard.as_mut() {
                Some(ebpf) => linux::sweep_rate_maps(
                    ebpf,
                    base.window_ms.saturating_mul(1_000_000),
                    base.gc_after_windows,
                    MAX_REAP_PER_PASS,
                ),
                None => Ok(()),
            }
        };
        if let Err(err) = result {
            tracing::debug!("XDP rate-map GC skipped: {err}");
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn flush_maps_full_blocking(&self, _proxy_dataplane_active: bool) {}

    /// T4: insert a node-dialed flow into XDP_OUT_CT so its replies
    /// redirect to the ingress queue's XSK. Fails when eBPF is not loaded
    /// — a dial must never proceed unregistered.
    #[cfg(target_os = "linux")]
    pub(crate) fn upsert_out_ct(
        &self,
        key: cloud_node_xdp_common::XdpOutCtKey,
    ) -> anyhow::Result<()> {
        let mut guard = self.ebpf.lock();
        match guard.as_mut() {
            Some(ebpf) => linux::upsert_out_ct(ebpf, key),
            None => anyhow::bail!("XDP eBPF program is not loaded"),
        }
    }

    /// T4: remove a node-dialed flow's XDP_OUT_CT row at close.
    #[cfg(target_os = "linux")]
    pub(crate) fn remove_out_ct(
        &self,
        key: &cloud_node_xdp_common::XdpOutCtKey,
    ) -> anyhow::Result<()> {
        let mut guard = self.ebpf.lock();
        match guard.as_mut() {
            Some(ebpf) => linux::remove_out_ct(ebpf, key),
            None => anyhow::bail!("XDP eBPF program is not loaded"),
        }
    }

    /// T4: the dial registry of the live bridge generation — `None` when
    /// no AF_XDP proxy bridge is running.
    #[cfg(target_os = "linux")]
    pub(crate) fn dial_registry(&self) -> Option<std::sync::Arc<af_xdp::AfXdpDialRegistry>> {
        self.dial_registry.lock().clone()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn set_dial_registry(&self, registry: Option<std::sync::Arc<af_xdp::AfXdpDialRegistry>>) {
        // Replacing/clearing the registry drains the previous
        // generation's XDP_OUT_CT rows so stale entries can never steer
        // replies into queues whose XSKs are gone.
        let old = std::mem::replace(&mut *self.dial_registry.lock(), registry);
        if let Some(old) = old {
            old.drain();
        }
    }

    /// T4-5: install the outbound-dial kernel guard (reserved-ports
    /// sysctl pin + nftables DROP) for the configured dial span. Failure
    /// is explicit — the bridge must not publish the dial registry
    /// without a guard report.
    #[cfg(target_os = "linux")]
    pub(crate) async fn ensure_dial_guard(
        &self,
    ) -> anyhow::Result<std::sync::Arc<dial_guard::DialGuardReport>> {
        let (start, end) = self.config.dial_port_range();
        match dial_guard::ensure_dial_port_guard(
            &crate::kernel_syn_defense::ProcSysctlStore,
            &crate::kernel_syn_defense::SystemCommandRunner,
            start,
            end,
        )
        .await
        {
            Ok(report) => {
                *self.dial_guard_detail.lock() = String::new();
                let report = std::sync::Arc::new(report);
                *self.dial_guard.lock() = Some(report.clone());
                Ok(report)
            }
            Err(err) => {
                *self.dial_guard_detail.lock() = format!("{err}");
                Err(err)
            }
        }
    }

    /// T4-5: async teardown — clears guard state and removes nft rules +
    /// sysctl pin. Preferred in async contexts.
    #[cfg(target_os = "linux")]
    pub(crate) async fn release_dial_guard(&self) {
        let report = self.dial_guard.lock().take();
        if let Some(report) = report {
            let (start, end) = report.port_range;
            if let Err(err) = dial_guard::remove_dial_port_guard(
                &crate::kernel_syn_defense::ProcSysctlStore,
                &crate::kernel_syn_defense::SystemCommandRunner,
                start,
                end,
            )
            .await
            {
                tracing::warn!("XDP dial guard removal failed (span {start}-{end}): {err}");
            }
        }
        self.dial_guard_hits.store(0, Ordering::Relaxed);
    }

    /// T4-5: synchronous teardown for call sites without an async
    /// context (manager swap, disable path). Uses std::process for nft;
    /// nftables invocations are one-shot and fast.
    #[cfg(target_os = "linux")]
    pub(crate) fn release_dial_guard_blocking(&self) {
        let report = self.dial_guard.lock().take();
        if let Some(report) = report {
            let (start, end) = report.port_range;
            if let Err(err) = dial_guard::remove_dial_port_guard_blocking(
                &crate::kernel_syn_defense::ProcSysctlStore,
                start,
                end,
            ) {
                tracing::warn!("XDP dial guard removal failed (span {start}-{end}): {err}");
            }
        }
        self.dial_guard_hits.store(0, Ordering::Relaxed);
    }

    /// T4-5: refresh the cached guard-hit counter — called on the rule
    /// sweeper tick so /status never shells out per read.
    #[cfg(target_os = "linux")]
    async fn refresh_dial_guard_hits(&self) {
        if self.dial_guard.lock().is_none() {
            return;
        }
        match dial_guard::dial_guard_hits(&crate::kernel_syn_defense::SystemCommandRunner).await {
            Ok(hits) => self.dial_guard_hits.store(hits, Ordering::Relaxed),
            Err(err) => tracing::debug!("XDP dial guard hit counter read failed: {err}"),
        }
    }

    /// EN-16: projected pinned kernel memory of the loaded eBPF object's
    /// maps (0 on non-Linux where no eBPF object is loaded).
    #[cfg(target_os = "linux")]
    fn bpf_map_projected_bytes(&self) -> u64 {
        let mut config = self.config.clone();
        if let Some(tables) = self.effective_state_tables.read().clone() {
            config.state_tables = Some(tables);
        }
        linux::projected_bpf_map_bytes(&config)
    }

    #[cfg(not(target_os = "linux"))]
    fn bpf_map_projected_bytes(&self) -> u64 {
        0
    }

    /// eBPF map bytes already pinned under bpffs at the effective spec —
    /// the share of `projectedBytes` a re-attach does not re-charge.
    #[cfg(target_os = "linux")]
    fn bpf_map_pinned_bytes(&self) -> u64 {
        let mut config = self.config.clone();
        if let Some(tables) = self.effective_state_tables.read().clone() {
            config.state_tables = Some(tables);
        }
        linux::pinned_spec_bytes(&config)
    }

    #[cfg(not(target_os = "linux"))]
    fn bpf_map_pinned_bytes(&self) -> u64 {
        0
    }

    #[cfg(target_os = "linux")]
    fn detach_after_runtime_failure(&self, reason: String) {
        if let Err(err) = linux::detach_blocking(&self.config) {
            let detail = format!("{reason}; detach failed: {err}");
            self.set_fallback_reason(detail.clone());
            tracing::warn!("failed to detach XDP after runtime failure: {}", err);
        } else {
            self.set_fallback_reason(reason);
        }
        *self.ebpf.lock() = None;
        *self.attach_permit.lock() = None;
        *self.af_xdp.lock() = None;
        self.attached.write().clear();
        self.xsk_status.write().clear();
        self.proxy_redirect_enabled.store(false, Ordering::Relaxed);
        self.set_proxy_fallback_reason("runtime failure detached XDP; socket path is active");
        self.persist_status_blocking();
    }

    fn refresh_counters(&self) {
        #[cfg(target_os = "linux")]
        {
            let counters = {
                let ebpf = self.ebpf.lock();
                ebpf.as_ref()
                    .and_then(|ebpf| linux::read_counters(ebpf).ok())
            };
            if let Some(counters) = counters {
                self.packets.store(counters.packets, Ordering::Relaxed);
                self.pass.store(counters.pass, Ordering::Relaxed);
                self.drop.store(counters.drop, Ordering::Relaxed);
                self.redirect.store(counters.redirect, Ordering::Relaxed);
                self.parse_errors
                    .store(counters.parse_errors, Ordering::Relaxed);
                self.map_miss.store(counters.map_miss, Ordering::Relaxed);
                self.xsk_drops.store(counters.xsk_drops, Ordering::Relaxed);
                self.rate_limited
                    .store(counters.rate_limited, Ordering::Relaxed);
                self.ratelimit_map_full
                    .store(counters.ratelimit_map_full, Ordering::Relaxed);
                self.udp_fwd_tx
                    .store(counters.udp_fwd_tx, Ordering::Relaxed);
                self.udp_fwd_map_full
                    .store(counters.udp_fwd_map_full, Ordering::Relaxed);
                self.tcp_fwd_tx
                    .store(counters.tcp_fwd_tx, Ordering::Relaxed);
                self.tcp_fwd_map_full
                    .store(counters.tcp_fwd_map_full, Ordering::Relaxed);
                self.snat_bound
                    .store(counters.snat_bound, Ordering::Relaxed);
                self.snat_alloc_fail
                    .store(counters.snat_alloc_fail, Ordering::Relaxed);
                self.snat_reply_tx
                    .store(counters.snat_reply_tx, Ordering::Relaxed);
                self.tx.store(counters.tx, Ordering::Relaxed);
                self.acl_blocked
                    .store(counters.acl_blocked, Ordering::Relaxed);
                self.malformed.store(counters.malformed, Ordering::Relaxed);
                self.unsupported
                    .store(counters.unsupported, Ordering::Relaxed);
                self.fragmented
                    .store(counters.fragmented, Ordering::Relaxed);
                self.control.store(counters.control, Ordering::Relaxed);
                self.acl_would_block
                    .store(counters.acl_would_block, Ordering::Relaxed);
                self.nonlocal_pass
                    .store(counters.nonlocal_pass, Ordering::Relaxed);
                self.unverified_limited
                    .store(counters.unverified_limited, Ordering::Relaxed);
                self.admission_limited
                    .store(counters.admission_limited, Ordering::Relaxed);
                self.pending_limited
                    .store(counters.pending_limited, Ordering::Relaxed);
                self.nat_conflict
                    .store(counters.nat_conflict, Ordering::Relaxed);
                self.verified_limited
                    .store(counters.verified_limited, Ordering::Relaxed);
                self.control_limited
                    .store(counters.control_limited, Ordering::Relaxed);
                self.nat_seq_rejected
                    .store(counters.nat_seq_rejected, Ordering::Relaxed);
                self.service_limited
                    .store(counters.service_limited, Ordering::Relaxed);
                self.svc_budget_full
                    .store(counters.svc_budget_full, Ordering::Relaxed);
                self.challenge_sent
                    .store(counters.challenge_sent, Ordering::Relaxed);
                self.challenge_rejected
                    .store(counters.challenge_rejected, Ordering::Relaxed);
                self.challenge_worker_err
                    .store(counters.challenge_worker_err, Ordering::Relaxed);
                self.out_ct_hit
                    .store(counters.out_ct_hit, Ordering::Relaxed);
                self.out_ct_icmp
                    .store(counters.out_ct_icmp, Ordering::Relaxed);
                self.flow_event_lost
                    .store(counters.flow_event_lost, Ordering::Relaxed);
            }
        }
    }

    fn dump_maps(&self) -> serde_json::Value {
        let queue_statuses = self.queue_statuses_for_config();
        let interfaces = self
            .config
            .interfaces
            .iter()
            .map(|interface| {
                serde_json::json!({
                    "name": interface.name,
                    "mode": interface.mode.as_str(),
                    "queues": interface.queues,
                    "frameSize": interface.frame_size,
                    "localIpFilter": !interface.local_ips.is_empty(),
                    "localIps": interface.local_ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>();
        let proxy_ports = self
            .config
            .proxy
            .ports
            .iter()
            .map(|port| {
                serde_json::json!({
                    "protocol": port.protocol.as_str(),
                    "port": port.port,
                    "proto": xdp_ip_proto(&port.protocol),
                    "dataplaneSupported": xdp_protocol_dataplane_supported(&port.protocol),
                    "portBeBytes": port.port.to_be_bytes(),
                })
            })
            .collect::<Vec<_>>();
        let state = self.state.read();
        let now = crate::utils::time::now_timestamp();
        #[cfg(target_os = "linux")]
        let counters = linux::read_pinned_counters()
            .map(|c| {
                serde_json::json!({
                    "packets": c.packets,
                    "pass": c.pass,
                    "drop": c.drop,
                    "redirect": c.redirect,
                    "parseErrors": c.parse_errors,
                    "mapMiss": c.map_miss,
                    "xskDrops": c.xsk_drops,
                    "rateLimited": c.rate_limited,
                    "ratelimitMapFull": c.ratelimit_map_full,
                    "udpFwdTx": c.udp_fwd_tx,
                    "udpFwdMapFull": c.udp_fwd_map_full,
                    "tcpFwdTx": c.tcp_fwd_tx,
                    "tcpFwdMapFull": c.tcp_fwd_map_full,
                    "snatBound": c.snat_bound,
                    "snatAllocFail": c.snat_alloc_fail,
                    "snatReplyTx": c.snat_reply_tx,
                    "tx": c.tx,
                    "aclBlocked": c.acl_blocked,
                    "malformed": c.malformed,
                    "unsupported": c.unsupported,
                    "fragmented": c.fragmented,
                    "control": c.control,
                    "aclWouldBlock": c.acl_would_block,
                    "nonlocalPass": c.nonlocal_pass,
                    "unverifiedLimited": c.unverified_limited,
                    "admissionLimited": c.admission_limited,
                    "pendingLimited": c.pending_limited,
                    "natConflict": c.nat_conflict,
                    "verifiedLimited": c.verified_limited,
                    "controlLimited": c.control_limited,
                    "natSeqRejected": c.nat_seq_rejected,
                    "serviceLimited": c.service_limited,
                    "svcBudgetFull": c.svc_budget_full,
                    "challengeSent": c.challenge_sent,
                    "challengeRejected": c.challenge_rejected,
                    "challengeWorkerErr": c.challenge_worker_err,
                    "outCtHit": c.out_ct_hit,
                    "outCtIcmp": c.out_ct_icmp,
                    "flowEventLost": c.flow_event_lost,
                })
            })
            .ok();
        #[cfg(not(target_os = "linux"))]
        let counters: Option<serde_json::Value> = None;
        serde_json::json!({
            "counters": counters,
            "interfaces": interfaces,
            "proxyPorts": proxy_ports,
            "proxyPortSummary": {
                "total": self.config.proxy.ports.len(),
                "supported": xdp_supported_proxy_port_count(&self.config),
                "unsupported": self.config.proxy.ports.len().saturating_sub(xdp_supported_proxy_port_count(&self.config)),
                "redirectEnabled": self.proxy_redirect_enabled.load(Ordering::Relaxed),
            },
            "kernelBpfBudget": {
                "projectedBytes": self.bpf_map_projected_bytes(),
                "pinnedBytes": self.bpf_map_pinned_bytes(),
                // Bytes committed to the shared account by this
                // generation's attach transaction (new pinned maps).
                "accountCommittedBytes": self.attach_committed_bytes(),
                "budgetBytes": crate::memory_governor::MEMORY_GOVERNOR
                    .snapshot(crate::memory_governor::MEMORY_GOVERNOR.pingora_worker_threads())
                    .kernel_bpf_budget_bytes,
            },
            "tcpDataplane": {
                "ready": xdp_tcp_dataplane_supported(),
                "detail": self.tcp_dataplane_detail(),
                // UMEM + ring bytes committed to the shared account.
                "umemAccountBytes": self.af_xdp_umem_committed_bytes(),
            },
            "flowFeedback": self.flow_feedback_json(),
            "xskQueues": queue_statuses,
            "blockedIps": state.blocked_ips.iter().filter(|(_, expiry)| **expiry > now).map(|(ip, expiry)| serde_json::json!({"ip": ip.to_string(), "expiresAt": expiry})).collect::<Vec<_>>(),
            "allowedIps": state.allowed_ips.iter().filter(|(_, expiry)| **expiry > now).map(|(ip, expiry)| serde_json::json!({"ip": ip.to_string(), "expiresAt": expiry})).collect::<Vec<_>>(),
            "blockedNetworks": state.blocked_networks.values().filter(|(_, expiry)| *expiry > now).map(|(net, expiry)| serde_json::json!({"network": net.to_string(), "expiresAt": expiry})).collect::<Vec<_>>(),
            "allowedNetworks": state.allowed_networks.values().filter(|(_, expiry)| *expiry > now).map(|(net, expiry)| serde_json::json!({"network": net.to_string(), "expiresAt": expiry})).collect::<Vec<_>>(),
            "blockedRanges": state.blocked_ranges.iter().filter(|(_, expiry)| **expiry > now).map(|(range, expiry)| serde_json::json!({"from": range_bound_to_ip(range.from, range.v6).to_string(), "to": range_bound_to_ip(range.to, range.v6).to_string(), "expiresAt": expiry})).collect::<Vec<_>>(),
            "allowedRanges": state.allowed_ranges.iter().filter(|(_, expiry)| **expiry > now).map(|(range, expiry)| serde_json::json!({"from": range_bound_to_ip(range.from, range.v6).to_string(), "to": range_bound_to_ip(range.to, range.v6).to_string(), "expiresAt": expiry})).collect::<Vec<_>>(),
        })
    }

    /// Committed shared-account bytes held by this generation's attach
    /// (0 when unattached or off-Linux).
    fn attach_committed_bytes(&self) -> u64 {
        #[cfg(target_os = "linux")]
        {
            self.attach_permit
                .lock()
                .as_ref()
                .map(|permit| permit.bytes())
                .unwrap_or(0)
        }
        #[cfg(not(target_os = "linux"))]
        {
            0
        }
    }

    /// Committed shared-account bytes held by the AF_XDP runtime's UMEM
    /// and rings (0 without a runtime).
    fn af_xdp_umem_committed_bytes(&self) -> u64 {
        #[cfg(target_os = "linux")]
        {
            self.af_xdp
                .lock()
                .as_ref()
                .map(|handle| handle.umem_committed_bytes())
                .unwrap_or(0)
        }
        #[cfg(not(target_os = "linux"))]
        {
            0
        }
    }

    /// EN-10 feedback/takeover state. `ownerEpoch` is read from the pinned
    /// map so a separate `xdp dump-maps` process reports the owning
    /// generation; the rest is per-manager state — when this manager never
    /// attached (CLI process), fall back to the daemon's persisted status
    /// snapshot so the numbers stay observable cross-process.
    fn flow_feedback_json(&self) -> serde_json::Value {
        let attached = !self.attached.read().is_empty();
        let persisted = if attached {
            None
        } else {
            persisted_status_snapshot()
        };
        let owner_epoch = {
            #[cfg(target_os = "linux")]
            {
                linux::read_pinned_owner_epoch()
                    .unwrap_or_else(|| self.owner_epoch.load(Ordering::Relaxed))
            }
            #[cfg(not(target_os = "linux"))]
            {
                self.owner_epoch.load(Ordering::Relaxed)
            }
        };
        let value = |local: &AtomicU64, field: fn(&XdpStatusSnapshot) -> u64| {
            if attached {
                local.load(Ordering::Relaxed)
            } else {
                persisted.as_ref().map(field).unwrap_or(0)
            }
        };
        serde_json::json!({
            "ownerEpoch": owner_epoch,
            "importedFlows": value(&self.imported_flows, |s| s.imported_flows),
            "eventsReceived": value(&self.flow_events_received, |s| s.flow_events_received),
            "eventsStale": value(&self.flow_events_stale, |s| s.flow_events_stale),
            "eventsEvicted": value(&self.flow_events_evicted, |s| s.flow_events_evicted),
        })
    }

    fn active_rule_snapshot(&self) -> KernelFilterSnapshot {
        self.state
            .read()
            .active_snapshot(crate::utils::time::now_timestamp())
    }

    /// Release this generation's in-process dataplane resources after a
    /// reload handover: the kernel links were already swapped by the new
    /// attach commit, so only the userspace handles (AF_XDP sockets, eBPF
    /// object fd) are dropped. The bridge reactor threads exit on the
    /// stale-manager check and close their queue sockets; the socket
    /// create path on the new generation retries across that window.
    /// The dial guard and registry are released here (not at publish) so
    /// a rejected or failed reload never disarms the guard mid-prepare.
    fn release_for_handover(&self) {
        self.stop_rule_sweeper();
        self.stop_map_sync_worker();
        self.stop_flow_event_consumer();
        self.proxy_redirect_enabled.store(false, Ordering::Relaxed);
        #[cfg(target_os = "linux")]
        {
            // Retiring the lease makes the workers abort live sessions
            // with wire RSTs before they drop the queue sockets — no
            // silent zombie flows.
            self.retire_dataplane_lease();
            self.dial_registry.lock().take();
            self.release_dial_guard_blocking();
            *self.af_xdp.lock() = None;
            *self.ebpf.lock() = None;
            *self.attach_permit.lock() = None;
        }
        self.attached.write().clear();
        self.xsk_status.write().clear();
    }

    /// F1: the dataplane lease this generation's AF_XDP runtime carries,
    /// while it is still live. `None` when no bridge ever spawned (sockets
    /// staged but no workers) or the lease was already retired.
    #[cfg(target_os = "linux")]
    fn live_dataplane_lease(
        &self,
    ) -> Option<std::sync::Arc<AfXdpDataplaneLease>> {
        let lease = self.af_xdp.lock().as_ref()?.lease.clone()?;
        if lease.is_retired() {
            None
        } else {
            Some(lease)
        }
    }

    /// F1: retire the lease carried by this generation's runtime — workers
    /// observing it abort their sessions (wire RST) and drop their queue
    /// sockets. No-op when the dataplane was adopted away or never ran.
    #[cfg(target_os = "linux")]
    fn retire_dataplane_lease(&self) {
        let lease = self
            .af_xdp
            .lock()
            .as_ref()
            .and_then(|runtime| runtime.lease.clone());
        if let Some(lease) = lease {
            lease.retire();
        }
    }

    /// F1: adopt the predecessor's live dataplane after an atomic attach
    /// commit. Everything the workers need moves wholesale: the runtime
    /// handle (status book), the dial registry (shared with workers —
    /// repointed to this generation), and the dial-guard report (the
    /// kernel-side nft/sysctl state was never torn down). Redirect
    /// bookkeeping is armed *before* the lease owner repoint so no worker
    /// observes a not-ready owner.
    #[cfg(target_os = "linux")]
    fn adopt_af_xdp_runtime(
        &self,
        old: &XdpManager,
        lease: &std::sync::Arc<AfXdpDataplaneLease>,
        self_arc: Option<&std::sync::Arc<XdpManager>>,
    ) {
        *self.xsk_status.write() = old.xsk_status.read().clone();
        *self.xsk_withdrawn.lock() = old.xsk_withdrawn.lock().clone();
        *self.af_xdp.lock() = old.af_xdp.lock().take();
        let registry = old.dial_registry.lock().take();
        if let (Some(registry), Some(owner)) = (&registry, self_arc) {
            registry.repoint(owner.clone());
        } else if registry.is_some() {
            tracing::error!(
                "F1 adoption: dial registry could not be repointed (no self Arc); \
                 AF_XDP upstream dials will fail explicitly"
            );
        }
        *self.dial_registry.lock() = registry;
        *self.dial_guard.lock() = old.dial_guard.lock().take();
        self.dial_guard_hits
            .store(old.dial_guard_hits.load(Ordering::Relaxed), Ordering::Relaxed);
        *self.dial_guard_detail.lock() = old.dial_guard_detail.lock().clone();
        self.proxy_redirect_enabled.store(
            old.proxy_redirect_enabled.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.dataplane_adopted.store(true, Ordering::Relaxed);
        if let Some(owner) = self_arc {
            lease.adopt(owner.clone());
        }
        tracing::info!(
            "F1: adopted live AF_XDP dataplane (lease adoptions={}); \
             existing sessions keep polling through the reload",
            lease.adoptions()
        );
        crate::logging::report_node_log(
            "info".to_string(),
            "xdp_proxy".to_string(),
            format!(
                "AF_XDP dataplane adopted across reload (adoptions={}); sessions preserved",
                lease.adoptions()
            ),
            0,
        );
    }

    /// F1: bookkeeping-only release for the adoption path — the AF_XDP
    /// runtime handle, dial registry and guard were already moved to the
    /// successor, so only sweepers, the eBPF object handle (frees the
    /// swapped-out programs) and stale status book are cleared here.
    /// Redirect flag clears after the lease owner repoint, which the
    /// caller performed first.
    #[cfg(target_os = "linux")]
    fn release_bookkeeping_for_adoption(&self) {
        self.stop_rule_sweeper();
        self.stop_map_sync_worker();
        self.stop_flow_event_consumer();
        self.proxy_redirect_enabled.store(false, Ordering::Relaxed);
        #[cfg(target_os = "linux")]
        {
            // Adoption/teardown releases this generation's map credential:
            // pinned bytes adopted by the successor are already inside
            // observed `used` — no double charge.
            *self.ebpf.lock() = None;
            *self.attach_permit.lock() = None;
        }
        self.attached.write().clear();
        self.xsk_status.write().clear();
    }

    async fn detach_runtime(&self, reason: &'static str) -> anyhow::Result<()> {
        self.stop_rule_sweeper();
        self.stop_map_sync_worker();
        self.stop_flow_event_consumer();
        self.proxy_redirect_enabled.store(false, Ordering::Relaxed);
        #[cfg(target_os = "linux")]
        {
            // F1: workers may still own the queue sockets — retire the
            // lease so they abort sessions with wire RSTs on exit.
            self.retire_dataplane_lease();
            let disable_result = {
                let mut ebpf = self.ebpf.lock();
                match ebpf.as_mut() {
                    Some(ebpf) => linux::disable_proxy_redirect(ebpf, &self.config),
                    None => Ok(()),
                }
            };
            if let Err(err) = disable_result {
                tracing::warn!(
                    "failed to clear AF_XDP redirect maps during XDP detach: {}",
                    err
                );
            }
            *self.af_xdp.lock() = None;
            linux::detach(&self.config).await?;
            *self.ebpf.lock() = None;
            *self.attach_permit.lock() = None;
        }
        self.attached.write().clear();
        self.xsk_status.write().clear();
        self.set_fallback_reason(reason);
        self.set_proxy_fallback_reason(String::new());
        self.persist_status_blocking();
        Ok(())
    }

    fn stop_map_sync_worker(&self) {
        self.map_sync_generation.fetch_add(1, Ordering::Relaxed);
        self.map_sync_started.store(false, Ordering::Relaxed);
        self.map_sync_notify.notify_one();
    }

    fn stop_rule_sweeper(&self) {
        self.rule_sweeper_generation.fetch_add(1, Ordering::Relaxed);
        self.rule_sweeper_started.store(false, Ordering::Relaxed);
    }

    /// EN-10: retire this generation's feedback consumer. The next consumer
    /// only starts after a new manager attaches and claims a newer
    /// XDP_OWNER_EPOCH, so feedback from a dead generation cannot be
    /// applied as if it were current.
    fn stop_flow_event_consumer(&self) {
        self.flow_event_consumer_generation
            .fetch_add(1, Ordering::Relaxed);
        self.flow_event_consumer_started
            .store(false, Ordering::Relaxed);
    }
}

static XDP_MANAGER: OnceLock<parking_lot::RwLock<std::sync::Arc<XdpManager>>> = OnceLock::new();

/// Pressure level used to scale the XDP per-source rate limiter. Release
/// builds always use the live aggregate pressure. Debug builds honor
/// `CLOUD_NODE_XDP_TEST_PRESSURE=normal|elevated|high|critical` so dataplane
/// e2e probes (scripts/edge/en08_rate_probe.py) can exercise the real
/// config→map→eBPF path without driving the host into memory pressure.
#[cfg(debug_assertions)]
fn xdp_rate_limit_pressure_level() -> crate::l4_defense::L4PressureLevel {
    use crate::l4_defense::L4PressureLevel;
    match std::env::var("CLOUD_NODE_XDP_TEST_PRESSURE").as_deref() {
        Ok("normal") => L4PressureLevel::Normal,
        Ok("elevated") => L4PressureLevel::Elevated,
        Ok("high") => L4PressureLevel::High,
        Ok("critical") => L4PressureLevel::Critical,
        _ => crate::l4_defense::current_pressure_level(),
    }
}

#[cfg(not(debug_assertions))]
fn xdp_rate_limit_pressure_level() -> crate::l4_defense::L4PressureLevel {
    crate::l4_defense::current_pressure_level()
}

/// Test-only EN-05 queue-withdrawal trigger (debug builds only): set
/// `CLOUD_NODE_XDP_TEST_WITHDRAW_QUEUE=iface:queue` and the bridge will run
/// the queue-local fault path once after redirect opens, so e2e probes can
/// verify slot withdrawal, status marking, and sibling-queue survival.
/// Release builds ignore the variable entirely.
#[cfg(all(debug_assertions, target_os = "linux"))]
pub(crate) fn test_withdraw_queue_request() -> Option<(String, u32)> {
    let spec = std::env::var("CLOUD_NODE_XDP_TEST_WITHDRAW_QUEUE").ok()?;
    let (interface, queue) = spec.split_once(':')?;
    Some((interface.to_string(), queue.parse().ok()?))
}

#[cfg(all(not(debug_assertions), target_os = "linux"))]
pub(crate) fn test_withdraw_queue_request() -> Option<(String, u32)> {
    None
}

/// EN-08: translate operator-facing rate settings into the eBPF ABI config.
/// Pressure scaling divides the per-source ceilings but clamps any nonzero
/// base at >=1 — "divide to zero" must never silently disable a dimension.
/// Prefix lengths are clamped to protocol width (32/128); 0 keeps the
/// default per-address granularity.
fn scaled_rate_limit_config(
    base: &crate::runtime_mode::XdpRateLimitSettings,
    divisor: u64,
) -> cloud_node_xdp_common::XdpRateLimitConfig {
    let scaled = |pps: u64| {
        if pps == 0 {
            0
        } else {
            (pps / divisor).max(1)
        }
    };
    cloud_node_xdp_common::XdpRateLimitConfig {
        udp_pps: scaled(base.udp_pps),
        tcp_syn_pps: scaled(base.tcp_syn_pps),
        window_ns: base.window_ms.saturating_mul(1_000_000),
        v4_prefix_len: base.prefix_v4_len.min(32),
        v6_prefix_len: base.prefix_v6_len.min(128),
    }
}

fn manager_from_runtime() -> std::sync::Arc<XdpManager> {
    let config = RuntimeConfig::current()
        .map(|runtime| runtime.xdp)
        .unwrap_or_default();
    let manager = XDP_MANAGER.get_or_init(|| {
        parking_lot::RwLock::new(std::sync::Arc::new(XdpManager::new(config.clone())))
    });

    {
        let current = manager.read();
        if current.config == config || (config.enabled && !current.attached.read().is_empty()) {
            return current.clone();
        }
    }

    let mut current = manager.write();
    if current.config != config && (!config.enabled || current.attached.read().is_empty()) {
        let previous = current.clone();
        *current = std::sync::Arc::new(XdpManager::new(config));
        previous.stop_rule_sweeper();
        previous.stop_map_sync_worker();
        previous.stop_flow_event_consumer();
        #[cfg(target_os = "linux")]
        {
            previous.set_dial_registry(None);
            previous.release_dial_guard_blocking();
        }
    }
    current.clone()
}

/// T4: front door for upstream connect paths that want an AF_XDP
/// outbound dial. `None` means no live AF_XDP bridge — the caller takes
/// its own explicit non-XDP path; the dial itself never falls back
/// silently.
#[cfg(target_os = "linux")]
pub(crate) fn af_xdp_dial_registry() -> Option<std::sync::Arc<af_xdp::AfXdpDialRegistry>> {
    manager_from_runtime().dial_registry()
}

/// T4-6: whether upstream dials ride the AF_XDP reactor. True whenever
/// the live runtime config has the XDP dataplane enabled — an enabled
/// dataplane is always bidirectional, there is no kernel-outbound mode
/// to select. Linux-only — every upstream surface gates its call site
/// and takes the kernel path unchanged elsewhere.
#[cfg(target_os = "linux")]
pub(crate) fn afxdp_upstream_selected() -> bool {
    RuntimeConfig::current()
        .map(|runtime| {
            runtime.xdp.upstream_mode() == crate::runtime_mode::XdpUpstreamMode::Afxdp
        })
        .unwrap_or(false)
}

/// T5: resolved transport policy for QUIC endpoints that are AF_XDP
/// scoped (demux-fed H3 server, AF_XDP H3 upstream). The controller is
/// pinned to EdgeCC like the TCP dataplane; callers keep quinn's stock
/// controller only on non-XDP-scoped endpoints (§A.4 contract).
#[cfg(target_os = "linux")]
pub(crate) fn xdp_quic_cc_factory(
) -> Option<Arc<dyn quinn::congestion::ControllerFactory + Send + Sync>> {
    let settings = RuntimeConfig::current()
        .and_then(|runtime| runtime.xdp.transport.clone())
        .unwrap_or_default()
        .production_pinned();
    Some(
        Arc::new(crate::quic_cc::XdpTransportControllerFactory::new(settings))
            as Arc<dyn quinn::congestion::ControllerFactory + Send + Sync>,
    )
}

/// T4-6: node-originated TCP connect through the AF_XDP dataplane.
/// Reached whenever the XDP dataplane is enabled (bidirectional is
/// mandatory); a missing registry is an explicit error, never a
/// silent kernel fallback.
#[cfg(target_os = "linux")]
pub(crate) async fn af_xdp_dial_tcp(
    remote: std::net::SocketAddr,
    syn_extra_options: Vec<u8>,
) -> std::io::Result<af_xdp::AfXdpTcpStream> {
    let registry = af_xdp_dial_registry().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "XDP enabled but no live AF_XDP dial registry \
             (bridge not started or dial guard install failed — see xdp status dialGuardDetail)",
        )
    })?;
    registry.dial_tcp(remote, syn_extra_options).await
}

/// T4-6: node-originated UDP "connect" through the AF_XDP dataplane —
/// same fail-closed registry contract as `af_xdp_dial_tcp`.
#[cfg(target_os = "linux")]
pub(crate) async fn af_xdp_dial_udp(
    remote: std::net::SocketAddr,
    preferred_port: Option<u16>,
) -> std::io::Result<af_xdp::AfXdpUdpSocket> {
    let registry = af_xdp_dial_registry().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "XDP enabled but no live AF_XDP dial registry \
             (bridge not started or dial guard install failed — see xdp status dialGuardDetail)",
        )
    })?;
    registry.dial_udp(remote, preferred_port).await
}

fn replace_manager_from_runtime() -> std::sync::Arc<XdpManager> {
    let config = RuntimeConfig::current()
        .map(|runtime| runtime.xdp)
        .unwrap_or_default();
    let manager = XDP_MANAGER.get_or_init(|| {
        parking_lot::RwLock::new(std::sync::Arc::new(XdpManager::new(config.clone())))
    });
    let mut current = manager.write();
    let previous = current.clone();
    let next = std::sync::Arc::new(XdpManager::new(config));
    #[cfg(target_os = "linux")]
    {
        // Share — never take — the predecessor's dial registry so new
        // upstream dials keep resolving the serving generation while this
        // one prepares (publish happens before `initialize_inner`, and a
        // registry-less current manager would fail every dial with
        // NotConnected). A failed prepare drops only this clone — the
        // predecessor's registry keeps serving after rollback; a real
        // handover replaces it via `set_dial_registry` or
        // `adopt_af_xdp_runtime`.
        *next.dial_registry.lock() = previous.dial_registry.lock().clone();
    }
    *current = next;
    previous.stop_rule_sweeper();
    previous.stop_map_sync_worker();
    previous.stop_flow_event_consumer();
    // F1: do NOT release the dial guard or registry at publish — the
    // successor's prepare may still fail or be rejected by the dataplane
    // compatibility gate, in which case this generation keeps serving.
    // Guard/registry move to `release_for_handover` (real handover) or
    // `adopt_af_xdp_runtime` (adoption).
    current.clone()
}

fn manager_is_current(candidate: &std::sync::Arc<XdpManager>) -> bool {
    let Some(manager) = XDP_MANAGER.get() else {
        return false;
    };
    let current = manager.read();
    std::sync::Arc::ptr_eq(candidate, &*current)
}

pub async fn ensure_current_xdp_auto_config() -> anyhow::Result<()> {
    let Some(mut runtime) = RuntimeConfig::current() else {
        return Ok(());
    };
    if !runtime.xdp.enabled || !runtime.xdp.interfaces.is_empty() {
        return Ok(());
    }

    // Derive only the missing pieces: explicit file-level knobs (interfaces,
    // budget, admission, ebpfObject, stateTables, rateLimit, proxy
    // ports/protocols) stay authoritative inside the derive call itself.
    let derived = crate::xdp_auto_config::derive_xdp_config_from_live_node_with_options(
        &runtime,
        crate::xdp_auto_config::XdpAutoConfigOptions {
            interfaces: Vec::new(),
            mode: crate::runtime_mode::XdpRuntimeMode::Proxy,
            attach_mode: runtime.xdp.attach_mode,
            fallback: runtime.xdp.fallback,
        },
    )
    .await?;
    runtime.xdp = derived;
    RuntimeConfig::set_current(runtime);
    Ok(())
}

/// EN-10 bounded advisory mirror of dataplane lifecycle transitions. Keyed
/// by (flow key, incarnation) so a recycled tuple never merges with state
/// an older admission left behind. Entries are observability only —
/// kernel maps remain the sole authority and nothing here admits trust.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct FlowEventLedger {
    entries:
        std::collections::HashMap<(cloud_node_xdp_common::XdpFlowKey, u64), FlowEventLedgerEntry>,
    evicted: u64,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct FlowEventLedgerEntry {
    owner_epoch: u64,
    seq: u64,
    /// Event kind — read by the eviction policy (terminal records first).
    kind: u8,
}

#[cfg(target_os = "linux")]
impl FlowEventLedger {
    const CAPACITY: usize = 65_536;

    /// Apply one event. Returns true when the event was accepted; a false
    /// result means it was older than the recorded triple for the tuple.
    fn apply(&mut self, event: &cloud_node_xdp_common::XdpFlowEvent) -> bool {
        let key = (event.key, event.flow_incarnation);
        if let Some(existing) = self.entries.get(&key) {
            if (event.flow_incarnation, event.owner_epoch, event.seq)
                <= (event.flow_incarnation, existing.owner_epoch, existing.seq)
            {
                return false;
            }
        } else if self.entries.len() >= Self::CAPACITY {
            // Bounded feedback: evict a terminal-state record first (it can
            // never transition again), otherwise the oldest-order entry.
            let victim = self
                .entries
                .iter()
                .filter(|(_, e)| {
                    e.kind == cloud_node_xdp_common::XDP_FLOW_EVENT_CLOSED
                        || e.kind == cloud_node_xdp_common::XDP_FLOW_EVENT_REJECTED
                })
                .map(|(k, _)| *k)
                .next()
                .or_else(|| {
                    self.entries
                        .iter()
                        .min_by_key(|(k, e)| (k.1, e.owner_epoch, e.seq))
                        .map(|(k, _)| *k)
                });
            match victim {
                Some(victim) => {
                    self.entries.remove(&victim);
                    self.evicted = self.evicted.saturating_add(1);
                }
                None => return false,
            }
        }
        self.entries.insert(
            key,
            FlowEventLedgerEntry {
                owner_epoch: event.owner_epoch,
                seq: event.seq,
                kind: event.kind,
            },
        );
        true
    }
}

/// EN-10 feedback consumer: drains the pinned XDP_FLOW_EVENTS ring into the
/// manager's advisory ledger. Lifecycle: tied to the manager's consumer
/// generation — manager replacement bumps the generation so an old
/// generation's consumer can never apply events to a new manager's ledger.
/// The ring itself is opened through its pin (own fd), so the consumer
/// never holds the manager's eBPF lock.
#[cfg(target_os = "linux")]
fn start_flow_event_consumer(manager: &std::sync::Arc<XdpManager>) {
    if manager
        .flow_event_consumer_started
        .swap(true, Ordering::Relaxed)
    {
        return;
    }
    let generation = manager
        .flow_event_consumer_generation
        .load(Ordering::Relaxed);
    let manager = std::sync::Arc::clone(manager);
    tokio::spawn(async move {
        run_flow_event_consumer(manager, generation).await;
    });
}

#[cfg(not(target_os = "linux"))]
fn start_flow_event_consumer(_manager: &std::sync::Arc<XdpManager>) {}

#[cfg(target_os = "linux")]
async fn run_flow_event_consumer(manager: std::sync::Arc<XdpManager>, generation: u64) {
    use tokio::io::unix::AsyncFd;
    tracing::info!("XDP flow-event consumer started (generation {generation})");
    let mut ring: Option<AsyncFd<aya::maps::RingBuf<aya::maps::MapData>>> = None;
    // A drain that loses the 10s status-write throttle would otherwise never
    // be persisted — retry on each loop tick until the write lands.
    let mut persist_pending = false;
    loop {
        if !manager_is_current(&manager) {
            tracing::info!("XDP flow-event consumer exiting: manager no longer current");
            break;
        }
        if manager
            .flow_event_consumer_generation
            .load(Ordering::Relaxed)
            != generation
        {
            tracing::info!("XDP flow-event consumer exiting: generation superseded");
            break;
        }
        if ring.is_none() {
            if manager.attached.read().is_empty() {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
            match linux::open_pinned_flow_events() {
                Ok(Some(rb)) => match AsyncFd::new(rb) {
                    Ok(fd) => {
                        tracing::info!("XDP flow-event consumer: ring open");
                        ring = Some(fd);
                    }
                    Err(err) => {
                        tracing::warn!("XDP flow-event consumer: AsyncFd failed: {err}");
                        return;
                    }
                },
                Ok(None) => {
                    // Attached object predates EN-10 or pinning failed:
                    // feedback channel is explicitly unavailable — record
                    // it rather than pretending the channel is live.
                    manager
                        .tcp_dataplane_detail
                        .write()
                        .push_str("; flow feedback channel unavailable");
                    return;
                }
                Err(err) => {
                    tracing::warn!("XDP flow-event consumer: open pinned ring failed: {err}");
                    return;
                }
            }
        }
        if persist_pending {
            // Retry the throttled status write on the next tick — the loop
            // wakes at least once per second via the poll timeout.
            let now = crate::utils::time::now_timestamp() as u64;
            if manager.claim_status_write_slot(now, false) {
                manager.write_status_snapshot();
                persist_pending = false;
            }
        }
        let Some(poll) = ring.as_mut() else {
            continue;
        };
        let mut guard = match tokio::time::timeout(
            std::time::Duration::from_secs(1),
            poll.readable_mut(),
        )
        .await
        {
            Ok(Ok(guard)) => guard,
            Ok(Err(err)) => {
                tracing::warn!("XDP flow-event consumer: poll failed: {err}");
                return;
            }
            Err(_) => continue,
        };
        let rb = guard.get_inner_mut();
        let mut drained = false;
        let mut batch = 0u64;
        while let Some(item) = rb.next() {
            let bytes: &[u8] = &item;
            if bytes.len() != core::mem::size_of::<cloud_node_xdp_common::XdpFlowEvent>() {
                manager.flow_events_stale.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            // SAFETY: ring-buffer records are 8-byte aligned and XdpFlowEvent
            // is a repr(C) Pod struct; read_unaligned tolerates either way.
            let event = unsafe {
                core::ptr::read_unaligned(
                    bytes.as_ptr() as *const cloud_node_xdp_common::XdpFlowEvent
                )
            };
            let mut ledger = manager.flow_event_ledger.lock();
            if ledger.apply(&event) {
                manager.flow_events_received.fetch_add(1, Ordering::Relaxed);
            } else {
                manager.flow_events_stale.fetch_add(1, Ordering::Relaxed);
            }
            let evicted = ledger.evicted;
            drop(ledger);
            manager
                .flow_events_evicted
                .store(evicted, Ordering::Relaxed);
            drained = true;
            batch += 1;
        }
        if batch > 0 {
            tracing::debug!("XDP flow-event consumer drained {batch} events");
        }
        guard.clear_ready();
        if drained {
            // Counters live in this process; make them visible in the
            // persisted status file. The write is throttled
            // (XDP_STATE_WRITE_INTERVAL_SECS) and retried on the next tick,
            // so this stays bounded I/O that always lands.
            persist_pending = true;
        }
    }
}

fn start_rule_sweeper(manager: &std::sync::Arc<XdpManager>) {
    if !manager.config.enabled {
        return;
    }
    if manager.rule_sweeper_started.swap(true, Ordering::Relaxed) {
        return;
    }
    let generation = manager.rule_sweeper_generation.load(Ordering::Relaxed);
    let manager = manager.clone();
    tokio::spawn(async move {
        let mut tick =
            tokio::time::interval(std::time::Duration::from_secs(XDP_RULE_SWEEP_INTERVAL_SECS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if manager.rule_sweeper_generation.load(Ordering::Relaxed) != generation {
                break;
            }
            if manager.sweep_expired_rules() {
                tracing::debug!("XDP rule sweeper removed expired shadow rules");
            }
            manager.sync_rate_limit_config();
            manager.sync_budget_config();
            #[cfg(target_os = "linux")]
            {
                manager.sweep_nat_maps();
                manager.sweep_rate_buckets();
                manager.refresh_dial_guard_hits().await;
            }
        }
    });
}

fn start_map_sync_worker(manager: &std::sync::Arc<XdpManager>) {
    if !manager.config.enabled {
        return;
    }
    if manager.map_sync_started.swap(true, Ordering::Relaxed) {
        return;
    }
    let generation = manager.map_sync_generation.load(Ordering::Relaxed);
    let manager = manager.clone();
    tokio::spawn(async move {
        loop {
            manager.map_sync_notify.notified().await;
            if manager.map_sync_generation.load(Ordering::Relaxed) != generation {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(XDP_MAP_SYNC_DEBOUNCE_MS)).await;
            if manager.map_sync_generation.load(Ordering::Relaxed) != generation
                || !manager_is_current(&manager)
            {
                break;
            }
            manager.flush_maps_diff();
        }
    });
}

pub async fn initialize_from_runtime() -> anyhow::Result<()> {
    ensure_current_xdp_auto_config().await?;
    let manager = manager_from_runtime();
    manager.initialize().await?;
    start_rule_sweeper(&manager);
    start_map_sync_worker(&manager);
    start_flow_event_consumer(&manager);
    Ok(())
}

pub async fn build_kernel_filter() -> Option<Box<dyn KernelFilter>> {
    if let Err(err) = ensure_current_xdp_auto_config().await {
        tracing::warn!("XDP kernel filter auto configuration failed: {}", err);
        return None;
    }
    let manager = manager_from_runtime();
    if !manager.config.enabled {
        manager.ensure_detached_when_disabled().await;
        return None;
    }
    if let Err(err) = manager.initialize().await {
        tracing::warn!("XDP kernel filter unavailable: {}", err);
        return None;
    }
    let status = manager.status();
    if !status.available {
        tracing::warn!(
            "XDP kernel filter unavailable; fallback_reason={}",
            status.fallback_reason
        );
        return None;
    }
    start_rule_sweeper(&manager);
    start_flow_event_consumer(&manager);
    Some(Box::new(XdpKernelFilter { manager }))
}

pub fn status_snapshot() -> XdpStatusSnapshot {
    let manager = manager_from_runtime();
    if !manager.config.enabled {
        manager.persist_status_blocking();
    }
    manager.status()
}

pub fn persisted_status_snapshot() -> Option<XdpStatusSnapshot> {
    let path = crate::paths::NodePaths::current().xdp_state_file();
    let body = std::fs::read(path).ok()?;
    serde_json::from_slice(&body).ok()
}

pub async fn attach_from_runtime() -> anyhow::Result<()> {
    ensure_current_xdp_auto_config().await?;
    let manager = manager_from_runtime();
    manager.initialize().await?;
    start_rule_sweeper(&manager);
    start_flow_event_consumer(&manager);
    manager.persist_status_blocking();
    Ok(())
}

pub async fn detach(purge_state: bool) -> anyhow::Result<()> {
    let manager = manager_from_runtime();
    manager.detach_runtime("detached by CLI").await?;
    if purge_state {
        #[cfg(target_os = "linux")]
        {
            let removed = linux::purge_pinned_state();
            tracing::warn!("xdp detach --purge-state removed {removed} pinned eBPF maps; all conntrack/SNAT/pending/accounting/cookie state is lost");
        }
        #[cfg(not(target_os = "linux"))]
        {
            tracing::warn!("--purge-state is a no-op on non-Linux platforms (no bpffs state)");
        }
    }
    Ok(())
}

pub async fn reload_from_runtime() -> anyhow::Result<()> {
    ensure_current_xdp_auto_config().await?;
    let runtime_config = RuntimeConfig::current()
        .map(|runtime| runtime.xdp)
        .unwrap_or_default();
    let current = manager_from_runtime();
    if current.config == runtime_config && !current.attached.read().is_empty() {
        current.flush_maps_full_blocking(current.proxy_redirect_ready());
        current.persist_status_blocking();
        return Ok(());
    }

    // Owner-respecting reload (R5): keep the old generation's kernel
    // links and AF_XDP sockets live while the new generation prepares.
    // `linux::attach` only detaches at its commit point, so a prepare
    // failure (bad object, stale pins, verifier rejection) leaves the old
    // dataplane untouched.
    let snapshot = current.active_rule_snapshot();
    let old_manager = current;
    let manager = replace_manager_from_runtime();
    manager.sync_snapshot(&snapshot);
    match manager
        .initialize_inner(Some(&old_manager), Some(&manager))
        .await
    {
        Ok(()) => {
            // Publish gate: an enabled generation that never attached must
            // not replace a serving predecessor. `initialize_inner` already
            // rejects every failure path on reload, so this is the last
            // line of defense — roll back instead of reporting success.
            if runtime_config.enabled && manager.attached.read().is_empty() {
                manager.release_for_handover();
                restore_manager(old_manager.clone());
                old_manager.persist_status_blocking();
                return Err(anyhow::anyhow!(
                    "XDP reload produced an unattached generation; previous generation kept serving"
                ));
            }
            start_rule_sweeper(&manager);
            start_flow_event_consumer(&manager);
            manager.persist_status_blocking();
            Ok(())
        }
        Err(err) => {
            // Roll back to the old generation. A prepare-phase failure
            // left its links live — restore bookkeeping only and never
            // detach. A commit-phase failure under the atomic path may
            // have reverted every link swap cleanly (`dataplane_restored`)
            // — the adopted dataplane is then untouched and keeps serving.
            // Only an unrestored commit failure needs the rebuild: remove
            // the partial generation's links, drain the orphaned workers,
            // then re-attach the previous object.
            let committed = manager.attach_committed.load(Ordering::Relaxed);
            #[cfg(target_os = "linux")]
            let dataplane_restored = manager
                .attach_dataplane_restored
                .load(Ordering::Relaxed);
            #[cfg(not(target_os = "linux"))]
            let dataplane_restored = false;
            // Release the failed generation's handles first: under a clean
            // revert this only drops its eBPF object (the reverted links
            // point at the predecessor's programs); under a dirty commit
            // it also retires any lease it managed to adopt.
            manager.release_for_handover();
            restore_manager(old_manager.clone());
            if committed && !dataplane_restored {
                #[cfg(target_os = "linux")]
                if let Err(detach_err) = linux::detach(&manager.config).await {
                    tracing::warn!(
                        "XDP reload rollback detach of partial generation failed: {detach_err}"
                    );
                }
                old_manager.attached.write().clear();
                #[cfg(target_os = "linux")]
                {
                    old_manager.ebpf.lock().take();
                    old_manager.attach_permit.lock().take();
                    // F1: an unrestored commit failure already mutated the
                    // live dataplane. Retire the lease so workers abort
                    // sessions explicitly (wire RST), then wait for the
                    // queue sockets to actually close before rebinding
                    // them on the rebuilt dataplane.
                    let lease = old_manager
                        .af_xdp
                        .lock()
                        .as_ref()
                        .and_then(|runtime| runtime.lease.clone());
                    if let Some(lease) = lease {
                        lease.retire();
                        if !lease
                            .wait_workers_drained(std::time::Duration::from_secs(3))
                            .await
                        {
                            tracing::warn!(
                                "XDP reload rollback: AF_XDP workers did not drain \
                                 within 3s; socket rebind may race a still-open queue fd"
                            );
                        }
                    }
                    *old_manager.af_xdp.lock() = None;
                }
                if let Err(reattach_err) = old_manager.initialize().await {
                    tracing::warn!(
                        "XDP reload rollback re-attach failed: {reattach_err}"
                    );
                }
            }
            old_manager.persist_status_blocking();
            Err(err)
        }
    }
}

/// Swap the global manager back after a failed reload. Does not touch
/// kernel state — the caller decides whether the failed generation left
/// pinned links that need cleanup.
fn restore_manager(candidate: std::sync::Arc<XdpManager>) {
    if let Some(manager) = XDP_MANAGER.get() {
        *manager.write() = candidate;
    }
}

pub fn doctor_report() -> String {
    let runtime = RuntimeConfig::current()
        .map(|runtime| runtime.xdp.clone())
        .unwrap_or_default();
    doctor_report_for_config(&runtime)
}

fn doctor_report_for_config(config: &XdpConfig) -> String {
    let mut lines = Vec::new();
    lines.push("CloudNode XDP doctor".to_string());
    lines.push(format!("  enabled:       {}", yes_no(config.enabled)));
    lines.push(format!("  attach mode:   {}", config.attach_mode.as_str()));
    lines.push(format!("  fallback:      {}", config.fallback.as_str()));
    lines.push("  L4 engine:     active".to_string());
    lines.push(format!(
        "  kernel backend: {}",
        if config.enabled {
            "xdp (fallback: nftables/iptables/noop)"
        } else {
            "nftables/iptables/noop"
        }
    ));
    lines.push(format!(
        "  protocols:     {}",
        config
            .proxy
            .protocols
            .iter()
            .map(XdpProxyProtocol::as_str)
            .collect::<Vec<_>>()
            .join(",")
    ));
    lines.push(format!("  proxy ports:   {}", config.proxy.ports.len()));
    lines.push(format!(
        "  eBPF object:   {}",
        ebpf_object_source_label(config)
    ));
    if let Some(path) = ebpf_object_override(config) {
        lines.push(format!("  object exists: {}", yes_no(path.exists())));
    }
    lines.push(format!("  platform:      {}", std::env::consts::OS));
    #[cfg(target_os = "linux")]
    {
        lines.push(format!("  bpffs pin dir: {}", xdp_bpf_pin_dir()));
        lines.push(format!(
            "  bpffs exists:  {}",
            yes_no(std::path::Path::new(xdp_bpf_pin_dir()).is_dir())
        ));
    }
    if config.enabled && config.interfaces.is_empty() {
        lines.push("  issue:         xdp.enabled=true but interfaces is empty".to_string());
    }
    if config.enabled
        && !config.proxy.ports.is_empty()
        && config
            .interfaces
            .iter()
            .any(|interface| interface.mode == XdpRuntimeMode::Proxy)
    {
        let supported = xdp_supported_proxy_port_count(config);
        let unsupported = xdp_unsupported_proxy_protocols(config);
        if !XDP_PROXY_DATAPLANE_ACTIVE {
            lines.push(
                "  warning:       AF_XDP proxy sockets can be staged, but userspace proxy dataplane registration is not active; traffic will PASS"
                    .to_string(),
            );
        } else {
            lines.push(format!(
                "  dataplane:     AF_XDP proxy ports supported={supported} total={}",
                config.proxy.ports.len()
            ));
        }
        if !unsupported.is_empty() {
            lines.push(format!(
                "  warning:       unsupported AF_XDP proxy protocols stay on socket fallback: {}",
                unsupported.join(",")
            ));
        }
        let tcp_detail = xdp_tcp_dataplane_detail(config);
        if !tcp_detail.is_empty() {
            lines.push(format!("  warning:       {tcp_detail}"));
        }
        let frame_size_detail = xdp_proxy_frame_size_detail(config);
        if !frame_size_detail.is_empty() {
            lines.push(format!("  issue:         {frame_size_detail}"));
        }
    }
    for interface in &config.interfaces {
        lines.push(format!(
            "  interface:     {} mode={} queues={:?} frameSize={} localIps={}",
            interface.name,
            interface.mode.as_str(),
            interface.queues,
            interface.frame_size,
            interface.local_ips.len()
        ));
        if interface.mode == XdpRuntimeMode::Proxy
            && interface.frame_size != cloud_node_xdp_common::XDP_DEFAULT_FRAME_SIZE
        {
            lines.push(format!(
                "  warning:       interface {} proxy mode requires frameSize={} until jumbo/multi-buffer support is enabled",
                interface.name,
                cloud_node_xdp_common::XDP_DEFAULT_FRAME_SIZE
            ));
        }
        if interface.mode == XdpRuntimeMode::Proxy && config.proxy.ports.is_empty() {
            lines.push(format!(
                "  warning:       interface {} proxy mode has no xdp.proxy.ports entries; traffic will PASS",
                interface.name
            ));
        }
        if interface.mode == XdpRuntimeMode::Proxy
            && !config.proxy.ports.is_empty()
            && interface.local_ips.is_empty()
        {
            lines.push(format!(
                "  warning:       interface {} proxy mode has no localIps; redirect matches configured ports on all destination IPs",
                interface.name
            ));
        }
    }
    lines.extend(crate::xdp_netdev_tuning::doctor_lines_for_config(config));
    #[cfg(not(target_os = "linux"))]
    lines.push("  issue:         XDP attach is supported on Linux only".to_string());
    lines.join("\n")
}

pub fn dump_maps() -> serde_json::Value {
    manager_from_runtime().dump_maps()
}

fn range_bound_to_ip(value: u128, v6: bool) -> IpAddr {
    if v6 {
        IpAddr::V6(Ipv6Addr::from(value))
    } else {
        IpAddr::V4(Ipv4Addr::from(value as u32))
    }
}

/// Explicit external eBPF object override. Precedence follows the project's
/// config convention: file config (`xdp.ebpfObject`) wins over the
/// `CLOUD_NODE_XDP_EBPF_OBJECT_PATH` environment variable; when neither is set
/// the binary loads the object embedded at build time.
fn ebpf_object_override(config: &XdpConfig) -> Option<PathBuf> {
    if let Some(path) = config
        .ebpf_object
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        return Some(PathBuf::from(path));
    }
    std::env::var_os("CLOUD_NODE_XDP_EBPF_OBJECT_PATH")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
}

fn ebpf_object_source_label(config: &XdpConfig) -> String {
    match ebpf_object_override(config) {
        Some(path) => format!("external: {}", path.display()),
        None => "embedded".to_string(),
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn xdp_ip_proto(protocol: &XdpProxyProtocol) -> u8 {
    match protocol {
        XdpProxyProtocol::Http | XdpProxyProtocol::Https | XdpProxyProtocol::Tcp => {
            cloud_node_xdp_common::XDP_PROTO_TCP
        }
        XdpProxyProtocol::Udp | XdpProxyProtocol::H3 => cloud_node_xdp_common::XDP_PROTO_UDP,
    }
}

fn xdp_protocol_dataplane_supported(protocol: &XdpProxyProtocol) -> bool {
    matches!(
        protocol,
        XdpProxyProtocol::Http
            | XdpProxyProtocol::Https
            | XdpProxyProtocol::Tcp
            | XdpProxyProtocol::Udp
            | XdpProxyProtocol::H3
    )
}

fn xdp_tcp_dataplane_supported() -> bool {
    true
}

fn xdp_tcp_dataplane_detail(config: &XdpConfig) -> String {
    if !xdp_proxy_has_tcp_like_ports(config) {
        return String::new();
    }
    String::new()
}

fn xdp_proxy_partial_detail(config: &XdpConfig) -> String {
    if !XDP_PROXY_DATAPLANE_ACTIVE {
        return "userspace proxy dataplane is not active; traffic will PASS".to_string();
    }
    let unsupported = xdp_unsupported_proxy_protocols(config);
    if unsupported.is_empty() {
        return String::new();
    }
    format!(
        "unsupported AF_XDP proxy protocols stay on socket fallback: {}",
        unsupported.join(",")
    )
}

fn xdp_proxy_frame_size_detail(config: &XdpConfig) -> String {
    let invalid = config
        .interfaces
        .iter()
        .filter(|interface| {
            interface.mode == XdpRuntimeMode::Proxy
                && interface.frame_size != cloud_node_xdp_common::XDP_DEFAULT_FRAME_SIZE
        })
        .map(|interface| format!("{} frameSize={}", interface.name, interface.frame_size))
        .collect::<Vec<_>>();
    if invalid.is_empty() {
        String::new()
    } else {
        format!(
            "XDP proxy mode requires frameSize={} until jumbo/multi-buffer support is enabled: {}",
            cloud_node_xdp_common::XDP_DEFAULT_FRAME_SIZE,
            invalid.join(",")
        )
    }
}

fn xdp_supported_proxy_port_count(config: &XdpConfig) -> usize {
    config
        .proxy
        .ports
        .iter()
        .filter(|port| xdp_protocol_dataplane_supported(&port.protocol))
        .count()
}

fn xdp_proxy_has_tcp_like_ports(config: &XdpConfig) -> bool {
    config.proxy.ports.iter().any(|port| {
        matches!(
            port.protocol,
            XdpProxyProtocol::Http | XdpProxyProtocol::Https | XdpProxyProtocol::Tcp
        )
    })
}

fn xdp_unsupported_proxy_protocols(config: &XdpConfig) -> Vec<&'static str> {
    let mut protocols = BTreeSet::new();
    for port in &config.proxy.ports {
        if !xdp_protocol_dataplane_supported(&port.protocol) {
            protocols.insert(port.protocol.as_str());
        }
    }
    protocols.into_iter().collect()
}

#[derive(Debug)]
struct XdpKernelFilter {
    manager: std::sync::Arc<XdpManager>,
}

impl KernelFilter for XdpKernelFilter {
    fn block(&self, ip: IpAddr, ttl_secs: i64) {
        self.manager.update_block_ip(ip, ttl_secs);
    }

    fn unblock(&self, ip: IpAddr) {
        self.manager.remove_block_ip(ip);
    }

    fn block_network(&self, net: IpNet, ttl_secs: i64) {
        self.manager.update_block_network(net, ttl_secs);
    }

    fn allow(&self, ip: IpAddr, ttl_secs: i64) {
        self.manager.update_allowed_ip(ip, ttl_secs);
    }

    fn unallow(&self, ip: IpAddr) {
        self.manager.remove_allowed_ip(ip);
    }

    fn allow_network(&self, net: IpNet, ttl_secs: i64) {
        self.manager.update_allowed_network(net, ttl_secs);
    }

    fn unallow_network(&self, net: IpNet) {
        self.manager.remove_allowed_network(net);
    }

    fn allow_range(&self, from: u128, to: u128, v6: bool, ttl_secs: i64) {
        self.manager.update_allowed_range(from, to, v6, ttl_secs);
    }

    fn unallow_range(&self, from: u128, to: u128, v6: bool) {
        self.manager.remove_allowed_range(from, to, v6);
    }

    fn unblock_network(&self, net: IpNet) {
        self.manager.remove_block_network(net);
    }

    fn block_range(&self, from: u128, to: u128, v6: bool, ttl_secs: i64) {
        self.manager.update_block_range(from, to, v6, ttl_secs);
    }

    fn unblock_range(&self, from: u128, to: u128, v6: bool) {
        self.manager.remove_block_range(from, to, v6);
    }

    fn sync_snapshot(&self, snapshot: &KernelFilterSnapshot) {
        self.manager.sync_snapshot(snapshot);
    }

    fn available(&self) -> bool {
        self.manager.status().available
    }

    fn name(&self) -> &'static str {
        "xdp"
    }

    fn status(&self) -> KernelFilterStatus {
        let status = self.manager.status();
        KernelFilterStatus {
            name: "xdp",
            available: status.available,
            detail: status.fallback_reason,
        }
    }
}

pub mod af_xdp;
#[cfg(target_os = "linux")]
pub(crate) mod dial_guard;
#[cfg(target_os = "linux")]
mod linux;
mod policy;
mod smoke;
#[cfg(test)]
mod tests;

pub use policy::XdpRuleVerdict;
pub(crate) use policy::*;
pub use smoke::*;
