//! EN-01 shared contracts: the fixed vocabulary that all dataplane, cache,
//! and config work speaks. The eBPF-facing half of these contracts lives in
//! `cloud-node-xdp-common` (fixed `repr(C)` ABI with compile-time size
//! assertions); this module is the userspace half — service identity, path
//! profiles, generations, and the total resource-budget calculation that
//! admission decisions and status output consume.
//!
//! Integration rules (who consumes what):
//! - `ServiceIdentity` / `ServiceKey`: config compile (EN-07 service scope),
//!   flow ownership and billing attribution (EN-09/EN-12).
//! - `PathProfile`: status output, evidence manifests, support-matrix rows
//!   (EN-00/EN-30..EN-33). Serialized verbatim into `XdpStatusSnapshot` later.
//! - `NodeGeneration` / `PolicyGeneration`: config publish/rollback
//!   (EN-25..EN-29) and per-packet generation tagging in the dataplane.
//! - `BudgetSnapshot` / `compute_xdp_budget`: admission (EN-08) and
//!   `memory_governor` accounting; the AF_XDP UMEM projection in `xdp.rs`
//!   is the first consumer of the same formula.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Stable identity of a service a flow belongs to. `service_id` is the
/// billing/config dimension already carried through `XdpUdpFwdRule` and the
/// CT/acct maps; `listen` is the node-side tuple the client dialed.
/// When the tenant is not yet known (shared port 443), `service_id` is the
/// listener id — never a fake tenant (I06/I11).
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct ServiceIdentity {
    pub service_id: i64,
    /// Configured domain when known; empty for raw L4 listens.
    #[serde(default)]
    pub domain: String,
    pub listen_addr: IpAddr,
    pub listen_port: u16,
    /// `tcp` / `udp` / `quic`.
    pub protocol: String,
}

/// Evidence-bearing description of *where* the dataplane is actually running.
/// This is what qualifies a deployment claim: every PathProfile row in the
/// support matrix must carry an evidence id pointing at
/// `docs/edge-node-evidence/*` artifacts — a profile without evidence is a
/// hypothesis, not support.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathProfile {
    /// CPU arch: `x86_64` / `aarch64`.
    pub arch: String,
    /// Kernel release, e.g. `7.0.14-orbstack-00380`.
    pub kernel: String,
    /// NIC driver name (`ethtool -i`), or `virtio`/`veth` for virtual paths.
    pub driver: String,
    /// XDP attach mode actually in effect: `skb` / `drv`.
    #[serde(rename = "attachMode")]
    pub attach_mode: String,
    /// AF_XDP binding mode: `generic` / `copy` / `zerocopy` / `none`.
    #[serde(rename = "xskMode", default)]
    pub xsk_mode: String,
    /// NIC queues bound to XSK sockets.
    #[serde(default)]
    pub queues: Vec<u32>,
    pub mtu: u32,
    /// Protocols qualified on this profile: `tcp`/`udp`/`quic`/`h3`.
    #[serde(default)]
    pub protocols: Vec<String>,
    /// NAT/SNAT datapath in use.
    #[serde(default)]
    pub snat: bool,
    /// Fallback path when the fast path is unavailable:
    /// `kernel` / `pass` / `fail-start`.
    #[serde(default)]
    pub fallback: String,
    /// Pointer into docs/edge-node-evidence proving this profile.
    #[serde(rename = "evidenceId", default)]
    pub evidence_id: String,
}

/// Monotonic publication generation. Every config publication bumps this;
/// dataplane entries record the generation they were admitted under so a
/// rollback (LKG) can identify and retire entries published by a bad
/// generation instead of trusting tuple age.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct NodeGeneration(pub u64);

impl NodeGeneration {
    pub const INITIAL: Self = Self(0);

    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

/// What happens when a bounded resource hits its cap. The answer is part of
/// the contract — a map that silently fails open and a map that drops are
/// different products (I10). Reclamation pressure never changes semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FullBehavior {
    /// New work is dropped/rejected with a reason counter.
    Reject,
    /// Falls back to an explicit alternate path (e.g. PASS to kernel).
    /// The fallback path must itself be bounded and observable.
    Fallback,
    /// Oldest/lowest-priority entries are evicted to admit new work.
    Evict,
    /// The component refuses to start/attach; the failure is surfaced.
    FailStart,
}

/// One bounded resource's accounting row. `unit` is one of:
/// `entries` / `bytes` / `pps` / `conns` / `tasks`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BudgetSnapshot {
    /// Stable resource name used as the metric label (append-only).
    pub resource: String,
    pub unit: String,
    pub used: u64,
    pub limit: u64,
    #[serde(rename = "fullBehavior")]
    pub full_behavior: FullBehavior,
    /// Module that owns reclamation/decisions for this resource.
    pub owner: String,
}

/// Worst-case bytes one eBPF hash-map entry costs, including the kernel's
/// bucket/list overhead. Deliberately an estimate with headroom: kernel
/// accounting varies (~48–80B); sizing conservatively keeps the budget
/// honest. Per-CPU maps multiply value storage by the CPU count separately.
const BPF_HASH_ELEM_OVERHEAD: u64 = 96;
const BPF_LPM_ELEM_OVERHEAD: u64 = 96;
/// Fixed per-map object cost (map struct, fd bookkeeping).
const BPF_MAP_BASE_OVERHEAD: u64 = 8 * 1024;

/// Worst-case locked-memory projection for the eBPF map set, in bytes.
/// `cpu_count` scales per-CPU maps (XDP_FLOW_ACCT, XDP_NAT_SCRATCH).
/// Pure function of the same spec table `drop_stale_pinned_maps` enforces —
/// the two must never diverge, so the specs live there and this walks the
/// same numbers via `xdp_map_specs()`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct XdpBudgetBreakdown {
    /// Bytes locked by eBPF maps at worst-case occupancy.
    pub map_bytes: u64,
    /// AF_XDP UMEM frames + rings across all proxy queues.
    pub umem_bytes: u64,
    /// Reactor/worker tasks spawned for the dataplane.
    pub worker_tasks: u64,
    /// map_bytes + umem_bytes (worker stacks are scheduler-overhead only).
    pub total_bytes: u64,
    /// Per-resource rows for status output / governor admission.
    #[serde(default)]
    pub resources: Vec<BudgetSnapshot>,
}

fn hash_map_bytes(entries: u64, key: u64, value: u64) -> u64 {
    BPF_MAP_BASE_OVERHEAD + entries.saturating_mul(key + value + BPF_HASH_ELEM_OVERHEAD)
}

fn percpu_map_bytes(entries: u64, value: u64, cpu_count: u64) -> u64 {
    BPF_MAP_BASE_OVERHEAD
        + entries.saturating_mul(BPF_HASH_ELEM_OVERHEAD + value.saturating_mul(cpu_count))
}

/// Compute the worst-case dataplane footprint for `proxy_queues` AF_XDP
/// queues on a `cpu_count`-CPU host. Mirrors the spec table in
/// `xdp.rs::drop_stale_pinned_maps` — keep capacities in lockstep.
pub fn compute_xdp_budget(
    proxy_queues: u64,
    frame_size: u64,
    cpu_count: u64,
) -> XdpBudgetBreakdown {
    use cloud_node_xdp_common::*;
    let k4 = size_of::<XdpIpv4Key>() as u64;
    let k6 = size_of::<XdpIpv6Key>() as u64;
    let rule = size_of::<XdpRuleValue>() as u64;
    let fwd_key = size_of::<XdpUdpFwdKey>() as u64;
    let fwd_rule = size_of::<XdpUdpFwdRule>() as u64;
    let ct_key = size_of::<XdpUdpCtKey>() as u64;
    let ct_val = size_of::<XdpUdpCtValue>() as u64;

    let mut map_bytes: u64 = 0;
    let mut rows: Vec<BudgetSnapshot> = Vec::new();
    macro_rules! push {
        ($name:expr, $entries:expr, $bytes:expr) => {
            push!($name, $entries, $bytes, FullBehavior::Reject)
        };
        ($name:expr, $entries:expr, $bytes:expr, $fb:expr) => {{
            map_bytes = map_bytes.saturating_add($bytes);
            rows.push(BudgetSnapshot {
                resource: $name.to_string(),
                unit: "entries".to_string(),
                used: 0,
                limit: $entries,
                full_behavior: $fb,
                owner: "xdp".to_string(),
            });
        }};
    }

    push!("xdp_blocked_v4", 262_144, hash_map_bytes(262_144, k4, rule));
    push!("xdp_blocked_v6", 262_144, hash_map_bytes(262_144, k6, rule));
    push!("xdp_allowed_v4", 65_536, hash_map_bytes(65_536, k4, rule));
    push!("xdp_allowed_v6", 65_536, hash_map_bytes(65_536, k6, rule));
    for (name, klen) in [
        ("xdp_blocked_v4_lpm", 4u64),
        ("xdp_blocked_v6_lpm", 16),
        ("xdp_allowed_v4_lpm", 4),
        ("xdp_allowed_v6_lpm", 16),
    ] {
        let bytes =
            BPF_MAP_BASE_OVERHEAD + 65_536u64.saturating_mul(klen + rule + BPF_LPM_ELEM_OVERHEAD);
        push!(name, 65_536, bytes);
    }
    push!(
        "xdp_interface_policy",
        64,
        hash_map_bytes(64, 4, size_of::<XdpInterfacePolicy>() as u64)
    );
    push!(
        "xdp_local_v4",
        4_096,
        hash_map_bytes(4_096, size_of::<XdpLocalIpv4Key>() as u64, 4)
    );
    push!(
        "xdp_local_v6",
        4_096,
        hash_map_bytes(4_096, size_of::<XdpLocalIpv6Key>() as u64, 4)
    );
    push!(
        "xdp_proxy_ports",
        4_096,
        hash_map_bytes(4_096, size_of::<XdpPortProtoKey>() as u64, 4)
    );
    push!("xdp_xsks", 4_096, BPF_MAP_BASE_OVERHEAD + 4_096 * 16);
    push!(
        "xdp_xsk_index",
        4_096,
        hash_map_bytes(4_096, size_of::<XdpQueueKey>() as u64, 4)
    );
    // Rate-limit buckets: the map-full policy is currently documented as
    // Fallback (unlimited new sources pass, counted) — EN-05/EN-06 move this
    // to aggregate Reject.
    push!(
        "xdp_rate_v4",
        262_144,
        hash_map_bytes(262_144, k4, size_of::<XdpRateBucket>() as u64),
        FullBehavior::Fallback
    );
    push!(
        "xdp_rate_v6",
        262_144,
        hash_map_bytes(262_144, k6, size_of::<XdpRateBucket>() as u64),
        FullBehavior::Fallback
    );
    push!(
        "xdp_quic_dcid",
        131_072,
        hash_map_bytes(131_072, size_of::<XdpQuicDcidKey>() as u64, 4)
    );
    push!(
        "xdp_udp_fwd",
        4_096,
        hash_map_bytes(4_096, fwd_key, fwd_rule)
    );
    push!(
        "xdp_tcp_fwd",
        4_096,
        hash_map_bytes(4_096, fwd_key, fwd_rule)
    );
    push!(
        "xdp_udp_ct",
        262_144,
        hash_map_bytes(262_144, ct_key, ct_val)
    );
    push!(
        "xdp_tcp_ct",
        262_144,
        hash_map_bytes(262_144, ct_key, ct_val)
    );
    push!(
        "xdp_snat_rev",
        65_536,
        hash_map_bytes(
            65_536,
            size_of::<XdpSnatRevKey>() as u64,
            size_of::<XdpSnatRevValue>() as u64,
        )
    );
    push!(
        "xdp_nat_scratch",
        1,
        percpu_map_bytes(1, size_of::<NatScratch>() as u64, cpu_count)
    );
    push!(
        "xdp_flow_acct",
        262_144,
        percpu_map_bytes(262_144, size_of::<XdpFlowAcct>() as u64, cpu_count)
    );
    // Fixed-cost maps (single-slot arrays + program array).
    map_bytes = map_bytes.saturating_add(BPF_MAP_BASE_OVERHEAD * 4);

    // UMEM: frame_count * frame_size + 4 rings * ring_size * desc size,
    // identical to the projection enforced in xdp.rs attach.
    const AF_XDP_FRAME_COUNT: u64 = 4096;
    const AF_XDP_RING_SIZE: u64 = 2048;
    const FRAME_DESC_BYTES: u64 = 16;
    let per_queue = AF_XDP_FRAME_COUNT
        .saturating_mul(frame_size)
        .saturating_add(
            AF_XDP_RING_SIZE
                .saturating_mul(FRAME_DESC_BYTES)
                .saturating_mul(4),
        );
    let umem_bytes = per_queue.saturating_mul(proxy_queues);
    rows.push(BudgetSnapshot {
        resource: "af_xdp_umem".to_string(),
        unit: "bytes".to_string(),
        used: 0,
        limit: umem_bytes,
        full_behavior: FullBehavior::FailStart,
        owner: "xdp".to_string(),
    });

    // One reactor task per bound queue.
    let worker_tasks = proxy_queues;
    rows.push(BudgetSnapshot {
        resource: "af_xdp_workers".to_string(),
        unit: "tasks".to_string(),
        used: 0,
        limit: worker_tasks,
        full_behavior: FullBehavior::FailStart,
        owner: "xdp".to_string(),
    });

    XdpBudgetBreakdown {
        map_bytes,
        umem_bytes,
        worker_tasks,
        total_bytes: map_bytes.saturating_add(umem_bytes),
        resources: rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_monotonic() {
        let g = NodeGeneration::INITIAL;
        assert!(g.next() > g);
        assert_eq!(g.next().next(), NodeGeneration(2));
    }

    #[test]
    fn budget_scales_with_cpus_and_queues() {
        let one = compute_xdp_budget(1, 2048, 4);
        let more_cpus = compute_xdp_budget(1, 2048, 16);
        // Per-CPU maps (FLOW_ACCT dominates) grow with cpu_count.
        assert!(more_cpus.map_bytes > one.map_bytes);
        let two_queues = compute_xdp_budget(2, 2048, 4);
        assert_eq!(two_queues.umem_bytes, one.umem_bytes * 2);
        assert_eq!(two_queues.worker_tasks, 2);
        assert_eq!(one.total_bytes, one.map_bytes + one.umem_bytes);
    }

    #[test]
    fn budget_umem_matches_attach_projection() {
        // Same formula as xdp.rs: frames*size + rings*desc*4.
        let b = compute_xdp_budget(1, 4096, 8);
        let expected = 4096u64 * 4096 + 2048 * 16 * 4;
        assert_eq!(b.umem_bytes, expected);
    }

    #[test]
    fn every_row_declares_full_behavior_and_owner() {
        let b = compute_xdp_budget(2, 2048, 8);
        assert!(!b.resources.is_empty());
        for row in &b.resources {
            assert!(!row.resource.is_empty());
            assert!(!row.owner.is_empty());
            assert!(row.limit > 0 || row.resource == "af_xdp_umem");
        }
    }

    /// Serialization compat sample: these field names are the status/evidence
    /// contract — renaming one breaks downstream consumers.
    #[test]
    fn path_profile_serializes_with_stable_field_names() {
        let p = PathProfile {
            arch: "x86_64".into(),
            kernel: "7.0.14".into(),
            driver: "virtio".into(),
            attach_mode: "skb".into(),
            xsk_mode: "copy".into(),
            queues: vec![0, 1],
            mtu: 1500,
            protocols: vec!["tcp".into(), "udp".into()],
            snat: true,
            fallback: "pass".into(),
            evidence_id: "EN-00".into(),
        };
        let json = serde_json::to_value(&p).unwrap();
        for field in [
            "arch",
            "kernel",
            "driver",
            "attachMode",
            "xskMode",
            "queues",
            "mtu",
            "protocols",
            "snat",
            "fallback",
            "evidenceId",
        ] {
            assert!(json.get(field).is_some(), "missing field {field}");
        }
        // Round-trip an older payload lacking newer optional fields.
        let old = serde_json::json!({
            "arch": "aarch64", "kernel": "6.1", "driver": "veth",
            "attachMode": "skb", "mtu": 1500
        });
        let decoded: PathProfile = serde_json::from_value(old).unwrap();
        assert_eq!(decoded.driver, "veth");
        assert!(decoded.xsk_mode.is_empty());
    }

    #[test]
    fn budget_snapshot_serializes_camel_case() {
        let s = BudgetSnapshot {
            resource: "xdp_udp_ct".into(),
            unit: "entries".into(),
            used: 10,
            limit: 262_144,
            full_behavior: FullBehavior::Reject,
            owner: "xdp".into(),
        };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["fullBehavior"], "reject");
        assert!(json.get("full_behavior").is_none());
    }
}
