use crate::api_config::ApiConfig;
use crate::pb;
use crate::rpc::client::SharedRpcClient;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock as Lazy;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tracing::{info, warn};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IpReportKind {
    Black,
    White,
    Gray,
}

pub struct IpReportMessage {
    pub ip_list_id: i64,
    pub value: String,
    pub ip_from: String,
    pub ip_to: String,
    pub expired_at: i64,
    pub reason: String,
    pub r#type: String,
    pub list_kind: IpReportKind,
    pub event_level: String,
    pub node_id: i64,
    pub server_id: i64,
    pub source_node_id: i64,
    pub source_server_id: i64,
    pub source_http_firewall_policy_id: i64,
    pub source_http_firewall_rule_group_id: i64,
    pub source_http_firewall_rule_set_id: i64,
    pub source_url: String,
    pub source_user_agent: String,
    pub source_category: String,
}

#[derive(Hash, Eq, PartialEq)]
struct ReportKey {
    ip_list_id: i64,
    value: String,
    r#type: String,
    server_id: i64,
    source_category: String,
}

static REPORT_CHAN: Lazy<(
    mpsc::Sender<IpReportMessage>,
    Mutex<Option<mpsc::Receiver<IpReportMessage>>>,
)> = Lazy::new(|| {
    let (tx, rx) = mpsc::channel(1000);
    (tx, Mutex::new(Some(rx)))
});

pub async fn start_ip_report_service(api_config: ApiConfig) {
    let mut rx_opt = REPORT_CHAN.1.lock().await;
    let mut rx = match rx_opt.take() {
        Some(r) => r,
        None => return,
    };
    drop(rx_opt);

    info!("IP Report service started.");

    loop {
        let mut items = Vec::new();
        if let Some(item) = rx.recv().await {
            items.push(item);
            while items.len() < 50 {
                match rx.try_recv() {
                    Ok(i) => items.push(i),
                    Err(_) => break,
                }
            }
        }

        if items.is_empty() {
            continue;
        }

        let client = match SharedRpcClient::get(&api_config).await {
            Ok(shared) => shared.as_rpc_client(),
            Err(e) => {
                warn!(
                    "Failed to connect to API for IP reporting: {}. Waiting 10s...",
                    e
                );
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };

        let mut merged = HashMap::new();
        for item in items {
            let Some(mut item) = normalize_item(item) else {
                continue;
            };
            if item.ip_list_id <= 0 {
                match resolve_ip_list_id(&item) {
                    Some(ip_list_id) => item.ip_list_id = ip_list_id,
                    None => continue,
                }
            }
            merge_item(&mut merged, item);
        }

        if merged.is_empty() {
            continue;
        }

        let mut ip_item_service = client.ip_item_service();
        let item_count = merged.len();
        let req = pb::CreateIpItemsRequest {
            ip_items: merged
                .into_values()
                .map(|i| pb::create_ip_items_request::IpItem {
                    ip_list_id: i.ip_list_id,
                    value: i.value,
                    ip_from: i.ip_from,
                    ip_to: i.ip_to,
                    expired_at: i.expired_at,
                    reason: i.reason,
                    r#type: i.r#type,
                    event_level: i.event_level,
                    node_id: i.node_id,
                    server_id: i.server_id,
                    source_node_id: i.source_node_id,
                    source_server_id: i.source_server_id,
                    source_http_firewall_policy_id: i.source_http_firewall_policy_id,
                    source_http_firewall_rule_group_id: i.source_http_firewall_rule_group_id,
                    source_http_firewall_rule_set_id: i.source_http_firewall_rule_set_id,
                    source_url: i.source_url,
                    source_user_agent: i.source_user_agent,
                    source_category: i.source_category,
                })
                .collect(),
        };

        match ip_item_service.create_ip_items(req).await {
            Ok(_) => info!("Successfully reported {} IP list items to API", item_count),
            Err(e) => warn!("Failed to report IP items: {}", e),
        }
    }
}

pub fn report_block(item: IpReportMessage) {
    report_item(item);
}

static DROPPED_REPORTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn report_item(item: IpReportMessage) {
    let tx = &REPORT_CHAN.0;
    if let Err(err) = tx.try_send(item) {
        // Channel full / closed → keep the IP list in sync with reality is best-effort
        // but losing every block silently can mask DDoS storms. Surface a periodic warn.
        let dropped = DROPPED_REPORTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        crate::pipeline_metrics::increment(
            crate::pipeline_metrics::PipelineCounter::IpReportDropped,
        );
        if dropped.is_power_of_two() {
            warn!(
                "IP report channel saturated; dropped {} report(s) so far ({})",
                dropped, err
            );
        }
    }
}

pub fn dropped_report_count() -> u64 {
    DROPPED_REPORTS.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn list_kind(value: &str) -> Option<IpReportKind> {
    match value.trim().to_ascii_lowercase().as_str() {
        "black" | "deny" | "" => Some(IpReportKind::Black),
        "white" | "allow" => Some(IpReportKind::White),
        "gray" | "grey" => Some(IpReportKind::Gray),
        _ => None,
    }
}

fn normalize_item(mut item: IpReportMessage) -> Option<IpReportMessage> {
    if let Ok(net) = item.value.trim().parse::<IpNet>() {
        let (ip_from, ip_to) = ip_net_bounds(net);
        item.value = net.to_string();
        item.ip_from = ip_from;
        item.ip_to = ip_to;
        item.r#type = match net {
            IpNet::V4(_) => "ipv4",
            IpNet::V6(_) => "ipv6",
        }
        .to_string();
        return Some(item);
    }
    if let Ok(ip) = item.value.trim().parse::<IpAddr>() {
        let ip_type = match ip {
            IpAddr::V4(_) => "ipv4",
            IpAddr::V6(_) => "ipv6",
        };
        let ip = ip.to_string();
        item.value = ip.clone();
        item.ip_from = ip.clone();
        item.ip_to = ip;
        item.r#type = ip_type.to_string();
        return Some(item);
    }
    if !item.ip_from.trim().is_empty()
        && item.ip_from.trim() == item.ip_to.trim()
        && let Ok(ip) = item.ip_from.trim().parse::<IpAddr>()
    {
        let ip_type = match ip {
            IpAddr::V4(_) => "ipv4",
            IpAddr::V6(_) => "ipv6",
        };
        let ip = ip.to_string();
        item.value = ip.clone();
        item.ip_from = ip.clone();
        item.ip_to = ip;
        item.r#type = ip_type.to_string();
        return Some(item);
    }

    warn!(
        "Skipping IP report with unsupported target {:?}",
        item.value
    );
    None
}

fn merge_item(items: &mut HashMap<ReportKey, IpReportMessage>, item: IpReportMessage) {
    let key = ReportKey {
        ip_list_id: item.ip_list_id,
        value: item.value.clone(),
        r#type: item.r#type.clone(),
        server_id: item.server_id,
        source_category: item.source_category.clone(),
    };
    match items.get_mut(&key) {
        Some(existing) if existing.expired_at < item.expired_at => *existing = item,
        Some(_) => {}
        None => {
            items.insert(key, item);
        }
    }
}

// cloud API exposes findIPListIdWithCode/createIPList only to admin+user credentials.
// Resolve the list id locally:
//   - server-scoped lists: caller must provide ip_list_id (we drop the report
//     otherwise — only WAF rule configs know the right server-scoped list id).
//   - global lists: use the well-known firewallconfigs.Global*ListId constants.
const GLOBAL_BLACK_LIST_ID: i64 = 2_000_000_000;
const GLOBAL_WHITE_LIST_ID: i64 = 2_000_000_001;
const GLOBAL_GRAY_LIST_ID: i64 = 2_000_000_002;

fn resolve_ip_list_id(item: &IpReportMessage) -> Option<i64> {
    if item.server_id > 0 {
        return None;
    }
    Some(match item.list_kind {
        IpReportKind::Black => GLOBAL_BLACK_LIST_ID,
        IpReportKind::White => GLOBAL_WHITE_LIST_ID,
        IpReportKind::Gray => GLOBAL_GRAY_LIST_ID,
    })
}

fn ip_net_bounds(net: IpNet) -> (String, String) {
    match net {
        IpNet::V4(net) => {
            let prefix = net.prefix_len();
            let host_bits = 32 - u32::from(prefix);
            let mask = if host_bits == 32 {
                0
            } else {
                u32::MAX << host_bits
            };
            let start = u32::from(net.addr()) & mask;
            let end = start | !mask;
            (
                Ipv4Addr::from(start).to_string(),
                Ipv4Addr::from(end).to_string(),
            )
        }
        IpNet::V6(net) => {
            let prefix = net.prefix_len();
            let host_bits = 128 - u32::from(prefix);
            let mask = if host_bits == 128 {
                0
            } else {
                u128::MAX << host_bits
            };
            let start = u128::from_be_bytes(net.addr().octets()) & mask;
            let end = start | !mask;
            (
                Ipv6Addr::from(start).to_string(),
                Ipv6Addr::from(end).to_string(),
            )
        }
    }
}
