use crate::api_config::ApiConfig;
use crate::pb;
use crate::rpc::client::RpcClient;
use dashmap::{DashMap, DashSet};
use serde::{Deserialize, Serialize};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{LazyLock as Lazy, OnceLock as OnceCell};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{Duration, timeout};
use tracing::debug;

struct KnownAgent {
    code: &'static str,
    suffixes: &'static [&'static str],
    keywords: &'static [&'static str],
}

const KNOWN_AGENTS: &[KnownAgent] = &[
    KnownAgent {
        code: "baidu",
        suffixes: &[".baidu.com."],
        keywords: &["Baidu"],
    },
    KnownAgent {
        code: "google",
        suffixes: &[".googlebot.com.", ".google.com."],
        keywords: &["Googlebot", "Google-InspectionTool"],
    },
    KnownAgent {
        code: "bing",
        suffixes: &[".search.msn.com."],
        keywords: &["bingbot"],
    },
    KnownAgent {
        code: "sogou",
        suffixes: &[".sogou.com."],
        keywords: &["Sogou"],
    },
    KnownAgent {
        code: "youdao",
        suffixes: &[".163.com."],
        keywords: &["Youdao"],
    },
    KnownAgent {
        code: "yahoo",
        suffixes: &[".yahoo.com."],
        keywords: &["Yahoo"],
    },
    KnownAgent {
        code: "bytedance",
        suffixes: &[".bytedance.com."],
        keywords: &["Bytespider"],
    },
    KnownAgent {
        code: "sm",
        suffixes: &[".sm.cn."],
        keywords: &["YisouSpider"],
    },
    KnownAgent {
        code: "yandex",
        suffixes: &[".yandex.com.", ".yndx.net."],
        keywords: &["Yandex"],
    },
    KnownAgent {
        code: "semrush",
        suffixes: &[".semrush.com."],
        keywords: &["SEMrush"],
    },
    KnownAgent {
        code: "facebook",
        suffixes: &["facebook-waw.1-ix.net.", "facebook.b-ix.net."],
        keywords: &["facebook"],
    },
];

const MAX_INFLIGHT_IPS: usize = 8_192;
const CLIENT_AGENT_QUEUE_CAPACITY: usize = 4_096;
const CLIENT_AGENT_WORKERS: usize = 8;
const PTR_LOOKUP_CONCURRENCY: usize = 16;
const PTR_LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);
const CLIENT_AGENT_RPC_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientAgentIpRecord {
    pub id: i64,
    pub ip: String,
    pub ptr: String,
    pub agent_code: String,
}

#[derive(Debug, Clone)]
struct ClientAgentCandidate {
    ip: String,
    agent_code: &'static str,
}

static CLIENT_AGENT_IPS: Lazy<DashMap<String, ClientAgentIpRecord>> = Lazy::new(DashMap::new);
static LAST_SYNC_ID: AtomicI64 = AtomicI64::new(0);
static CLIENT_AGENT_QUEUE: OnceCell<mpsc::Sender<ClientAgentCandidate>> = OnceCell::new();
static PTR_LOOKUP_SEMAPHORE: Lazy<Arc<Semaphore>> =
    Lazy::new(|| Arc::new(Semaphore::new(PTR_LOOKUP_CONCURRENCY)));
static INFLIGHT_IPS: Lazy<DashSet<String>> = Lazy::new(DashSet::new);
static INFLIGHT_COUNT: AtomicUsize = AtomicUsize::new(0);

fn detect_agent_by_ua(user_agent: &str) -> Option<&'static KnownAgent> {
    KNOWN_AGENTS.iter().find(|agent| {
        agent
            .keywords
            .iter()
            .any(|keyword| user_agent.contains(keyword))
    })
}

fn detect_agent_by_ptr(ptr: &str) -> Option<&'static KnownAgent> {
    KNOWN_AGENTS
        .iter()
        .find(|agent| agent.suffixes.iter().any(|suffix| ptr.ends_with(suffix)))
}

pub fn is_known_agent_code(code: &str) -> bool {
    KNOWN_AGENTS.iter().any(|agent| agent.code == code)
}

pub fn load_client_agent_ip_index() {
    let records = crate::metrics::storage::STORAGE.load_client_agent_ips();
    let last_id = crate::metrics::storage::STORAGE.get_client_agent_last_id();
    CLIENT_AGENT_IPS.clear();
    for record in records {
        apply_client_agent_ip_record(record);
    }
    LAST_SYNC_ID.store(last_id, Ordering::Relaxed);
}

pub fn apply_client_agent_ip_record(record: ClientAgentIpRecord) -> bool {
    if record.ip.parse::<IpAddr>().is_err() || !is_known_agent_code(&record.agent_code) {
        return false;
    }
    CLIENT_AGENT_IPS.insert(record.ip.clone(), record);
    true
}

pub fn persist_and_apply_client_agent_ip_record(record: ClientAgentIpRecord) -> bool {
    if record.ip.parse::<IpAddr>().is_err() || !is_known_agent_code(&record.agent_code) {
        return false;
    }
    if !crate::metrics::storage::STORAGE.save_client_agent_ip(&record) {
        return false;
    }
    CLIENT_AGENT_IPS.insert(record.ip.clone(), record);
    true
}

pub fn apply_synced_client_agent_ip_records(records: &[ClientAgentIpRecord], last_id: i64) {
    for record in records {
        apply_client_agent_ip_record(record.clone());
    }
    LAST_SYNC_ID.store(last_id, Ordering::Relaxed);
}

pub fn last_sync_id() -> i64 {
    LAST_SYNC_ID.load(Ordering::Relaxed)
}

pub fn is_verified_client_agent_ip(ip: &str) -> bool {
    CLIENT_AGENT_IPS.contains_key(ip)
}

pub fn verified_agent_code_for_ip(ip: &str) -> Option<String> {
    CLIENT_AGENT_IPS
        .get(ip)
        .map(|record| record.agent_code.clone())
}

pub fn is_verified_search_engine_ip(ip: IpAddr, user_agent: &str) -> bool {
    let Some(ua_agent) = detect_agent_by_ua(user_agent) else {
        return false;
    };
    CLIENT_AGENT_IPS
        .get(&ip.to_string())
        .is_some_and(|record| record.agent_code == ua_agent.code)
}

pub fn start_client_agent_queue(api_config: Arc<ApiConfig>) {
    let (tx, mut rx) = mpsc::channel(CLIENT_AGENT_QUEUE_CAPACITY);
    if CLIENT_AGENT_QUEUE.set(tx).is_err() {
        return;
    }

    let worker_semaphore = Arc::new(Semaphore::new(CLIENT_AGENT_WORKERS));
    tokio::spawn(async move {
        while let Some(candidate) = rx.recv().await {
            let Ok(permit) = Arc::clone(&worker_semaphore).acquire_owned().await else {
                return;
            };
            let api_config = Arc::clone(&api_config);
            tokio::spawn(async move {
                let _permit = permit;
                process_client_agent_candidate(&api_config, candidate).await;
            });
        }
    });
}

async fn process_client_agent_candidate(
    api_config: &Arc<ApiConfig>,
    candidate: ClientAgentCandidate,
) {
    let ip = candidate.ip.clone();
    async {
        let Some(ptr) = lookup_ptr(&ip).await else {
            return;
        };
        let Some(ptr_agent) = detect_agent_by_ptr(&ptr) else {
            return;
        };
        if ptr_agent.code != candidate.agent_code {
            return;
        }

        let record = ClientAgentIpRecord {
            id: 0,
            ip: ip.clone(),
            ptr: ptr.clone(),
            agent_code: candidate.agent_code.to_string(),
        };
        persist_and_apply_client_agent_ip_record(record);

        let client = match timeout(CLIENT_AGENT_RPC_TIMEOUT, RpcClient::new(api_config)).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                debug!("Failed to connect for client agent reporting: {}", e);
                return;
            }
            Err(_) => {
                debug!("Timed out connecting for client agent reporting");
                return;
            }
        };
        let mut service = client.client_agent_ip_service();
        let report = service.create_client_agent_i_ps(pb::CreateClientAgentIPsRequest {
            agent_i_ps: vec![pb::create_client_agent_i_ps_request::AgentIpInfo {
                agent_code: candidate.agent_code.to_string(),
                ip: ip.clone(),
                ptr,
            }],
        });
        match timeout(CLIENT_AGENT_RPC_TIMEOUT, report).await {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => debug!("Failed to report verified client agent IP: {}", err),
            Err(_) => debug!("Timed out reporting verified client agent IP"),
        }
    }
    .await;

    INFLIGHT_IPS.remove(&ip);
    INFLIGHT_COUNT.fetch_sub(1, Ordering::Relaxed);
}

async fn lookup_ptr(ip: &str) -> Option<String> {
    let ip = ip.parse::<IpAddr>().ok()?;
    let permit = timeout(
        PTR_LOOKUP_TIMEOUT,
        PTR_LOOKUP_SEMAPHORE.clone().acquire_owned(),
    )
    .await
    .ok()?
    .ok()?;
    timeout(
        PTR_LOOKUP_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            lookup_ptr_blocking(ip)
        }),
    )
    .await
    .ok()?
    .ok()?
}

fn lookup_ptr_blocking(ip: IpAddr) -> Option<String> {
    let mut host = vec![0 as libc::c_char; libc::NI_MAXHOST as usize];
    let flags = libc::NI_NAMEREQD;
    let result = match ip {
        IpAddr::V4(ip) => lookup_ptr_v4(ip, &mut host, flags),
        IpAddr::V6(ip) => lookup_ptr_v6(ip, &mut host, flags),
    };
    if result != 0 {
        return None;
    }
    let ptr = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) }
        .to_string_lossy()
        .trim()
        .trim_end_matches('.')
        .to_string();
    if ptr.is_empty() {
        None
    } else {
        Some(format!("{}.", ptr))
    }
}

fn lookup_ptr_v4(ip: Ipv4Addr, host: &mut [libc::c_char], flags: libc::c_int) -> libc::c_int {
    let sockaddr = libc::sockaddr_in {
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    };
    unsafe {
        libc::getnameinfo(
            &sockaddr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            flags,
        )
    }
}

fn lookup_ptr_v6(ip: Ipv6Addr, host: &mut [libc::c_char], flags: libc::c_int) -> libc::c_int {
    let sockaddr = libc::sockaddr_in6 {
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        sin6_len: mem::size_of::<libc::sockaddr_in6>() as u8,
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: ip.octets(),
        },
        sin6_scope_id: 0,
    };
    unsafe {
        libc::getnameinfo(
            &sockaddr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            flags,
        )
    }
}

pub fn maybe_report_client_agent(_api_config: &Arc<ApiConfig>, ip: &str, user_agent: &str) {
    let Some(ua_agent) = detect_agent_by_ua(user_agent) else {
        return;
    };

    if CLIENT_AGENT_IPS.contains_key(ip) {
        return;
    }

    let previous = INFLIGHT_COUNT.fetch_add(1, Ordering::Relaxed);
    if previous >= MAX_INFLIGHT_IPS {
        INFLIGHT_COUNT.fetch_sub(1, Ordering::Relaxed);
        return;
    }

    if !INFLIGHT_IPS.insert(ip.to_string()) {
        INFLIGHT_COUNT.fetch_sub(1, Ordering::Relaxed);
        return;
    }

    let Some(queue) = CLIENT_AGENT_QUEUE.get() else {
        INFLIGHT_IPS.remove(ip);
        INFLIGHT_COUNT.fetch_sub(1, Ordering::Relaxed);
        return;
    };

    let candidate = ClientAgentCandidate {
        ip: ip.to_string(),
        agent_code: ua_agent.code,
    };
    if queue.try_send(candidate).is_err() {
        INFLIGHT_IPS.remove(ip);
        INFLIGHT_COUNT.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_agent_by_ua() {
        assert_eq!(detect_agent_by_ua("Googlebot").unwrap().code, "google");
        assert_eq!(detect_agent_by_ua("bingbot").unwrap().code, "bing");
        assert_eq!(detect_agent_by_ua("Baidu").unwrap().code, "baidu");
        assert!(detect_agent_by_ua("Mozilla/5.0").is_none());
    }

    #[test]
    fn detects_agent_by_ptr() {
        assert_eq!(
            detect_agent_by_ptr("crawl-1.googlebot.com.").unwrap().code,
            "google"
        );
        assert_eq!(
            detect_agent_by_ptr("msnbot-1.search.msn.com.")
                .unwrap()
                .code,
            "bing"
        );
        assert!(detect_agent_by_ptr("example.com.").is_none());
    }

    #[test]
    fn verified_search_engine_requires_ip_and_matching_ua() {
        CLIENT_AGENT_IPS.clear();
        let ip: IpAddr = "66.249.66.1".parse().unwrap();
        assert!(!is_verified_search_engine_ip(ip, "Googlebot"));

        apply_client_agent_ip_record(ClientAgentIpRecord {
            id: 1,
            ip: "66.249.66.1".to_string(),
            ptr: "crawl-1.googlebot.com.".to_string(),
            agent_code: "bing".to_string(),
        });
        assert!(!is_verified_search_engine_ip(ip, "Googlebot"));

        apply_client_agent_ip_record(ClientAgentIpRecord {
            id: 2,
            ip: "66.249.66.1".to_string(),
            ptr: "crawl-1.googlebot.com.".to_string(),
            agent_code: "google".to_string(),
        });
        assert!(is_verified_search_engine_ip(ip, "Googlebot"));
        CLIENT_AGENT_IPS.clear();
    }

    #[test]
    fn rejects_invalid_records() {
        assert!(!apply_client_agent_ip_record(ClientAgentIpRecord {
            id: 1,
            ip: "not-ip".to_string(),
            ptr: "crawl.googlebot.com.".to_string(),
            agent_code: "google".to_string(),
        }));
        assert!(!apply_client_agent_ip_record(ClientAgentIpRecord {
            id: 1,
            ip: "127.0.0.1".to_string(),
            ptr: "localhost.".to_string(),
            agent_code: "unknown".to_string(),
        }));
    }
}
