use crate::api_config::ApiConfig;
use crate::rpc::client::RpcClient;
use dashmap::DashSet;
use once_cell::sync::Lazy;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::process::Command;
use tokio::sync::Semaphore;
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

const MAX_REPORTED_IPS: usize = 100_000;
const MAX_INFLIGHT_IPS: usize = 1_024;
const PTR_LOOKUP_CONCURRENCY: usize = 16;
const PTR_LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);
const CLIENT_AGENT_RPC_TIMEOUT: Duration = Duration::from_secs(5);

static REPORTED_IPS: Lazy<DashSet<String>> = Lazy::new(DashSet::new);
static INFLIGHT_IPS: Lazy<DashSet<String>> = Lazy::new(DashSet::new);
static INFLIGHT_COUNT: AtomicUsize = AtomicUsize::new(0);
static PTR_LOOKUP_SEMAPHORE: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(PTR_LOOKUP_CONCURRENCY));

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

async fn lookup_ptr(ip: &str) -> Option<String> {
    let _permit = PTR_LOOKUP_SEMAPHORE.acquire().await.ok()?;
    let child = Command::new("/usr/bin/host")
        .arg(ip)
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let output = timeout(PTR_LOOKUP_TIMEOUT, child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let ptr = stdout
        .split(" pointer ")
        .nth(1)?
        .trim()
        .trim_end_matches('.')
        .to_string();
    if ptr.is_empty() {
        None
    } else {
        Some(format!("{}.", ptr))
    }
}

pub fn maybe_report_client_agent(api_config: &Arc<ApiConfig>, ip: &str, user_agent: &str) {
    let Some(ua_agent) = detect_agent_by_ua(user_agent) else {
        return;
    };

    if REPORTED_IPS.contains(ip) {
        return;
    }

    let previous = INFLIGHT_COUNT.fetch_add(1, Ordering::Relaxed);
    if previous >= MAX_INFLIGHT_IPS {
        INFLIGHT_COUNT.fetch_sub(1, Ordering::Relaxed);
        return;
    }

    let ip = ip.to_string();
    if !INFLIGHT_IPS.insert(ip.clone()) {
        INFLIGHT_COUNT.fetch_sub(1, Ordering::Relaxed);
        return;
    }

    let api_config = Arc::clone(api_config);
    tokio::spawn(async move {
        async {
            let Some(ptr) = lookup_ptr(&ip).await else {
                return;
            };
            let Some(ptr_agent) = detect_agent_by_ptr(&ptr) else {
                return;
            };
            if ptr_agent.code != ua_agent.code {
                return;
            }

            let client = match timeout(CLIENT_AGENT_RPC_TIMEOUT, RpcClient::new(&api_config)).await
            {
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
                    agent_code: ua_agent.code.to_string(),
                    ip: ip.clone(),
                    ptr: ptr.clone(),
                }],
            });
            if timeout(CLIENT_AGENT_RPC_TIMEOUT, report)
                .await
                .is_ok_and(|result| result.is_ok())
            {
                if REPORTED_IPS.len() < MAX_REPORTED_IPS {
                    REPORTED_IPS.insert(ip.clone());
                }
            }
        }
        .await;

        INFLIGHT_IPS.remove(&ip);
        INFLIGHT_COUNT.fetch_sub(1, Ordering::Relaxed);
    });
}

use crate::pb;
