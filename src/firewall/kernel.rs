use std::net::IpAddr;

pub trait KernelFilter: Send + Sync {
    fn block(&self, ip: IpAddr, ttl_secs: i64);
    fn unblock(&self, ip: IpAddr);
    fn available(&self) -> bool;
}

pub struct NoopFilter;

impl KernelFilter for NoopFilter {
    fn block(&self, _ip: IpAddr, _ttl_secs: i64) {}
    fn unblock(&self, _ip: IpAddr) {}
    fn available(&self) -> bool {
        false
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use tokio::process::Command;

    pub struct NftablesFilter;
    pub struct IptablesFilter;

    impl NftablesFilter {
        pub async fn probe() -> bool {
            Command::new("nft")
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false)
        }
    }

    impl IptablesFilter {
        pub async fn probe() -> bool {
            Command::new("iptables")
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false)
        }
    }

    impl KernelFilter for NftablesFilter {
        fn block(&self, ip: IpAddr, ttl_secs: i64) {
            // nft set with per-element timeout avoids a separate gc sweep;
            // the kernel expires the entry automatically.
            let expr = format!(
                "add element inet cloud_node blocked {{ {} timeout {}s }}",
                ip, ttl_secs
            );
            tokio::spawn(async move {
                let out = Command::new("nft")
                    .args(expr.split_whitespace())
                    .output()
                    .await;
                if let Ok(out) = out {
                    if !out.status.success() {
                        tracing::trace!(
                            stderr = %String::from_utf8_lossy(&out.stderr),
                            "nft block failed"
                        );
                    }
                }
            });
        }

        fn unblock(&self, ip: IpAddr) {
            let expr = format!("delete element inet cloud_node blocked {{ {} }}", ip);
            tokio::spawn(async move {
                let out = Command::new("nft")
                    .args(expr.split_whitespace())
                    .output()
                    .await;
                if let Ok(out) = out {
                    if !out.status.success() {
                        tracing::trace!(
                            stderr = %String::from_utf8_lossy(&out.stderr),
                            "nft unblock failed"
                        );
                    }
                }
            });
        }

        fn available(&self) -> bool {
            true
        }
    }

    impl KernelFilter for IptablesFilter {
        fn block(&self, ip: IpAddr, ttl_secs: i64) {
            let ip_str = ip.to_string();
            let ttl = ttl_secs.to_string();
            tokio::spawn(async move {
                let out = Command::new("iptables")
                    .args([
                        "-I",
                        "INPUT",
                        "-s",
                        &ip_str,
                        "-j",
                        "DROP",
                        "-m",
                        "comment",
                        "--comment",
                        &format!("waf_ttl={}", ttl),
                    ])
                    .output()
                    .await;
                if let Ok(out) = out {
                    if !out.status.success() {
                        tracing::trace!(
                            stderr = %String::from_utf8_lossy(&out.stderr),
                            "iptables block failed"
                        );
                    }
                }
            });
        }

        fn unblock(&self, ip: IpAddr) {
            let ip_str = ip.to_string();
            tokio::spawn(async move {
                let out = Command::new("iptables")
                    .args(["-D", "INPUT", "-s", &ip_str, "-j", "DROP"])
                    .output()
                    .await;
                if let Ok(out) = out {
                    if !out.status.success() {
                        tracing::trace!(
                            stderr = %String::from_utf8_lossy(&out.stderr),
                            "iptables unblock failed"
                        );
                    }
                }
            });
        }

        fn available(&self) -> bool {
            true
        }
    }
}

pub async fn build_filter(mode: Option<&str>) -> Box<dyn KernelFilter> {
    match mode {
        #[cfg(target_os = "linux")]
        Some("nftables") => {
            if linux::NftablesFilter::probe().await {
                return Box::new(linux::NftablesFilter);
            }
            Box::new(NoopFilter)
        }
        #[cfg(target_os = "linux")]
        Some("iptables") => {
            if linux::IptablesFilter::probe().await {
                return Box::new(linux::IptablesFilter);
            }
            Box::new(NoopFilter)
        }
        #[cfg(target_os = "linux")]
        Some("auto") | None => {
            if linux::NftablesFilter::probe().await {
                return Box::new(linux::NftablesFilter);
            }
            if linux::IptablesFilter::probe().await {
                return Box::new(linux::IptablesFilter);
            }
            Box::new(NoopFilter)
        }
        _ => Box::new(NoopFilter),
    }
}
