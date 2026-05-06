#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::anyhow;

#[derive(Debug, Clone)]
pub struct LocalFirewallStatus {
    pub name: String,
    pub version: String,
}

pub async fn check_nftables() -> anyhow::Result<LocalFirewallStatus> {
    #[cfg(not(target_os = "linux"))]
    {
        return Err(anyhow!("nftables check is only supported on Linux"));
    }

    #[cfg(target_os = "linux")]
    {
        let output = tokio::task::spawn_blocking(|| {
            std::process::Command::new("nft").arg("--version").output()
        })
        .await
        .context("failed to join nft version check")?
        .context("'nft' not found")?;

        if !output.status.success() {
            return Err(anyhow!(
                "nft --version failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let version = stdout
            .split_whitespace()
            .find(|part| part.chars().next().is_some_and(|c| c.is_ascii_digit()))
            .unwrap_or("")
            .to_string();
        if version.is_empty() {
            return Err(anyhow!(
                "can not parse nftables version from '{}'",
                stdout.trim()
            ));
        }

        Ok(LocalFirewallStatus {
            name: "nftables".to_string(),
            version,
        })
    }
}
