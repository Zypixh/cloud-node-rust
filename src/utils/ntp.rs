use anyhow::{Context, Result, anyhow};
use reqwest::header::{CACHE_CONTROL, DATE, PRAGMA};
use std::time::Duration;
use tokio::net::UdpSocket;

const NTP_UNIX_EPOCH_DELTA_SECONDS: u64 = 2_208_988_800;
const NTP_PACKET_LEN: usize = 48;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
const SUCCESS_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const FAILURE_INTERVAL: Duration = Duration::from_secs(5 * 60);

pub const DEFAULT_NTP_SERVERS: &[&str] = &[
    "time.cloudflare.com",
    "time.google.com",
    "pool.ntp.org",
    "time.apple.com",
    "time.windows.com",
    "ntp.ubuntu.com",
    "ntp.aliyun.com",
    "cn.pool.ntp.org",
];

pub const DEFAULT_HTTPS_TIME_SOURCES: &[&str] = &[
    "https://www.cloudflare.com/",
    "https://www.google.com/generate_204",
    "https://www.apple.com/",
    "https://www.microsoft.com/",
    "https://www.aliyun.com/",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpSyncResult {
    pub server: String,
    pub offset_millis: i64,
    pub round_trip_millis: i64,
    pub applied_offset_millis: i64,
}

impl NtpSyncResult {
    pub fn log_message(&self) -> String {
        if self.applied_offset_millis == 0 {
            format!(
                "NTP sync completed via {}: no clock offset detected, rtt={}ms",
                self.server, self.round_trip_millis
            )
        } else {
            format!(
                "NTP sync completed via {}: corrected internal clock offset by {}ms, measured_offset={}ms, rtt={}ms",
                self.server, self.applied_offset_millis, self.offset_millis, self.round_trip_millis
            )
        }
    }

    pub fn system_clock_log_message(&self, adjusted_millis: i64) -> String {
        if adjusted_millis == 0 {
            format!(
                "NTP sync completed via {}: no system clock offset detected, rtt={}ms",
                self.server, self.round_trip_millis
            )
        } else {
            format!(
                "NTP sync completed via {}: corrected system clock by {}ms, measured_offset={}ms, rtt={}ms",
                self.server, adjusted_millis, self.offset_millis, self.round_trip_millis
            )
        }
    }
}

pub async fn start_auto_ntp_syncer() {
    loop {
        crate::utils::time::init_local_timezone();
        let sleep_for = match sync_once_default().await {
            Ok(result) => {
                let message = result.log_message();
                tracing::info!("{}", message);
                crate::logging::report_node_log("info".to_string(), "ntp".to_string(), message, 0);
                SUCCESS_INTERVAL
            }
            Err(err) => {
                let message = format!("Time sync failed: {}", err);
                tracing::warn!("{}", message);
                crate::logging::report_node_log("warn".to_string(), "ntp".to_string(), message, 0);
                FAILURE_INTERVAL
            }
        };
        tokio::time::sleep(sleep_for).await;
    }
}

pub async fn sync_once_default() -> Result<NtpSyncResult> {
    let servers = DEFAULT_NTP_SERVERS
        .iter()
        .map(|server| (*server).to_string())
        .collect::<Vec<_>>();
    sync_once(&servers, DEFAULT_TIMEOUT).await
}

pub async fn sync_once(servers: &[String], timeout: Duration) -> Result<NtpSyncResult> {
    let mut failures = Vec::new();
    let timeout = if timeout.is_zero() {
        DEFAULT_TIMEOUT
    } else {
        timeout
    };
    let mut has_https_source = false;

    for server in servers.iter().filter(|server| !server.trim().is_empty()) {
        let server = server.trim();
        let result = if is_https_time_source(server) {
            has_https_source = true;
            query_https_time_source(server, timeout).await
        } else {
            query_ntp_server(server, timeout).await
        };
        match result {
            Ok(mut result) => {
                result.applied_offset_millis =
                    crate::utils::time::set_time_offset_millis(result.offset_millis);
                return Ok(result);
            }
            Err(err) => failures.push(format!("{}: {}", server, err)),
        }
    }

    if !has_https_source {
        for source in DEFAULT_HTTPS_TIME_SOURCES {
            match query_https_time_source(source, timeout).await {
                Ok(mut result) => {
                    result.applied_offset_millis =
                        crate::utils::time::set_time_offset_millis(result.offset_millis);
                    return Ok(result);
                }
                Err(err) => failures.push(format!("{}: {}", source, err)),
            }
        }
    }

    if failures.is_empty() {
        Err(anyhow!("no time sources configured"))
    } else {
        Err(anyhow!("all time sources failed: {}", failures.join("; ")))
    }
}

fn is_https_time_source(source: &str) -> bool {
    source.starts_with("https://")
}

async fn query_ntp_server(server: &str, timeout: Duration) -> Result<NtpSyncResult> {
    let mut addrs = tokio::net::lookup_host((server, 123))
        .await
        .with_context(|| format!("resolve {}", server))?;
    let addr = addrs
        .next()
        .ok_or_else(|| anyhow!("resolve {} returned no addresses", server))?;

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("bind UDP socket")?;
    socket
        .connect(addr)
        .await
        .with_context(|| format!("connect {}", addr))?;

    let mut packet = [0u8; NTP_PACKET_LEN];
    packet[0] = 0x23; // LI=0, VN=4, Mode=3 client
    let send_millis = crate::utils::time::system_timestamp_millis();
    write_ntp_timestamp(&mut packet[40..48], send_millis);

    tokio::time::timeout(timeout, socket.send(&packet))
        .await
        .context("send timeout")?
        .with_context(|| format!("send NTP request to {}", server))?;

    let mut response = [0u8; NTP_PACKET_LEN];
    let received = tokio::time::timeout(timeout, socket.recv(&mut response))
        .await
        .context("receive timeout")?
        .with_context(|| format!("receive NTP response from {}", server))?;
    let receive_millis = crate::utils::time::system_timestamp_millis();
    if received < NTP_PACKET_LEN {
        return Err(anyhow!("short NTP response: {} bytes", received));
    }

    let mode = response[0] & 0b0000_0111;
    if mode != 4 {
        return Err(anyhow!("unexpected NTP response mode {}", mode));
    }
    if response[1] == 0 {
        return Err(anyhow!("NTP server returned stratum 0"));
    }

    let server_receive_millis = read_ntp_timestamp(&response[32..40])
        .ok_or_else(|| anyhow!("invalid NTP receive timestamp"))?;
    let server_transmit_millis = read_ntp_timestamp(&response[40..48])
        .ok_or_else(|| anyhow!("invalid NTP transmit timestamp"))?;
    if server_transmit_millis == 0 {
        return Err(anyhow!("empty NTP transmit timestamp"));
    }

    let offset_millis =
        ((server_receive_millis - send_millis) + (server_transmit_millis - receive_millis)) / 2;
    let round_trip_millis =
        (receive_millis - send_millis) - (server_transmit_millis - server_receive_millis);

    Ok(NtpSyncResult {
        server: server.to_string(),
        offset_millis,
        round_trip_millis: round_trip_millis.max(0),
        applied_offset_millis: 0,
    })
}

async fn query_https_time_source(source: &str, timeout: Duration) -> Result<NtpSyncResult> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .context("build HTTPS time client")?;
    let send_millis = crate::utils::time::system_timestamp_millis();
    let response = client
        .get(source)
        .header(CACHE_CONTROL, "no-cache")
        .header(PRAGMA, "no-cache")
        .send()
        .await
        .with_context(|| format!("fetch HTTPS Date from {}", source))?;
    let receive_millis = crate::utils::time::system_timestamp_millis();
    let date = response
        .headers()
        .get(DATE)
        .ok_or_else(|| anyhow!("missing Date header"))?
        .to_str()
        .context("Date header is not valid ASCII")?;
    let (offset_millis, round_trip_millis) =
        offset_from_http_date(date, send_millis, receive_millis)?;
    Ok(NtpSyncResult {
        server: source.to_string(),
        offset_millis,
        round_trip_millis,
        applied_offset_millis: 0,
    })
}

fn offset_from_http_date(date: &str, send_millis: i64, receive_millis: i64) -> Result<(i64, i64)> {
    let server_millis = chrono::DateTime::parse_from_rfc2822(date)
        .context("parse HTTPS Date header")?
        .timestamp_millis();
    let round_trip_millis = receive_millis.saturating_sub(send_millis).max(0);
    let midpoint_millis = send_millis.saturating_add(round_trip_millis / 2);
    Ok((
        server_millis.saturating_sub(midpoint_millis),
        round_trip_millis,
    ))
}

fn write_ntp_timestamp(dst: &mut [u8], unix_millis: i64) {
    if dst.len() != 8 {
        return;
    }
    let unix_millis = unix_millis.max(0) as u64;
    let unix_seconds = unix_millis / 1000;
    let millis = unix_millis % 1000;
    let ntp_seconds = unix_seconds.saturating_add(NTP_UNIX_EPOCH_DELTA_SECONDS);
    let fraction = ((millis as u128) << 32) / 1000;
    dst[..4].copy_from_slice(&(ntp_seconds as u32).to_be_bytes());
    dst[4..].copy_from_slice(&(fraction as u32).to_be_bytes());
}

fn read_ntp_timestamp(src: &[u8]) -> Option<i64> {
    if src.len() != 8 {
        return None;
    }
    let seconds = u32::from_be_bytes(src[..4].try_into().ok()?) as u64;
    let fraction = u32::from_be_bytes(src[4..].try_into().ok()?) as u64;
    if seconds < NTP_UNIX_EPOCH_DELTA_SECONDS {
        return None;
    }
    let unix_seconds = seconds - NTP_UNIX_EPOCH_DELTA_SECONDS;
    let millis = (((fraction as u128) * 1000) + (1u128 << 31)) >> 32;
    let unix_millis = (unix_seconds as u128)
        .saturating_mul(1000)
        .saturating_add(millis);
    i64::try_from(unix_millis).ok()
}

pub fn default_servers_as_strings() -> Vec<String> {
    DEFAULT_NTP_SERVERS
        .iter()
        .map(|server| (*server).to_string())
        .collect()
}

#[cfg(target_os = "linux")]
pub fn apply_system_clock_offset(offset_millis: i64) -> Result<i64> {
    if offset_millis == 0 {
        crate::utils::time::set_time_offset_millis(0);
        return Ok(0);
    }

    let target_millis = crate::utils::time::system_timestamp_millis()
        .saturating_add(offset_millis)
        .max(0);
    set_system_clock_millis(target_millis)?;
    crate::utils::time::set_time_offset_millis(0);
    Ok(offset_millis)
}

#[cfg(not(target_os = "linux"))]
pub fn apply_system_clock_offset(_offset_millis: i64) -> Result<i64> {
    Err(anyhow!("setting system clock is only supported on Linux"))
}

#[cfg(target_os = "linux")]
fn set_system_clock_millis(unix_millis: i64) -> Result<()> {
    let seconds = unix_millis.div_euclid(1000);
    let nanos = unix_millis.rem_euclid(1000) * 1_000_000;
    let ts = libc::timespec {
        tv_sec: seconds as libc::time_t,
        tv_nsec: nanos as libc::c_long,
    };

    // SAFETY: clock_settime only reads the provided timespec pointer.
    if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()).context("set system clock with clock_settime")
    }
}

#[cfg(target_os = "linux")]
pub fn detect_system_timezone() -> Option<String> {
    if let Ok(output) = std::process::Command::new("timedatectl")
        .args(["show", "-p", "Timezone", "--value"])
        .output()
        && output.status.success()
    {
        let timezone = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !timezone.is_empty() {
            return Some(timezone);
        }
    }

    std::fs::read_to_string("/etc/timezone")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(not(target_os = "linux"))]
pub fn detect_system_timezone() -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
pub fn set_system_timezone(timezone: &str) -> Result<()> {
    validate_timezone_name(timezone)?;
    let zoneinfo = std::path::Path::new("/usr/share/zoneinfo").join(timezone);
    if !zoneinfo.is_file() {
        return Err(anyhow!("timezone not found: {}", timezone));
    }

    if let Ok(status) = std::process::Command::new("timedatectl")
        .args(["set-timezone", timezone])
        .status()
        && status.success()
    {
        crate::utils::time::init_local_timezone();
        return Ok(());
    }

    let _ = std::fs::remove_file("/etc/localtime");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&zoneinfo, "/etc/localtime")
            .with_context(|| format!("link /etc/localtime to {}", zoneinfo.display()))?;
    }
    std::fs::write("/etc/timezone", format!("{}\n", timezone)).context("write /etc/timezone")?;
    crate::utils::time::init_local_timezone();
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_system_timezone(_timezone: &str) -> Result<()> {
    Err(anyhow!(
        "setting system timezone is only supported on Linux"
    ))
}

pub fn validate_timezone_name(timezone: &str) -> Result<()> {
    if timezone.is_empty()
        || timezone.starts_with('/')
        || timezone.contains("..")
        || timezone.contains('\\')
        || timezone
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_whitespace())
    {
        return Err(anyhow!("invalid timezone name: {}", timezone));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntp_timestamp_round_trips_millis() {
        let millis = 1_700_000_000_123;
        let mut raw = [0u8; 8];
        write_ntp_timestamp(&mut raw, millis);
        assert_eq!(read_ntp_timestamp(&raw).unwrap(), millis);
    }

    #[test]
    fn timezone_validation_rejects_paths_and_whitespace() {
        assert!(validate_timezone_name("Asia/Shanghai").is_ok());
        assert!(validate_timezone_name("/etc/passwd").is_err());
        assert!(validate_timezone_name("../UTC").is_err());
        assert!(validate_timezone_name("Asia/ Shanghai").is_err());
    }

    #[test]
    fn https_time_source_detection_accepts_urls_only() {
        assert!(is_https_time_source("https://www.cloudflare.com/"));
        assert!(!is_https_time_source("http://example.com/"));
        assert!(!is_https_time_source("time.cloudflare.com"));
    }

    #[test]
    fn http_date_offset_uses_request_midpoint() {
        let date = "Tue, 14 Nov 2023 22:13:20 GMT";
        let send_millis = 1_699_999_999_800;
        let receive_millis = 1_700_000_000_000;
        let (offset, rtt) = offset_from_http_date(date, send_millis, receive_millis).unwrap();
        assert_eq!(rtt, 200);
        assert_eq!(offset, 100);
    }

    #[test]
    fn log_message_reports_correction_or_no_offset() {
        let corrected = NtpSyncResult {
            server: "time.example".to_string(),
            offset_millis: -1200,
            round_trip_millis: 15,
            applied_offset_millis: -1200,
        };
        assert!(
            corrected
                .log_message()
                .contains("corrected internal clock offset by -1200ms")
        );

        let no_offset = NtpSyncResult {
            applied_offset_millis: 0,
            offset_millis: 0,
            ..corrected
        };
        assert!(no_offset.log_message().contains("no clock offset detected"));
    }

    #[test]
    fn system_clock_log_message_reports_system_adjustment() {
        let result = NtpSyncResult {
            server: "time.example".to_string(),
            offset_millis: 900,
            round_trip_millis: 12,
            applied_offset_millis: 900,
        };
        assert!(
            result
                .system_clock_log_message(900)
                .contains("corrected system clock by 900ms")
        );
        assert!(
            result
                .system_clock_log_message(0)
                .contains("no system clock offset detected")
        );
    }
}
