#[cfg_attr(not(target_os = "linux"), allow(unused_imports))]
use super::*;
#[cfg(target_os = "linux")]
pub async fn raw_smoke(
    duration: std::time::Duration,
    ready_file: Option<std::path::PathBuf>,
) -> anyhow::Result<serde_json::Value> {
    let manager = manager_from_runtime();
    manager.initialize().await?;
    start_rule_sweeper(&manager);
    manager.enable_proxy_redirect("raw smoke")?;
    let result = raw_smoke_inner(manager, duration, ready_file).await;
    if let Err(err) = detach(false).await {
        tracing::warn!("failed to detach XDP after raw smoke: {}", err);
    }
    result
}

#[cfg(target_os = "linux")]
async fn raw_smoke_inner(
    manager: std::sync::Arc<XdpManager>,
    duration: std::time::Duration,
    ready_file: Option<std::path::PathBuf>,
) -> anyhow::Result<serde_json::Value> {
    let initial_status = manager.status();
    anyhow::ensure!(
        initial_status.proxy_ready,
        "AF_XDP proxy runtime is not ready: {}",
        if initial_status.proxy_fallback_reason.is_empty() {
            initial_status.fallback_reason.as_str()
        } else {
            initial_status.proxy_fallback_reason.as_str()
        }
    );
    if let Some(path) = ready_file.as_ref() {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, b"ready\n")?;
    }

    let deadline = tokio::time::Instant::now() + duration;
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(10));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut frames_seen = 0u64;
    let mut udp_seen = 0u64;
    let mut tcp_seen = 0u64;
    let mut unparseable_seen = 0u64;
    let mut samples = Vec::new();

    while tokio::time::Instant::now() < deadline {
        let mut frames = Vec::with_capacity(64);
        let stats = {
            let mut runtime = manager.af_xdp.lock();
            let Some(runtime) = runtime.as_mut() else {
                anyhow::bail!("AF_XDP runtime is not initialized");
            };
            runtime.poll_raw_once(|interface, queue, frame| {
                frames.push((interface.to_string(), queue, frame));
            })?
        };

        for (interface, queue, frame) in frames {
            frames_seen = frames_seen.saturating_add(1);
            match af_xdp::parse_proxy_frame(interface.as_str(), queue, &frame) {
                Some(af_xdp::AfXdpProxyFrame::Udp { packet, .. }) => {
                    udp_seen = udp_seen.saturating_add(1);
                    if samples.len() < 8 {
                        samples.push(serde_json::json!({
                            "protocol": "udp",
                            "interface": interface,
                            "queue": queue,
                            "local": packet.local_addr.to_string(),
                            "peer": packet.peer_addr.to_string(),
                            "payloadBytes": packet.payload.len(),
                        }));
                    }
                }
                Some(af_xdp::AfXdpProxyFrame::Tcp {
                    flow, ip_packet, ..
                }) => {
                    tcp_seen = tcp_seen.saturating_add(1);
                    if samples.len() < 8 {
                        samples.push(serde_json::json!({
                            "protocol": "tcp",
                            "interface": interface,
                            "queue": queue,
                            "local": flow.local_addr.to_string(),
                            "peer": flow.peer_addr.to_string(),
                            "ipPacketBytes": ip_packet.len(),
                        }));
                    }
                }
                None => {
                    unparseable_seen = unparseable_seen.saturating_add(1);
                }
            }
        }

        if stats.packets == 0 {
            tick.tick().await;
        } else {
            tokio::task::yield_now().await;
        }
    }

    let status = manager.status();
    let report = serde_json::json!({
        "durationMillis": duration.as_millis(),
        "frames": frames_seen,
        "udp": udp_seen,
        "tcp": tcp_seen,
        "unparseable": unparseable_seen,
        "tcpDataplaneReady": status.tcp_dataplane_ready,
        "tcpDataplaneDetail": status.tcp_dataplane_detail,
        "proxyReady": status.proxy_ready,
        "xskReadyQueues": status.xsk_ready_queues,
        "packets": status.packets,
        "pass": status.pass,
        "drop": status.drop,
        "redirect": status.redirect,
        "parseErrors": status.parse_errors,
        "mapMiss": status.map_miss,
        "xskDrops": status.xsk_drops,
        "rateLimited": status.rate_limited,
        "ratelimitMapFull": status.ratelimit_map_full,
        "udpFwdTx": status.udp_fwd_tx,
        "udpFwdMapFull": status.udp_fwd_map_full,
        "tcpFwdTx": status.tcp_fwd_tx,
        "tcpFwdMapFull": status.tcp_fwd_map_full,
        "snatBound": status.snat_bound,
        "snatAllocFail": status.snat_alloc_fail,
        "snatReplyTx": status.snat_reply_tx,
        "tx": status.tx,
        "aclBlocked": status.acl_blocked,
        "samples": samples,
    });
    Ok(report)
}

#[cfg(target_os = "linux")]
pub async fn proxy_smoke(
    duration: std::time::Duration,
    ready_file: Option<std::path::PathBuf>,
    kernel_mode: bool,
    remote: Option<std::net::IpAddr>,
) -> anyhow::Result<serde_json::Value> {
    af_xdp::reset_tcp_diag();
    crate::tcp_proxy::reset_af_xdp_tcp_proxy_diag();
    let manager = manager_from_runtime();
    let ports = xdp_proxy_smoke_ports(&manager.config)?;

    if kernel_mode {
        return proxy_smoke_kernel(ports, duration, ready_file, remote).await;
    }

    manager.initialize().await?;
    start_rule_sweeper(&manager);
    let services = match XdpProxySmokeServices::start(remote).await {
        Ok(services) => services,
        Err(err) => {
            if let Err(detach_err) = detach(false).await {
                tracing::warn!("failed to detach XDP after proxy smoke setup error: {detach_err}");
            }
            return Err(err);
        }
    };
    let (quic_demux, tcp_manager, http_manager) =
        match xdp_proxy_smoke_managers(&services, &ports).await {
            Ok(managers) => managers,
            Err(err) => {
                services.abort();
                if let Err(detach_err) = detach(false).await {
                    tracing::warn!(
                        "failed to detach XDP after proxy smoke manager setup error: {detach_err}"
                    );
                }
                return Err(err);
            }
        };

    let bridge = tokio::spawn(af_xdp::start_proxy_bridge(
        quic_demux,
        tcp_manager,
        http_manager,
    ));
    let result = proxy_smoke_inner(manager, services, ports, duration, ready_file, &bridge).await;
    bridge.abort();
    let _ = bridge.await;
    if let Err(err) = detach(false).await {
        tracing::warn!("failed to detach XDP after proxy smoke: {}", err);
    }
    result
}

#[cfg(target_os = "linux")]
pub async fn proxy_reload_smoke(
    duration: std::time::Duration,
    ready_file: Option<std::path::PathBuf>,
) -> anyhow::Result<serde_json::Value> {
    let old_manager = manager_from_runtime();
    let ports = xdp_proxy_smoke_ports(&old_manager.config)?;

    old_manager
        .initialize()
        .await
        .map_err(|err| anyhow::anyhow!("AF_XDP reload initial initialize failed: {err}"))?;
    start_rule_sweeper(&old_manager);
    let services = match XdpProxySmokeServices::start(None).await {
        Ok(services) => services,
        Err(err) => {
            if let Err(detach_err) = detach(false).await {
                tracing::warn!(
                    "failed to detach XDP after proxy reload smoke setup error: {detach_err}"
                );
            }
            return Err(err);
        }
    };
    let (old_quic_demux, old_tcp_manager, old_http_manager) = match xdp_proxy_smoke_managers(
        &services, &ports,
    )
    .await
    {
        Ok(managers) => managers,
        Err(err) => {
            services.abort();
            if let Err(detach_err) = detach(false).await {
                tracing::warn!(
                    "failed to detach XDP after proxy reload smoke manager setup error: {detach_err}"
                );
            }
            return Err(err);
        }
    };

    let old_bridge = tokio::spawn(af_xdp::start_proxy_bridge(
        old_quic_demux,
        old_tcp_manager,
        old_http_manager,
    ));
    let result = proxy_reload_smoke_inner(
        old_manager,
        services,
        ports,
        duration,
        ready_file,
        old_bridge,
    )
    .await;
    if let Err(err) = detach(false).await {
        tracing::warn!("failed to detach XDP after proxy reload smoke: {}", err);
    }
    result
}

#[cfg(target_os = "linux")]
async fn proxy_reload_smoke_inner(
    old_manager: std::sync::Arc<XdpManager>,
    services: XdpProxySmokeServices,
    _ports: XdpProxySmokePorts,
    duration: std::time::Duration,
    ready_file: Option<std::path::PathBuf>,
    old_bridge: tokio::task::JoinHandle<()>,
) -> anyhow::Result<serde_json::Value> {
    wait_for_proxy_smoke_ready(&old_manager, duration, &old_bridge).await?;
    let before_reload = old_manager.status();

    // Force a real generation replacement: with an identical config the
    // reload fast-path returns early and proves nothing about the
    // prepare→commit→handover path. Pinning the auto-scaled state tables
    // as explicit config keeps the loaded map specs identical to the live
    // pins while making the config differ, so reload builds a full second
    // generation — the strongest no-downtime check available in-process.
    let mut runtime = crate::runtime_mode::RuntimeConfig::current().unwrap_or_default();
    if let Some(tables) = old_manager.effective_state_tables.read().clone() {
        runtime.xdp.state_tables = Some(tables);
    }
    if runtime.xdp == old_manager.config {
        // Config still identical (tables were already explicit, or the
        // node fit defaults without scaling): materialize the default
        // admission contract — semantically identical to None but a real
        // config change that forces a generation replacement.
        runtime.xdp.admission = Some(crate::runtime_mode::XdpAdmissionSettings::default());
    }
    crate::runtime_mode::RuntimeConfig::set_current(runtime);
    reload_from_runtime().await?;
    let after_manager = manager_from_runtime();
    anyhow::ensure!(
        !std::sync::Arc::ptr_eq(&old_manager, &after_manager),
        "reload did not replace the XDP manager generation"
    );
    // The bridge supervisor is generation-aware: it must stay alive across
    // the handover and re-serve the new manager's workers. Per-generation
    // workers exit inside `run_proxy_bridge` when their manager goes stale.
    let result = async {
        wait_for_proxy_smoke_ready(&after_manager, duration, &old_bridge).await?;
        write_ready_file(ready_file.as_ref())?;
        tokio::time::sleep(duration).await;
        let after_reload = after_manager.status();
        anyhow::ensure!(
            before_reload.proxy_ready && before_reload.proxy_redirect_enabled,
            "proxy bridge was not ready before reload"
        );
        anyhow::ensure!(
            after_reload.proxy_ready && after_reload.proxy_redirect_enabled,
            "proxy bridge was not ready after reload"
        );
        anyhow::ensure!(
            after_reload.tcp_dataplane_ready,
            "TCP dataplane was not ready after reload: {}",
            after_reload.tcp_dataplane_detail
        );
        anyhow::ensure!(
            before_reload.redirect <= after_reload.redirect,
            "XDP redirect counter moved backwards across reload"
        );
        Ok(serde_json::json!({
            "durationMillis": duration.as_millis(),
            "bridgeSupervisorAlive": !old_bridge.is_finished(),
            "managerReplaced": true,
            "beforeReload": {
                "proxyReady": before_reload.proxy_ready,
                "proxyRedirectEnabled": before_reload.proxy_redirect_enabled,
                "tcpDataplaneReady": before_reload.tcp_dataplane_ready,
                "xskReadyQueues": before_reload.xsk_ready_queues,
                "fallbackReason": before_reload.fallback_reason,
                "proxyFallbackReason": before_reload.proxy_fallback_reason,
                "redirect": before_reload.redirect,
                "xskDrops": before_reload.xsk_drops,
            },
            "afterReload": {
                "proxyReady": after_reload.proxy_ready,
                "proxyRedirectEnabled": after_reload.proxy_redirect_enabled,
                "tcpDataplaneReady": after_reload.tcp_dataplane_ready,
                "tcpDataplaneDetail": after_reload.tcp_dataplane_detail,
                "xskReadyQueues": after_reload.xsk_ready_queues,
                "fallbackReason": after_reload.fallback_reason,
                "proxyFallbackReason": after_reload.proxy_fallback_reason,
                "packets": after_reload.packets,
                "pass": after_reload.pass,
                "drop": after_reload.drop,
                "redirect": after_reload.redirect,
                "parseErrors": after_reload.parse_errors,
                "mapMiss": after_reload.map_miss,
                "xskDrops": after_reload.xsk_drops,
            },
        }))
    }
    .await;
    old_bridge.abort();
    let _ = old_bridge.await;
    services.abort();
    result
}

/// T4-8: attach AF_XDP and open a real userspace-TCP dial to an on-wire
/// target, then hold the session for `duration` so the out-CT / ICMP PMTU
/// path can be exercised with live traffic. The ready file carries the
/// dialed flow's local endpoint so an orchestrator can quote that exact
/// tuple in crafted ICMP errors. Failure to dial is an explicit error —
/// never a kernel fallback.
#[cfg(target_os = "linux")]
pub async fn dial_smoke(
    target: std::net::SocketAddr,
    duration: std::time::Duration,
    ready_file: Option<std::path::PathBuf>,
    payload: Vec<u8>,
    send_interval: std::time::Duration,
    reload_at: Option<std::time::Duration>,
) -> anyhow::Result<serde_json::Value> {
    af_xdp::reset_tcp_diag();
    let manager = manager_from_runtime();
    let ports = xdp_proxy_smoke_ports(&manager.config)?;
    manager.initialize().await?;
    start_rule_sweeper(&manager);
    let services = match XdpProxySmokeServices::start(None).await {
        Ok(services) => services,
        Err(err) => {
            if let Err(detach_err) = detach(false).await {
                tracing::warn!("failed to detach XDP after dial smoke setup error: {detach_err}");
            }
            return Err(err);
        }
    };
    let (quic_demux, tcp_manager, http_manager) =
        match xdp_proxy_smoke_managers(&services, &ports).await {
            Ok(managers) => managers,
            Err(err) => {
                services.abort();
                if let Err(detach_err) = detach(false).await {
                    tracing::warn!(
                        "failed to detach XDP after dial smoke manager setup error: {detach_err}"
                    );
                }
                return Err(err);
            }
        };
    let bridge = tokio::spawn(af_xdp::start_proxy_bridge(
        quic_demux,
        tcp_manager,
        http_manager,
    ));
    let result = dial_smoke_inner(
        manager,
        target,
        duration,
        ready_file,
        payload,
        send_interval,
        reload_at,
        &bridge,
    )
    .await;
    bridge.abort();
    let _ = bridge.await;
    services.abort();
    if let Err(err) = detach(false).await {
        tracing::warn!("failed to detach XDP after dial smoke: {}", err);
    }
    result
}

#[cfg(target_os = "linux")]
async fn dial_smoke_inner(
    manager: std::sync::Arc<XdpManager>,
    target: std::net::SocketAddr,
    duration: std::time::Duration,
    ready_file: Option<std::path::PathBuf>,
    payload: Vec<u8>,
    send_interval: std::time::Duration,
    reload_at: Option<std::time::Duration>,
    bridge: &tokio::task::JoinHandle<()>,
) -> anyhow::Result<serde_json::Value> {
    use anyhow::Context as _;
    use futures_util::FutureExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    wait_for_proxy_smoke_ready(&manager, duration, bridge).await?;
    let dial_timeout = duration.min(std::time::Duration::from_secs(15));
    let mut stream = tokio::time::timeout(dial_timeout, af_xdp_dial_tcp(target, Vec::new()))
        .await
        .with_context(|| format!("timed out AF_XDP dialing {target}"))?
        .map_err(|err| anyhow::anyhow!("AF_XDP dial {target} failed: {err}"))?;
    let local = stream
        .local_addr()
        .map_err(|err| anyhow::anyhow!("AF_XDP stream has no local addr: {err}"))?;
    let session_established = tokio::time::Instant::now();
    if let Some(path) = ready_file.as_ref() {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "ready": true,
                "local": local.to_string(),
                "peer": target.to_string(),
            }))?,
        )?;
    }
    let mut sent = 0u64;
    let mut received = 0u64;
    let mut io_error: Option<String> = None;
    let mut io_error_at_ms: Option<u64> = None;
    // T4-8/F1: optional in-process manager reload while the dialed session
    // is live. The reload task is spawned at `reload_at` after session
    // establishment; the send loop keeps probing the old session through
    // the whole prepare→commit window so the report can timestamp exactly
    // when (if) the session broke relative to the generation swap.
    let mut reload_fut: Option<
        std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>>>>,
    > = None;
    let mut reload_started_ms: Option<u64> = None;
    let mut reload_finished_ms: Option<u64> = None;
    let mut reload_outcome: Option<serde_json::Value> = None;
    let mut sent_at_reload: Option<u64> = None;
    let mut received_at_reload: Option<u64> = None;
    let mut io_error_before_reload_end = false;
    let mut send_tick = if send_interval.is_zero() {
        None
    } else {
        let mut tick =
            tokio::time::interval_at(tokio::time::Instant::now(), send_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Some(tick)
    };
    // A zero interval still sends the payload once at session start.
    let mut send_once = !payload.is_empty();
    let deadline = tokio::time::Instant::now() + duration;
    let mut buf = vec![0u8; 8192];
    while tokio::time::Instant::now() < deadline {
        // Trigger the scheduled in-process reload exactly once.
        if let Some(at) = reload_at
            && reload_started_ms.is_none()
            && session_established.elapsed() >= at
        {
            // Force a real generation replacement — an identical config
            // takes the reload fast-path and proves nothing about the
            // prepare→commit→handover contract (same trick as
            // proxy_reload_smoke).
            let mut runtime =
                crate::runtime_mode::RuntimeConfig::current().unwrap_or_default();
            if let Some(tables) = manager.effective_state_tables.read().clone() {
                runtime.xdp.state_tables = Some(tables);
            }
            if runtime.xdp == manager.config {
                runtime.xdp.admission =
                    Some(crate::runtime_mode::XdpAdmissionSettings::default());
            }
            crate::runtime_mode::RuntimeConfig::set_current(runtime);
            reload_started_ms = Some(session_established.elapsed().as_millis() as u64);
            sent_at_reload = Some(sent);
            received_at_reload = Some(received);
            // Polled manually each loop round — no Send/spawn needed, and
            // the session's send/read probes keep running through the
            // whole prepare→commit window.
            reload_fut = Some(Box::pin(reload_from_runtime()));
        }
        // Advance the in-process reload without stalling session traffic.
        if let Some(fut) = reload_fut.as_mut()
            && reload_finished_ms.is_none()
            && let std::task::Poll::Ready(res) = futures_util::poll!(fut)
        {
            reload_finished_ms = Some(session_established.elapsed().as_millis() as u64);
            match res {
                Ok(()) => {
                    let after = manager_from_runtime();
                    let status = after.status();
                    reload_outcome = Some(serde_json::json!({
                        "ok": true,
                        "managerReplaced": !std::sync::Arc::ptr_eq(&manager, &after),
                        "postReloadProxyReady": status.proxy_ready,
                        "postReloadRedirectEnabled": status.proxy_redirect_enabled,
                        "postReloadXskReadyQueues": status.xsk_ready_queues,
                        "postReloadFallbackReason": status.fallback_reason,
                        "postReloadDialGuardInstalled": status.dial_guard_installed,
                    }));
                }
                Err(err) => {
                    reload_outcome = Some(serde_json::json!({
                        "ok": false,
                        "error": format!("{err}"),
                    }));
                }
            }
        }
        let due = send_once
            || send_tick
                .as_mut()
                .map(|tick| tick.tick().now_or_never().is_some())
                .unwrap_or(false);
        if due && !payload.is_empty() && io_error.is_none() {
            match stream.write_all(&payload).await {
                Ok(()) => sent = sent.saturating_add(payload.len() as u64),
                Err(err) => {
                    io_error = Some(err.to_string());
                    io_error_at_ms = Some(session_established.elapsed().as_millis() as u64);
                    io_error_before_reload_end =
                        reload_started_ms.is_some() && reload_finished_ms.is_none();
                }
            }
            send_once = false;
            continue;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(
            remaining.min(std::time::Duration::from_millis(100)),
            stream.read(&mut buf),
        )
        .await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => received = received.saturating_add(n as u64),
            Ok(Err(err)) => {
                if io_error.is_none() {
                    io_error = Some(err.to_string());
                    io_error_at_ms =
                        Some(session_established.elapsed().as_millis() as u64);
                    io_error_before_reload_end =
                        reload_started_ms.is_some() && reload_finished_ms.is_none();
                }
            }
            Err(_) => {}
        }
    }
    // Give a reload that is still running at the deadline one last poll.
    if let Some(fut) = reload_fut.as_mut()
        && reload_finished_ms.is_none()
        && let std::task::Poll::Ready(res) = futures_util::poll!(fut)
    {
        reload_finished_ms = Some(session_established.elapsed().as_millis() as u64);
        reload_outcome = Some(serde_json::json!({
            "ok": res.is_ok(),
            "error": res.err().map(|err| format!("{err}")).unwrap_or_default(),
        }));
    }
    // After an adoption the reporting manager's bookkeeping was moved to
    // the successor — its own status reads zeros. When the reload actually
    // swapped the global manager, report status from the live successor so
    // the outer fields stay meaningful.
    let status_owner = manager_from_runtime();
    let status = status_owner.status();
    Ok(serde_json::json!({
        "durationMillis": duration.as_millis(),
        "target": target.to_string(),
        "local": local.to_string(),
        "sent": sent,
        "received": received,
        "ioError": io_error,
        "ioErrorAtMs": io_error_at_ms,
        "ioErrorBeforeReloadFinished": io_error_before_reload_end,
        "sentAtReloadStart": sent_at_reload,
        "receivedAtReloadStart": received_at_reload,
        "reloadAtMs": reload_at.map(|at| at.as_millis() as u64),
        "reloadStartedMs": reload_started_ms,
        "reloadFinishedMs": reload_finished_ms,
        "reload": reload_outcome,
        "proxyReady": status.proxy_ready,
        "proxyRedirectEnabled": status.proxy_redirect_enabled,
        "tcpDataplaneReady": status.tcp_dataplane_ready,
        "xskReadyQueues": status.xsk_ready_queues,
        "packets": status.packets,
        "pass": status.pass,
        "drop": status.drop,
        "redirect": status.redirect,
        "outCtHit": status.out_ct_hit,
        "outCtIcmp": status.out_ct_icmp,
        "xskDrops": status.xsk_drops,
        "dialGuardInstalled": status.dial_guard_installed,
        "dialGuardHits": status.dial_guard_hits,
        "tcpDiag": af_xdp::tcp_diag_snapshot(),
    }))
}

#[cfg(target_os = "linux")]
async fn proxy_smoke_inner(
    manager: std::sync::Arc<XdpManager>,
    services: XdpProxySmokeServices,
    ports: XdpProxySmokePorts,
    duration: std::time::Duration,
    ready_file: Option<std::path::PathBuf>,
    bridge: &tokio::task::JoinHandle<()>,
) -> anyhow::Result<serde_json::Value> {
    wait_for_proxy_smoke_ready(&manager, duration, bridge).await?;
    write_ready_file(ready_file.as_ref())?;

    tokio::time::sleep(duration).await;
    let status = manager.status();
    let report = serde_json::json!({
        "durationMillis": duration.as_millis(),
        "proxyReady": status.proxy_ready,
        "proxyRedirectEnabled": status.proxy_redirect_enabled,
        "tcpDataplaneReady": status.tcp_dataplane_ready,
        "tcpDataplaneDetail": status.tcp_dataplane_detail,
        "xskReadyQueues": status.xsk_ready_queues,
        "packets": status.packets,
        "pass": status.pass,
        "drop": status.drop,
        "redirect": status.redirect,
        "parseErrors": status.parse_errors,
        "mapMiss": status.map_miss,
        "xskDrops": status.xsk_drops,
        "ports": {
            "http": ports.http,
            "https": ports.https,
            "tcp": ports.tcp,
            "udp": ports.udp,
            "h3": ports.h3,
        },
        "backends": {
            "http": services.http_addr.to_string(),
            "https": services.https_addr.to_string(),
            "tcp": services.tcp_addr.to_string(),
            "udp": services.udp_addr.to_string(),
            "h3": services.h3_addr.to_string(),
            "sni": services.sni_addr.to_string(),
            "quic": services.quic_addr.to_string(),
        },
        "app": {
            "httpRequests": services.http_requests.load(Ordering::Relaxed),
            "httpsRequests": services.https_requests.load(Ordering::Relaxed),
            "tcpConnections": services.tcp_connections.load(Ordering::Relaxed),
            "udpDatagrams": services.udp_datagrams.load(Ordering::Relaxed),
            "h3Requests": services.h3_requests.load(Ordering::Relaxed),
            "sniConnections": services.sni_connections.load(Ordering::Relaxed),
            "quicRequests": services.quic_requests.load(Ordering::Relaxed),
        },
        "tcpDiag": af_xdp::tcp_diag_snapshot(),
        "tcpProxyDiag": crate::tcp_proxy::af_xdp_tcp_proxy_diag_snapshot(),
    });
    services.abort();
    Ok(report)
}

/// Kernel-socket counterpart of `proxy_smoke`: identical site set, backends
/// and proxy managers, but ingress is the kernel TCP/UDP stack instead of
/// AF_XDP. Used as the XDP-off arm of dataplane A/B benchmarks — both arms
/// serve `xdp-smoke-*.local` through the same EdgeProxy pipeline, so the only
/// changed variable is the packet path.
#[cfg(target_os = "linux")]
async fn proxy_smoke_kernel(
    ports: XdpProxySmokePorts,
    duration: std::time::Duration,
    ready_file: Option<std::path::PathBuf>,
    remote: Option<std::net::IpAddr>,
) -> anyhow::Result<serde_json::Value> {
    let services = XdpProxySmokeServices::start(remote).await?;
    let (quic_demux, tcp_manager, http_manager) =
        xdp_proxy_smoke_managers(&services, &ports).await?;
    let listener_tasks: Vec<tokio::task::JoinHandle<()>> = {
        let quic_demux = quic_demux.clone();
        let tcp_manager = tcp_manager.clone();
        let http_manager = http_manager.clone();
        vec![
            tokio::spawn(async move { quic_demux.start_listeners().await }),
            tokio::spawn(async move { tcp_manager.start_listeners().await }),
            tokio::spawn(async move { http_manager.start_listeners().await }),
        ]
    };

    // Readiness = the TCP listeners actually accepting. UDP binds land in the
    // same reconcile pass, so a live TCP accept implies the set is up.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut ready = false;
    while tokio::time::Instant::now() < deadline {
        if listener_tasks.iter().any(|task| task.is_finished()) {
            anyhow::bail!("kernel proxy-smoke listener task exited before ready");
        }
        if tokio::net::TcpStream::connect(("127.0.0.1", ports.http))
            .await
            .is_ok()
            && tokio::net::TcpStream::connect(("127.0.0.1", ports.tcp))
                .await
                .is_ok()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    if !ready {
        anyhow::bail!("timed out waiting for kernel proxy-smoke listeners");
    }
    write_ready_file(ready_file.as_ref())?;

    tokio::time::sleep(duration).await;
    let report = serde_json::json!({
        "durationMillis": duration.as_millis(),
        "dataplane": "kernel",
        "proxyReady": true,
        "ports": {
            "http": ports.http,
            "https": ports.https,
            "tcp": ports.tcp,
            "udp": ports.udp,
            "h3": ports.h3,
        },
        "backends": {
            "http": services.http_addr.to_string(),
            "https": services.https_addr.to_string(),
            "tcp": services.tcp_addr.to_string(),
            "udp": services.udp_addr.to_string(),
            "h3": services.h3_addr.to_string(),
            "sni": services.sni_addr.to_string(),
            "quic": services.quic_addr.to_string(),
        },
        "app": {
            "httpRequests": services.http_requests.load(Ordering::Relaxed),
            "httpsRequests": services.https_requests.load(Ordering::Relaxed),
            "tcpConnections": services.tcp_connections.load(Ordering::Relaxed),
            "udpDatagrams": services.udp_datagrams.load(Ordering::Relaxed),
            "h3Requests": services.h3_requests.load(Ordering::Relaxed),
            "sniConnections": services.sni_connections.load(Ordering::Relaxed),
            "quicRequests": services.quic_requests.load(Ordering::Relaxed),
        },
        "tcpProxyDiag": crate::tcp_proxy::af_xdp_tcp_proxy_diag_snapshot(),
    });
    services.abort();
    for task in &listener_tasks {
        task.abort();
    }
    Ok(report)
}

#[cfg(target_os = "linux")]
fn write_ready_file(path: Option<&std::path::PathBuf>) -> anyhow::Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, b"ready\n")?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn wait_for_proxy_smoke_ready(
    manager: &XdpManager,
    timeout: std::time::Duration,
    bridge: &tokio::task::JoinHandle<()>,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout.max(std::time::Duration::from_millis(1));
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(25));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let status = manager.status();
        if status.proxy_ready && status.tcp_dataplane_ready {
            return Ok(());
        }
        if bridge.is_finished() {
            anyhow::bail!(
                "AF_XDP proxy bridge exited before smoke was ready: {}",
                if status.proxy_fallback_reason.is_empty() {
                    status.fallback_reason
                } else {
                    status.proxy_fallback_reason
                }
            );
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for AF_XDP proxy bridge readiness: {}",
                if status.proxy_fallback_reason.is_empty() {
                    status.fallback_reason
                } else {
                    status.proxy_fallback_reason
                }
            );
        }
        tick.tick().await;
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct XdpProxySmokePorts {
    http: u16,
    https: u16,
    tcp: u16,
    udp: u16,
    h3: u16,
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_ports(config: &XdpConfig) -> anyhow::Result<XdpProxySmokePorts> {
    let mut http = None;
    let mut https = None;
    let mut tcp = None;
    let mut udp = None;
    let mut h3 = None;
    for port in &config.proxy.ports {
        if port.port == 0 {
            continue;
        }
        match port.protocol {
            XdpProxyProtocol::Http => http.get_or_insert(port.port),
            XdpProxyProtocol::Https => https.get_or_insert(port.port),
            XdpProxyProtocol::Tcp => tcp.get_or_insert(port.port),
            XdpProxyProtocol::Udp => udp.get_or_insert(port.port),
            XdpProxyProtocol::H3 => h3.get_or_insert(port.port),
        };
    }
    Ok(XdpProxySmokePorts {
        http: http.ok_or_else(|| anyhow::anyhow!("xdp.proxy.ports is missing an http port"))?,
        https: https.ok_or_else(|| anyhow::anyhow!("xdp.proxy.ports is missing an https port"))?,
        tcp: tcp.ok_or_else(|| anyhow::anyhow!("xdp.proxy.ports is missing a tcp port"))?,
        udp: udp.ok_or_else(|| anyhow::anyhow!("xdp.proxy.ports is missing a udp port"))?,
        h3: h3.ok_or_else(|| anyhow::anyhow!("xdp.proxy.ports is missing an h3 port"))?,
    })
}

#[cfg(target_os = "linux")]
struct XdpProxySmokeServices {
    http_addr: std::net::SocketAddr,
    https_addr: std::net::SocketAddr,
    tcp_addr: std::net::SocketAddr,
    udp_addr: std::net::SocketAddr,
    h3_addr: std::net::SocketAddr,
    sni_addr: std::net::SocketAddr,
    quic_addr: std::net::SocketAddr,
    http_requests: std::sync::Arc<AtomicU64>,
    https_requests: std::sync::Arc<AtomicU64>,
    tcp_connections: std::sync::Arc<AtomicU64>,
    udp_datagrams: std::sync::Arc<AtomicU64>,
    h3_requests: std::sync::Arc<AtomicU64>,
    sni_connections: std::sync::Arc<AtomicU64>,
    quic_requests: std::sync::Arc<AtomicU64>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

#[cfg(target_os = "linux")]
impl XdpProxySmokeServices {
    /// `remote = Some(ip)` points upstreams at a backend fleet on that host
    /// (port convention: 19000 http/h3, 19002 tcp-echo, 19003 udp-echo,
    /// 19005 sni-tls). The QUIC backend stays in-process — a remote QUIC
    /// endpoint is not part of the remote fleet contract. Per-backend
    /// counters stay zero in remote mode.
    async fn start(remote: Option<std::net::IpAddr>) -> anyhow::Result<Self> {
        let http_requests = std::sync::Arc::new(AtomicU64::new(0));
        let https_requests = std::sync::Arc::new(AtomicU64::new(0));
        let tcp_connections = std::sync::Arc::new(AtomicU64::new(0));
        let udp_datagrams = std::sync::Arc::new(AtomicU64::new(0));
        let h3_requests = std::sync::Arc::new(AtomicU64::new(0));
        let sni_connections = std::sync::Arc::new(AtomicU64::new(0));
        let quic_requests = std::sync::Arc::new(AtomicU64::new(0));

        if let Some(ip) = remote {
            let (quic_addr, quic_task) =
                start_xdp_smoke_quic_backend(quic_requests.clone()).await?;
            return Ok(Self {
                http_addr: std::net::SocketAddr::new(ip, 19000),
                https_addr: std::net::SocketAddr::new(ip, 19000),
                tcp_addr: std::net::SocketAddr::new(ip, 19002),
                udp_addr: std::net::SocketAddr::new(ip, 19003),
                h3_addr: std::net::SocketAddr::new(ip, 19000),
                sni_addr: std::net::SocketAddr::new(ip, 19005),
                quic_addr,
                http_requests,
                https_requests,
                tcp_connections,
                udp_datagrams,
                h3_requests,
                sni_connections,
                quic_requests,
                tasks: vec![quic_task],
            });
        }

        let (http_addr, http_task) =
            start_xdp_smoke_http_backend(http_requests.clone(), b"xdp-http-smoke\n").await?;
        let (https_addr, https_task) =
            start_xdp_smoke_http_backend(https_requests.clone(), b"xdp-https-smoke\n").await?;
        let (tcp_addr, tcp_task) = start_xdp_smoke_tcp_backend(tcp_connections.clone()).await?;
        let (udp_addr, udp_task) = start_xdp_smoke_udp_backend(udp_datagrams.clone()).await?;
        let (h3_addr, h3_task) =
            start_xdp_smoke_http_backend(h3_requests.clone(), b"xdp-h3-smoke\n").await?;
        let (sni_addr, sni_task) = start_xdp_smoke_sni_backend(sni_connections.clone()).await?;
        let (quic_addr, quic_task) = start_xdp_smoke_quic_backend(quic_requests.clone()).await?;

        Ok(Self {
            http_addr,
            https_addr,
            tcp_addr,
            udp_addr,
            h3_addr,
            sni_addr,
            quic_addr,
            http_requests,
            https_requests,
            tcp_connections,
            udp_datagrams,
            h3_requests,
            sni_connections,
            quic_requests,
            tasks: vec![
                http_task, https_task, tcp_task, udp_task, h3_task, sni_task, quic_task,
            ],
        })
    }

    fn abort(self) {
        for task in self.tasks {
            task.abort();
        }
    }
}

#[cfg(target_os = "linux")]
async fn start_xdp_smoke_http_backend(
    requests: std::sync::Arc<AtomicU64>,
    body: &'static [u8],
) -> anyhow::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let requests = requests.clone();
            tokio::spawn(async move {
                let mut request = Vec::with_capacity(512);
                let mut buf = [0u8; 512];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            request.extend_from_slice(&buf[..n]);
                            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                    if request.len() >= 8192 {
                        break;
                    }
                }
                requests.fetch_add(1, Ordering::Relaxed);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(body).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Ok((addr, task))
}

#[cfg(target_os = "linux")]
async fn start_xdp_smoke_tcp_backend(
    connections: std::sync::Arc<AtomicU64>,
) -> anyhow::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let connections = connections.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let Ok(n) = stream.read(&mut buf).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                connections.fetch_add(1, Ordering::Relaxed);
                let _ = stream.write_all(b"xdp-tcp-smoke:").await;
                let _ = stream.write_all(&buf[..n]).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Ok((addr, task))
}

#[cfg(target_os = "linux")]
async fn start_xdp_smoke_udp_backend(
    datagrams: std::sync::Arc<AtomicU64>,
) -> anyhow::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            datagrams.fetch_add(1, Ordering::Relaxed);
            let mut response = Vec::with_capacity("xdp-udp-smoke:".len() + n);
            response.extend_from_slice(b"xdp-udp-smoke:");
            response.extend_from_slice(&buf[..n]);
            let _ = socket.send_to(&response, peer).await;
        }
    });
    Ok((addr, task))
}

#[cfg(target_os = "linux")]
async fn start_xdp_smoke_sni_backend(
    connections: std::sync::Arc<AtomicU64>,
) -> anyhow::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::io::{Read, Write};

    let certs = rustls_pemfile::certs(
        &mut include_bytes!("../../pingora-main/pingora-core/examples/keys/server/cert.pem")
            .as_slice(),
    )
    .collect::<Result<Vec<CertificateDer<'static>>, _>>()?;
    let key = rustls_pemfile::private_key(
        &mut include_bytes!("../../pingora-main/pingora-core/examples/keys/server/key.pem").as_slice(),
    )?
    .ok_or_else(|| anyhow::anyhow!("xdp smoke SNI backend key is missing"))?;
    let mut tls_config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(certs, PrivateKeyDer::clone_key(&key))?;
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls_config = std::sync::Arc::new(tls_config);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let connections = connections.clone();
            let tls_config = tls_config.clone();
            tokio::spawn(async move {
                let Ok(std_stream) = stream.into_std() else {
                    return;
                };
                let result = tokio::task::spawn_blocking(move || {
                    std_stream.set_nonblocking(false)?;
                    let mut tls_stream = rustls::StreamOwned::new(
                        rustls::ServerConnection::new(tls_config)?,
                        std_stream,
                    );
                    let mut request = Vec::with_capacity(512);
                    let mut buf = [0u8; 512];
                    loop {
                        let n = tls_stream.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        request.extend_from_slice(&buf[..n]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                        if request.len() >= 8192 {
                            break;
                        }
                    }
                    connections.fetch_add(1, Ordering::Relaxed);
                    let body = b"xdp-sni-smoke\n";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n",
                        body.len()
                    );
                    tls_stream.write_all(response.as_bytes())?;
                    tls_stream.write_all(body)?;
                    tls_stream.flush()?;
                    anyhow::Ok(())
                })
                .await;
                if let Ok(Err(err)) = result {
                    tracing::debug!("xdp smoke SNI backend connection failed: {}", err);
                }
            });
        }
    });
    Ok((addr, task))
}

#[cfg(target_os = "linux")]
async fn start_xdp_smoke_quic_backend(
    requests: std::sync::Arc<AtomicU64>,
) -> anyhow::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let certs = rustls_pemfile::certs(
        &mut include_bytes!("../../pingora-main/pingora-core/examples/keys/server/cert.pem")
            .as_slice(),
    )
    .collect::<Result<Vec<CertificateDer<'static>>, _>>()?;
    let key = rustls_pemfile::private_key(
        &mut include_bytes!("../../pingora-main/pingora-core/examples/keys/server/key.pem").as_slice(),
    )?
    .ok_or_else(|| anyhow::anyhow!("xdp smoke QUIC backend key is missing"))?;
    let mut tls_config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(certs, PrivateKeyDer::clone_key(&key))?;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let mut server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(std::sync::Arc::new(tls_config))?,
    ));
    if let Some(transport_config) = std::sync::Arc::get_mut(&mut server_config.transport) {
        transport_config.max_concurrent_bidi_streams(32u32.into());
        transport_config.max_concurrent_uni_streams(32u32.into());
    }
    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let addr = endpoint.local_addr()?;
    let task = tokio::spawn(async move {
        while let Some(connecting) = endpoint.accept().await {
            let requests = requests.clone();
            tokio::spawn(async move {
                let Ok(connection) = connecting.await else {
                    return;
                };
                let Ok(mut h3_conn) = h3::server::builder()
                    .build(h3_quinn::Connection::new(connection))
                    .await
                else {
                    return;
                };
                loop {
                    let resolver = match h3_conn.accept().await {
                        Ok(Some(resolver)) => resolver,
                        Ok(None) => break,
                        Err(_) => break,
                    };
                    let requests = requests.clone();
                    tokio::spawn(async move {
                        let Ok((_request, mut stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        requests.fetch_add(1, Ordering::Relaxed);
                        let body = bytes::Bytes::from_static(b"xdp-quic-smoke\n");
                        let Ok(response) = http::Response::builder().status(200).body(()) else {
                            return;
                        };
                        let _ = stream.send_response(response).await;
                        let _ = stream.send_data(body).await;
                        let _ = stream.finish().await;
                    });
                }
            });
        }
    });
    Ok((addr, task))
}

#[cfg(target_os = "linux")]
async fn xdp_proxy_smoke_managers(
    services: &XdpProxySmokeServices,
    ports: &XdpProxySmokePorts,
) -> anyhow::Result<(
    std::sync::Arc<crate::quic_udp_demux::QuicUdpDemuxManager>,
    std::sync::Arc<crate::tcp_proxy::TcpProxyManager>,
    std::sync::Arc<crate::http_proxy_manager::HttpProxyManager>,
)> {
    let store = xdp_proxy_smoke_config_store(services, ports).await;
    let waf_state = std::sync::Arc::new(crate::firewall::state::WafStateManager::new());
    let cert_selector = std::sync::Arc::new(crate::ssl::DynamicCertSelector::new());
    crate::ssl::sync_certs(&cert_selector, &[xdp_proxy_smoke_ssl_cert()]).await;
    let api_config = std::sync::Arc::new(crate::api_config::ApiConfig {
        rpc_endpoints: Vec::new(),
        rpc_disable_update: true,
        node_id: "1".to_string(),
        secret: "xdp-smoke-secret".to_string(),
        billing_count_inbound_traffic: false,
        access_log_pipeline: crate::api_config::AccessLogPipelineConfig::default(),
        relay: crate::api_config::RelayConfig::default(),
        kernel_tuning: crate::api_config::KernelTuningConfig::default(),
    });
    let proxy_logic = crate::proxy::EdgeProxy {
        config: std::sync::Arc::new(store.clone()),
        waf_state: waf_state.clone(),
        api_config: api_config.clone(),
        cert_selector: cert_selector.clone(),
        waf_verifier: std::sync::Arc::new(crate::firewall::verifier::WafVerifier::new(
            &api_config.secret,
        )),
        tls_downstream: false,
    };
    let server_conf =
        std::sync::Arc::new(pingora_core::server::configuration::ServerConf::default());
    let http_manager = crate::http_proxy_manager::HttpProxyManager::new(
        store.clone(),
        cert_selector.clone(),
        proxy_logic.clone(),
        server_conf.clone(),
    );
    let http3_manager = crate::http3_proxy_manager::Http3ProxyManager::new(
        store.clone(),
        cert_selector.clone(),
        proxy_logic,
        server_conf,
    );
    let udp_manager = crate::udp_proxy::UdpProxyManager::new(store.clone(), waf_state.clone(), 1);
    let quic_demux =
        crate::quic_udp_demux::QuicUdpDemuxManager::new(store.clone(), http3_manager, udp_manager);
    let tcp_manager = crate::tcp_proxy::TcpProxyManager::new(store, cert_selector, waf_state, 1);
    Ok((quic_demux, tcp_manager, http_manager))
}

#[cfg(target_os = "linux")]
async fn xdp_proxy_smoke_config_store(
    services: &XdpProxySmokeServices,
    ports: &XdpProxySmokePorts,
) -> crate::config::ConfigStore {
    let store = crate::config::ConfigStore::new();
    let http_server = xdp_proxy_smoke_http_server(ports.http, services.http_addr);
    let https_server = xdp_proxy_smoke_https_server(ports.https, services.https_addr);
    let tcp_server = xdp_proxy_smoke_tcp_server(ports.tcp, services.tcp_addr);
    let udp_server = xdp_proxy_smoke_udp_server(ports.udp, services.udp_addr);
    let h3_server = xdp_proxy_smoke_h3_server(ports.h3, services.h3_addr);
    let sni_server = xdp_proxy_smoke_sni_server(ports.https, services.sni_addr);
    let quic_server = xdp_proxy_smoke_quic_server(ports.h3, services.quic_addr);
    let all_servers = vec![
        http_server,
        https_server,
        tcp_server,
        udp_server,
        h3_server,
        sni_server,
        quic_server,
    ];
    let mut servers = std::collections::HashMap::new();
    let mut routes = std::collections::HashMap::new();
    let mut id_to_lb = std::collections::HashMap::new();

    for server in &all_servers {
        for host in server.get_plain_server_names() {
            servers.insert(host, server.clone());
        }
        if let Some(reverse_proxy) = server.reverse_proxy.as_ref() {
            let (lb, _) = crate::lb_factory::build_lb(
                server.numeric_id(),
                reverse_proxy,
                1,
                &std::collections::HashMap::new(),
                false,
                true,
            );
            id_to_lb.insert(server.numeric_id(), lb.clone());
            for host in server.get_plain_server_names() {
                routes.insert(host, lb.clone());
            }
        }
    }

    let mut global_http = crate::config_models::GlobalHTTPAllConfig::default();
    global_http.allow_lan_ip = true;
    let mut http3_policies = std::collections::HashMap::new();
    http3_policies.insert(
        1,
        crate::config_models::HTTP3Policy {
            is_on: true,
            port: 0,
            support_mobile_browsers: true,
            ..Default::default()
        },
    );
    store
        .update_config(
            1,
            1,
            1,
            1,
            all_servers,
            servers,
            routes,
            id_to_lb,
            vec![],
            vec![],
            vec![],
            vec![xdp_proxy_smoke_ssl_cert()],
            None,
            0,
            1,
            true,
            false,
            std::collections::HashMap::new(),
            false,
            false,
            String::new(),
            std::collections::HashMap::new(),
            None,
            false,
            false,
            String::new(),
            false,
            false,
            0,
            true,
            false,
            false,
            String::new(),
            None,
            Some(global_http),
            vec![],
            vec![],
            vec![],
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            http3_policies,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            None,
            None,
        )
        .await;
    store
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_http_server(
    listen_port: u16,
    backend_addr: std::net::SocketAddr,
) -> std::sync::Arc<crate::config_models::ServerConfig> {
    std::sync::Arc::new(crate::config_models::ServerConfig {
        id: Some(7101),
        is_on: true,
        server_names: vec![crate::config_models::ServerNameConfig {
            name: "xdp-smoke-http.local".to_string(),
            ..Default::default()
        }],
        http: Some(crate::config_models::HTTPConfig {
            is_on: true,
            listen: vec![xdp_proxy_smoke_listen("http", listen_port)],
        }),
        reverse_proxy: Some(xdp_proxy_smoke_reverse_proxy(8101, "http", backend_addr)),
        ..Default::default()
    })
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_https_server(
    listen_port: u16,
    backend_addr: std::net::SocketAddr,
) -> std::sync::Arc<crate::config_models::ServerConfig> {
    std::sync::Arc::new(crate::config_models::ServerConfig {
        id: Some(7104),
        is_on: true,
        server_names: vec![crate::config_models::ServerNameConfig {
            name: "xdp-smoke-https.local".to_string(),
            ..Default::default()
        }],
        https: Some(crate::config_models::HTTPSConfig {
            is_on: true,
            listen: vec![xdp_proxy_smoke_listen("https", listen_port)],
            ssl_policy: None,
            supports_http3: Some(false),
        }),
        reverse_proxy: Some(xdp_proxy_smoke_reverse_proxy(8104, "http", backend_addr)),
        ..Default::default()
    })
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_h3_server(
    listen_port: u16,
    backend_addr: std::net::SocketAddr,
) -> std::sync::Arc<crate::config_models::ServerConfig> {
    std::sync::Arc::new(crate::config_models::ServerConfig {
        id: Some(7105),
        is_on: true,
        server_names: vec![crate::config_models::ServerNameConfig {
            name: "xdp-smoke-h3.local".to_string(),
            ..Default::default()
        }],
        https: Some(crate::config_models::HTTPSConfig {
            is_on: true,
            listen: vec![xdp_proxy_smoke_listen("https", listen_port)],
            ssl_policy: None,
            supports_http3: Some(true),
        }),
        reverse_proxy: Some(xdp_proxy_smoke_reverse_proxy(8105, "http", backend_addr)),
        ..Default::default()
    })
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_sni_server(
    listen_port: u16,
    backend_addr: std::net::SocketAddr,
) -> std::sync::Arc<crate::config_models::ServerConfig> {
    std::sync::Arc::new(crate::config_models::ServerConfig {
        id: Some(7106),
        is_on: true,
        server_names: vec![crate::config_models::ServerNameConfig {
            name: "xdp-smoke-sni.local@sni_passthrough".to_string(),
            ..Default::default()
        }],
        https: Some(crate::config_models::HTTPSConfig {
            is_on: true,
            listen: vec![xdp_proxy_smoke_listen("https", listen_port)],
            ssl_policy: None,
            supports_http3: Some(false),
        }),
        reverse_proxy: Some(xdp_proxy_smoke_reverse_proxy(8106, "tcp", backend_addr)),
        ..Default::default()
    })
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_quic_server(
    listen_port: u16,
    backend_addr: std::net::SocketAddr,
) -> std::sync::Arc<crate::config_models::ServerConfig> {
    std::sync::Arc::new(crate::config_models::ServerConfig {
        id: Some(7107),
        is_on: true,
        server_names: vec![crate::config_models::ServerNameConfig {
            name: "xdp-smoke-quic.local@quic".to_string(),
            ..Default::default()
        }],
        udp: Some(crate::config_models::UDPConfig {
            is_on: true,
            listen: vec![xdp_proxy_smoke_listen("udp", listen_port)],
        }),
        reverse_proxy: Some(xdp_proxy_smoke_reverse_proxy(8107, "udp", backend_addr)),
        ..Default::default()
    })
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_tcp_server(
    listen_port: u16,
    backend_addr: std::net::SocketAddr,
) -> std::sync::Arc<crate::config_models::ServerConfig> {
    std::sync::Arc::new(crate::config_models::ServerConfig {
        id: Some(7102),
        is_on: true,
        server_names: vec![crate::config_models::ServerNameConfig {
            name: "xdp-smoke-tcp.local".to_string(),
            ..Default::default()
        }],
        tcp: Some(crate::config_models::TCPConfig {
            is_on: true,
            listen: vec![xdp_proxy_smoke_listen("tcp", listen_port)],
            tls: None,
        }),
        reverse_proxy: Some(xdp_proxy_smoke_reverse_proxy(8102, "tcp", backend_addr)),
        ..Default::default()
    })
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_udp_server(
    listen_port: u16,
    backend_addr: std::net::SocketAddr,
) -> std::sync::Arc<crate::config_models::ServerConfig> {
    std::sync::Arc::new(crate::config_models::ServerConfig {
        id: Some(7103),
        is_on: true,
        server_names: vec![crate::config_models::ServerNameConfig {
            name: "xdp-smoke-udp.local".to_string(),
            ..Default::default()
        }],
        udp: Some(crate::config_models::UDPConfig {
            is_on: true,
            listen: vec![xdp_proxy_smoke_listen("udp", listen_port)],
        }),
        reverse_proxy: Some(xdp_proxy_smoke_reverse_proxy(8103, "udp", backend_addr)),
        ..Default::default()
    })
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_listen(protocol: &str, port: u16) -> crate::config_models::NetworkAddressConfig {
    crate::config_models::NetworkAddressConfig {
        protocol: Some(protocol.to_string()),
        host: Some("0.0.0.0".to_string()),
        port_range: Some(port.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_reverse_proxy(
    origin_id: i64,
    protocol: &str,
    backend_addr: std::net::SocketAddr,
) -> crate::config_models::ReverseProxyConfig {
    crate::config_models::ReverseProxyConfig {
        is_on: true,
        primary_origins: vec![crate::config_models::OriginConfig {
            id: origin_id,
            name: format!("xdp-smoke-origin-{origin_id}"),
            addr: Some(crate::config_models::FlexibleAddr::Object(
                crate::config_models::NetworkAddressConfig {
                    protocol: Some(protocol.to_string()),
                    host: Some(backend_addr.ip().to_string()),
                    port_range: Some(backend_addr.port().to_string()),
                },
            )),
            is_on: true,
            weight: 1,
            health_check: None,
            request_host: String::new(),
            follow_host: false,
            follow_port: false,
            http2_enabled: false,
            http3_enabled: false,
            conn_timeout: None,
            read_timeout: None,
            idle_timeout: None,
            write_timeout: None,
            cert: None,
            tls_security_verify_mode: crate::config_models::OriginTlsSecurityVerifyMode::Skip,
            tls_verify: None,
            oss: None,
        }],
        backup_origins: Vec::new(),
        scheduling: None,
        request_host: String::new(),
        request_host_type: 0,
        request_host_excluding_port: false,
        proxy_protocol: crate::config_models::ProxyProtocolConfig::default(),
    }
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_ssl_cert() -> crate::config_models::SSLCertConfig {
    crate::config_models::SSLCertConfig {
        id: 7104,
        is_on: true,
        is_default: true,
        cert_data_json: Some(serde_json::json!(include_str!(
            "../../pingora-main/pingora-core/examples/keys/server/cert.pem"
        ))),
        key_data_json: Some(serde_json::json!(include_str!(
            "../../pingora-main/pingora-core/examples/keys/server/key.pem"
        ))),
        dns_names: vec![
            "xdp-smoke-https.local".to_string(),
            "xdp-smoke-h3.local".to_string(),
            "xdp-smoke-sni.local".to_string(),
        ],
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn raw_smoke(
    _duration: std::time::Duration,
    _ready_file: Option<std::path::PathBuf>,
) -> anyhow::Result<serde_json::Value> {
    anyhow::bail!("XDP raw smoke is supported on Linux only")
}

#[cfg(not(target_os = "linux"))]
pub async fn proxy_smoke(
    _duration: std::time::Duration,
    _ready_file: Option<std::path::PathBuf>,
    _kernel_mode: bool,
    _remote: Option<std::net::IpAddr>,
) -> anyhow::Result<serde_json::Value> {
    anyhow::bail!("XDP proxy smoke is supported on Linux only")
}

#[cfg(not(target_os = "linux"))]
pub async fn proxy_reload_smoke(
    _duration: std::time::Duration,
    _ready_file: Option<std::path::PathBuf>,
) -> anyhow::Result<serde_json::Value> {
    anyhow::bail!("XDP proxy reload smoke is supported on Linux only")
}

#[cfg(not(target_os = "linux"))]
pub async fn dial_smoke(
    _target: std::net::SocketAddr,
    _duration: std::time::Duration,
    _ready_file: Option<std::path::PathBuf>,
    _payload: Vec<u8>,
    _send_interval: std::time::Duration,
    _reload_at: Option<std::time::Duration>,
) -> anyhow::Result<serde_json::Value> {
    anyhow::bail!("XDP dial smoke is supported on Linux only")
}
