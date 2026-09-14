use super::*;
use crate::firewall::kernel::{KernelFilterRange, KernelFilterSnapshot};

fn test_proxy_config(interface: &str) -> XdpConfig {
    XdpConfig {
        enabled: true,
        interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
            name: interface.to_string(),
            queues: vec![0],
            cpus: Vec::new(),
            mode: XdpRuntimeMode::Proxy,
            ..Default::default()
        }],
        proxy: crate::runtime_mode::XdpProxyConfig {
            ports: vec![crate::runtime_mode::XdpProxyPortConfig {
                protocol: XdpProxyProtocol::Udp,
                port: 443,
            }],
            ..Default::default()
        },
        ..XdpConfig::default()
    }
}

fn mark_test_proxy_bridge_ready(manager: &std::sync::Arc<XdpManager>) {
    let interface = manager.config.interfaces[0].name.clone();
    let queue = manager.config.interfaces[0].queues[0];
    manager.attached.write().insert(interface.clone());
    *manager.xsk_status.write() = vec![XdpQueueStatus {
        interface,
        queue,
        configured: true,
        socket_created: true,
        registered: true,
        ready: true,
        detail: "AF_XDP ready".to_string(),
        ..Default::default()
    }];
    manager
        .proxy_redirect_enabled
        .store(true, Ordering::Relaxed);
}

#[test]
fn xdp_shadow_rules_prefer_allow_over_block() {
    let manager = XdpManager::new(XdpConfig {
        enabled: true,
        ..XdpConfig::default()
    });
    let now = crate::utils::time::now_timestamp();
    manager.sync_snapshot(&KernelFilterSnapshot {
        blocked_ips: vec![("192.0.2.10".parse().unwrap(), now + 60)],
        allowed_ips: vec![("192.0.2.10".parse().unwrap(), now + 60)],
        ..KernelFilterSnapshot::default()
    });
    assert_eq!(
        manager.rule_verdict_for_ip("192.0.2.10".parse().unwrap()),
        XdpRuleVerdict::Allow
    );
}

#[test]
fn xdp_shadow_rules_match_network_and_range() {
    let manager = XdpManager::new(XdpConfig {
        enabled: true,
        ..XdpConfig::default()
    });
    let now = crate::utils::time::now_timestamp();
    manager.sync_snapshot(&KernelFilterSnapshot {
        blocked_networks: vec![("198.51.100.0/24".parse().unwrap(), now + 60)],
        blocked_ranges: vec![KernelFilterRange {
            from: u32::from_be_bytes([203, 0, 113, 10]) as u128,
            to: u32::from_be_bytes([203, 0, 113, 20]) as u128,
            v6: false,
            expires_at: now + 60,
        }],
        ..KernelFilterSnapshot::default()
    });
    assert_eq!(
        manager.rule_verdict_for_ip("198.51.100.9".parse().unwrap()),
        XdpRuleVerdict::Block
    );
    assert_eq!(
        manager.rule_verdict_for_ip("203.0.113.15".parse().unwrap()),
        XdpRuleVerdict::Block
    );
    assert_eq!(
        manager.rule_verdict_for_ip("203.0.113.30".parse().unwrap()),
        XdpRuleVerdict::Pass
    );
}

#[test]
fn xdp_rule_sweeper_removes_expired_shadow_rules() {
    let manager = XdpManager::new(XdpConfig {
        enabled: true,
        ..XdpConfig::default()
    });
    let now = crate::utils::time::now_timestamp();
    let expired_ip: IpAddr = "192.0.2.1".parse().unwrap();
    let active_ip: IpAddr = "192.0.2.2".parse().unwrap();
    let expired_net: IpNet = "198.51.100.0/24".parse().unwrap();
    let active_net: IpNet = "203.0.113.0/24".parse().unwrap();
    let expired_range = RangeKey {
        from: u32::from_be_bytes([198, 51, 100, 10]) as u128,
        to: u32::from_be_bytes([198, 51, 100, 20]) as u128,
        v6: false,
    };
    let active_range = RangeKey {
        from: u32::from_be_bytes([203, 0, 113, 10]) as u128,
        to: u32::from_be_bytes([203, 0, 113, 20]) as u128,
        v6: false,
    };

    {
        let mut state = manager.state.write();
        state.blocked_ips.insert(expired_ip, now - 1);
        state.blocked_ips.insert(active_ip, now + 60);
        state
            .blocked_networks
            .insert(expired_net.to_string(), (expired_net, now - 1));
        state
            .blocked_networks
            .insert(active_net.to_string(), (active_net, now + 60));
        state.blocked_ranges.insert(expired_range.clone(), now - 1);
        state.blocked_ranges.insert(active_range.clone(), now + 60);
    }

    assert!(manager.sweep_expired_rules());
    {
        let state = manager.state.read();
        assert!(!state.blocked_ips.contains_key(&expired_ip));
        assert!(state.blocked_ips.contains_key(&active_ip));
        assert!(!state
            .blocked_networks
            .contains_key(&expired_net.to_string()));
        assert!(state.blocked_networks.contains_key(&active_net.to_string()));
        assert!(!state.blocked_ranges.contains_key(&expired_range));
        assert!(state.blocked_ranges.contains_key(&active_range));
    }
    assert_eq!(
        manager.rule_verdict_for_ip(active_ip),
        XdpRuleVerdict::Block
    );
    assert!(!manager.sweep_expired_rules());
}

#[test]
fn xdp_rule_sweeper_stop_invalidates_running_generation() {
    let manager = XdpManager::new(XdpConfig {
        enabled: true,
        ..XdpConfig::default()
    });

    assert_eq!(manager.rule_sweeper_generation.load(Ordering::Relaxed), 0);
    assert!(!manager.rule_sweeper_started.swap(true, Ordering::Relaxed));

    manager.stop_rule_sweeper();

    assert_eq!(manager.rule_sweeper_generation.load(Ordering::Relaxed), 1);
    assert!(!manager.rule_sweeper_started.load(Ordering::Relaxed));
    assert!(!manager.rule_sweeper_started.swap(true, Ordering::Relaxed));
}

#[test]
fn xdp_reload_manager_replacement_preserves_active_rules() {
    let _guard = crate::runtime_mode::runtime_config_test_guard();
    let first_config = XdpConfig {
        enabled: true,
        interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
            name: "eth-old".to_string(),
            queues: vec![0],
            cpus: Vec::new(),
            mode: XdpRuntimeMode::Protect,
            ..Default::default()
        }],
        ..XdpConfig::default()
    };
    RuntimeConfig::set_current(RuntimeConfig {
        xdp: first_config,
        ..RuntimeConfig::default()
    });

    let old_manager = replace_manager_from_runtime();
    let now = crate::utils::time::now_timestamp();
    old_manager.sync_snapshot(&KernelFilterSnapshot {
        blocked_ips: vec![("192.0.2.10".parse().unwrap(), now + 60)],
        allowed_networks: vec![("198.51.100.0/24".parse().unwrap(), now + 60)],
        blocked_ranges: vec![KernelFilterRange {
            from: u32::from_be_bytes([203, 0, 113, 10]) as u128,
            to: u32::from_be_bytes([203, 0, 113, 20]) as u128,
            v6: false,
            expires_at: now + 60,
        }],
        ..KernelFilterSnapshot::default()
    });
    let snapshot = old_manager.active_rule_snapshot();

    RuntimeConfig::set_current(RuntimeConfig {
        xdp: XdpConfig {
            enabled: true,
            interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
                name: "eth-new".to_string(),
                queues: vec![1],
                cpus: Vec::new(),
                mode: XdpRuntimeMode::Proxy,
                ..Default::default()
            }],
            ..XdpConfig::default()
        },
        ..RuntimeConfig::default()
    });

    let new_manager = replace_manager_from_runtime();
    new_manager.sync_snapshot(&snapshot);

    assert_eq!(new_manager.config.interfaces[0].name, "eth-new");
    assert_eq!(
        new_manager.rule_verdict_for_ip("192.0.2.10".parse().unwrap()),
        XdpRuleVerdict::Block
    );
    assert_eq!(
        new_manager.rule_verdict_for_ip("198.51.100.42".parse().unwrap()),
        XdpRuleVerdict::Allow
    );
    assert_eq!(
        new_manager.rule_verdict_for_ip("203.0.113.15".parse().unwrap()),
        XdpRuleVerdict::Block
    );
}

#[test]
fn xdp_manager_current_identity_changes_after_replacement() {
    let _guard = crate::runtime_mode::runtime_config_test_guard();
    RuntimeConfig::set_current(RuntimeConfig {
        xdp: test_proxy_config("eth-old"),
        ..RuntimeConfig::default()
    });
    let old_manager = replace_manager_from_runtime();
    assert!(manager_is_current(&old_manager));

    RuntimeConfig::set_current(RuntimeConfig {
        xdp: test_proxy_config("eth-new"),
        ..RuntimeConfig::default()
    });
    let new_manager = replace_manager_from_runtime();

    assert!(!manager_is_current(&old_manager));
    assert!(manager_is_current(&new_manager));
}

#[test]
fn xdp_runtime_disabled_replaces_stale_attached_manager() {
    let _guard = crate::runtime_mode::runtime_config_test_guard();
    let enabled_config = test_proxy_config("eth-stale");
    RuntimeConfig::set_current(RuntimeConfig {
        xdp: enabled_config.clone(),
        ..RuntimeConfig::default()
    });
    let old_manager = replace_manager_from_runtime();
    mark_test_proxy_bridge_ready(&old_manager);
    assert!(old_manager.status().attached);

    let mut disabled_config = enabled_config;
    disabled_config.enabled = false;
    RuntimeConfig::set_current(RuntimeConfig {
        xdp: disabled_config,
        ..RuntimeConfig::default()
    });

    let disabled_manager = manager_from_runtime();
    let status = disabled_manager.status();
    assert!(!std::sync::Arc::ptr_eq(&old_manager, &disabled_manager));
    assert!(!status.enabled);
    assert!(!status.available);
    assert!(!status.attached);
    assert!(status.fallback_reason.is_empty());
}

#[cfg(any(test, target_os = "linux"))]
#[test]
fn xdp_proxy_bridge_lifecycle_stops_on_reload_detach_and_degrade() {
    let _guard = crate::runtime_mode::runtime_config_test_guard();
    RuntimeConfig::set_current(RuntimeConfig {
        xdp: test_proxy_config("eth-old"),
        ..RuntimeConfig::default()
    });
    let old_manager = replace_manager_from_runtime();
    mark_test_proxy_bridge_ready(&old_manager);
    assert!(af_xdp::proxy_bridge_should_continue(&old_manager));

    RuntimeConfig::set_current(RuntimeConfig {
        xdp: test_proxy_config("eth-new"),
        ..RuntimeConfig::default()
    });
    let new_manager = replace_manager_from_runtime();
    mark_test_proxy_bridge_ready(&new_manager);

    assert!(!af_xdp::proxy_bridge_should_continue(&old_manager));
    assert!(af_xdp::proxy_bridge_should_continue(&new_manager));

    new_manager.mark_proxy_dataplane_degraded("test forced degraded");
    assert!(!af_xdp::proxy_bridge_should_continue(&new_manager));
}

#[test]
#[cfg(target_os = "linux")]
fn apply_rule_diff_adds_removes_only_deltas() {
    use std::net::IpAddr;

    let old_state = RuleState {
        blocked_ips: [
            ("192.0.2.1".parse::<IpAddr>().unwrap(), 9999),
            ("192.0.2.2".parse::<IpAddr>().unwrap(), 9999),
        ]
        .into_iter()
        .collect(),
        allowed_ips: [("198.51.100.1".parse::<IpAddr>().unwrap(), 9999)]
            .into_iter()
            .collect(),
        blocked_networks: [(
            "203.0.113.0/24".to_string(),
            ("203.0.113.0/24".parse::<IpNet>().unwrap(), 9999),
        )]
        .into_iter()
        .collect(),
        allowed_networks: Default::default(),
        blocked_ranges: Default::default(),
        allowed_ranges: Default::default(),
    };

    let new_state = RuleState {
        blocked_ips: [
            ("192.0.2.2".parse::<IpAddr>().unwrap(), 9999), // kept
            ("192.0.2.3".parse::<IpAddr>().unwrap(), 9999), // added
        ]
        .into_iter()
        .collect(),
        allowed_ips: [
            ("198.51.100.1".parse::<IpAddr>().unwrap(), 9999), // kept
            ("198.51.100.2".parse::<IpAddr>().unwrap(), 9999), // added
        ]
        .into_iter()
        .collect(),
        blocked_networks: Default::default(), // entire network removed
        allowed_networks: [(
            "2001:db8::/32".to_string(),
            ("2001:db8::/32".parse::<IpNet>().unwrap(), 9999),
        )]
        .into_iter()
        .collect(),
        blocked_ranges: Default::default(),
        allowed_ranges: Default::default(),
    };

    let old_img = super::linux::rule_map_images(&old_state);
    let new_img = super::linux::rule_map_images(&new_state);

    // Exact v4 blocked: 192.0.2.1 removed, 192.0.2.3 added, 192.0.2.2 kept (no-op)
    assert!(old_img
        .blocked_v4
        .contains_key(&u32::from_be_bytes([192, 0, 2, 1])));
    assert!(old_img
        .blocked_v4
        .contains_key(&u32::from_be_bytes([192, 0, 2, 2])));
    assert!(!old_img
        .blocked_v4
        .contains_key(&u32::from_be_bytes([192, 0, 2, 3])));

    assert!(!new_img
        .blocked_v4
        .contains_key(&u32::from_be_bytes([192, 0, 2, 1])));
    assert!(new_img
        .blocked_v4
        .contains_key(&u32::from_be_bytes([192, 0, 2, 2])));
    assert!(new_img
        .blocked_v4
        .contains_key(&u32::from_be_bytes([192, 0, 2, 3])));

    // Exact v4 allowed: 198.51.100.2 added, 198.51.100.1 kept
    assert!(old_img
        .allowed_v4
        .contains_key(&u32::from_be_bytes([198, 51, 100, 1])));
    assert!(!old_img
        .allowed_v4
        .contains_key(&u32::from_be_bytes([198, 51, 100, 2])));

    assert!(new_img
        .allowed_v4
        .contains_key(&u32::from_be_bytes([198, 51, 100, 1])));
    assert!(new_img
        .allowed_v4
        .contains_key(&u32::from_be_bytes([198, 51, 100, 2])));

    // LPM v4 blocked: 203.0.113.0/24 removed
    assert!(!old_img.blocked_v4_lpm.is_empty());
    assert!(new_img.blocked_v4_lpm.is_empty());

    // LPM v6 allowed: 2001:db8::/32 added
    assert!(old_img.allowed_v6_lpm.is_empty());
    assert!(!new_img.allowed_v6_lpm.is_empty());
}

#[cfg(any(test, target_os = "linux"))]
#[test]
fn xdp_proxy_bridge_lifecycle_continues_only_when_ready() {
    let _guard = crate::runtime_mode::runtime_config_test_guard();
    RuntimeConfig::set_current(RuntimeConfig {
        xdp: test_proxy_config("eth-new"),
        ..RuntimeConfig::default()
    });
    let new_manager = replace_manager_from_runtime();
    mark_test_proxy_bridge_ready(&new_manager);
    assert!(af_xdp::proxy_bridge_should_continue(&new_manager));

    new_manager.attached.write().clear();
    new_manager
        .proxy_redirect_enabled
        .store(false, Ordering::Relaxed);
    assert!(!af_xdp::proxy_bridge_should_continue(&new_manager));

    mark_test_proxy_bridge_ready(&new_manager);
    assert!(af_xdp::proxy_bridge_should_continue(&new_manager));
    new_manager.mark_proxy_dataplane_degraded(
        "AF_XDP proxy bridge poll failed repeatedly; proxy redirect disabled, traffic will PASS",
    );
    assert!(!af_xdp::proxy_bridge_should_continue(&new_manager));
}

#[test]
fn xdp_rule_value_monotonic_deadline_controls_active_match() {
    let legacy = cloud_node_xdp_common::XdpRuleValue::new(
        10,
        0,
        cloud_node_xdp_common::XdpRuleValue::FLAG_BLOCK,
    );
    assert!(legacy.is_active_at_mono(u64::MAX));

    let active = cloud_node_xdp_common::XdpRuleValue::with_monotonic_deadline(
        10,
        1_000,
        0,
        cloud_node_xdp_common::XdpRuleValue::FLAG_BLOCK,
    );
    assert!(active.is_active_at_mono(999));
    assert!(!active.is_active_at_mono(1_000));
}

#[test]
fn xdp_range_to_nets_covers_only_requested_span() {
    let range = RangeKey {
        from: u32::from_be_bytes([203, 0, 113, 10]) as u128,
        to: u32::from_be_bytes([203, 0, 113, 20]) as u128,
        v6: false,
    };
    let nets = range_to_nets(&range);
    assert!(!nets.is_empty());
    for last_octet in 10..=20 {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, last_octet));
        assert!(nets.iter().any(|net| net.contains(&ip)));
    }
    assert!(!nets
        .iter()
        .any(|net| net.contains(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)))));
    assert!(!nets
        .iter()
        .any(|net| net.contains(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 21)))));
}

#[test]
fn doctor_reports_missing_interface_when_enabled() {
    let report = doctor_report_for_config(&XdpConfig {
        enabled: true,
        ..XdpConfig::default()
    });
    assert!(report.contains("interfaces is empty"));
}

#[test]
fn xdp_doctor_warns_proxy_without_ports() {
    let report = doctor_report_for_config(&XdpConfig {
        enabled: true,
        interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
            name: "eth0".to_string(),
            queues: vec![0, 1],
            mode: XdpRuntimeMode::Proxy,
            ..Default::default()
        }],
        ..XdpConfig::default()
    });
    assert!(report.contains("proxy mode has no xdp.proxy.ports entries"));
}

#[test]
fn xdp_doctor_warns_proxy_without_local_ips() {
    let report = doctor_report_for_config(&XdpConfig {
        enabled: true,
        interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
            name: "eth0".to_string(),
            queues: vec![0],
            cpus: Vec::new(),
            mode: XdpRuntimeMode::Proxy,
            ..Default::default()
        }],
        proxy: crate::runtime_mode::XdpProxyConfig {
            ports: vec![crate::runtime_mode::XdpProxyPortConfig {
                protocol: XdpProxyProtocol::Udp,
                port: 443,
            }],
            ..Default::default()
        },
        ..XdpConfig::default()
    });

    assert!(report.contains("proxy mode has no localIps"));
}

#[test]
fn xdp_doctor_rejects_proxy_jumbo_frame_size() {
    let report = doctor_report_for_config(&XdpConfig {
        enabled: true,
        interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
            name: "eth0".to_string(),
            queues: vec![0],
            cpus: Vec::new(),
            mode: XdpRuntimeMode::Proxy,
            frame_size: 4096,
            ..Default::default()
        }],
        proxy: crate::runtime_mode::XdpProxyConfig {
            ports: vec![crate::runtime_mode::XdpProxyPortConfig {
                protocol: XdpProxyProtocol::Udp,
                port: 443,
            }],
            ..Default::default()
        },
        ..XdpConfig::default()
    });

    assert!(
        report.contains(&format!(
            "requires frameSize={}",
            cloud_node_xdp_common::XDP_DEFAULT_FRAME_SIZE
        )),
        "doctor report should reject jumbo proxy frames: {report}"
    );
    assert!(
        report.contains("until jumbo/multi-buffer support is enabled"),
        "doctor report should mention jumbo/multi-buffer gating: {report}"
    );
}

#[tokio::test]
async fn xdp_initialize_fallbacks_proxy_jumbo_frame_size() {
    let manager = XdpManager::new(XdpConfig {
        enabled: true,
        interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
            name: "eth0".to_string(),
            queues: vec![0],
            cpus: Vec::new(),
            mode: XdpRuntimeMode::Proxy,
            frame_size: 4096,
            ..Default::default()
        }],
        ..XdpConfig::default()
    });

    manager
        .initialize()
        .await
        .expect("fallback mode should not fail start");
    let status = manager.status();
    assert!(!status.available);
    assert!(!status.attached);
    assert!(
        status.fallback_reason.contains(&format!(
            "frameSize={}",
            cloud_node_xdp_common::XDP_DEFAULT_FRAME_SIZE
        )),
        "fallback reason should reject jumbo proxy frames: {}",
        status.fallback_reason
    );
}

#[tokio::test]
async fn xdp_initialize_fail_start_rejects_proxy_jumbo_frame_size() {
    let manager = XdpManager::new(XdpConfig {
        enabled: true,
        fallback: crate::runtime_mode::XdpFallbackMode::FailStart,
        interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
            name: "eth0".to_string(),
            queues: vec![0],
            cpus: Vec::new(),
            mode: XdpRuntimeMode::Proxy,
            frame_size: 4096,
            ..Default::default()
        }],
        ..XdpConfig::default()
    });

    let err = manager
        .initialize()
        .await
        .expect_err("fail-start must reject");
    let err = err.to_string();
    assert!(
        err.contains(&format!(
            "frameSize={}",
            cloud_node_xdp_common::XDP_DEFAULT_FRAME_SIZE
        )),
        "fail-start should reject jumbo proxy frames: {err}"
    );
}

#[test]
fn xdp_protocol_mapping_uses_l4_protocol_numbers() {
    assert_eq!(
        xdp_ip_proto(&XdpProxyProtocol::Https),
        cloud_node_xdp_common::XDP_PROTO_TCP
    );
    assert_eq!(
        xdp_ip_proto(&XdpProxyProtocol::H3),
        cloud_node_xdp_common::XDP_PROTO_UDP
    );
}

#[test]
fn xdp_dataplane_supports_tcp_udp_and_h3_proxy_protocols() {
    assert!(xdp_protocol_dataplane_supported(&XdpProxyProtocol::Http));
    assert!(xdp_protocol_dataplane_supported(&XdpProxyProtocol::Https));
    assert!(xdp_protocol_dataplane_supported(&XdpProxyProtocol::Tcp));
    assert!(xdp_protocol_dataplane_supported(&XdpProxyProtocol::Udp));
    assert!(xdp_protocol_dataplane_supported(&XdpProxyProtocol::H3));
}

#[test]
fn xdp_tcp_dataplane_is_supported_without_diagnostic_gate() {
    assert!(xdp_tcp_dataplane_supported());
    assert!(xdp_protocol_dataplane_supported(&XdpProxyProtocol::Http));
    assert!(xdp_protocol_dataplane_supported(&XdpProxyProtocol::Https));
    assert!(xdp_protocol_dataplane_supported(&XdpProxyProtocol::Tcp));
}

#[test]
fn xdp_status_reports_tcp_ports_supported_but_not_ready_without_xsk() {
    let manager = XdpManager::new(XdpConfig {
        enabled: true,
        interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
            name: "eth0".to_string(),
            queues: vec![0],
            cpus: Vec::new(),
            mode: XdpRuntimeMode::Proxy,
            local_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))],
            ..Default::default()
        }],
        proxy: crate::runtime_mode::XdpProxyConfig {
            ports: vec![crate::runtime_mode::XdpProxyPortConfig {
                protocol: XdpProxyProtocol::Tcp,
                port: 8443,
            }],
            ..Default::default()
        },
        ..XdpConfig::default()
    });

    let status = manager.status();
    assert!(!status.tcp_dataplane_ready);
    assert!(status.tcp_dataplane_detail.is_empty());
    assert_eq!(status.proxy_ports, 1);
    assert_eq!(status.proxy_supported_ports, 1);
    assert_eq!(status.proxy_unsupported_ports, 0);
}

#[test]
fn xdp_doctor_reports_tcp_ports_as_supported() {
    let report = doctor_report_for_config(&XdpConfig {
        enabled: true,
        interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
            name: "eth0".to_string(),
            queues: vec![0],
            cpus: Vec::new(),
            mode: XdpRuntimeMode::Proxy,
            local_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))],
            ..Default::default()
        }],
        proxy: crate::runtime_mode::XdpProxyConfig {
            ports: vec![crate::runtime_mode::XdpProxyPortConfig {
                protocol: XdpProxyProtocol::Https,
                port: 443,
            }],
            ..Default::default()
        },
        ..XdpConfig::default()
    });

    assert!(report.contains("dataplane:     AF_XDP proxy ports supported=1 total=1"));
    assert!(!report.contains("warning:"));
}

#[test]
fn xdp_dump_maps_exposes_tcp_dataplane_support() {
    let manager = XdpManager::new(XdpConfig {
        enabled: true,
        proxy: crate::runtime_mode::XdpProxyConfig {
            ports: vec![crate::runtime_mode::XdpProxyPortConfig {
                protocol: XdpProxyProtocol::Tcp,
                port: 8443,
            }],
            ..Default::default()
        },
        ..XdpConfig::default()
    });

    let maps = manager.dump_maps();
    assert_eq!(maps["tcpDataplane"]["ready"], true);
    assert_eq!(
        maps["tcpDataplane"]["detail"].as_str().unwrap_or_default(),
        ""
    );
}

#[test]
fn xdp_dump_maps_exposes_local_ip_filter_state() {
    let manager = XdpManager::new(XdpConfig {
        enabled: true,
        interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
            name: "eth0".to_string(),
            queues: vec![0],
            cpus: Vec::new(),
            mode: XdpRuntimeMode::Proxy,
            local_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))],
            ..Default::default()
        }],
        ..XdpConfig::default()
    });

    let maps = manager.dump_maps();
    assert_eq!(maps["interfaces"][0]["name"], "eth0");
    assert_eq!(maps["interfaces"][0]["localIpFilter"], true);
    assert_eq!(maps["interfaces"][0]["localIps"][0], "198.51.100.5");
}

#[test]
fn xdp_partial_proxy_detail_is_empty_for_supported_protocols() {
    let config = XdpConfig {
        enabled: true,
        proxy: crate::runtime_mode::XdpProxyConfig {
            ports: vec![
                crate::runtime_mode::XdpProxyPortConfig {
                    protocol: XdpProxyProtocol::Https,
                    port: 443,
                },
                crate::runtime_mode::XdpProxyPortConfig {
                    protocol: XdpProxyProtocol::Tcp,
                    port: 8443,
                },
                crate::runtime_mode::XdpProxyPortConfig {
                    protocol: XdpProxyProtocol::Udp,
                    port: 443,
                },
            ],
            ..Default::default()
        },
        ..XdpConfig::default()
    };

    assert_eq!(xdp_supported_proxy_port_count(&config), 3);
    assert!(xdp_unsupported_proxy_protocols(&config).is_empty());
    assert!(xdp_proxy_partial_detail(&config).is_empty());

    let manager = XdpManager::new(config);
    let status = manager.status();
    assert_eq!(status.proxy_ports, 3);
    assert_eq!(status.proxy_supported_ports, 3);
    assert_eq!(status.proxy_unsupported_ports, 0);
}

#[test]
fn xdp_proxy_port_status_counts_dataplane_support() {
    let manager = XdpManager::new(XdpConfig {
        enabled: true,
        proxy: crate::runtime_mode::XdpProxyConfig {
            ports: vec![
                crate::runtime_mode::XdpProxyPortConfig {
                    protocol: XdpProxyProtocol::Https,
                    port: 443,
                },
                crate::runtime_mode::XdpProxyPortConfig {
                    protocol: XdpProxyProtocol::Udp,
                    port: 443,
                },
            ],
            ..Default::default()
        },
        ..XdpConfig::default()
    });

    let ports = manager
        .config
        .proxy
        .ports
        .iter()
        .map(|port| {
            serde_json::json!({
                "protocol": port.protocol.as_str(),
                "port": port.port,
                "dataplaneSupported": xdp_protocol_dataplane_supported(&port.protocol),
            })
        })
        .collect::<Vec<_>>();

    assert_eq!(ports[0]["dataplaneSupported"], true);
    assert_eq!(ports[1]["dataplaneSupported"], true);
    let status = manager.status();
    assert_eq!(status.proxy_supported_ports, 2);
    assert_eq!(status.proxy_unsupported_ports, 0);
}

#[test]
fn xdp_proxy_port_key_uses_network_order_bytes() {
    let key = cloud_node_xdp_common::XdpPortProtoKey {
        port_be: 443u16.to_be(),
        proto: cloud_node_xdp_common::XDP_PROTO_TCP,
        _pad: 0,
    };

    assert_eq!(key.port_be.to_ne_bytes(), 443u16.to_be_bytes());
}

#[test]
fn xdp_local_ip_keys_are_interface_scoped_and_network_ordered() {
    let v4 = cloud_node_xdp_common::host::local_ipv4_key(7, Ipv4Addr::new(198, 51, 100, 5));
    let v6 = cloud_node_xdp_common::host::local_ipv6_key(
        9,
        "2001:db8::443".parse::<Ipv6Addr>().unwrap(),
    );

    assert_eq!(v4.ifindex, 7);
    assert_eq!(v4.addr_be.to_be_bytes(), [198, 51, 100, 5]);
    assert_eq!(v6.ifindex, 9);
    assert_eq!(
        v6.addr,
        "2001:db8::443".parse::<Ipv6Addr>().unwrap().octets()
    );
}

#[test]
fn xdp_status_reports_configured_proxy_queues() {
    let manager = XdpManager::new(XdpConfig {
        enabled: true,
        interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
            name: "eth0".to_string(),
            queues: vec![0, 1],
            mode: XdpRuntimeMode::Proxy,
            ..Default::default()
        }],
        ..XdpConfig::default()
    });

    let status = manager.status();
    assert_eq!(status.xsk_configured_queues, 2);
    assert_eq!(status.xsk_ready_queues, 0);
    assert!(!status.proxy_ready);
    assert_eq!(status.interfaces[0].xsk_queues.len(), 2);
}

#[test]
fn xdp_proxy_ready_requires_explicit_redirect_enable_after_xsk_registration() {
    let manager = XdpManager::new(XdpConfig {
        enabled: true,
        interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
            name: "eth0".to_string(),
            queues: vec![0],
            cpus: Vec::new(),
            mode: XdpRuntimeMode::Proxy,
            ..Default::default()
        }],
        proxy: crate::runtime_mode::XdpProxyConfig {
            ports: vec![crate::runtime_mode::XdpProxyPortConfig {
                protocol: XdpProxyProtocol::Udp,
                port: 443,
            }],
            ..Default::default()
        },
        ..XdpConfig::default()
    });
    manager.attached.write().insert("eth0".to_string());
    *manager.xsk_status.write() = vec![XdpQueueStatus {
        interface: "eth0".to_string(),
        queue: 0,
        configured: true,
        socket_created: true,
        registered: true,
        ready: true,
        detail: "AF_XDP socket registered".to_string(),
        ..Default::default()
    }];

    let status = manager.status();
    assert!(status.interfaces[0].xsk_ready);
    assert!(!status.proxy_ready);
    assert!(!status.proxy_redirect_enabled);
    assert!(status.interfaces[0]
        .detail
        .contains("redirect disabled until proxy bridge starts"));

    manager
        .proxy_redirect_enabled
        .store(true, Ordering::Relaxed);
    let status = manager.status();
    assert!(status.proxy_ready);
    assert!(status.proxy_redirect_enabled);
}

#[test]
fn xdp_status_force_write_bypasses_rate_limit() {
    let manager = XdpManager::new(XdpConfig::default());

    assert!(manager.claim_status_write_slot(100, false));
    assert!(!manager.claim_status_write_slot(105, false));
    assert_eq!(manager.last_state_write_at.load(Ordering::Relaxed), 100);

    assert!(manager.claim_status_write_slot(105, true));
    assert_eq!(manager.last_state_write_at.load(Ordering::Relaxed), 105);
    assert!(!manager.claim_status_write_slot(106, false));
}

#[test]
fn xdp_proxy_degradation_disables_ready_queues() {
    let manager = XdpManager::new(XdpConfig {
        enabled: true,
        interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
            name: "eth0".to_string(),
            queues: vec![0],
            cpus: Vec::new(),
            mode: XdpRuntimeMode::Proxy,
            ..Default::default()
        }],
        proxy: crate::runtime_mode::XdpProxyConfig {
            ports: vec![crate::runtime_mode::XdpProxyPortConfig {
                protocol: XdpProxyProtocol::Udp,
                port: 443,
            }],
            ..Default::default()
        },
        ..XdpConfig::default()
    });
    *manager.xsk_status.write() = vec![
        XdpQueueStatus {
            interface: "eth0".to_string(),
            queue: 0,
            configured: true,
            socket_created: true,
            registered: true,
            ready: true,
            detail: "AF_XDP ready".to_string(),
            ..Default::default()
        },
        XdpQueueStatus {
            interface: "eth0".to_string(),
            queue: 1,
            configured: true,
            detail: "AF_XDP socket setup failed".to_string(),
            ..Default::default()
        },
    ];

    manager
        .proxy_redirect_enabled
        .store(true, Ordering::Relaxed);
    assert!(manager.proxy_redirect_ready());
    manager.mark_proxy_dataplane_degraded(
        "AF_XDP proxy bridge poll failed repeatedly; proxy redirect disabled, traffic will PASS",
    );

    let status = manager.status();
    assert!(!manager.proxy_redirect_ready());
    assert!(!status.proxy_ready);
    assert_eq!(status.xsk_ready_queues, 0);
    assert!(status.proxy_fallback_reason.contains("redirect disabled"));
    assert!(status.interfaces[0].xsk_queues[0]
        .detail
        .contains("redirect disabled"));
    assert_eq!(
        status.interfaces[0].xsk_queues[1].detail,
        "AF_XDP socket setup failed"
    );
    assert!(status.interfaces[0]
        .xsk_queues
        .iter()
        .all(|queue| !queue.registered && !queue.ready));
}

#[test]
fn xdp_proxy_queue_fault_keeps_sibling_ready() {
    // EN-05: withdrawing a faulted queue must not tear down redirect for
    // its siblings. A faulted queue counts as handled — its traffic takes
    // the explicit dataplane fallback — not as a readiness blocker.
    let manager = XdpManager::new(XdpConfig {
        enabled: true,
        interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
            name: "eth0".to_string(),
            queues: vec![0, 1],
            cpus: Vec::new(),
            mode: XdpRuntimeMode::Proxy,
            ..Default::default()
        }],
        proxy: crate::runtime_mode::XdpProxyConfig {
            ports: vec![crate::runtime_mode::XdpProxyPortConfig {
                protocol: XdpProxyProtocol::Udp,
                port: 443,
            }],
            ..Default::default()
        },
        ..XdpConfig::default()
    });
    *manager.xsk_status.write() = vec![
        XdpQueueStatus {
            interface: "eth0".to_string(),
            queue: 0,
            configured: true,
            socket_created: true,
            registered: true,
            ready: true,
            detail: "AF_XDP ready".to_string(),
            ..Default::default()
        },
        XdpQueueStatus {
            interface: "eth0".to_string(),
            queue: 1,
            configured: true,
            socket_created: true,
            registered: false,
            ready: false,
            faulted: true,
            detail: "withdrawn after queue fault".to_string(),
            ..Default::default()
        },
    ];
    manager
        .proxy_redirect_enabled
        .store(true, Ordering::Relaxed);
    assert!(
        manager.proxy_redirect_ready(),
        "a withdrawn queue must not block redirect for its siblings"
    );

    // A queue that is simply not-ready (never withdrew cleanly) still
    // blocks readiness — faulted is not a free pass.
    if let Some(status) = manager
        .xsk_status
        .write()
        .iter_mut()
        .find(|status| status.queue == 1)
    {
        status.faulted = false;
    }
    assert!(!manager.proxy_redirect_ready());
}

#[test]
fn xdp_map_sync_failure_status_is_fail_open() {
    let manager = XdpManager::new(XdpConfig {
        enabled: true,
        interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
            name: "eth0".to_string(),
            queues: vec![0],
            cpus: Vec::new(),
            mode: XdpRuntimeMode::Proxy,
            ..Default::default()
        }],
        ..XdpConfig::default()
    });

    manager.attached.write().insert("eth0".to_string());
    manager
        .proxy_redirect_enabled
        .store(true, Ordering::Relaxed);
    *manager.xsk_status.write() = vec![XdpQueueStatus {
        interface: "eth0".to_string(),
        queue: 0,
        configured: true,
        socket_created: true,
        registered: true,
        ready: true,
        detail: "ready".to_string(),
        ..Default::default()
    }];
    manager.set_fallback_reason("map sync failed: injected");
    manager.attached.write().clear();
    manager.xsk_status.write().clear();
    manager
        .proxy_redirect_enabled
        .store(false, Ordering::Relaxed);
    manager.set_proxy_fallback_reason("runtime failure detached XDP; socket path is active");

    let status = manager.status();
    assert!(!status.available);
    assert!(!status.attached);
    assert!(!status.proxy_redirect_enabled);
    assert_eq!(status.xsk_ready_queues, 0);
    assert!(status.fallback_reason.contains("map sync failed"));
    assert!(status
        .proxy_fallback_reason
        .contains("socket path is active"));
}

#[test]
fn af_xdp_parser_extracts_ipv4_udp_datagram() {
    let frame = ipv4_udp_frame(false, 0, b"hello");
    let packet = af_xdp::parse_l4_packet(&frame).expect("valid UDP frame");

    assert_eq!(packet.protocol, af_xdp::AfXdpTransportProtocol::Udp);
    assert_eq!(packet.peer_addr, "192.0.2.10:53000".parse().unwrap());
    assert_eq!(packet.local_addr, "198.51.100.5:443".parse().unwrap());
    assert_eq!(&packet.payload[..], b"hello");
    assert_eq!(packet.link.destination_mac, [0x02, 0, 0, 0, 0, 1]);
    assert_eq!(packet.link.source_mac, [0x02, 0, 0, 0, 0, 2]);
}

#[test]
fn af_xdp_proxy_frame_classifies_udp_with_route_meta() {
    let frame = ipv4_udp_frame(false, 0, b"hello");
    let proxy_frame = af_xdp::parse_proxy_frame("eth0", 3, &frame).expect("valid UDP proxy frame");

    let af_xdp::AfXdpProxyFrame::Udp { route, packet } = proxy_frame else {
        panic!("expected UDP proxy frame");
    };
    assert_eq!(route.interface, "eth0");
    assert_eq!(route.queue, 3);
    assert_eq!(packet.protocol, af_xdp::AfXdpTransportProtocol::Udp);
    assert_eq!(packet.peer_addr, "192.0.2.10:53000".parse().unwrap());
    assert_eq!(packet.local_addr, "198.51.100.5:443".parse().unwrap());
    assert_eq!(&packet.payload[..], b"hello");
}

#[test]
fn af_xdp_proxy_frame_classifies_tcp_and_preserves_ip_packet() {
    let frame = ipv4_tcp_frame(true, b"GET / HTTP/1.1\r\n\r\n");
    let proxy_frame = af_xdp::parse_proxy_frame("eth1", 7, &frame).expect("valid TCP proxy frame");

    let af_xdp::AfXdpProxyFrame::Tcp {
        route,
        flow,
        ip_packet,
    } = proxy_frame
    else {
        panic!("expected TCP proxy frame");
    };
    assert_eq!(route.interface, "eth1");
    assert_eq!(route.queue, 7);
    assert_eq!(route.link.vlan_tag_count, 1);
    assert_eq!(flow.peer_addr, "192.0.2.10:53000".parse().unwrap());
    assert_eq!(flow.local_addr, "198.51.100.5:443".parse().unwrap());
    assert_eq!(ip_packet[0] >> 4, 4);
    assert_eq!(
        usize::from(u16::from_be_bytes([ip_packet[2], ip_packet[3]])),
        ip_packet.len()
    );
    assert_eq!(
        &ip_packet[ip_packet.len() - 18..],
        b"GET / HTTP/1.1\r\n\r\n"
    );
}

#[test]
fn af_xdp_proxy_frame_classifies_ipv6_tcp_with_destination_options() {
    let payload = b"hello";
    let mut frame = ethernet_header(0x86dd, false);
    let payload_len = 8 + 20 + payload.len();
    frame.extend_from_slice(&[
        0x60,
        0,
        0,
        0,
        (payload_len >> 8) as u8,
        payload_len as u8,
        60,
        64,
    ]);
    frame.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
    frame.extend_from_slice(&[
        0xcf, 0x08, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0x40, 0, 0, 0, 0, 0,
    ]);
    frame.extend_from_slice(payload);

    let proxy_frame =
        af_xdp::parse_proxy_frame("eth0", 2, &frame).expect("valid IPv6 TCP proxy frame");

    let af_xdp::AfXdpProxyFrame::Tcp {
        route,
        flow,
        ip_packet,
    } = proxy_frame
    else {
        panic!("expected TCP proxy frame");
    };
    assert_eq!(route.interface, "eth0");
    assert_eq!(route.queue, 2);
    assert_eq!(flow.peer_addr, "[2001:db8::1]:53000".parse().unwrap());
    assert_eq!(flow.local_addr, "[2001:db8::2]:443".parse().unwrap());
    assert_eq!(ip_packet[0] >> 4, 6);
    assert_eq!(&ip_packet[ip_packet.len() - payload.len()..], payload);
}

#[test]
fn af_xdp_reply_flow_key_maps_reply_packet_to_original_flow() {
    let ip_packet = ipv4_tcp_reply_ip_packet();
    let flow = af_xdp::reply_flow_key_from_ip_packet(&ip_packet).expect("valid TCP reply flow");

    assert_eq!(flow.local_addr, "198.51.100.5:443".parse().unwrap());
    assert_eq!(flow.peer_addr, "192.0.2.10:53000".parse().unwrap());
}

#[cfg(any(test, target_os = "linux"))]
#[test]
fn af_xdp_tcp_reactor_answers_syn_with_syn_ack() {
    let frame = ipv4_tcp_syn_frame(false);
    let af_xdp::AfXdpProxyFrame::Tcp {
        route,
        flow,
        ip_packet,
    } = af_xdp::parse_proxy_frame("eth0", 0, &frame).expect("valid TCP SYN frame")
    else {
        panic!("expected TCP proxy frame");
    };
    let mut reactor = af_xdp::AfXdpTcpReactor::new_with_session_limit_for_test(None, None, 1024);

    assert_eq!(
        reactor.ingest(route.clone(), flow, ip_packet),
        af_xdp::AfXdpTcpIngestStatus::Accepted
    );
    let egress = reactor.poll();

    assert_eq!(egress.len(), 1);
    assert_eq!(egress[0].0, route);
    let reply = &egress[0].1;
    assert_eq!(reply[0] >> 4, 4);
    assert_eq!(reply[9], cloud_node_xdp_common::XDP_PROTO_TCP);
    assert_eq!(&reply[12..16], &[198, 51, 100, 5]);
    assert_eq!(&reply[16..20], &[192, 0, 2, 10]);
    let tcp_offset = 20;
    assert_eq!(
        u16::from_be_bytes([reply[tcp_offset], reply[tcp_offset + 1]]),
        443
    );
    assert_eq!(
        u16::from_be_bytes([reply[tcp_offset + 2], reply[tcp_offset + 3]]),
        53000
    );
    assert_eq!(reply[tcp_offset + 13] & 0x12, 0x12);
    assert!(reactor.encode_egress_frame(&route, reply).is_some());
}

#[cfg(any(test, target_os = "linux"))]
#[test]
fn af_xdp_tcp_reactor_ignores_unknown_non_syn_flow() {
    let frame = ipv4_tcp_frame(false, b"GET / HTTP/1.1\r\n\r\n");
    let af_xdp::AfXdpProxyFrame::Tcp {
        route,
        flow,
        ip_packet,
    } = af_xdp::parse_proxy_frame("eth0", 0, &frame).expect("valid TCP frame")
    else {
        panic!("expected TCP proxy frame");
    };
    let mut reactor = af_xdp::AfXdpTcpReactor::new_with_session_limit_for_test(None, None, 1024);

    assert_eq!(
        reactor.ingest(route, flow, ip_packet),
        af_xdp::AfXdpTcpIngestStatus::IgnoredUnknownFlow
    );

    assert!(reactor.poll().is_empty());
    assert_eq!(reactor.session_count(), 0);
}

#[cfg(any(test, target_os = "linux"))]
#[test]
fn af_xdp_tcp_reactor_requires_handler_for_new_syn() {
    let frame = ipv4_tcp_syn_frame(false);
    let af_xdp::AfXdpProxyFrame::Tcp {
        route,
        flow,
        ip_packet,
    } = af_xdp::parse_proxy_frame("eth0", 0, &frame).expect("valid TCP SYN frame")
    else {
        panic!("expected TCP proxy frame");
    };
    let mut reactor = af_xdp::AfXdpTcpReactor::new(None, None);

    assert_eq!(
        reactor.ingest(route, flow, ip_packet),
        af_xdp::AfXdpTcpIngestStatus::NoHandler
    );

    assert!(reactor.poll().is_empty());
    assert_eq!(reactor.session_count(), 0);
}

#[cfg(any(test, target_os = "linux"))]
#[test]
fn af_xdp_tcp_reactor_refuses_new_sessions_at_limit() {
    let first_frame = ipv4_tcp_syn_frame_with_source_port(false, 53000);
    let second_frame = ipv4_tcp_syn_frame_with_source_port(false, 53001);
    let af_xdp::AfXdpProxyFrame::Tcp {
        route: first_route,
        flow: first_flow,
        ip_packet: first_packet,
    } = af_xdp::parse_proxy_frame("eth0", 0, &first_frame).expect("valid first TCP SYN frame")
    else {
        panic!("expected first TCP proxy frame");
    };
    let af_xdp::AfXdpProxyFrame::Tcp {
        route: second_route,
        flow: second_flow,
        ip_packet: second_packet,
    } = af_xdp::parse_proxy_frame("eth0", 0, &second_frame).expect("valid second TCP SYN frame")
    else {
        panic!("expected second TCP proxy frame");
    };
    assert_ne!(first_flow, second_flow);

    let mut reactor = af_xdp::AfXdpTcpReactor::new_with_session_limit_for_test(None, None, 1);

    assert_eq!(
        reactor.ingest(first_route.clone(), first_flow, first_packet),
        af_xdp::AfXdpTcpIngestStatus::Accepted
    );
    let first_egress = reactor.poll();
    assert_eq!(
        reactor.ingest(second_route, second_flow, second_packet),
        af_xdp::AfXdpTcpIngestStatus::RefusedAtCapacity
    );
    let second_egress = reactor.poll();

    assert_eq!(reactor.session_count(), 1);
    assert_eq!(first_egress.len(), 1);
    assert_eq!(first_egress[0].0, first_route);
    assert!(second_egress.is_empty());
}

#[cfg(any(test, target_os = "linux"))]
#[test]
fn af_xdp_tcp_reactor_reaps_idle_sessions() {
    let frame = ipv4_tcp_syn_frame(false);
    let af_xdp::AfXdpProxyFrame::Tcp {
        route,
        flow,
        ip_packet,
    } = af_xdp::parse_proxy_frame("eth0", 0, &frame).expect("valid TCP SYN frame")
    else {
        panic!("expected TCP proxy frame");
    };
    let mut reactor = af_xdp::AfXdpTcpReactor::new_with_session_limit_for_test(None, None, 1024);

    assert_eq!(
        reactor.ingest(route, flow, ip_packet),
        af_xdp::AfXdpTcpIngestStatus::Accepted
    );
    assert_eq!(reactor.session_count(), 1);

    let reap_at = smoltcp::time::Instant::from_millis(
        crate::utils::time::now_timestamp_millis()
            + af_xdp::AF_XDP_TCP_SESSION_IDLE_TIMEOUT.as_millis() as i64
            + 1,
    );
    let _ = reactor.poll_at_for_test(reap_at);

    assert_eq!(reactor.session_count(), 0);
}

#[cfg(any(test, target_os = "linux"))]
#[test]
fn af_xdp_tcp_reactor_reaps_closing_time_wait_sessions() {
    assert!(af_xdp::af_xdp_tcp_session_reapable(
        true,
        smoltcp::socket::tcp::State::TimeWait
    ));
    assert!(af_xdp::af_xdp_tcp_session_reapable(
        true,
        smoltcp::socket::tcp::State::Closed
    ));
    assert!(!af_xdp::af_xdp_tcp_session_reapable(
        false,
        smoltcp::socket::tcp::State::TimeWait
    ));
    assert!(!af_xdp::af_xdp_tcp_session_reapable(
        true,
        smoltcp::socket::tcp::State::Established
    ));
}

#[cfg(any(test, target_os = "linux"))]
#[test]
fn af_xdp_tcp_reactor_resolves_egress_route_before_reaping_session() {
    let frame = ipv4_tcp_syn_frame(false);
    let af_xdp::AfXdpProxyFrame::Tcp {
        route,
        flow,
        ip_packet,
    } = af_xdp::parse_proxy_frame("eth0", 0, &frame).expect("valid TCP SYN frame")
    else {
        panic!("expected TCP proxy frame");
    };
    let mut reactor = af_xdp::AfXdpTcpReactor::new_with_session_limit_for_test(None, None, 1024);
    assert_eq!(
        reactor.ingest(route.clone(), flow, ip_packet),
        af_xdp::AfXdpTcpIngestStatus::Accepted
    );
    let _ = reactor.poll();

    let reply_packet = ipv4_tcp_reply_ip_packet();
    reactor.close_session_and_push_routeless_egress_for_test(flow, reply_packet.clone());

    let egress = reactor.poll();

    assert!(egress
        .iter()
        .any(|(egress_route, ip_packet)| *egress_route == route && *ip_packet == reply_packet));
    assert_eq!(reactor.session_count(), 0);
}

#[cfg(any(test, target_os = "linux"))]
#[test]
fn af_xdp_tcp_reactor_keeps_stream_read_side_open_during_half_close() {
    assert!(!af_xdp::af_xdp_tcp_stream_read_side_closed(
        smoltcp::socket::tcp::State::SynReceived
    ));
    assert!(!af_xdp::af_xdp_tcp_stream_read_side_closed(
        smoltcp::socket::tcp::State::Established
    ));
    assert!(!af_xdp::af_xdp_tcp_stream_read_side_closed(
        smoltcp::socket::tcp::State::CloseWait
    ));
    assert!(af_xdp::af_xdp_tcp_stream_read_side_closed(
        smoltcp::socket::tcp::State::LastAck
    ));
}

#[cfg(any(test, target_os = "linux"))]
#[test]
fn af_xdp_tcp_admission_failure_tracker_requires_consecutive_refusals() {
    let mut tracker = af_xdp::AfXdpTcpAdmissionFailureTracker::new(2);

    assert!(!tracker.record(af_xdp::AfXdpTcpIngestStatus::IgnoredUnknownFlow));
    assert_eq!(tracker.consecutive_refusals(), 0);
    assert!(!tracker.record(af_xdp::AfXdpTcpIngestStatus::NoHandler));
    assert_eq!(tracker.consecutive_refusals(), 0);
    assert!(!tracker.record(af_xdp::AfXdpTcpIngestStatus::BlockedByL4));
    assert_eq!(tracker.consecutive_refusals(), 0);
    assert!(!tracker.record(af_xdp::AfXdpTcpIngestStatus::RefusedAtCapacity));
    assert_eq!(tracker.consecutive_refusals(), 1);
    assert!(!tracker.record(af_xdp::AfXdpTcpIngestStatus::Accepted));
    assert_eq!(tracker.consecutive_refusals(), 0);
    assert!(!tracker.record(af_xdp::AfXdpTcpIngestStatus::RefusedAtCapacity));
    assert!(tracker.record(af_xdp::AfXdpTcpIngestStatus::RefusedAtCapacity));

    let mut immediate = af_xdp::AfXdpTcpAdmissionFailureTracker::new(0);
    assert!(immediate.record(af_xdp::AfXdpTcpIngestStatus::RefusedAtCapacity));
}

#[cfg(any(test, target_os = "linux"))]
#[test]
fn af_xdp_tcp_session_limit_uses_actual_af_xdp_budget() {
    assert_eq!(af_xdp::af_xdp_tcp_session_limit_from_budget(0), 512);
    assert_eq!(
        af_xdp::af_xdp_tcp_session_limit_from_budget(u64::MAX),
        16_384
    );
    let modest = af_xdp::af_xdp_tcp_session_limit_from_budget(256 * 1024 * 1024);
    assert!((512..=16_384).contains(&modest));
    assert!(modest < 16_384);
}

/// EN-12 T18: the whole-node session budget is divided across queue workers;
/// adding queues must not multiply the aggregate quota.
#[cfg(any(test, target_os = "linux"))]
#[test]
fn af_xdp_tcp_session_limit_per_worker_divides_node_budget() {
    use af_xdp::af_xdp_tcp_session_limit_per_worker as per_worker;
    let node = 8_192usize;
    // Aggregate capacity never exceeds the node budget when queues multiply.
    for workers in [1usize, 2, 4, 8, 16] {
        assert!(per_worker(node, workers) * workers <= node);
        assert_eq!(per_worker(node, workers), node / workers);
    }
    // More workers than budget still admits at least one session per worker,
    // and the aggregate stays bounded by worker count.
    assert_eq!(per_worker(4, 16), 1);
    assert_eq!(per_worker(0, 8), 1);
    assert_eq!(per_worker(node, 0), node);
}

/// EN-12: xskMode config parsing and defaults — auto probes, explicit modes
/// pin the bind attempt.
#[test]
fn xdp_interface_xsk_mode_parses_and_defaults_to_auto() {
    use crate::runtime_mode::{XdpInterfaceConfig, XdpXskMode};
    let cfg: XdpInterfaceConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(cfg.xsk_mode, XdpXskMode::Auto);
    let cfg: XdpInterfaceConfig = serde_json::from_str(r#"{"xskMode":"copy"}"#).unwrap();
    assert_eq!(cfg.xsk_mode, XdpXskMode::Copy);
    let cfg: XdpInterfaceConfig = serde_json::from_str(r#"{"xskMode":"zero-copy"}"#).unwrap();
    assert_eq!(cfg.xsk_mode, XdpXskMode::ZeroCopy);
    assert!(serde_json::from_str::<XdpInterfaceConfig>(r#"{"xskMode":"bogus"}"#).is_err());
}

#[cfg(any(test, target_os = "linux"))]
#[test]
fn af_xdp_tcp_initial_syn_accepts_ecn_variants() {
    let mut frame = ipv4_tcp_syn_frame(false);
    let (_, ip_packet) = af_xdp::extract_ip_frame(&frame).expect("valid IP frame");
    assert!(af_xdp::tcp_packet_is_initial_syn(&ip_packet));

    let tcp_flags_offset = ethernet_header_len(false) + 20 + 13;
    frame[tcp_flags_offset] = 0xc2;
    let (_, ip_packet) = af_xdp::extract_ip_frame(&frame).expect("valid ECN SYN frame");
    assert_eq!(af_xdp::tcp_flags_from_ip_packet(&ip_packet), Some(0xc2));
    assert!(af_xdp::tcp_packet_is_initial_syn(&ip_packet));

    frame[tcp_flags_offset] = 0x52;
    let (_, ip_packet) = af_xdp::extract_ip_frame(&frame).expect("valid SYN ACK frame");
    assert_eq!(af_xdp::tcp_flags_from_ip_packet(&ip_packet), Some(0x52));
    assert!(!af_xdp::tcp_packet_is_initial_syn(&ip_packet));
}

#[cfg(any(test, target_os = "linux"))]
#[test]
fn af_xdp_tcp_flow_flag_prefilter_parses_without_ip_packet_copy() {
    let mut frame = ipv4_tcp_syn_frame_with_source_port(false, 53123);
    let tcp_flags_offset = ethernet_header_len(false) + 20 + 13;
    frame[tcp_flags_offset] = 0xc2;

    let (flow, flags) = af_xdp::parse_tcp_flow_flags_from_frame(&frame)
        .expect("TCP flow flags should parse from Ethernet frame");

    assert_eq!(flow.peer_addr, "192.0.2.10:53123".parse().unwrap());
    assert_eq!(flow.local_addr, "198.51.100.5:443".parse().unwrap());
    assert_eq!(flags, 0xc2);
}

#[cfg(any(test, target_os = "linux"))]
#[test]
fn af_xdp_attack_pcap_samples_parse_without_state_growth() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut captures_seen = 0;
    for name in ["1.pcap", "2.pcap", "443.pcap"] {
        let path = root.join(name);
        if !path.exists() {
            continue;
        }
        captures_seen += 1;
        let stats = pcap_sample_stats(&path, 50_000).expect("pcap sample should parse");
        assert!(stats.frames > 0, "{name} should contain frames");
        assert!(stats.tcp > 0, "{name} should contain TCP frames");
        assert!(stats.initial_syn > 0, "{name} should contain TCP SYNs");
        assert_eq!(
            stats.reactor_sessions, 0,
            "{name} unknown non-SYNs must not create sessions"
        );
    }
    if captures_seen == 0 {
        eprintln!("attack pcap sample test skipped: no local 1.pcap/2.pcap/443.pcap files");
    }
}

#[cfg(any(test, target_os = "linux"))]
#[test]
fn af_xdp_proxy_bridge_idles_only_when_no_work_remains() {
    assert!(af_xdp::proxy_bridge_should_idle(0, 0, 0, 0, false));
    assert!(!af_xdp::proxy_bridge_should_idle(1, 0, 0, 0, false));
    assert!(!af_xdp::proxy_bridge_should_idle(0, 1, 0, 0, false));
    assert!(!af_xdp::proxy_bridge_should_idle(0, 0, 1, 0, false));
    assert!(!af_xdp::proxy_bridge_should_idle(0, 0, 0, 1, false));
    assert!(!af_xdp::proxy_bridge_should_idle(0, 0, 0, 0, true));
}

#[test]
fn xsk_status_refresh_throttles_idle_kernel_stats() {
    let start = std::time::Instant::now();
    assert!(xsk_status_refresh_due(None, start, false));
    assert!(!xsk_status_refresh_due(
        Some(start),
        start + XDP_XSK_STATUS_REFRESH_INTERVAL / 2,
        false
    ));
    assert!(xsk_status_refresh_due(
        Some(start),
        start + XDP_XSK_STATUS_REFRESH_INTERVAL,
        false
    ));
    assert!(xsk_status_refresh_due(Some(start), start, true));
}

#[test]
fn af_xdp_udp_packet_converts_to_datagram_only_for_udp() {
    let udp = af_xdp::AfXdpL4Packet {
        protocol: af_xdp::AfXdpTransportProtocol::Udp,
        local_addr: "127.0.0.1:443".parse().unwrap(),
        peer_addr: "127.0.0.1:53000".parse().unwrap(),
        payload: bytes::Bytes::from_static(b"hello"),
        link: test_link_meta(false),
    };
    assert!(udp.into_udp_datagram().is_some());

    let tcp = af_xdp::AfXdpL4Packet {
        protocol: af_xdp::AfXdpTransportProtocol::Tcp,
        local_addr: "127.0.0.1:443".parse().unwrap(),
        peer_addr: "127.0.0.1:53000".parse().unwrap(),
        payload: bytes::Bytes::from_static(b"hello"),
        link: test_link_meta(false),
    };
    assert!(tcp.into_udp_datagram().is_none());
}

#[test]
fn af_xdp_udp_route_cache_expires_and_evicts_oldest_without_clearing_all() {
    use dashmap::DashMap;
    use std::net::SocketAddr;
    use std::time::Duration;

    let routes = DashMap::new();
    for idx in 0..4u16 {
        let local = SocketAddr::from(([198, 51, 100, 5], 443));
        let peer = SocketAddr::from(([192, 0, 2, 10], 53000 + idx));
        routes.insert(
            (local, peer),
            af_xdp::AfXdpUdpRouteEntry {
                route: af_xdp::AfXdpRouteMeta {
                    interface: "eth0".to_string(),
                    queue: u32::from(idx),
                    link: test_link_meta(false),
                },
                last_seen_ms: u64::from(idx) * 10,
            },
        );
    }

    af_xdp::compact_udp_route_cache(&routes, 115, Duration::from_millis(100), 8, 2);

    assert_eq!(routes.len(), 2);
    assert!(routes.iter().all(|entry| entry.key().1.port() >= 53002));

    af_xdp::compact_udp_route_cache(&routes, 116, Duration::from_millis(1_000), 2, 1);

    assert_eq!(routes.len(), 1);
    let remaining = routes.iter().next().unwrap();
    assert_eq!(remaining.key().1.port(), 53003);
    assert_eq!(remaining.value().route.queue, 3);
}

#[cfg(target_os = "linux")]
#[test]
fn udp_forward_parse_mac_and_entry_validation() {
    use std::net::SocketAddr;

    assert_eq!(
        linux::parse_mac("aa:bb:cc:dd:ee:ff").unwrap(),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    );
    assert!(linux::parse_mac("aa:bb").is_err());
    assert!(linux::parse_mac("gg:bb:cc:dd:ee:ff").is_err());

    let fwd = crate::runtime_mode::XdpUdpForwardConfig {
        listen: SocketAddr::from(([192, 0, 2, 10], 5353)),
        backend: "10.0.0.5:53".to_string(),
        next_hop_mac: "02:00:00:00:00:01".to_string(),
        server_id: 42,
        snat: false,
    };
    let (key, rule) = linux::udp_forward_entry(&fwd).unwrap();
    assert_eq!(key.family, 4);
    assert_eq!(&key.addr[..4], &[192, 0, 2, 10]);
    assert_eq!(key.port_be, 5353u16.to_be());
    assert_eq!(&rule.backend_addr[..4], &[10, 0, 0, 5]);
    assert_eq!(rule.backend_port_be, 53u16.to_be());
    assert_eq!(rule.server_id, 42);
    assert_eq!(rule.snat, 0);
    assert_eq!(rule.next_hop_mac, [0x02, 0, 0, 0, 0, 1]);

    let fwd_snat = crate::runtime_mode::XdpUdpForwardConfig { snat: true, ..fwd };
    let (_, rule_snat) = linux::udp_forward_entry(&fwd_snat).unwrap();
    assert_eq!(rule_snat.snat, 1);

    // Family mismatch is rejected explicitly.
    let bad = crate::runtime_mode::XdpUdpForwardConfig {
        listen: SocketAddr::from(([192, 0, 2, 10], 5353)),
        backend: "[2001:db8::5]:53".to_string(),
        next_hop_mac: "02:00:00:00:00:01".to_string(),
        server_id: 0,
        snat: false,
    };
    assert!(linux::udp_forward_entry(&bad).is_err());
}

#[test]
fn af_xdp_udp_route_cache_sweep_uses_saturating_interval() {
    use std::time::Duration;

    assert!(!af_xdp::udp_route_cache_sweep_due(
        1_000,
        900,
        Duration::from_millis(101)
    ));
    assert!(af_xdp::udp_route_cache_sweep_due(
        1_000,
        900,
        Duration::from_millis(100)
    ));
    assert!(!af_xdp::udp_route_cache_sweep_due(
        100,
        1_000,
        Duration::from_millis(100)
    ));
}

#[test]
fn af_xdp_tx_failure_tracker_requires_consecutive_failures() {
    let mut tracker = af_xdp::AfXdpTxFailureTracker::new(3);

    assert!(!tracker.record(af_xdp::AfXdpTxStatus::Backpressured));
    assert_eq!(tracker.consecutive_failures(), 1);
    assert!(!tracker.record(af_xdp::AfXdpTxStatus::Failed));
    assert_eq!(tracker.consecutive_failures(), 2);
    assert!(!tracker.record(af_xdp::AfXdpTxStatus::Sent));
    assert_eq!(tracker.consecutive_failures(), 0);
    assert!(!tracker.record(af_xdp::AfXdpTxStatus::Failed));
    assert!(!tracker.record(af_xdp::AfXdpTxStatus::Backpressured));
    assert!(tracker.record(af_xdp::AfXdpTxStatus::Failed));
    assert_eq!(tracker.consecutive_failures(), 3);

    let mut immediate = af_xdp::AfXdpTxFailureTracker::new(0);
    assert!(immediate.record(af_xdp::AfXdpTxStatus::Failed));
}

#[test]
fn af_xdp_udp_ingress_failure_tracker_resets_after_delivery() {
    let mut tracker = af_xdp::AfXdpTxFailureTracker::new(2);

    assert!(!tracker.record(af_xdp::AfXdpTxStatus::Backpressured));
    assert!(!tracker.record(af_xdp::AfXdpTxStatus::Sent));
    assert_eq!(tracker.consecutive_failures(), 0);
    assert!(!tracker.record(af_xdp::AfXdpTxStatus::Failed));
    assert!(tracker.record(af_xdp::AfXdpTxStatus::Backpressured));
}

#[tokio::test]
async fn af_xdp_tcp_stream_bridges_bounded_channels() {
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let af_xdp::AfXdpTcpStreamParts {
        mut stream,
        ingress_tx,
        mut egress_rx,
    } = af_xdp::AfXdpTcpStream::channel_pair(1);

    ingress_tx.send(Bytes::from_static(b"hello")).await.unwrap();
    let mut read = [0u8; 3];
    stream.read_exact(&mut read).await.unwrap();
    assert_eq!(&read, b"hel");

    let mut read = [0u8; 2];
    stream.read_exact(&mut read).await.unwrap();
    assert_eq!(&read, b"lo");

    stream.write_all(b"world").await.unwrap();
    assert_eq!(
        egress_rx.recv().await.unwrap(),
        Bytes::from_static(b"world")
    );

    stream.shutdown().await.unwrap();
    assert!(egress_rx.recv().await.is_none());
}

#[tokio::test]
async fn af_xdp_tcp_stream_chunks_large_writes_with_backpressure() {
    use tokio::io::AsyncWriteExt;

    let af_xdp::AfXdpTcpStreamParts {
        mut stream,
        mut egress_rx,
        ..
    } = af_xdp::AfXdpTcpStream::channel_pair(1);
    let payload = vec![0x5au8; 40 * 1024];

    let writer = tokio::spawn(async move {
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let mut chunks = Vec::new();
    while let Some(chunk) = egress_rx.recv().await {
        chunks.push(chunk);
    }
    writer.await.unwrap();

    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks[0].len(), 16 * 1024);
    assert_eq!(chunks[1].len(), 16 * 1024);
    assert_eq!(chunks[2].len(), 8 * 1024);
    assert!(chunks
        .iter()
        .all(|chunk| chunk.iter().all(|byte| *byte == 0x5a)));
}

#[tokio::test]
async fn af_xdp_ingress_delivery_preserves_backpressured_chunk() {
    use bytes::Bytes;

    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let mut pending = Bytes::new();

    assert_eq!(
        af_xdp::send_or_store_ingress(&tx, &mut pending, Bytes::from_static(b"first")),
        af_xdp::IngressDelivery::Delivered
    );
    assert_eq!(
        af_xdp::send_or_store_ingress(&tx, &mut pending, Bytes::from_static(b"second")),
        af_xdp::IngressDelivery::Backpressured
    );
    assert_eq!(&pending[..], b"second");
    assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"first"));

    assert_eq!(
        af_xdp::flush_pending_ingress(&tx, &mut pending),
        af_xdp::IngressDelivery::Delivered
    );
    assert!(pending.is_empty());
    assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"second"));

    drop(rx);
    pending = Bytes::from_static(b"orphaned");
    assert_eq!(
        af_xdp::flush_pending_ingress(&tx, &mut pending),
        af_xdp::IngressDelivery::Closed
    );
    assert!(pending.is_empty());
}

#[tokio::test]
async fn af_xdp_tcp_stream_reports_broken_pipe_when_reactor_side_closes() {
    use tokio::io::AsyncWriteExt;

    let af_xdp::AfXdpTcpStreamParts {
        mut stream,
        egress_rx,
        ..
    } = af_xdp::AfXdpTcpStream::channel_pair(1);
    drop(egress_rx);

    let err = stream.write_all(b"boom").await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
}

#[test]
fn af_xdp_extracts_ip_frame_with_vlan_link_meta() {
    let frame = ipv4_tcp_frame(true, b"GET / HTTP/1.1\r\n\r\n");
    let (link, ip_packet) = af_xdp::extract_ip_frame(&frame).expect("valid IP frame");

    assert_eq!(link.vlan_tag_count, 1);
    assert_eq!(link.ethertype, 0x0800);
    assert_eq!(ip_packet[0] >> 4, 4);
    assert_eq!(
        usize::from(u16::from_be_bytes([ip_packet[2], ip_packet[3]])),
        ip_packet.len()
    );
    assert_eq!(
        &ip_packet[ip_packet.len() - 18..],
        b"GET / HTTP/1.1\r\n\r\n"
    );
}

#[test]
fn af_xdp_encodes_ip_reply_frame_with_reversed_l2() {
    let link = test_link_meta(true);
    let mut ip_packet = Vec::new();
    ip_packet.extend_from_slice(&[
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 198, 51, 100, 5, 192, 0, 2, 10,
    ]);
    let mut frame = Vec::new();

    af_xdp::encode_ip_reply_frame(&link, &ip_packet, &mut frame).expect("reply frame");

    assert_eq!(&frame[0..6], &[0x02, 0, 0, 0, 0, 2]);
    assert_eq!(&frame[6..12], &[0x02, 0, 0, 0, 0, 1]);
    assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([frame[16], frame[17]]), 0x0800);
    assert_eq!(&frame[18..], ip_packet.as_slice());
}

#[test]
fn af_xdp_parser_extracts_vlan_ipv4_tcp_payload() {
    let frame = ipv4_tcp_frame(true, b"GET / HTTP/1.1\r\n\r\n");
    let packet = af_xdp::parse_l4_packet(&frame).expect("valid TCP frame");

    assert_eq!(packet.protocol, af_xdp::AfXdpTransportProtocol::Tcp);
    assert_eq!(packet.peer_addr, "192.0.2.10:53000".parse().unwrap());
    assert_eq!(packet.local_addr, "198.51.100.5:443".parse().unwrap());
    assert_eq!(&packet.payload[..], b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(packet.link.vlan_tag_count, 1);
    assert_eq!(packet.link.vlan_tags[0].tpid, 0x8100);
}

#[test]
fn af_xdp_parser_extracts_qinq_ipv4_tcp_payload() {
    let payload = b"GET /qinq HTTP/1.1\r\n\r\n";
    let mut frame = ethernet_header_with_vlan_tags(0x0800, &[(0x88a8, 10), (0x9100, 20)]);
    let total_len = 20 + 20 + payload.len();
    frame.extend_from_slice(&[
        0x45,
        0,
        (total_len >> 8) as u8,
        total_len as u8,
        0,
        1,
        0,
        0,
        64,
        6,
        0,
        0,
        192,
        0,
        2,
        10,
        198,
        51,
        100,
        5,
    ]);
    frame.extend_from_slice(&[
        0xcf, 0x08, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0x40, 0, 0, 0, 0, 0,
    ]);
    frame.extend_from_slice(payload);

    let packet = af_xdp::parse_l4_packet(&frame).expect("valid QinQ TCP frame");

    assert_eq!(packet.protocol, af_xdp::AfXdpTransportProtocol::Tcp);
    assert_eq!(packet.peer_addr, "192.0.2.10:53000".parse().unwrap());
    assert_eq!(packet.local_addr, "198.51.100.5:443".parse().unwrap());
    assert_eq!(&packet.payload[..], payload);
    assert_eq!(packet.link.vlan_tag_count, 2);
    assert_eq!(packet.link.vlan_tags[0].tpid, 0x88a8);
    assert_eq!(packet.link.vlan_tags[0].tci, 10);
    assert_eq!(packet.link.vlan_tags[1].tpid, 0x9100);
    assert_eq!(packet.link.vlan_tags[1].tci, 20);
}

#[test]
fn af_xdp_encodes_ipv4_udp_reply_frame_with_reversed_l2() {
    let link = test_link_meta(true);
    let mut frame = Vec::new();
    af_xdp::encode_udp_reply_frame(
        &link,
        "198.51.100.5:443".parse().unwrap(),
        "192.0.2.10:53000".parse().unwrap(),
        b"pong",
        &mut frame,
    )
    .expect("reply frame");

    assert_eq!(&frame[0..6], &[0x02, 0, 0, 0, 0, 2]);
    assert_eq!(&frame[6..12], &[0x02, 0, 0, 0, 0, 1]);
    assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), 0x8100);
    assert_eq!(u16::from_be_bytes([frame[16], frame[17]]), 0x0800);
    let ip_offset = 18;
    assert_eq!(frame[ip_offset], 0x45);
    assert_eq!(frame[ip_offset + 9], 17);
    assert_eq!(
        &frame[ip_offset + 12..ip_offset + 20],
        &[198, 51, 100, 5, 192, 0, 2, 10]
    );
    let udp_offset = ip_offset + 20;
    assert_eq!(
        u16::from_be_bytes([frame[udp_offset], frame[udp_offset + 1]]),
        443
    );
    assert_eq!(
        u16::from_be_bytes([frame[udp_offset + 2], frame[udp_offset + 3]]),
        53000
    );
    assert_eq!(&frame[udp_offset + 8..], b"pong");
    assert_ne!(
        u16::from_be_bytes([frame[udp_offset + 6], frame[udp_offset + 7]]),
        0
    );
}

#[test]
fn af_xdp_parser_rejects_fragmented_ipv4() {
    let frame = ipv4_udp_frame(false, 0x2000, b"hello");
    assert!(af_xdp::parse_l4_packet(&frame).is_none());
}

#[test]
fn af_xdp_parser_skips_ipv6_destination_options() {
    let mut frame = ethernet_header(0x86dd, false);
    let udp_payload = b"quic";
    let payload_len = 8 + 8 + udp_payload.len();
    frame.extend_from_slice(&[
        0x60,
        0,
        0,
        0,
        (payload_len >> 8) as u8,
        payload_len as u8,
        60,
        64,
    ]);
    frame.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
    frame.extend_from_slice(&[
        0xcf,
        0x08,
        0x01,
        0xbb,
        0,
        (8 + udp_payload.len()) as u8,
        0,
        0,
    ]);
    frame.extend_from_slice(udp_payload);

    let packet = af_xdp::parse_l4_packet(&frame).expect("valid IPv6 UDP frame");
    assert_eq!(packet.protocol, af_xdp::AfXdpTransportProtocol::Udp);
    assert_eq!(packet.peer_addr, "[2001:db8::1]:53000".parse().unwrap());
    assert_eq!(packet.local_addr, "[2001:db8::2]:443".parse().unwrap());
    assert_eq!(&packet.payload[..], udp_payload);
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Default)]
struct PcapSampleStats {
    frames: usize,
    tcp: usize,
    initial_syn: usize,
    reactor_sessions: usize,
}

#[cfg(any(test, target_os = "linux"))]
fn pcap_sample_stats(
    path: &std::path::Path,
    max_packets: usize,
) -> std::io::Result<PcapSampleStats> {
    let mut file = std::fs::File::open(path)?;
    let mut global = [0u8; 24];
    std::io::Read::read_exact(&mut file, &mut global)?;
    let little_endian = match &global[0..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported pcap magic",
            ));
        }
    };
    let linktype = pcap_u32(&global[20..24], little_endian);
    if linktype != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported pcap linktype {linktype}"),
        ));
    }

    let mut stats = PcapSampleStats::default();
    let mut reactor = af_xdp::AfXdpTcpReactor::new(None, None);
    for _ in 0..max_packets {
        let mut record = [0u8; 16];
        match std::io::Read::read_exact(&mut file, &mut record) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(err),
        }
        let incl_len = pcap_u32(&record[8..12], little_endian) as usize;
        if incl_len > 256 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("pcap record too large: {incl_len}"),
            ));
        }
        let mut frame = vec![0u8; incl_len];
        std::io::Read::read_exact(&mut file, &mut frame)?;
        stats.frames = stats.frames.saturating_add(1);

        let Some(proxy_frame) = af_xdp::parse_proxy_frame("eth0", 0, &frame) else {
            continue;
        };
        if let af_xdp::AfXdpProxyFrame::Tcp {
            route,
            flow,
            ip_packet,
        } = proxy_frame
        {
            stats.tcp = stats.tcp.saturating_add(1);
            if af_xdp::tcp_packet_is_initial_syn(&ip_packet) {
                stats.initial_syn = stats.initial_syn.saturating_add(1);
            }
            let _ = reactor.ingest(route, flow, ip_packet);
        }
    }
    stats.reactor_sessions = reactor.session_count();
    Ok(stats)
}

#[cfg(any(test, target_os = "linux"))]
fn pcap_u32(bytes: &[u8], little_endian: bool) -> u32 {
    let mut array = [0u8; 4];
    array.copy_from_slice(bytes);
    if little_endian {
        u32::from_le_bytes(array)
    } else {
        u32::from_be_bytes(array)
    }
}

fn ethernet_header(ethertype: u16, vlan: bool) -> Vec<u8> {
    if vlan {
        return ethernet_header_with_vlan_tags(ethertype, &[(0x8100, 0)]);
    }
    ethernet_header_with_vlan_tags(ethertype, &[])
}

fn ethernet_header_with_vlan_tags(ethertype: u16, tags: &[(u16, u16)]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    for (tpid, tci) in tags {
        frame.extend_from_slice(&tpid.to_be_bytes());
        frame.extend_from_slice(&tci.to_be_bytes());
    }
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame
}

fn test_link_meta(vlan: bool) -> af_xdp::AfXdpLinkMeta {
    af_xdp::AfXdpLinkMeta {
        destination_mac: [0x02, 0, 0, 0, 0, 1],
        source_mac: [0x02, 0, 0, 0, 0, 2],
        vlan_tags: [
            af_xdp::AfXdpVlanTag {
                tpid: if vlan { 0x8100 } else { 0 },
                tci: 0,
            },
            af_xdp::AfXdpVlanTag { tpid: 0, tci: 0 },
        ],
        vlan_tag_count: u8::from(vlan),
        ethertype: 0x0800,
    }
}

fn ipv4_udp_frame(vlan: bool, fragment: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = ethernet_header(0x0800, vlan);
    let total_len = 20 + 8 + payload.len();
    frame.extend_from_slice(&[
        0x45,
        0,
        (total_len >> 8) as u8,
        total_len as u8,
        0,
        1,
        (fragment >> 8) as u8,
        fragment as u8,
        64,
        17,
        0,
        0,
        192,
        0,
        2,
        10,
        198,
        51,
        100,
        5,
    ]);
    frame.extend_from_slice(&[0xcf, 0x08, 0x01, 0xbb, 0, (8 + payload.len()) as u8, 0, 0]);
    frame.extend_from_slice(payload);
    frame
}

fn ipv4_tcp_frame(vlan: bool, payload: &[u8]) -> Vec<u8> {
    let mut frame = ethernet_header(0x0800, vlan);
    let total_len = 20 + 20 + payload.len();
    frame.extend_from_slice(&[
        0x45,
        0,
        (total_len >> 8) as u8,
        total_len as u8,
        0,
        1,
        0,
        0,
        64,
        6,
        0,
        0,
        192,
        0,
        2,
        10,
        198,
        51,
        100,
        5,
    ]);
    frame.extend_from_slice(&[
        0xcf, 0x08, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0,
    ]);
    frame.extend_from_slice(payload);
    frame
}

#[cfg(any(test, target_os = "linux"))]
fn ipv4_tcp_syn_frame(vlan: bool) -> Vec<u8> {
    ipv4_tcp_syn_frame_with_source_port(vlan, 53000)
}

#[cfg(any(test, target_os = "linux"))]
fn ipv4_tcp_syn_frame_with_source_port(vlan: bool, source_port: u16) -> Vec<u8> {
    let mut frame = ethernet_header(0x0800, vlan);
    let total_len = 20 + 20;
    frame.extend_from_slice(&[
        0x45,
        0,
        (total_len >> 8) as u8,
        total_len as u8,
        0,
        1,
        0,
        0,
        64,
        6,
        0,
        0,
        192,
        0,
        2,
        10,
        198,
        51,
        100,
        5,
    ]);
    let [source_port_hi, source_port_lo] = source_port.to_be_bytes();
    frame.extend_from_slice(&[
        source_port_hi,
        source_port_lo,
        0x01,
        0xbb,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0x50,
        0x02,
        0xff,
        0xff,
        0,
        0,
        0,
        0,
    ]);
    write_ipv4_checksum(&mut frame, ethernet_header_len(vlan));
    write_tcp4_checksum(&mut frame, ethernet_header_len(vlan));
    frame
}

fn ipv4_tcp_reply_ip_packet() -> Vec<u8> {
    let total_len = 20 + 20;
    let mut packet = Vec::with_capacity(total_len);
    packet.extend_from_slice(&[
        0x45,
        0,
        (total_len >> 8) as u8,
        total_len as u8,
        0,
        1,
        0,
        0,
        64,
        6,
        0,
        0,
        198,
        51,
        100,
        5,
        192,
        0,
        2,
        10,
    ]);
    packet.extend_from_slice(&[
        0x01, 0xbb, 0xcf, 0x08, 0, 0, 0, 2, 0, 0, 0, 2, 0x50, 0x10, 0xff, 0xff, 0, 0, 0, 0,
    ]);
    packet
}

#[cfg(any(test, target_os = "linux"))]
fn ethernet_header_len(vlan: bool) -> usize {
    14 + if vlan { 4 } else { 0 }
}

#[cfg(any(test, target_os = "linux"))]
fn write_ipv4_checksum(frame: &mut [u8], ip_offset: usize) {
    frame[ip_offset + 10] = 0;
    frame[ip_offset + 11] = 0;
    let checksum = test_internet_checksum(&frame[ip_offset..ip_offset + 20]);
    frame[ip_offset + 10..ip_offset + 12].copy_from_slice(&checksum.to_be_bytes());
}

#[cfg(any(test, target_os = "linux"))]
fn write_tcp4_checksum(frame: &mut [u8], ip_offset: usize) {
    let tcp_offset = ip_offset + 20;
    let tcp_len = frame.len() - tcp_offset;
    frame[tcp_offset + 16] = 0;
    frame[tcp_offset + 17] = 0;
    let mut pseudo = Vec::with_capacity(12 + tcp_len);
    pseudo.extend_from_slice(&frame[ip_offset + 12..ip_offset + 20]);
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&frame[tcp_offset..]);
    let checksum = test_internet_checksum(&pseudo);
    frame[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&checksum.to_be_bytes());
}

#[cfg(any(test, target_os = "linux"))]
fn test_internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum = sum.wrapping_add(word);
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    !(sum as u16)
}

#[cfg(target_os = "linux")]
#[test]
fn percpu_counter_aggregation_sums_all_cpu_slots() {
    use cloud_node_xdp_common::XdpCounters;
    let mut a = XdpCounters::default();
    a.packets = 7;
    a.pass = 3;
    a.tx = 2;
    a.acl_blocked = 1;
    let mut b = XdpCounters::default();
    b.packets = 5;
    b.drop = 4;
    b.redirect = 9;
    b.tx = 11;
    b.acl_blocked = 13;
    let slots = vec![a, b, XdpCounters::default()];
    let total = linux::sum_percpu_counters(slots.iter());
    assert_eq!(total.packets, 12);
    assert_eq!(total.pass, 3);
    assert_eq!(total.drop, 4);
    assert_eq!(total.redirect, 9);
    assert_eq!(total.tx, 13);
    assert_eq!(total.acl_blocked, 14);
    assert_eq!(total.parse_errors, 0);
    assert_eq!(total.snat_reply_tx, 0);
}

#[cfg(target_os = "linux")]
#[test]
fn percpu_counter_aggregation_saturates_instead_of_wrapping() {
    use cloud_node_xdp_common::XdpCounters;
    let mut a = XdpCounters::default();
    a.packets = u64::MAX;
    a.tx = u64::MAX - 1;
    let mut b = XdpCounters::default();
    b.packets = 10;
    b.tx = 10;
    let slots = vec![a, b];
    let total = linux::sum_percpu_counters(slots.iter());
    assert_eq!(total.packets, u64::MAX);
    assert_eq!(total.tx, u64::MAX);
}

// ---- EN-05: parse classification mirror ----------------------------------

fn ipv4_tcp_flags_frame(flags: u8, doff_words: u8) -> Vec<u8> {
    let mut frame = ethernet_header(0x0800, false);
    let tcp_len = usize::from(doff_words) * 4;
    let total_len = 20 + tcp_len;
    frame.extend_from_slice(&[
        0x45,
        0,
        (total_len >> 8) as u8,
        total_len as u8,
        0,
        1,
        0,
        0,
        64,
        6,
        0,
        0,
        192,
        0,
        2,
        10,
        198,
        51,
        100,
        5,
    ]);
    frame.extend_from_slice(&[0xcf, 0x08, 0x01, 0xbb]);
    frame.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]);
    frame.push(doff_words << 4);
    frame.push(flags);
    frame.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
    for _ in 20..tcp_len {
        frame.push(1); // option bytes (e.g. MSS/TFO cookie space)
    }
    frame
}

fn ipv4_proto_frame(proto: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = ethernet_header(0x0800, false);
    let total_len = 20 + payload.len();
    frame.extend_from_slice(&[
        0x45,
        0,
        (total_len >> 8) as u8,
        total_len as u8,
        0,
        1,
        0,
        0,
        64,
        proto,
        0,
        0,
        192,
        0,
        2,
        10,
        198,
        51,
        100,
        5,
    ]);
    frame.extend_from_slice(payload);
    frame
}

fn ipv6_ext_frame(next: u8, ext_chain: &[u8], l4: &[u8]) -> Vec<u8> {
    let mut frame = ethernet_header(0x86dd, false);
    let payload_len = ext_chain.len() + l4.len();
    frame.extend_from_slice(&[
        0x60,
        0,
        0,
        0,
        (payload_len >> 8) as u8,
        payload_len as u8,
        next,
        64,
    ]);
    frame.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(ext_chain);
    frame.extend_from_slice(l4);
    frame
}

#[test]
fn classify_supported_tcp_udp_and_atomic_fragments() {
    use af_xdp::AfXdpFrameClass::*;
    assert_eq!(
        af_xdp::classify_frame(&ipv4_tcp_syn_frame(false)),
        Supported
    );
    assert_eq!(
        af_xdp::classify_frame(&ipv4_udp_frame(false, 0, b"hi")),
        Supported
    );
    // Atomic fragment (offset 0, MF clear) parses through to L4.
    assert_eq!(
        af_xdp::classify_frame(&ipv4_udp_frame(false, 0x4000, b"hi")),
        Supported
    );
}

#[test]
fn classify_fragments_never_reach_l4() {
    use af_xdp::AfXdpFrameClass::*;
    // First fragment: offset 0 + MF set — must NOT be treated as a flow.
    assert_eq!(
        af_xdp::classify_frame(&ipv4_udp_frame(false, 0x2000, b"hi")),
        Fragmented
    );
    // Non-first fragment.
    assert_eq!(
        af_xdp::classify_frame(&ipv4_udp_frame(false, 0x2001, b"hi")),
        Fragmented
    );
    // IPv6 first fragment (M=1, offset 0).
    let frag_first = [17, 0, 0, 1, 0, 0, 0, 1];
    assert_eq!(
        af_xdp::classify_frame(&ipv6_ext_frame(44, &frag_first, &[])),
        Fragmented
    );
    // IPv6 atomic fragment header continues to L4.
    let frag_atomic = [17, 0, 0, 0, 0, 0, 0, 1];
    let udp = [0xcf, 0x08, 0x01, 0xbb, 0, 8, 0, 0];
    assert_eq!(
        af_xdp::classify_frame(&ipv6_ext_frame(44, &frag_atomic, &udp)),
        Supported
    );
}

#[test]
fn classify_malformed_tcp_flag_combos() {
    use af_xdp::AfXdpFrameClass::*;
    assert_eq!(
        af_xdp::classify_frame(&ipv4_tcp_flags_frame(0x00, 5)),
        Malformed
    ); // NULL scan
    assert_eq!(
        af_xdp::classify_frame(&ipv4_tcp_flags_frame(0x03, 5)),
        Malformed
    ); // SYN|FIN
    assert_eq!(
        af_xdp::classify_frame(&ipv4_tcp_flags_frame(0x06, 5)),
        Malformed
    ); // SYN|RST
    assert_eq!(
        af_xdp::classify_frame(&ipv4_tcp_flags_frame(0x02, 5)),
        Supported
    ); // SYN
    assert_eq!(
        af_xdp::classify_frame(&ipv4_tcp_flags_frame(0x10, 5)),
        Supported
    ); // ACK
       // ECN flags are legal: SYN|ECE|CWR must not be hurt.
    assert_eq!(
        af_xdp::classify_frame(&ipv4_tcp_flags_frame(0xc2, 5)),
        Supported
    );
    // FIN|RST without SYN is unusual but not deterministic-illegal.
    assert_eq!(
        af_xdp::classify_frame(&ipv4_tcp_flags_frame(0x05, 5)),
        Supported
    );
}

#[test]
fn classify_malformed_lengths() {
    use af_xdp::AfXdpFrameClass::*;
    // TCP data offset below the 20-byte minimum.
    assert_eq!(
        af_xdp::classify_frame(&ipv4_tcp_flags_frame(0x02, 4)),
        Malformed
    );
    // TCP data offset beyond the declared datagram end.
    let mut f = ipv4_tcp_flags_frame(0x02, 15);
    f[16] = 0;
    f[17] = 50; // tot_len = 50 < 20 + 15*4 = 80
    assert_eq!(af_xdp::classify_frame(&f), Malformed);
    // UDP length field below the header size.
    let mut f = ipv4_udp_frame(false, 0, b"hello");
    let udp_off = f.len() - 8 - 5;
    f[udp_off + 4] = 0;
    f[udp_off + 5] = 4;
    assert_eq!(af_xdp::classify_frame(&f), Malformed);
    // UDP length beyond the datagram.
    let mut f = ipv4_udp_frame(false, 0, b"hello");
    f[udp_off + 4] = 0;
    f[udp_off + 5] = 60;
    assert_eq!(af_xdp::classify_frame(&f), Malformed);
    // IPv4 tot_len beyond what arrived (truncation).
    let mut f = ipv4_udp_frame(false, 0, b"hello");
    let ip_off = 14;
    f[ip_off + 2] = 0xff;
    f[ip_off + 3] = 0xff;
    assert_eq!(af_xdp::classify_frame(&f), Malformed);
}

#[test]
fn classify_tfo_and_options_unharmed() {
    use af_xdp::AfXdpFrameClass::*;
    // SYN with doff=8 (12 option bytes, e.g. MSS+TFO cookie) — legal.
    assert_eq!(
        af_xdp::classify_frame(&ipv4_tcp_flags_frame(0x02, 8)),
        Supported
    );
}

#[test]
fn classify_control_and_unsupported() {
    use af_xdp::AfXdpFrameClass::*;
    // ICMPv4 echo + PTB.
    assert_eq!(
        af_xdp::classify_frame(&ipv4_proto_frame(1, &[8, 0, 0, 0, 0, 0, 0, 0])),
        Control
    );
    assert_eq!(
        af_xdp::classify_frame(&ipv4_proto_frame(1, &[3, 4, 0, 0, 0, 0, 0, 0])),
        Control
    );
    // ICMPv6 NS.
    let udp_len8 = [135u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        af_xdp::classify_frame(&ipv6_ext_frame(58, &[], &udp_len8)),
        Control
    );
    // GRE/ESP etc: legal but unsupported by this dataplane.
    assert_eq!(
        af_xdp::classify_frame(&ipv4_proto_frame(47, &[0; 20])),
        Unsupported
    );
    // Non-IP ethertype (ARP).
    assert_eq!(
        af_xdp::classify_frame(&ethernet_header(0x0806, false)),
        NonIp
    );
    // Triple VLAN tag exceeds the bounded walk.
    let mut f = ethernet_header_with_vlan_tags(0x0800, &[(0x8100, 1), (0x8100, 2), (0x8100, 3)]);
    // fix: the third tag's TPID is what classify sees after two tags
    assert_eq!(af_xdp::classify_frame(&f), Unsupported);
    f.clear();
    // IPv6 unknown next-header and exhausted chain.
    assert_eq!(
        af_xdp::classify_frame(&ipv6_ext_frame(99, &[], &[0; 8])),
        Unsupported
    );
    // 9 chained dest-opts headers exceed the 8-iteration bound.
    let mut chain = Vec::new();
    for _ in 0..9 {
        chain.extend_from_slice(&[60, 0, 0, 0, 0, 0, 0, 0]);
    }
    assert_eq!(
        af_xdp::classify_frame(&ipv6_ext_frame(60, &chain, &[0; 8])),
        Unsupported
    );
    // Extension header length beyond the datagram -> malformed.
    let bad_ext = [17, 200, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        af_xdp::classify_frame(&ipv6_ext_frame(60, &bad_ext, &[0; 8])),
        Malformed
    );
}

#[test]
fn effective_budget_config_baseline_and_share_math() {
    // Baseline is always on (Normal pressure, no config): nonzero per-CPU
    // shares with both enforcement flags set.
    let manager = XdpManager::new(XdpConfig {
        enabled: true,
        interfaces: Vec::new(),
        ..XdpConfig::default()
    });
    let cfg = manager.effective_budget_config();
    assert_eq!(cfg.flags, 0b11_0111);
    assert!(cfg.unverified_pps >= 1);
    assert!(cfg.new_flow_per_sec >= 1);
    assert!(cfg.verified_pps >= 1);
    assert!(cfg.xsk_redirect_pps >= 1);
    assert!(cfg.control_pps >= 1);
    assert!(cfg.window_ns > 0);

    // Per-CPU share = ceil(total / ncpu): total quota cannot multiply with
    // CPU count. With ncpu unknown on this host, verify the share never
    // exceeds the configured total and never hits zero.
    let manager = XdpManager::new(XdpConfig {
        enabled: true,
        interfaces: Vec::new(),
        budget: Some(crate::runtime_mode::XdpBudgetSettings {
            enabled: true,
            unverified_pps: 8,
            new_flow_per_sec: 3,
            verified_pps: 16,
            xsk_redirect_pps: 4,
            control_pps: 2,
            window_ms: 1000,
        }),
        ..XdpConfig::default()
    });
    let cfg = manager.effective_budget_config();
    assert!(cfg.unverified_pps >= 1 && cfg.unverified_pps <= 8);
    assert!(cfg.new_flow_per_sec >= 1 && cfg.new_flow_per_sec <= 3);
    assert!(cfg.verified_pps >= 1 && cfg.verified_pps <= 16);
    assert!(cfg.xsk_redirect_pps >= 1 && cfg.xsk_redirect_pps <= 4);
    assert!(cfg.control_pps >= 1 && cfg.control_pps <= 2);

    // enabled=false writes an explicit all-zero config (flag bits clear) —
    // the only off switch, and it is operator-explicit.
    let manager = XdpManager::new(XdpConfig {
        enabled: true,
        interfaces: Vec::new(),
        budget: Some(crate::runtime_mode::XdpBudgetSettings {
            enabled: false,
            ..Default::default()
        }),
        ..XdpConfig::default()
    });
    let cfg = manager.effective_budget_config();
    assert_eq!(cfg.flags, 0);
    assert_eq!(cfg.unverified_pps, 0);
}

#[test]
fn scaled_rate_limit_config_window_prefix_and_floor() {
    use crate::runtime_mode::XdpRateLimitSettings;
    let base = XdpRateLimitSettings {
        udp_pps: 10_000,
        tcp_syn_pps: 3,
        window_ms: 250,
        prefix_v4_len: 24,
        prefix_v6_len: 200, // out of range: must clamp to 128
        gc_after_windows: 8,
    };
    let cfg = scaled_rate_limit_config(&base, 4);
    assert_eq!(cfg.udp_pps, 2_500);
    // Nonzero base divided below 1 clamps to 1 — never silently off.
    assert_eq!(cfg.tcp_syn_pps, 1);
    assert_eq!(cfg.window_ns, 250_000_000);
    assert_eq!(cfg.v4_prefix_len, 24);
    assert_eq!(cfg.v6_prefix_len, 128);

    // Zero base stays zero (explicit per-protocol off switch).
    let cfg = scaled_rate_limit_config(
        &XdpRateLimitSettings {
            udp_pps: 0,
            prefix_v4_len: 64, // clamps to 32
            ..Default::default()
        },
        2,
    );
    assert_eq!(cfg.udp_pps, 0);
    assert_eq!(cfg.v4_prefix_len, 32);
    assert_eq!(cfg.v6_prefix_len, 0);
}

/// EN-16: the eBPF map memory projection stays aligned with the spec table —
/// a sane nonzero bound well under 1 GiB on any plausible CPU count, and it
/// must never silently become zero (that would let attach pin unbounded
/// kernel memory unaccounted).
#[test]
#[cfg(target_os = "linux")]
fn projected_bpf_map_bytes_bounded() {
    let bytes = linux::projected_bpf_map_bytes();
    assert!(bytes > 100 * 1024 * 1024, "projection too small: {bytes}");
    assert!(bytes < 2 * 1024 * 1024 * 1024, "projection insane: {bytes}");
}

#[test]
fn kernel_bpf_budget_is_bounded_by_state_budget() {
    let snapshot = crate::memory_governor::MEMORY_GOVERNOR
        .snapshot(crate::memory_governor::MEMORY_GOVERNOR.pingora_worker_threads());
    assert!(snapshot.kernel_bpf_budget_bytes >= 32 * 1024 * 1024);
    assert!(snapshot.kernel_bpf_budget_bytes <= snapshot.memory_total_bytes);
}

/// EN-12: during reactor startup the worker lease keeps the bridge alive
/// without redirect; once workers are proven the gate hands off to redirect
/// readiness, and any degradation releases both.
#[test]
fn xdp_proxy_bridge_worker_lease_covers_startup_without_redirect() {
    let _guard = crate::runtime_mode::runtime_config_test_guard();
    RuntimeConfig::set_current(RuntimeConfig {
        xdp: test_proxy_config("eth-new"),
        ..RuntimeConfig::default()
    });
    let manager = replace_manager_from_runtime();
    mark_test_proxy_bridge_ready(&manager);
    // Redirect enabled but workers not starting: normal dataplane semantics.
    manager
        .proxy_redirect_enabled
        .store(false, Ordering::Relaxed);
    assert!(!af_xdp::proxy_bridge_should_continue(&manager));

    // Worker lease during startup keeps reactors alive before redirect opens.
    manager.set_proxy_workers_starting(true);
    assert!(af_xdp::proxy_bridge_should_continue(&manager));

    // Degradation during startup releases the lease and stops the workers.
    manager.mark_proxy_dataplane_degraded("test forced degraded");
    assert!(!manager.proxy_workers_starting());
    assert!(!af_xdp::proxy_bridge_should_continue(&manager));
}

/// EN-10: lifecycle feedback is ordered by (incarnation, owner_epoch, seq) —
/// a stale triple must never overwrite a newer record for the same tuple.
#[cfg(target_os = "linux")]
#[test]
fn flow_event_ledger_orders_by_incarnation_epoch_seq() {
    use cloud_node_xdp_common::*;

    let mut key = XdpFlowKey::default();
    key.family = 4;
    key.proto = XDP_PROTO_TCP;
    key.client_port_be = 1234u16.to_be();

    let event = |incarnation: u64, epoch: u64, seq: u64, kind: u8| XdpFlowEvent {
        key,
        flow_incarnation: incarnation,
        owner_epoch: epoch,
        seq,
        kind,
        ..Default::default()
    };

    let mut ledger = FlowEventLedger::default();
    assert!(ledger.apply(&event(1, 3, 1, XDP_FLOW_EVENT_ADMITTED)));
    // Same incarnation, older seq: stale.
    assert!(!ledger.apply(&event(1, 3, 0, XDP_FLOW_EVENT_VALIDATED)));
    assert!(ledger.apply(&event(1, 3, 2, XDP_FLOW_EVENT_VALIDATED)));
    // Older generation (smaller owner_epoch) can never renew the record.
    assert!(!ledger.apply(&event(1, 2, 99, XDP_FLOW_EVENT_ADMITTED)));
    // A recycled tuple (new incarnation) gets its own record, not a merge.
    assert!(ledger.apply(&event(2, 1, 0, XDP_FLOW_EVENT_ADMITTED)));
    assert_eq!(ledger.entries.len(), 2);
}

/// EN-10: at capacity the ledger evicts terminal records before live ones,
/// keeping feedback state bounded instead of growing without limit.
#[cfg(target_os = "linux")]
#[test]
fn flow_event_ledger_capacity_evicts_terminal_first() {
    use cloud_node_xdp_common::*;

    let mut ledger = FlowEventLedger::default();
    // Vary client_addr (not just port) so CAPACITY > u16::MAX stays distinct.
    let event = |index: u32, kind: u8| {
        let mut key = XdpFlowKey {
            family: 4,
            proto: XDP_PROTO_TCP,
            ..Default::default()
        };
        key.client_addr[12..16].copy_from_slice(&index.to_be_bytes());
        XdpFlowEvent {
            key,
            flow_incarnation: 1,
            owner_epoch: 1,
            seq: 1,
            kind,
            ..Default::default()
        }
    };

    for index in 0..(FlowEventLedger::CAPACITY as u32) {
        let kind = if index % 2 == 0 {
            XDP_FLOW_EVENT_CLOSED
        } else {
            XDP_FLOW_EVENT_ADMITTED
        };
        assert!(ledger.apply(&event(index, kind)));
    }
    assert_eq!(ledger.entries.len(), FlowEventLedger::CAPACITY);
    let closed_before = ledger
        .entries
        .values()
        .filter(|e| e.kind == XDP_FLOW_EVENT_CLOSED)
        .count();

    // New flow: evicts a CLOSED record, keeps every live (ADMITTED) one.
    assert!(ledger.apply(&event(u32::MAX, XDP_FLOW_EVENT_ADMITTED)));
    assert_eq!(ledger.entries.len(), FlowEventLedger::CAPACITY);
    assert_eq!(ledger.evicted, 1);
    let closed_after = ledger
        .entries
        .values()
        .filter(|e| e.kind == XDP_FLOW_EVENT_CLOSED)
        .count();
    let admitted_after = ledger
        .entries
        .values()
        .filter(|e| e.kind == XDP_FLOW_EVENT_ADMITTED)
        .count();
    assert_eq!(closed_before - closed_after, 1);
    assert_eq!(admitted_after, FlowEventLedger::CAPACITY / 2 + 1);
}
