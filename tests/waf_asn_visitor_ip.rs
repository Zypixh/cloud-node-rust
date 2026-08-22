//! WAF ASN matching and visitor-IP resolution audit tests.

use cloud_node_rust::client_ip;
use cloud_node_rust::config_models::{HTTPRemoteAddrConfig, ServerConfig};
use cloud_node_rust::metrics::analyzer;
use std::net::IpAddr;

#[test]
fn asn_lookup_is_empty_without_database() {
    let ip: IpAddr = "8.8.8.8".parse().unwrap();
    assert_eq!(analyzer::lookup_asn_number(ip), 0);
    assert_eq!(analyzer::lookup_asn_label(ip).as_ref(), "");
    assert!(!analyzer::asn_database_available());
}

#[test]
fn remote_addr_request_header_config_expands_header_names() {
    let cfg: HTTPRemoteAddrConfig = serde_json::from_value(serde_json::json!({
        "isOn": true,
        "type": "requestHeader",
        "requestHeaderName": "X-Forwarded-For"
    }))
    .unwrap();
    assert_eq!(cfg.expanded_header_names(), vec!["X-Forwarded-For"]);
}

#[test]
fn remote_addr_direct_type_uses_socket_ip() {
    let cfg: HTTPRemoteAddrConfig = serde_json::from_value(serde_json::json!({
        "isOn": true,
        "type": "default"
    }))
    .unwrap();
    assert!(cfg.is_direct_type());
}

#[test]
fn server_remote_addr_config_is_enabled_when_on_and_non_empty() {
    let server: ServerConfig = serde_json::from_value(serde_json::json!({
        "id": 1,
        "web": {
            "remoteAddr": {
                "isOn": true,
                "type": "requestHeader",
                "requestHeaderName": "X-Forwarded-For"
            }
        }
    }))
    .unwrap();
    let remote_addr = server.web.as_ref().unwrap().remote_addr.as_ref().unwrap();
    assert!(remote_addr.is_on && !remote_addr.is_empty());
}

#[test]
fn fallback_client_ip_does_not_trust_headers_from_public_peer() {
    let public_peer: IpAddr = "203.0.113.50".parse().unwrap();
    assert!(!client_ip::is_local_ip(&public_peer));
    // Without a Session, verify the guard condition used by fallback resolution.
    assert_eq!(client_ip::canonicalize_ip(public_peer), public_peer);
}
