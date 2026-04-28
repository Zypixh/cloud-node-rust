use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cloud_node_rust::logging::{next_request_id, set_numeric_node_id};
use cloud_node_rust::firewall::matcher::evaluate_operator;
use cloud_node_rust::utils::time::{now_timestamp_millis, local_from_timestamp_millis};
use cloud_node_rust::utils::fnv_hash64;
use std::collections::HashMap;

/// Simulates the full request processing pipeline in isolation
fn bench_request_pipeline(c: &mut Criterion) {
    set_numeric_node_id(42);

    let mut group = c.benchmark_group("request_pipeline");

    // Stage 1: Request ID generation (atomic timestamp + counter)
    group.bench_function("stage1_request_id", |b| {
        b.iter(|| {
            let _ = black_box(next_request_id());
        })
    });

    // Stage 2: Header parsing — Host, Cookie, Authorization
    group.bench_function("stage2_header_parsing", |b| {
        let host = "www.example.com:8443";
        let cookie = "session=abc123; user=john; theme=dark; lang=en; _ga=GA1.2.123.456";
        let auth = "Basic dXNlcjpwYXNzd29yZA==";
        b.iter(|| {
            let h = black_box(host).split(':').next().unwrap_or(host);
            let mut cookies = HashMap::new();
            for part in black_box(cookie).split(';') {
                if let Some((k, v)) = part.trim().split_once('=') {
                    cookies.insert(k.trim().to_string(), v.trim().to_string());
                }
            }
            let user = if auth.to_lowercase().starts_with("basic ") {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD
                    .decode(auth[6..].trim().as_bytes())
                    .ok()
                    .and_then(|d| String::from_utf8(d).ok())
                    .and_then(|c| c.split_once(':').map(|(u, _)| u.to_string()))
            } else {
                None
            };
            black_box((h, cookies.len(), user))
        })
    });

    // Stage 3: URI parsing
    group.bench_function("stage3_uri_parsing", |b| {
        let uri = "https://example.com/api/v1/users/123/profile?format=json&lang=en";
        b.iter(|| {
            let path = if let Some(idx) = uri.find("://") {
                let rest = &uri[idx + 3..];
                if let Some(path_idx) = rest.find('/') {
                    &rest[path_idx..]
                } else {
                    "/"
                }
            } else {
                "/"
            };
            let query = path.split('?').nth(1).unwrap_or("");
            black_box((path, query))
        })
    });

    // Stage 4: Firewall/WAF evaluation (multiple operators)
    group.bench_function("stage4_firewall_eval", |b| {
        let payload = "SELECT * FROM users UNION SELECT password FROM admin--";
        b.iter(|| {
            let _ = evaluate_operator(
                black_box(payload), "contains sql injection", "", false
            );
        })
    });

    // Stage 5: Time formatting (for access logs)
    group.bench_function("stage5_log_time_formatting", |b| {
        let ts = now_timestamp_millis();
        b.iter(|| {
            let dt = local_from_timestamp_millis(black_box(ts));
            let iso = dt.format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string();
            let apache = dt.format("%d/%b/%Y:%H:%M:%S %z").to_string();
            black_box((iso, apache))
        })
    });

    // Stage 6: Hash computation for cache keys
    group.bench_function("stage6_cache_key_hash", |b| {
        let url = "https://www.example.com/some/very/long/path/with/args?id=123456&timestamp=987654321";
        b.iter(|| {
            let _ = black_box(fnv_hash64(black_box(url)));
        })
    });

    group.finish();
}

fn bench_firewall_comprehensive(c: &mut Criterion) {
    let mut group = c.benchmark_group("firewall_comprehensive");

    let payloads: [(&str, &str, &str, &str); 12] = [
        ("clean_text", "Hello World, this is normal text with numbers 12345", "eq string", "Hello World, this is normal text with numbers 12345"),
        ("sqli_union", "SELECT * FROM users UNION SELECT password FROM admin--", "contains sql injection", ""),
        ("sqli_strict", "' OR 1=1 --", "contains sql injection strictly", ""),
        ("xss_script", "<img src=x onerror=alert(1)>", "contains xss", ""),
        ("xss_strict", "<script>alert(1)</script>", "contains xss strictly", ""),
        ("cmd_injection", "foo; /bin/sh -c 'cat /etc/passwd'", "contains cmd injection", ""),
        ("ip_range", "10.0.5.100", "in ip list", "10.0.0.0/8\n172.16.0.0/12"),
        ("regex_match", "https://example.com/api/v2/users/12345/profile", "regexp", r"^https?://[^/]+/api/v\d+/users/\d+/profile"),
        ("regex_notmatch", "https://example.com/admin/login", "not regexp", r"^https?://[^/]+/api/"),
        ("wildcard_match", "/api/v1/users/123/profile", "wildcard match", "/api/v1/users/*/profile"),
        ("wildcard_notmatch", "/admin/delete/user/123", "wildcard not match", "/api/v1/*"),
        ("version_gt", "2.0.1", "version gt", "1.9.9"),
    ];

    for (name, payload, op, expected) in &payloads {
        group.bench_function(*name, |b| {
            b.iter(|| {
                evaluate_operator(black_box(payload), black_box(op), black_box(expected), false)
            })
        });
    }

    group.finish();
}

fn bench_string_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("string_operations");

    group.bench_function("host_header_strip_port", |b| {
        let host = "www.example.com:8080";
        b.iter(|| {
            black_box(black_box(host).split(':').next().unwrap_or(host))
        })
    });

    group.bench_function("xff_split_limit_5", |b| {
        let xff = "1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5, 6.6.6.6, 7.7.7.7";
        b.iter(|| {
            let parts: Vec<&str> = black_box(xff).split(',').map(|s| s.trim()).collect();
            let limited = if parts.len() > 5 { &parts[parts.len() - 5..] } else { &parts };
            black_box(limited.join(", "))
        })
    });

    group.bench_function("content_type_get_mime", |b| {
        let ct = "text/html; charset=utf-8; boundary=something";
        b.iter(|| {
            black_box(black_box(ct).split(';').next().unwrap_or(ct))
        })
    });

    group.bench_function("port_from_addr", |b| {
        let addr = "192.168.1.100:54321";
        b.iter(|| {
            black_box(black_box(addr).rsplit(':').next().and_then(|p| p.parse::<u16>().ok()))
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_request_pipeline,
    bench_firewall_comprehensive,
    bench_string_operations,
);
criterion_main!(benches);
