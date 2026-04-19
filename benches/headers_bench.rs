use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cloud_node_rust::headers::apply_response_header_policy_to_map;
use cloud_node_rust::config_models::{HTTPHeaderPolicy, HTTPHeaderConfig};
use std::collections::HashMap;

fn bench_headers_policy(c: &mut Criterion) {
    let mut headers = HashMap::new();
    headers.insert("server".to_string(), "nginx".to_string());
    headers.insert("content-type".to_string(), "text/html".to_string());
    headers.insert("x-powered-by".to_string(), "php".to_string());

    let policy = HTTPHeaderPolicy {
        delete_headers: vec!["x-powered-by".to_string()],
        set_headers: vec![
            HTTPHeaderConfig { name: "server".to_string(), value: "CloudNode".to_string(), is_on: true },
        ],
        add_headers: vec![
            HTTPHeaderConfig { name: "x-frame-options".to_string(), value: "SAMEORIGIN".to_string(), is_on: true },
        ],
        ..Default::default()
    };

    c.bench_function("headers_policy_apply", |b| {
        b.iter(|| {
            let mut h = headers.clone();
            apply_response_header_policy_to_map(black_box(&mut h), black_box(&policy));
        })
    });
}

criterion_group!(benches, bench_headers_policy);
criterion_main!(benches);
