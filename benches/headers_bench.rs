use cloud_node_rust::config_models::{HTTPHeaderConfig, HTTPHeaderPolicy};
use cloud_node_rust::headers::apply_response_header_policy_to_map;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::collections::HashMap;

fn bench_headers_policy(c: &mut Criterion) {
    let mut headers = HashMap::new();
    headers.insert("server".to_string(), "nginx".to_string());
    headers.insert("content-type".to_string(), "text/html".to_string());
    headers.insert("x-powered-by".to_string(), "php".to_string());

    let policy = HTTPHeaderPolicy {
        delete_headers: vec!["x-powered-by".to_string()],
        set_headers: vec![HTTPHeaderConfig {
            name: "server".to_string(),
            value: "CloudNode".to_string(),
            is_on: true,
            status: None,
            disable_redirect: false,
            should_append: false,
            should_replace: false,
            replace_values: Vec::new(),
            methods: Vec::new(),
            domains: Vec::new(),
        }],
        add_headers: vec![HTTPHeaderConfig {
            name: "x-frame-options".to_string(),
            value: "SAMEORIGIN".to_string(),
            is_on: true,
            status: None,
            disable_redirect: false,
            should_append: false,
            should_replace: false,
            replace_values: Vec::new(),
            methods: Vec::new(),
            domains: Vec::new(),
        }],
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
