use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cloud_node_rust::rewrite::evaluate_rewrites;
use cloud_node_rust::config_models::{HTTPRewriteRule, HTTPRewriteRef};

fn bench_rewrite_logic(c: &mut Criterion) {
    // Mock rules: /api/v1/(.*) -> /v1/$1
    let rules = vec![
        HTTPRewriteRule {
            pattern: Some("^/api/v1/(.*)$".to_string()),
            replace: Some("/v1/$1".to_string()),
            is_on: true,
            ..Default::default()
        },
        HTTPRewriteRule {
            pattern: Some("^/old/(.*)$".to_string()),
            replace: Some("/new/$1".to_string()),
            is_on: true,
            ..Default::default()
        }
    ];
    let refs = vec![
        HTTPRewriteRef { is_on: true },
        HTTPRewriteRef { is_on: true },
    ];

    let uri = "/api/v1/user/profile";
    
    c.bench_function("rewrite_regex_match", |b| {
        b.iter(|| {
            let _ = black_box(evaluate_rewrites(uri, "", &refs, &rules));
        })
    });
}

criterion_group!(benches, bench_rewrite_logic);
criterion_main!(benches);
