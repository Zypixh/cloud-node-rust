use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cloud_node_rust::rewrite::{evaluate_rewrites, evaluate_host_redirects};
use cloud_node_rust::config_models::{HTTPRewriteRule, HTTPRewriteRef, HTTPHostRedirectConfig};

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
        },
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

    c.bench_function("rewrite_no_match", |b| {
        b.iter(|| {
            let _ = black_box(evaluate_rewrites("/other/path", "", &refs, &rules));
        })
    });

    // Test with query string
    c.bench_function("rewrite_with_query", |b| {
        b.iter(|| {
            let _ = black_box(evaluate_rewrites(
                "/api/v1/search?q=test&page=1",
                "q=test&page=1",
                &refs,
                &rules,
            ));
        })
    });

    // 20 rules to measure iteration cost
    let many_rules: Vec<HTTPRewriteRule> = (0..20)
        .map(|i| HTTPRewriteRule {
            pattern: Some(format!("^/api/v{}/users/(.*)$", i)),
            replace: Some(format!("/v{}/users/$1", i)),
            is_on: true,
            ..Default::default()
        })
        .collect();
    let many_refs: Vec<HTTPRewriteRef> = (0..20)
        .map(|_| HTTPRewriteRef { is_on: true })
        .collect();

    c.bench_function("rewrite_20_rules_last_match", |b| {
        b.iter(|| {
            let _ = black_box(evaluate_rewrites(
                "/api/v19/users/profile",
                "",
                &many_refs,
                &many_rules,
            ));
        })
    });

    c.bench_function("rewrite_20_rules_no_match", |b| {
        b.iter(|| {
            let _ = black_box(evaluate_rewrites(
                "/something/else/entirely",
                "",
                &many_refs,
                &many_rules,
            ));
        })
    });

    // Redirect mode
    let redirect_rules = vec![HTTPRewriteRule {
        pattern: Some("^/old-site/(.*)$".to_string()),
        replace: Some("https://newsite.com/$1".to_string()),
        mode: Some("redirect".to_string()),
        is_on: true,
        ..Default::default()
    }];
    let redirect_refs = vec![HTTPRewriteRef { is_on: true }];

    c.bench_function("rewrite_redirect_mode", |b| {
        b.iter(|| {
            let _ = black_box(evaluate_rewrites(
                "/old-site/page.html",
                "",
                &redirect_refs,
                &redirect_rules,
            ));
        })
    });
}

fn bench_host_redirects(c: &mut Criterion) {
    let host = "www.example.com";
    let scheme = "http";

    let rules = vec![
        HTTPHostRedirectConfig {
            before: "old.example.com".to_string(),
            after: "www.example.com".to_string(),
            status_code: 301,
            is_on: true,
            before_host: None,
            after_host: None,
            keep_request_uri: false,
        },
        HTTPHostRedirectConfig {
            before: "www.example.com".to_string(),
            after: "https://www.example.com".to_string(),
            status_code: 301,
            is_on: true,
            before_host: None,
            after_host: None,
            keep_request_uri: false,
        },
    ];

    let mut group = c.benchmark_group("host_redirects");

    group.bench_function("evaluate_hit", |b| {
        b.iter(|| {
            let _ = black_box(evaluate_host_redirects(
                black_box(host),
                black_box(scheme),
                black_box(&rules),
            ));
        })
    });

    group.bench_function("evaluate_miss", |b| {
        b.iter(|| {
            let _ = black_box(evaluate_host_redirects(
                black_box("other.example.com"),
                black_box(scheme),
                black_box(&rules),
            ));
        })
    });

    group.bench_function("evaluate_10_rules", |b| {
        let many_rules: Vec<HTTPHostRedirectConfig> = (0..10)
            .map(|i| HTTPHostRedirectConfig {
                before: format!("host{}.example.com", i),
                after: format!("redirect{}.example.com", i),
                status_code: 301,
                is_on: true,
                before_host: None,
                after_host: None,
                keep_request_uri: false,
            })
            .collect();
        b.iter(|| {
            let _ = black_box(evaluate_host_redirects(
                black_box("host9.example.com"),
                black_box(scheme),
                black_box(&many_rules),
            ));
        })
    });

    group.finish();
}

criterion_group!(benches, bench_rewrite_logic, bench_host_redirects);
criterion_main!(benches);
