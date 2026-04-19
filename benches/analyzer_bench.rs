use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cloud_node_rust::metrics::analyzer::analyze_request;
use std::net::IpAddr;

fn bench_request_analysis(c: &mut Criterion) {
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1";

    c.bench_function("request_analysis_full", |b| {
        b.iter(|| {
            let _ = black_box(analyze_request(black_box(ip), black_box(ua)));
        })
    });
}

criterion_group!(benches, bench_request_analysis);
criterion_main!(benches);
