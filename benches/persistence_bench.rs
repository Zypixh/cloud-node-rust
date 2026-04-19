use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde_json;

fn bench_serialization_large_list(c: &mut Criterion) {
    // Mock 10,000 blocked IPs with (IP, ServerID, ExpireTimestamp)
    let mut ips = Vec::new();
    for i in 0..10000 {
        ips.push((format!("103.20.{}.{}", i % 255, i % 100), i as i64, 1770000000 + i as u64));
    }

    c.bench_function("serialize_10k_blocked_ips", |b| {
        b.iter(|| {
            let _ = black_box(serde_json::to_string(&ips).unwrap());
        })
    });

    let json_data = serde_json::to_string(&ips).unwrap();
    c.bench_function("deserialize_10k_blocked_ips", |b| {
        b.iter(|| {
            let _: Vec<(String, i64, u64)> = black_box(serde_json::from_str(&json_data).unwrap());
        })
    });
}

criterion_group!(benches, bench_serialization_large_list);
criterion_main!(benches);
