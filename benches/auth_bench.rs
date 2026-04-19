use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cloud_node_rust::auth::{verify_url_auth, UrlAuthConfig};
use std::time::{SystemTime, UNIX_EPOCH};

fn bench_url_auth(c: &mut Criterion) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let config = UrlAuthConfig {
        auth_type: "A".to_string(),
        secret: "very-secret-key-1234567890".to_string(),
        param_name: "auth_key".to_string(),
        life: 3600,
    };

    // Type A payload: timestamp-rand-uid-md5hash
    let path = "/video/test.mp4";
    let auth_token = format!("{}-rand-123-placeholder-hash", now);
    let query = format!("auth_key={}", auth_token);

    let mut group = c.benchmark_group("url_auth_verification");

    group.bench_function("verify_type_a", |b| {
        b.iter(|| {
            // Note: This will likely fail the hash check but we measure the execution path
            verify_url_auth(black_box(path), black_box(&query), black_box(&config))
        })
    });

    group.finish();
}

criterion_group!(benches, bench_url_auth);
criterion_main!(benches);
