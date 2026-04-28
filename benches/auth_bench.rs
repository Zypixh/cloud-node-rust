use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cloud_node_rust::auth::{generate_token, verify_url_auth, UrlAuthConfig};
use std::time::{SystemTime, UNIX_EPOCH};

fn bench_generate_token(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth_token_generation");

    group.bench_function("generate_token_typical", |b| {
        b.iter(|| {
            generate_token(black_box("node-abc123"), black_box("secret-key-32bytes!!!"), black_box("edge"))
        })
    });

    group.bench_function("generate_token_short_secret", |b| {
        b.iter(|| {
            generate_token(black_box("n1"), black_box("sh0rt"), black_box("edge"))
        })
    });

    group.bench_function("generate_token_long_inputs", |b| {
        b.iter(|| {
            generate_token(
                black_box("node-very-long-id-0123456789-abcdef"),
                black_box("super-secret-key-that-is-very-long-0123456789-abcdefghijklmnop"),
                black_box("edge"),
            )
        })
    });

    group.finish();
}

fn bench_url_auth(c: &mut Criterion) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let config = UrlAuthConfig {
        auth_type: "A".to_string(),
        secret: "very-secret-key-1234567890".to_string(),
        param_name: "auth_key".to_string(),
        life: 3600,
    };

    let path = "/video/test.mp4";
    let auth_token = format!("{}-rand-123-placeholder-hash", now);
    let query = format!("auth_key={}", auth_token);

    let mut group = c.benchmark_group("url_auth_verification");

    group.bench_function("verify_type_a", |b| {
        b.iter(|| {
            verify_url_auth(black_box(path), black_box(&query), black_box(&config))
        })
    });

    group.finish();
}

criterion_group!(benches, bench_generate_token, bench_url_auth);
criterion_main!(benches);
