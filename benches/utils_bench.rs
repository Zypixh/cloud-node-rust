use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cloud_node_rust::utils::fnv_hash64;

fn bench_utility_functions(c: &mut Criterion) {
    let mut group = c.benchmark_group("utils_operations");

    // 1. Bench FNV Hash used for fast caching lookups
    let sample_string = "https://www.example.com/some/very/long/path/with/args?id=123456&timestamp=987654321";
    group.bench_function("fnv_hash64_url", |b| {
        b.iter(|| {
            let _ = black_box(fnv_hash64(black_box(sample_string)));
        })
    });

    group.finish();
}

criterion_group!(benches, bench_utility_functions);
criterion_main!(benches);
