use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cloud_node_rust::cache_hybrid::HybridStorage;
use pingora_cache::{CacheKey, Storage, trace::Span};
use tokio::runtime::Runtime;

async fn setup_hybrid_storage() -> HybridStorage {
    let disk_path = "target/cache_bench_disk";
    let _ = std::fs::remove_dir_all(disk_path);
    HybridStorage::new(1024 * 1024 * 10, disk_path)
}

fn bench_cache_lookup(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let storage: &'static HybridStorage = Box::leak(Box::new(rt.block_on(setup_hybrid_storage())));
    
    // Create a dummy CacheKey (namespace, primary, user_tag)
    let key = CacheKey::new("http", "example.com", "/static/image.png");

    c.bench_function("cache_hybrid_lookup_miss", |b| {
        b.to_async(&rt).iter(|| async {
            let _ = black_box(storage.lookup(&key, &Span::inactive().handle()).await);
        })
    });
}

criterion_group!(benches, bench_cache_lookup);
criterion_main!(benches);
