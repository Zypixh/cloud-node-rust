use cloud_node_rust::config::ConfigStore;
use cloud_node_rust::config_models::ServerConfig;
use criterion::{Criterion, criterion_group, criterion_main};
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;
use tokio::runtime::Runtime;

fn bench_config_lookup(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let store = Arc::new(ConfigStore::new());

    // Setup 1000 servers
    let mut servers = HashMap::new();
    for i in 0..1000 {
        let server_id = i as i64;
        let cfg = Arc::new(ServerConfig {
            id: Some(server_id),
            ..Default::default()
        });
        servers.insert(format!("host{}.example.com", i), cfg);
    }

    rt.block_on(async {
        let all_servers: Vec<Arc<ServerConfig>> = servers.values().cloned().collect();
        store
            .update_config(
                1,
                1,
                1,
                1,
                all_servers,
                servers,
                HashMap::new(),
                HashMap::new(),
                vec![],
                vec![],
                vec![],
                vec![],
                None,
                1,
                1,
                true,
                false,
                HashMap::new(),
                false,
                false,
                String::new(),
                HashMap::new(),
                None,
                false,
                false,
                String::new(),
                false,
                false,
                0,
                false,
                false,
                false,
                String::new(),
                None,
                None,
                vec![],
                vec![],
                vec![],
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                None,
                None,
            )
            .await;
    });

    c.bench_function("config_lookup_1000_items", |b| {
        b.to_async(&rt).iter(|| async {
            let _ = black_box(store.get_server("host500.example.com").await);
        })
    });

    c.bench_function("config_lookup_miss", |b| {
        b.to_async(&rt).iter(|| async {
            let _ = black_box(store.get_server("nonexistent.example.com").await);
        })
    });

    let mut group = c.benchmark_group("config_hotpath");

    group.bench_function("get_global_http_config_sync", |b| {
        b.iter(|| {
            let _ = black_box(store.get_global_http_config_sync());
        })
    });

    group.bench_function("get_request_context_sync", |b| {
        b.to_async(&rt).iter(|| async {
            let _ = black_box(store.get_request_context_sync("host500.example.com"));
        })
    });

    group.finish();
}

criterion_group!(benches, bench_config_lookup);
criterion_main!(benches);
