use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cloud_node_rust::config::ConfigStore;
use cloud_node_rust::config_models::ServerConfig;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Runtime;

fn bench_config_lookup(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let store = Arc::new(ConfigStore::new());
    
    // Setup 1000 servers
    let mut servers = HashMap::new();
    for i in 0..1000 {
        let server_id = i as i64;
        let cfg = ServerConfig {
            id: Some(server_id),
            ..Default::default()
        };
        // Use string ID as host key for testing
        servers.insert(server_id.to_string(), cfg);
    }
    
    rt.block_on(async {
        store.update_config(
            1, 1, servers, HashMap::new(), vec![], vec![], vec![], 1, HashMap::new(), false, None, vec![], vec![]
        ).await;
    });
    
    c.bench_function("config_lookup_1000_items", |b| {
        b.to_async(&rt).iter(|| async {
            let _ = black_box(store.get_server("500").await);
        })
    });
}

criterion_group!(benches, bench_config_lookup);
criterion_main!(benches);
