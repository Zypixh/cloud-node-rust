use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pingora_load_balancing::{LoadBalancer, Backends, discovery::Static, selection::RoundRobin};
use std::sync::Arc;

fn bench_lb_selection(c: &mut Criterion) {
    let mut upstreams = Vec::new();
    for i in 0..100 {
        upstreams.push(format!("127.0.0.1:{}", 8000 + i));
    }
    
    // Create Static service discovery from the list of strings
    let discovery = Static::try_from_iter(upstreams).expect("Failed to create static discovery");
    let backends = Backends::new(discovery);
    let lb = Arc::new(LoadBalancer::<RoundRobin>::from_backends(backends));
    
    c.bench_function("lb_selection_100_nodes", |b| {
        b.iter(|| {
            let _ = black_box(lb.select(b"", 256));
        })
    });
}

criterion_group!(benches, bench_lb_selection);
criterion_main!(benches);
