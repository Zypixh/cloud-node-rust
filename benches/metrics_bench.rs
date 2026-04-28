use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cloud_node_rust::metrics::record;

fn bench_metrics_recording(c: &mut Criterion) {
    let server_id = 123;
    let client_ip = "1.2.3.4";

    let mut group = c.benchmark_group("metrics_overhead");

    group.bench_function("request_start_record", |b| {
        b.iter(|| {
            record::request_start(
                black_box(server_id),
                black_box(client_ip.to_string()),
                black_box(0),
                black_box(0),
                black_box(0),
                black_box(None),
                black_box(false),
            )
        })
    });

    group.bench_function("request_end_record", |b| {
        b.iter(|| {
            record::request_end(
                black_box(server_id),
                black_box(1024),
                black_box(512),
                black_box(true),
                black_box(false),
                black_box(false),
                black_box(None),
            )
        })
    });

    group.finish();
}

criterion_group!(benches, bench_metrics_recording);
criterion_main!(benches);
