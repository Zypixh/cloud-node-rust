use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cloud_node_rust::logging::{
    next_request_id, report_node_log, set_numeric_node_id,
};
use cloud_node_rust::utils::time::{local_from_timestamp_millis, now_timestamp_millis};

fn bench_request_id(c: &mut Criterion) {
    set_numeric_node_id(42);

    let mut group = c.benchmark_group("request_id_generation");

    group.bench_function("next_request_id", |b| {
        b.iter(|| {
            let _ = black_box(next_request_id());
        })
    });

    group.bench_function("next_request_id_batch_10", |b| {
        b.iter(|| {
            for _ in 0..10 {
                black_box(next_request_id());
            }
        })
    });

    group.finish();
}

fn bench_time_formatting(c: &mut Criterion) {
    let now_millis = now_timestamp_millis();

    let mut group = c.benchmark_group("access_log_time_formatting");

    group.bench_function("local_from_timestamp_millis", |b| {
        b.iter(|| {
            let _ = black_box(local_from_timestamp_millis(black_box(now_millis)));
        })
    });

    group.bench_function("iso8601_format", |b| {
        b.iter(|| {
            let dt = local_from_timestamp_millis(black_box(now_millis));
            let _ = black_box(dt.format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string());
        })
    });

    group.bench_function("apache_common_format", |b| {
        b.iter(|| {
            let dt = local_from_timestamp_millis(black_box(now_millis));
            let _ = black_box(dt.format("%d/%b/%Y:%H:%M:%S %z").to_string());
        })
    });

    group.finish();
}

fn bench_node_log_report(c: &mut Criterion) {
    // report_node_log uses a static OnceCell sender; when not initialized, it's a no-op
    // This measures the fast path (no sender configured)
    let mut group = c.benchmark_group("node_log_reporting");

    group.bench_function("report_node_log_noop", |b| {
        b.iter(|| {
            report_node_log(
                black_box("info".to_string()),
                black_box("TEST_TAG".to_string()),
                black_box("test message for benchmarking".to_string()),
                black_box(0),
            );
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_request_id,
    bench_time_formatting,
    bench_node_log_report,
);
criterion_main!(benches);
