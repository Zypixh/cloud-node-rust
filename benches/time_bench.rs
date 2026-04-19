use criterion::{black_box, criterion_group, criterion_main, Criterion};
use chrono::{Utc, Local};
use cloud_node_rust::utils::time::{now_utc, now_local, update_time_offset};

fn bench_time_functions(c: &mut Criterion) {
    let mut group = c.benchmark_group("time_resolution");

    // 1. Baseline: Raw chrono::Utc::now()
    group.bench_function("raw_chrono_utc_now", |b| {
        b.iter(|| {
            let _ = black_box(Utc::now());
        })
    });

    // 2. Optimized: Offset-adjusted now_utc()
    update_time_offset(Utc::now().timestamp() + 3600);
    group.bench_function("optimized_now_utc", |b| {
        b.iter(|| {
            let _ = black_box(now_utc());
        })
    });

    // 3. Baseline: Raw chrono::Local::now() (usually VERY slow in containers)
    group.bench_function("raw_chrono_local_now", |b| {
        b.iter(|| {
            let _ = black_box(Local::now());
        })
    });

    // 4. Optimized: Offset-adjusted now_local() with cached TZ
    group.bench_function("optimized_now_local", |b| {
        b.iter(|| {
            let _ = black_box(now_local());
        })
    });

    group.finish();
}

criterion_group!(benches, bench_time_functions);
criterion_main!(benches);
