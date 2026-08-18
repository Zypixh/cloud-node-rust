mod storage_backends;

use cloud_node_rust::metrics::storage::{CacheMetaUpsert, MetricStorage};
use storage_backends::{
    BackendKind, StorageBackend, open_backend, prefill_firewall_records, sample_metric_updates,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn bench_kv_basic(c: &mut Criterion) {
    let mut group = c.benchmark_group("compare_kv_basic");
    group.measurement_time(Duration::from_secs(8));

    for backend in BackendKind::ALL {
        group.bench_with_input(BenchmarkId::new("put_json", backend.name()), &backend, |b, kind| {
            let storage = open_backend(*kind, "put_json");
            let mut n = 0u64;
            b.iter(|| {
                n += 1;
                black_box(storage.put_json(&format!("meta_{n}"), &n));
            });
        });

        group.bench_with_input(
            BenchmarkId::new("get_json_hit", backend.name()),
            &backend,
            |b, kind| {
                let storage = open_backend(*kind, "get_json_hit");
                storage.put_json("meta_hit", &42u64);
                b.iter(|| black_box(storage.get_json::<u64>("meta_hit")));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("get_value_counter", backend.name()),
            &backend,
            |b, kind| {
                let storage = open_backend(*kind, "get_value");
                storage.increment_batch(vec![("counter".to_string(), 100)]);
                b.iter(|| black_box(storage.get_value("counter")));
            },
        );
    }

    group.finish();
}

fn bench_metrics_write_paths(c: &mut Criterion) {
    let mut group = c.benchmark_group("compare_metrics_write");
    group.measurement_time(Duration::from_secs(8));

    for backend in BackendKind::ALL {
        for count in [10usize, 50, 100] {
            group.throughput(Throughput::Elements(count as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("increment_batch/{count}"), backend.name()),
                &(backend, count),
                |b, (kind, count)| {
                    let storage = open_backend(*kind, &format!("incr_{count}"));
                    let updates: Vec<(String, u64)> = (0..*count)
                        .map(|i| (format!("S1_T1000_req_{i}"), 1))
                        .collect();
                    b.iter(|| black_box(storage.increment_batch(updates.clone())));
                },
            );

            group.bench_with_input(
                BenchmarkId::new(format!("record_server_batch/{count}"), backend.name()),
                &(backend, count),
                |b, (kind, count)| {
                    let storage = open_backend(*kind, &format!("server_batch_{count}"));
                    let updates = sample_metric_updates(*count);
                    b.iter(|| {
                        black_box(storage.record_server_batch(
                            1_700_000_000,
                            updates.clone(),
                            4096,
                            2048,
                        ))
                    });
                },
            );
        }
    }

    group.finish();
}

fn bench_firewall_and_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("compare_firewall_scan");
    group.measurement_time(Duration::from_secs(8));

    for backend in BackendKind::ALL {
        group.throughput(Throughput::Elements(100));
        group.bench_with_input(
            BenchmarkId::new("write_raw_batch_100", backend.name()),
            &backend,
            |b, kind| {
                let storage = open_backend(*kind, "fw_batch");
                let mut seq = 0u64;
                b.iter(|| {
                    seq += 100;
                    let puts = (0..100)
                        .map(|i| {
                            (
                                format!("FWBLK_V1_bench_{}_{i}", seq + i as u64),
                                br#"{"target":"192.0.2.1"}"#.to_vec(),
                            )
                        })
                        .collect();
                    black_box(storage.write_raw_batch(puts, Vec::new()));
                });
            },
        );

        for count in [100usize, 1000] {
            group.throughput(Throughput::Elements(count as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("scan_json_prefix/{count}"), backend.name()),
                &(backend, count),
                |b, (kind, count)| {
                    let storage = open_backend(*kind, &format!("scan_{count}"));
                    prefill_firewall_records(&storage, *count);
                    b.iter(|| black_box(storage.scan_json_prefix_count("FWBLK_V1_")));
                },
            );
        }
    }

    group.finish();
}

fn bench_cache_disk_paths(c: &mut Criterion) {
    let mut group = c.benchmark_group("compare_cache_disk");
    group.measurement_time(Duration::from_secs(8));

    for backend in BackendKind::ALL {
        group.throughput(Throughput::Elements(200));
        group.bench_with_input(
            BenchmarkId::new("put_cache_meta_json", backend.name()),
            &backend,
            |b, kind| {
                let storage = open_backend(*kind, "cache_put");
                let mut n = 0u64;
                b.iter(|| {
                    n += 1;
                    let key = format!("CMETA_hash_{n}");
                    let json = format!(
                        r#"{{"k":"/assets/app.js","s":8192,"e":9999999,"a":1,"f":1,"st":200,"h":{{}},"c":false}}"#
                    );
                    black_box(storage.put_raw(key.as_bytes(), json.as_bytes()));
                });
            },
        );

        group.throughput(Throughput::Elements(500));
        group.bench_with_input(
            BenchmarkId::new("batch_put_cache_meta_500", backend.name()),
            &backend,
            |b, kind| {
                let storage = open_backend(*kind, "cache_batch");
                b.iter(|| {
                    let puts = (0..500)
                        .map(|i| {
                            (
                                format!("CMETA_batch_{i}"),
                                br#"{"k":"/f","s":1024,"e":1,"a":1,"f":1,"st":200,"h":{},"c":false}"#
                                    .to_vec(),
                            )
                        })
                        .collect();
                    black_box(storage.write_raw_batch(puts, Vec::new()));
                });
            },
        );
    }

    group.finish();
}

fn bench_cache_hot_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_hot_path_memory");
    group.measurement_time(Duration::from_secs(5));

    group.bench_function("record_cache_access", |b| {
        let storage = MetricStorage::open(storage_backends::temp_store(
            "cache_access",
            BackendKind::Mace,
        ))
        .expect("open mace storage");
        storage.upsert_cache_meta_absolute(CacheMetaUpsert {
            hash: "benchhash",
            cache_key: "/index.html",
            size: 4096,
            expires: 9_999_999,
            access_time: 1,
            access_count: 0,
            status: 200,
            headers: &[],
            compressed: false,
            shard_id: None,
            relative_path: None,
            event_version: None,
            updated_at: Some(1),
            stale_while_revalidate_secs: 0,
            created_at: 1,
        });
        b.iter(|| black_box(storage.record_cache_access("benchhash")));
    });

    group.bench_function("get_cache_meta", |b| {
        let storage = MetricStorage::open(storage_backends::temp_store(
            "cache_get",
            BackendKind::Mace,
        ))
        .expect("open mace storage");
        storage.upsert_cache_meta_absolute(CacheMetaUpsert {
            hash: "benchhash",
            cache_key: "/index.html",
            size: 4096,
            expires: 9_999_999,
            access_time: 1,
            access_count: 1,
            status: 200,
            headers: &[],
            compressed: false,
            shard_id: None,
            relative_path: None,
            event_version: None,
            updated_at: Some(1),
            stale_while_revalidate_secs: 0,
            created_at: 1,
        });
        b.iter(|| black_box(storage.get_cache_meta("benchhash")));
    });

    group.finish();
}

fn bench_concurrent_stress(c: &mut Criterion) {
    let mut group = c.benchmark_group("compare_concurrent");
    group.measurement_time(Duration::from_secs(12));

    for backend in BackendKind::ALL {
        group.throughput(Throughput::Elements(4));
        group.bench_with_input(
            BenchmarkId::new("parallel_increment_4x500", backend.name()),
            &backend,
            |b, kind| {
                b.iter(|| {
                    let storage = Arc::new(open_backend(*kind, "parallel_incr"));
                    let handles: Vec<_> = (0..4)
                        .map(|t| {
                            let storage = Arc::clone(&storage);
                            thread::spawn(move || {
                                for i in 0..500 {
                                    storage.increment_batch(vec![(format!("t{t}_k{i}"), 1)]);
                                }
                            })
                        })
                        .collect();
                    for handle in handles {
                        handle.join().expect("thread join");
                    }
                    black_box(storage.get_value("t0_k0"));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("parallel_read_4x1000", backend.name()),
            &backend,
            |b, kind| {
                b.iter(|| {
                    let storage = Arc::new(open_backend(*kind, "parallel_read"));
                    for i in 0..1000 {
                        storage.put_json(&format!("read_{i}"), &i);
                    }
                    let handles: Vec<_> = (0..4)
                        .map(|t| {
                            let storage = Arc::clone(&storage);
                            thread::spawn(move || {
                                let mut sum = 0u64;
                                for i in 0..1000 {
                                    sum += storage.get_value(&format!("read_{}", (i + t * 17) % 1000));
                                }
                                sum
                            })
                        })
                        .collect();
                    let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
                    black_box(total);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_kv_basic,
    bench_metrics_write_paths,
    bench_firewall_and_scan,
    bench_cache_disk_paths,
    bench_cache_hot_path,
    bench_concurrent_stress
);
criterion_main!(benches);
