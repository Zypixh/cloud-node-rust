use cloud_node_rust::metrics::storage::{CacheMetaUpsert, MetricStorage};
use cloud_node_rust::rpc::metrics::ServerMetricUpdate;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn temp_store(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "cn-storage-bench-{tag}-{}",
        uuid::Uuid::new_v4()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn open_store(tag: &str) -> MetricStorage {
    MetricStorage::open(temp_store(tag)).expect("open storage")
}

fn sample_metric_updates(count: usize) -> Vec<ServerMetricUpdate> {
    (0..count)
        .map(|i| ServerMetricUpdate {
            server_id: (i as i64) + 1,
            user_id: 0,
            user_plan_id: 0,
            plan_id: 0,
            total_requests: 10,
            bytes_sent: 1024,
            bytes_received: 512,
            cached_bytes: 256,
            count_cached_requests: 2,
            count_attack_requests: 0,
            attack_bytes: 0,
            active_connections: 4,
            count_websocket_connections: 0,
            count_ips: 3,
        })
        .collect()
}

fn prefill_firewall_records(storage: &MetricStorage, count: usize) {
    let puts = (0..count)
        .map(|i| {
            (
                format!("FWBLK_V1_server_{i}_192.0.2.{i}"),
                format!(
                    r#"{{"target":"192.0.2.{i}","serverId":{i},"scope":"server","source":"runtime","reason":"bench","expiresAt":9999999999,"createdAt":1,"updatedAt":1,"kernelWanted":true,"kernelApplied":false,"kernelStatus":"pending"}}"#
                )
                .into_bytes(),
            )
        })
        .collect();
    assert!(storage.write_raw_batch(puts, Vec::new()));
}

fn bench_kv_basic(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_kv_basic");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("put_json", |b| {
        let storage = open_store("put_json");
        let mut n = 0u64;
        b.iter(|| {
            n += 1;
            black_box(storage.put_json(&format!("meta_{n}"), &n));
        });
    });

    group.bench_function("get_json_hit", |b| {
        let storage = open_store("get_json_hit");
        storage.put_json("meta_hit", &42u64);
        b.iter(|| black_box(storage.get_json::<u64>("meta_hit")));
    });

    group.bench_function("get_value_counter", |b| {
        let storage = open_store("get_value");
        storage.increment_batch(vec![("counter".to_string(), 100)]);
        b.iter(|| black_box(storage.get_value("counter")));
    });

    group.finish();
}

fn bench_metrics_write_paths(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_metrics_write");
    group.measurement_time(Duration::from_secs(10));

    for count in [10usize, 50, 100] {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::new("increment_batch", count),
            &count,
            |b, &count| {
                let storage = open_store(&format!("incr_{count}"));
                let updates: Vec<(String, u64)> = (0..count)
                    .map(|i| (format!("S1_T1000_req_{i}"), 1))
                    .collect();
                b.iter(|| black_box(storage.increment_batch(updates.clone())));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("record_server_batch", count),
            &count,
            |b, &count| {
                let storage = open_store(&format!("server_batch_{count}"));
                let updates = sample_metric_updates(count);
                b.iter(|| {
                    black_box(storage.record_server_batch(1_700_000_000, updates.clone(), 4096, 2048))
                });
            },
        );
    }

    group.finish();
}

fn bench_firewall_and_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_firewall_scan");
    group.measurement_time(Duration::from_secs(10));

    group.throughput(Throughput::Elements(100));
    group.bench_function("write_raw_batch_100", |b| {
        let storage = open_store("fw_batch");
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
    });

    for count in [100usize, 1000] {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::new("scan_json_prefix", count),
            &count,
            |b, &count| {
                let storage = open_store(&format!("scan_{count}"));
                prefill_firewall_records(&storage, count);
                b.iter(|| {
                    black_box(
                        storage
                            .scan_json_prefix::<serde_json::Value>("FWBLK_V1_")
                            .len(),
                    )
                });
            },
        );
    }

    group.finish();
}

fn bench_cache_paths(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_cache_paths");
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("record_cache_access_memory", |b| {
        let storage = open_store("cache_access");
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

    group.bench_function("get_cache_meta_memory", |b| {
        let storage = open_store("cache_get");
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

    group.throughput(Throughput::Elements(200));
    group.bench_function("upsert_cache_meta_absolute", |b| {
        let storage = open_store("cache_upsert");
        let mut n = 0u64;
        b.iter(|| {
            n += 1;
            let hash = format!("hash_{n}");
            black_box(storage.upsert_cache_meta_absolute(CacheMetaUpsert {
                hash: &hash,
                cache_key: "/assets/app.js",
                size: 8192,
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
            }));
        });
    });

    group.throughput(Throughput::Elements(500));
    group.bench_function("flush_cache_accesses_500", |b| {
        let storage = open_store("cache_flush");
        for i in 0..500 {
            let hash = format!("hash_{i}");
            storage.upsert_cache_meta_absolute(CacheMetaUpsert {
                hash: &hash,
                cache_key: "/file",
                size: 1024,
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
            storage.record_cache_access(&hash);
        }
        b.iter(|| black_box(storage.flush_cache_accesses()));
    });

    group.finish();
}

fn bench_concurrent_stress(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_concurrent");
    group.measurement_time(Duration::from_secs(15));

    group.throughput(Throughput::Elements(4));
    group.bench_function("parallel_increment_4x500", |b| {
        b.iter(|| {
            let storage = Arc::new(open_store("parallel_incr"));
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
    });

    group.throughput(Throughput::Elements(4));
    group.bench_function("parallel_read_4x1000", |b| {
        let storage = Arc::new(open_store("parallel_read"));
        for i in 0..1000 {
            storage.put_json(&format!("read_{i}"), &i);
        }
        b.iter(|| {
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
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_kv_basic,
    bench_metrics_write_paths,
    bench_firewall_and_scan,
    bench_cache_paths,
    bench_concurrent_stress
);
criterion_main!(benches);
