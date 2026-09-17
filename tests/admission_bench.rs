// Portable contention microbenchmark — runs on both trees (same try_admit
// signature on mainline v1.2.7 and the memory-governance branch).
//
//   BENCH_ADMISSION_THREADS=8 BENCH_ADMISSION_ITERS=2000000 \
//     cargo test --release --test admission_bench -- --nocapture
//
// Each thread loops try_admit+drop on HttpConnection, saturating the shared
// admission path the way a per-request pipeline would at high QPS.

use cloud_node_rust::memory_governor::{AdmissionClass, MEMORY_GOVERNOR};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

#[test]
fn bench_admission_throughput() {
    if std::env::var_os("BENCH_ADMISSION_ITERS").is_none() {
        eprintln!("skip: set BENCH_ADMISSION_ITERS to run");
        return;
    }
    let threads: usize = std::env::var("BENCH_ADMISSION_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8);
    let iters: u64 = std::env::var("BENCH_ADMISSION_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000);

    let granted = Arc::new(AtomicU64::new(0));
    let rejected = Arc::new(AtomicU64::new(0));
    let go = Arc::new(AtomicBool::new(false));
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let granted = Arc::clone(&granted);
            let rejected = Arc::clone(&rejected);
            let go = Arc::clone(&go);
            std::thread::spawn(move || {
                while !go.load(Ordering::Acquire) {
                    std::hint::spin_loop();
                }
                for _ in 0..iters {
                    if let Some(permit) = MEMORY_GOVERNOR.try_admit(AdmissionClass::HttpConnection) {
                        granted.fetch_add(1, Ordering::Relaxed);
                        drop(permit);
                    } else {
                        rejected.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();

    let start = Instant::now();
    go.store(true, Ordering::Release);
    for h in handles {
        h.join().unwrap();
    }
    let elapsed = start.elapsed();
    let total = granted.load(Ordering::Relaxed) + rejected.load(Ordering::Relaxed);
    println!(
        "ADMISSION_BENCH threads={} iters={} total={} granted={} rejected={} elapsed={:?} ops_per_sec={:.0}",
        threads,
        iters,
        total,
        granted.load(Ordering::Relaxed),
        rejected.load(Ordering::Relaxed),
        elapsed,
        total as f64 / elapsed.as_secs_f64(),
    );
}
