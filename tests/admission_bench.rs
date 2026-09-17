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
    // Class selection ablation: HttpConnection exercises the shared-connection
    // byte budget; RequestBodyWaf exercises only the per-class count path;
    // "mixed" rotates classes per thread to expose cross-class false sharing.
    // "pooled" draws per-thread from a per-connection ticket bucket (the
    // memory_ticket path) instead of the global counter per op.
    let class_sel = std::env::var("BENCH_ADMISSION_CLASS").unwrap_or_else(|_| "http".into());
    let class_for = |i: usize| match class_sel.as_str() {
        "waf" => AdmissionClass::RequestBodyWaf,
        "tcp" => AdmissionClass::TcpConnection,
        "pooled" | "mixed" => [
            AdmissionClass::HttpConnection,
            AdmissionClass::RequestBodyWaf,
            AdmissionClass::TcpConnection,
            AdmissionClass::ResponseTransform,
            AdmissionClass::UdpSession,
            AdmissionClass::CacheRevalidate,
            AdmissionClass::Http2Stream,
            AdmissionClass::OriginConnect,
        ][i % 8],
        _ => AdmissionClass::HttpConnection,
    };
    let pooled = class_sel == "pooled";

    let granted = Arc::new(AtomicU64::new(0));
    let rejected = Arc::new(AtomicU64::new(0));
    let go = Arc::new(AtomicBool::new(false));
    let handles: Vec<_> = (0..threads)
        .map(|i| {
            let granted = Arc::clone(&granted);
            let rejected = Arc::clone(&rejected);
            let go = Arc::clone(&go);
            let class = class_for(i);
            std::thread::spawn(move || {
                // One bucket per thread models one connection's pool; pooled
                // spends stay on a thread-private line.
                let bucket = Arc::new(cloud_node_rust::memory_ticket::TicketBucket::new(
                    std::sync::LazyLock::force(&MEMORY_GOVERNOR),
                ));
                while !go.load(Ordering::Acquire) {
                    std::hint::spin_loop();
                }
                for _ in 0..iters {
                    let permit = if pooled {
                        bucket
                            .spend(class, cloud_node_rust::memory_governor::class_estimated_bytes(class))
                            .map(|p| cloud_node_rust::memory_ticket::WorkspacePermit::Pooled(p))
                    } else {
                        MEMORY_GOVERNOR
                            .try_admit(class)
                            .map(|p| cloud_node_rust::memory_ticket::WorkspacePermit::Direct(p))
                    };
                    if let Some(permit) = permit {
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
