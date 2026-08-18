use cloud_node_rust::metrics::storage::MetricStorage;
use serde::Serialize;
use std::env;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Put,
    Get,
    Mixed,
    Merge,
    Reopen,
}

impl Mode {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "put" => Ok(Self::Put),
            "get" => Ok(Self::Get),
            "mixed" => Ok(Self::Mixed),
            "merge" => Ok(Self::Merge),
            "reopen" => Ok(Self::Reopen),
            other => anyhow::bail!("unsupported mode: {other}"),
        }
    }
}

#[derive(Debug)]
struct Args {
    path: PathBuf,
    mode: Mode,
    duration: Duration,
    workers: usize,
    batch_size: usize,
}

impl Args {
    fn parse() -> anyhow::Result<Self> {
        let mut path = None;
        let mut mode = Mode::Mixed;
        let mut duration = Duration::from_secs(10);
        let mut workers = 1usize;
        let mut batch_size = 1usize;
        let mut args = env::args().skip(1);

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--path" => path = Some(PathBuf::from(next_value("--path", &mut args)?)),
                "--mode" => mode = Mode::parse(&next_value("--mode", &mut args)?)?,
                "--duration-secs" => {
                    duration =
                        Duration::from_secs(next_value("--duration-secs", &mut args)?.parse()?)
                }
                "--workers" => workers = next_value("--workers", &mut args)?.parse()?,
                "--batch-size" => batch_size = next_value("--batch-size", &mut args)?.parse()?,
                "--help" | "-h" => {
                    println!(
                        "mace-perf --path DIR --mode put|get|mixed|merge|reopen \\\n+                         [--duration-secs N] [--workers N] [--batch-size N]"
                    );
                    std::process::exit(0);
                }
                other => anyhow::bail!("unknown argument: {other}"),
            }
        }

        Ok(Self {
            path: path.ok_or_else(|| anyhow::anyhow!("--path is required"))?,
            mode,
            duration,
            workers: workers.max(1),
            batch_size: batch_size.max(1),
        })
    }
}

fn next_value<I: Iterator<Item = String>>(name: &str, args: &mut I) -> anyhow::Result<String> {
    args.next()
        .ok_or_else(|| anyhow::anyhow!("missing value for {name}"))
}

#[derive(Default)]
struct WorkerResult {
    operations: u64,
    successes: u64,
    errors: u64,
    latencies_us: Vec<u64>,
}

#[derive(Serialize)]
struct Report {
    mode: &'static str,
    workers: usize,
    batch_size: usize,
    duration_secs: f64,
    operations: u64,
    successes: u64,
    errors: u64,
    operations_per_sec: f64,
    latency_us: LatencyReport,
    reopen_ok: Option<bool>,
}

#[derive(Serialize)]
struct LatencyReport {
    p50: u64,
    p95: u64,
    p99: u64,
    max: u64,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse()?;
    std::fs::create_dir_all(&args.path)?;

    if args.mode == Mode::Reopen {
        let value = serde_json::json!({"value": "reopen-check"});
        {
            let db = MetricStorage::open(&args.path)?;
            if !db.put_json("BENCH_REOPEN_KEY", &value) {
                anyhow::bail!("initial Mace write failed");
            }
        }
        let db = MetricStorage::open(&args.path)?;
        let reopen_ok = db
            .get_json::<serde_json::Value>("BENCH_REOPEN_KEY")
            .is_some_and(|found| found == value);
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "mode": "reopen",
                "reopen_ok": reopen_ok,
            }))?
        );
        if !reopen_ok {
            anyhow::bail!("Mace reopen verification failed");
        }
        return Ok(());
    }

    let db = Arc::new(MetricStorage::open(&args.path)?);
    if matches!(args.mode, Mode::Get | Mode::Mixed) {
        for worker in 0..args.workers {
            let key = format!("BENCH_GET_{worker}");
            if !db.put_json(&key, &serde_json::json!({"worker": worker})) {
                anyhow::bail!("Mace warmup write failed for {key}");
            }
        }
    }

    let barrier = Arc::new(Barrier::new(args.workers));
    let deadline = Instant::now() + args.duration;
    let mut handles = Vec::with_capacity(args.workers);
    for worker in 0..args.workers {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        let mode = args.mode;
        let batch_size = args.batch_size;
        handles.push(thread::spawn(move || {
            let mut result = WorkerResult::default();
            let key = format!("BENCH_GET_{worker}");
            let merge_key = format!("S{worker}_T1_req");
            barrier.wait();
            let mut sequence = 0u64;
            while Instant::now() < deadline {
                let started = Instant::now();
                let ok = match mode {
                    Mode::Put => {
                        let mut ok = true;
                        for _ in 0..batch_size {
                            let put_key = format!("BENCH_PUT_{worker}_{sequence}");
                            ok &= db.put_json(
                                &put_key,
                                &serde_json::json!({
                                    "worker": worker,
                                    "sequence": sequence,
                                }),
                            );
                            sequence = sequence.wrapping_add(1);
                        }
                        ok
                    }
                    Mode::Get => db.get_json::<serde_json::Value>(&key).is_some(),
                    Mode::Mixed => {
                        if sequence % 2 == 0 {
                            db.put_json(
                                &format!("BENCH_MIXED_{worker}"),
                                &serde_json::json!({
                                    "sequence": sequence,
                                }),
                            )
                        } else {
                            db.get_json::<serde_json::Value>(&format!("BENCH_MIXED_{worker}"))
                                .is_some()
                        }
                    }
                    Mode::Merge => {
                        let mut updates = Vec::with_capacity(batch_size);
                        for _ in 0..batch_size {
                            updates.push((merge_key.clone(), 1));
                        }
                        db.increment_batch(updates);
                        true
                    }
                    Mode::Reopen => unreachable!(),
                };
                result.operations += 1;
                result
                    .latencies_us
                    .push(started.elapsed().as_micros() as u64);
                if ok {
                    result.successes += 1;
                } else {
                    result.errors += 1;
                }
                sequence = sequence.wrapping_add(1);
            }
            result
        }));
    }

    let mut total = WorkerResult::default();
    for handle in handles {
        let result = handle
            .join()
            .map_err(|_| anyhow::anyhow!("Mace worker panicked"))?;
        total.operations += result.operations;
        total.successes += result.successes;
        total.errors += result.errors;
        total.latencies_us.extend(result.latencies_us);
    }

    total.latencies_us.sort_unstable();
    let elapsed = args.duration.as_secs_f64();
    let report = Report {
        mode: match args.mode {
            Mode::Put => "put",
            Mode::Get => "get",
            Mode::Mixed => "mixed",
            Mode::Merge => "merge",
            Mode::Reopen => "reopen",
        },
        workers: args.workers,
        batch_size: args.batch_size,
        duration_secs: elapsed,
        operations: total.operations,
        successes: total.successes,
        errors: total.errors,
        operations_per_sec: total.operations as f64 / elapsed,
        latency_us: LatencyReport {
            p50: percentile(&total.latencies_us, 0.50),
            p95: percentile(&total.latencies_us, 0.95),
            p99: percentile(&total.latencies_us, 0.99),
            max: total.latencies_us.last().copied().unwrap_or(0),
        },
        reopen_ok: None,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn percentile(values: &[u64], quantile: f64) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let index = ((values.len() - 1) as f64 * quantile).round() as usize;
    values[index.min(values.len() - 1)]
}
