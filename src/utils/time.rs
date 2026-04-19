use std::sync::atomic::{AtomicI32, AtomicI64, Ordering};
use chrono::{DateTime, FixedOffset, TimeZone, Utc};

// We store the offset in SECONDS for maximum speed (raw integer math)
pub static TIME_OFFSET_SECONDS: AtomicI64 = AtomicI64::new(0);
// Cache the timezone offset to avoid expensive Local::now() calls
pub static LOCAL_TZ_OFFSET_SECONDS: AtomicI32 = AtomicI32::new(8 * 3600);

pub fn update_time_offset(server_timestamp: i64) {
    let local_ts = Utc::now().timestamp();
    let diff = server_timestamp - local_ts;
    if diff.abs() > 1 {
        TIME_OFFSET_SECONDS.store(diff, Ordering::Relaxed);
        tracing::info!("Time auto-synced. System clock drift: {}s", diff);
    }
}

#[inline]
pub fn now_utc() -> DateTime<Utc> {
    // Fast path: Atomic load + Integer addition
    let ts = Utc::now().timestamp() + TIME_OFFSET_SECONDS.load(Ordering::Relaxed);
    Utc.timestamp_opt(ts, 0).unwrap()
}

#[inline]
pub fn now_local() -> DateTime<FixedOffset> {
    let utc_ts = Utc::now().timestamp() + TIME_OFFSET_SECONDS.load(Ordering::Relaxed);
    // Reuse cached TZ offset (default +0800)
    let tz = FixedOffset::east_opt(LOCAL_TZ_OFFSET_SECONDS.load(Ordering::Relaxed))
        .unwrap_or_else(|| FixedOffset::east_opt(0).unwrap());
    tz.from_utc_datetime(&DateTime::from_timestamp(utc_ts, 0).unwrap().naive_utc())
}
