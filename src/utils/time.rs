use chrono::{DateTime, FixedOffset, Local, TimeZone, Utc};
use std::sync::atomic::{AtomicI32, AtomicI64, Ordering};

// We store the offset in SECONDS for maximum speed (raw integer math)
pub static TIME_OFFSET_SECONDS: AtomicI64 = AtomicI64::new(0);
pub static TIME_OFFSET_MILLIS: AtomicI64 = AtomicI64::new(0);
// Cache the timezone offset to avoid expensive Local::now() calls
pub static LOCAL_TZ_OFFSET_SECONDS: AtomicI32 = AtomicI32::new(8 * 3600);

pub fn init_local_timezone() {
    LOCAL_TZ_OFFSET_SECONDS.store(Local::now().offset().local_minus_utc(), Ordering::Relaxed);
}

pub fn update_time_offset(server_timestamp: i64) {
    let local_ts = Utc::now().timestamp();
    let diff = server_timestamp - local_ts;
    if diff.abs() > 1 {
        set_time_offset_millis(diff.saturating_mul(1000));
        tracing::info!("Time auto-synced. System clock drift: {}s", diff);
    }
}

pub fn set_time_offset_millis(offset_millis: i64) -> i64 {
    TIME_OFFSET_MILLIS.store(offset_millis, Ordering::Relaxed);
    TIME_OFFSET_SECONDS.store(offset_millis / 1000, Ordering::Relaxed);
    offset_millis
}

#[inline]
pub fn system_timestamp() -> i64 {
    Utc::now().timestamp()
}

#[inline]
pub fn system_timestamp_millis() -> i64 {
    Utc::now().timestamp_millis()
}

#[inline]
pub fn now_timestamp() -> i64 {
    now_timestamp_millis() / 1000
}

#[inline]
pub fn now_timestamp_millis() -> i64 {
    system_timestamp_millis() + TIME_OFFSET_MILLIS.load(Ordering::Relaxed)
}

#[inline]
pub fn now_utc() -> DateTime<Utc> {
    Utc.timestamp_opt(now_timestamp(), 0).unwrap()
}

#[inline]
pub fn system_local() -> DateTime<FixedOffset> {
    let tz = FixedOffset::east_opt(LOCAL_TZ_OFFSET_SECONDS.load(Ordering::Relaxed))
        .unwrap_or_else(|| FixedOffset::east_opt(0).unwrap());
    tz.from_utc_datetime(
        &DateTime::from_timestamp(system_timestamp(), 0)
            .unwrap()
            .naive_utc(),
    )
}

#[inline]
pub fn now_local() -> DateTime<FixedOffset> {
    let tz = FixedOffset::east_opt(LOCAL_TZ_OFFSET_SECONDS.load(Ordering::Relaxed))
        .unwrap_or_else(|| FixedOffset::east_opt(0).unwrap());
    tz.from_utc_datetime(
        &DateTime::from_timestamp(now_timestamp(), 0)
            .unwrap()
            .naive_utc(),
    )
}

#[inline]
pub fn system_local_millis() -> DateTime<FixedOffset> {
    local_from_timestamp_millis(system_timestamp_millis())
}

#[inline]
pub fn now_local_millis() -> DateTime<FixedOffset> {
    local_from_timestamp_millis(now_timestamp_millis())
}

#[inline]
pub fn local_from_timestamp_millis(timestamp_millis: i64) -> DateTime<FixedOffset> {
    let tz = FixedOffset::east_opt(LOCAL_TZ_OFFSET_SECONDS.load(Ordering::Relaxed))
        .unwrap_or_else(|| FixedOffset::east_opt(0).unwrap());
    DateTime::from_timestamp_millis(timestamp_millis)
        .map(|dt| dt.with_timezone(&tz))
        .unwrap_or_else(now_local)
}
