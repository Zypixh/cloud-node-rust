use arc_swap::ArcSwapOption;
use lru::LruCache;
use maxminddb::geoip2;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::LazyLock as Lazy;
use std::sync::{Arc, Mutex};
use tracing::warn;
use woothee::parser::Parser;

pub struct GeoInfo {
    pub country: Arc<str>,
    pub country_id: i64,
    pub country_iso: Arc<str>,
    pub region: Arc<str>,
    pub region_id: i64,
    pub region_iso: Arc<str>,
    pub city: Arc<str>,
    pub city_id: i64,
    pub provider: Arc<str>,
}

impl Clone for GeoInfo {
    fn clone(&self) -> Self {
        Self {
            country: self.country.clone(),
            country_id: self.country_id,
            country_iso: self.country_iso.clone(),
            region: self.region.clone(),
            region_id: self.region_id,
            region_iso: self.region_iso.clone(),
            city: self.city.clone(),
            city_id: self.city_id,
            provider: self.provider.clone(),
        }
    }
}

pub struct RequestStats {
    pub geo: Option<GeoInfo>,
    pub browser: Arc<str>,
    pub browser_version: Arc<str>,
    pub os: Arc<str>,
    pub os_version: Arc<str>,
}

impl Clone for RequestStats {
    fn clone(&self) -> Self {
        Self {
            geo: self.geo.clone(),
            browser: self.browser.clone(),
            browser_version: self.browser_version.clone(),
            os: self.os.clone(),
            os_version: self.os_version.clone(),
        }
    }
}

static GEO_AVAILABLE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

static GEO_CITY_READER: Lazy<ArcSwapOption<maxminddb::Reader<Vec<u8>>>> =
    Lazy::new(ArcSwapOption::empty);

pub fn initialize_geoip_readers() {
    for path in crate::paths::NodePaths::current().geoip_city_candidates() {
        if path.exists() {
            if let Err(err) = reload_city_reader(&path) {
                warn!(
                    "Failed to load GeoIP City database at {}: {}",
                    path.display(),
                    err
                );
            }
            return;
        }
    }
}

pub fn reload_city_reader(path: &std::path::Path) -> anyhow::Result<()> {
    let reader = maxminddb::Reader::open_readfile(path)?;
    reader.verify()?;
    anyhow::ensure!(
        reader
            .metadata()
            .database_type
            .to_ascii_lowercase()
            .contains("city"),
        "GeoIP database is not a City database: {}",
        reader.metadata().database_type
    );
    GEO_CITY_READER.store(Some(Arc::new(reader)));
    GEO_AVAILABLE.store(true, std::sync::atomic::Ordering::Release);
    GEO_CACHE.clear();
    Ok(())
}

static GEO_ASN_READER: Lazy<Option<maxminddb::Reader<Vec<u8>>>> = Lazy::new(|| {
    let paths = crate::paths::NodePaths::current().geoip_asn_candidates();
    for path in &paths {
        if path.exists() {
            return match maxminddb::Reader::open_readfile(path) {
                Ok(r) => Some(r),
                Err(e) => {
                    warn!(
                        "Failed to load GeoIP ASN database at {}: {}. ASN stats will be disabled.",
                        path.display(),
                        e
                    );
                    None
                }
            };
        }
    }
    warn!(
        "Failed to load GeoIP ASN database from {:?}. ASN stats will be disabled.",
        paths
    );
    None
});

const CACHE_SHARDS: usize = 64;
const GEO_CACHE_ENTRY_ESTIMATED_BYTES: u64 = 384;
const UA_CACHE_ENTRY_ESTIMATED_BYTES: u64 = 768;

fn cache_capacity_per_shard(estimated_entry_bytes: u64, budget_share: u64) -> usize {
    let budget = crate::memory_governor::MEMORY_GOVERNOR
        .snapshot(crate::memory_governor::MEMORY_GOVERNOR.pingora_worker_threads())
        .cardinality_state_budget_bytes
        / budget_share.max(1);
    usize::try_from(budget / estimated_entry_bytes.max(1) / CACHE_SHARDS as u64)
        .unwrap_or(usize::MAX)
        .max(1)
}

struct ShardedLru<K, V> {
    shards: Vec<Mutex<LruCache<K, V>>>,
}

impl<K: Hash + Eq, V: Clone> ShardedLru<K, V> {
    fn new(capacity_per_shard: usize) -> Self {
        let mut shards = Vec::with_capacity(CACHE_SHARDS);
        for _ in 0..CACHE_SHARDS {
            shards.push(Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity_per_shard).unwrap(),
            )));
        }
        Self { shards }
    }

    fn clear(&self) {
        for shard in &self.shards {
            shard.lock().unwrap().clear();
        }
    }

    fn get_shard(&self, key: &K) -> &Mutex<LruCache<K, V>> {
        let mut s = DefaultHasher::new();
        key.hash(&mut s);
        let hash = s.finish();
        &self.shards[(hash as usize) % CACHE_SHARDS]
    }

    fn get_shard_by<Q>(&self, key: &Q) -> &Mutex<LruCache<K, V>>
    where
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut s = DefaultHasher::new();
        key.hash(&mut s);
        let hash = s.finish();
        &self.shards[(hash as usize) % CACHE_SHARDS]
    }
}

// Cache for GeoIP results (IP -> GeoInfo)
static GEO_CACHE: Lazy<ShardedLru<IpAddr, Option<GeoInfo>>> = Lazy::new(|| {
    ShardedLru::new(cache_capacity_per_shard(
        GEO_CACHE_ENTRY_ESTIMATED_BYTES,
        4,
    ))
});

// Cache for User-Agent results (UA string -> (Arc<str>, Arc<str>))
static UA_CACHE: Lazy<ShardedLru<String, (Arc<str>, Arc<str>, Arc<str>, Arc<str>)>> =
    Lazy::new(|| {
        ShardedLru::new(cache_capacity_per_shard(
            UA_CACHE_ENTRY_ESTIMATED_BYTES,
            4,
        ))
    });

static UA_PARSER: Lazy<Parser> = Lazy::new(Parser::new);

pub fn analyze_request(ip: IpAddr, ua: &str) -> RequestStats {
    // Fast path: skip Mutex lock when GeoIP database is unavailable
    let geo = if GEO_AVAILABLE.load(std::sync::atomic::Ordering::Relaxed) {
        let mutex = GEO_CACHE.get_shard(&ip);
        let mut cache = mutex.lock().unwrap();
        if let Some(cached) = cache.get(&ip) {
            cached.clone()
        } else {
            let res = lookup_geo_internal(ip);
            cache.put(ip, res.clone());
            res
        }
    } else {
        None
    };

    let (browser, browser_version, os, os_version) = if ua.is_empty() {
        (Arc::from(""), Arc::from(""), Arc::from(""), Arc::from(""))
    } else {
        let mutex = UA_CACHE.get_shard_by(ua);
        let mut cache = mutex.lock().unwrap();
        if let Some(cached) = cache.get(ua) {
            cached.clone()
        } else {
            let parsed_ua = UA_PARSER.parse(ua);
            let res = match parsed_ua {
                Some(p) => (
                    Arc::from(p.name),
                    Arc::from(p.version),
                    Arc::from(p.os),
                    Arc::from(p.os_version.as_ref()),
                ),
                None => (
                    Arc::from("Unknown"),
                    Arc::from(""),
                    Arc::from("Unknown"),
                    Arc::from(""),
                ),
            };
            cache.put(ua.to_string(), res.clone());
            res
        }
    };

    RequestStats {
        geo,
        browser,
        browser_version,
        os,
        os_version,
    }
}

fn get_isp_name(ip: IpAddr) -> String {
    if let Some(reader) = &*GEO_ASN_READER {
        match reader
            .lookup(ip)
            .and_then(|result| result.decode::<geoip2::Asn>())
        {
            Ok(Some(asn)) => asn
                .autonomous_system_organization
                .map(|s| s.to_string())
                .unwrap_or_else(|| "Unknown".to_string()),
            Err(_) => "Unknown".to_string(),
            Ok(None) => "Unknown".to_string(),
        }
    } else {
        "Unknown".to_string()
    }
}

fn lookup_geo_internal(ip: IpAddr) -> Option<GeoInfo> {
    if let Some(reader) = GEO_CITY_READER.load_full() {
        match reader
            .lookup(ip)
            .and_then(|result| result.decode::<geoip2::City>())
        {
            Ok(Some(city)) => Some(GeoInfo {
                country: Arc::from(city.country.names.english.unwrap_or_default()),
                country_id: city.country.geoname_id.map(|id| id as i64).unwrap_or(0),
                country_iso: Arc::from(city.country.iso_code.unwrap_or_default()),
                region: Arc::from(
                    city.subdivisions
                        .first()
                        .and_then(|sd| sd.names.english)
                        .unwrap_or_default(),
                ),
                region_id: city
                    .subdivisions
                    .first()
                    .and_then(|sd| sd.geoname_id)
                    .map(|id| id as i64)
                    .unwrap_or(0),
                region_iso: Arc::from(
                    city.subdivisions
                        .first()
                        .and_then(|sd| sd.iso_code)
                        .unwrap_or_default(),
                ),
                city: Arc::from(city.city.names.english.unwrap_or_default()),
                city_id: city.city.geoname_id.map(|id| id as i64).unwrap_or(0),
                provider: Arc::from(get_isp_name(ip)),
            }),
            Err(_) => None,
            Ok(None) => None,
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze_request_reuses_ua_cache_result_shape() {
        let ip = "127.0.0.1".parse().expect("valid ip");
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36";

        let first = analyze_request(ip, ua);
        let second = analyze_request(ip, ua);

        assert_eq!(&*first.browser, &*second.browser);
        assert_eq!(&*first.os, &*second.os);
    }

    #[test]
    fn lookup_asn_label_formats_as_prefix_when_number_known() {
        assert_eq!(lookup_asn_label("127.0.0.1".parse().unwrap()).as_ref(), "");
        assert_eq!(lookup_asn_number("127.0.0.1".parse().unwrap()), 0);
    }
}

pub fn lookup_isp_name(ip: IpAddr) -> Arc<str> {
    Arc::from(get_isp_name(ip))
}

pub fn lookup_asn_number(ip: IpAddr) -> i64 {
    if let Some(reader) = &*GEO_ASN_READER {
        match reader
            .lookup(ip)
            .and_then(|result| result.decode::<geoip2::Asn>())
        {
            Ok(Some(asn)) => asn.autonomous_system_number.map(i64::from).unwrap_or(0),
            Ok(None) | Err(_) => 0,
        }
    } else {
        0
    }
}

pub fn lookup_asn_label(ip: IpAddr) -> Arc<str> {
    let number = lookup_asn_number(ip);
    if number > 0 {
        Arc::from(format!("AS{number}"))
    } else {
        Arc::from("")
    }
}

pub fn asn_database_available() -> bool {
    GEO_ASN_READER.is_some()
}

pub fn lookup_geo(ip: IpAddr) -> Option<GeoInfo> {
    lookup_geo_internal(ip)
}

pub fn reclaim_geo_ua_caches(clear_all: bool) -> (usize, usize) {
    GEO_CACHE.clear();
    if clear_all {
        UA_CACHE.clear();
    }
    (1, usize::from(clear_all))
}
