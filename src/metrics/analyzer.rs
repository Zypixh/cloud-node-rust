use maxminddb::geoip2;
use once_cell::sync::Lazy;
use std::net::IpAddr;
use tracing::warn;
use woothee::parser::Parser;
use std::sync::{Mutex, Arc};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub struct GeoInfo {
    pub country: Arc<str>,
    pub country_id: i64,
    pub region: Arc<str>,
    pub region_id: i64,
    pub city: Arc<str>,
    pub city_id: i64,
    pub provider: Arc<str>,
}

impl Clone for GeoInfo {
    fn clone(&self) -> Self {
        Self {
            country: self.country.clone(),
            country_id: self.country_id,
            region: self.region.clone(),
            region_id: self.region_id,
            city: self.city.clone(),
            city_id: self.city_id,
            provider: self.provider.clone(),
        }
    }
}

pub struct RequestStats {
    pub geo: Option<GeoInfo>,
    pub browser: Arc<str>,
    pub os: Arc<str>,
}

impl Clone for RequestStats {
    fn clone(&self) -> Self {
        Self {
            geo: self.geo.clone(),
            browser: self.browser.clone(),
            os: self.os.clone(),
        }
    }
}

static GEO_CITY_READER: Lazy<Option<maxminddb::Reader<Vec<u8>>>> = Lazy::new(|| {
    let path = "GeoLite2-City.mmdb";
    match maxminddb::Reader::open_readfile(path) {
        Ok(r) => Some(r),
        Err(e) => {
            warn!(
                "Failed to load GeoIP City database at {}: {}. Geo stats will be disabled.",
                path, e
            );
            None
        }
    }
});

static GEO_ASN_READER: Lazy<Option<maxminddb::Reader<Vec<u8>>>> = Lazy::new(|| {
    let path = "GeoLite2-ASN.mmdb";
    match maxminddb::Reader::open_readfile(path) {
        Ok(r) => Some(r),
        Err(e) => {
            warn!(
                "Failed to load GeoIP ASN database at {}: {}. ASN stats will be disabled.",
                path, e
            );
            None
        }
    }
});

const CACHE_SHARDS: usize = 64;

struct ShardedLru<K, V> {
    shards: Vec<Mutex<LruCache<K, V>>>,
}

impl<K: Hash + Eq, V: Clone> ShardedLru<K, V> {
    fn new(capacity_per_shard: usize) -> Self {
        let mut shards = Vec::with_capacity(CACHE_SHARDS);
        for _ in 0..CACHE_SHARDS {
            shards.push(Mutex::new(LruCache::new(NonZeroUsize::new(capacity_per_shard).unwrap())));
        }
        Self { shards }
    }

    fn get_shard(&self, key: &K) -> &Mutex<LruCache<K, V>> {
        let mut s = DefaultHasher::new();
        key.hash(&mut s);
        let hash = s.finish();
        &self.shards[(hash as usize) % CACHE_SHARDS]
    }
}

// Cache for GeoIP results (IP -> GeoInfo)
static GEO_CACHE: Lazy<ShardedLru<IpAddr, Option<GeoInfo>>> = Lazy::new(|| {
    ShardedLru::new(200) // 64 * 200 = ~12.8k entries
});

// Cache for User-Agent results (UA string -> (Arc<str>, Arc<str>))
static UA_CACHE: Lazy<ShardedLru<String, (Arc<str>, Arc<str>)>> = Lazy::new(|| {
    ShardedLru::new(100) // 64 * 100 = ~6.4k entries
});

static UA_PARSER: Lazy<Parser> = Lazy::new(Parser::new);

pub fn analyze_request(ip: IpAddr, ua: &str) -> RequestStats {
    let geo = {
        let mutex = GEO_CACHE.get_shard(&ip);
        let mut cache = mutex.lock().unwrap();
        if let Some(cached) = cache.get(&ip) {
            cached.clone()
        } else {
            let res = lookup_geo_internal(ip);
            cache.put(ip, res.clone());
            res
        }
    };

    let (browser, os) = {
        let mutex = UA_CACHE.get_shard(&ua.to_string());
        let mut cache = mutex.lock().unwrap();
        if let Some(cached) = cache.get(&ua.to_string()) {
            cached.clone()
        } else {
            let parsed_ua = UA_PARSER.parse(ua);
            let res = match parsed_ua {
                Some(p) => (Arc::from(p.name), Arc::from(p.os)),
                None => (Arc::from("Unknown"), Arc::from("Unknown")),
            };
            cache.put(ua.to_string(), res.clone());
            res
        }
    };

    RequestStats { geo, browser, os }
}

fn get_isp_name(ip: IpAddr) -> String {
    if let Some(reader) = &*GEO_ASN_READER {
        match reader.lookup::<serde_json::Value>(ip) {
            Ok(val) => val
                .get("autonomous_system_organization")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "Unknown".to_string()),
            Err(_) => "Unknown".to_string(),
        }
    } else {
        "Unknown".to_string()
    }
}

fn lookup_geo_internal(ip: IpAddr) -> Option<GeoInfo> {
    if let Some(reader) = &*GEO_CITY_READER {
        match reader.lookup::<geoip2::City>(ip) {
            Ok(city) => Some(GeoInfo {
                country: Arc::from(city
                    .country
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en"))
                    .map(|s| s.as_ref())
                    .unwrap_or_default()),
                country_id: city
                    .country
                    .as_ref()
                    .and_then(|c| c.geoname_id)
                    .map(|id| id as i64)
                    .unwrap_or(0),
                region: Arc::from(city
                    .subdivisions
                    .as_ref()
                    .and_then(|s| s.first())
                    .and_then(|sd| sd.names.as_ref())
                    .and_then(|n| n.get("en"))
                    .map(|s| s.as_ref())
                    .unwrap_or_default()),
                region_id: city
                    .subdivisions
                    .as_ref()
                    .and_then(|s| s.first())
                    .and_then(|sd| sd.geoname_id)
                    .map(|id| id as i64)
                    .unwrap_or(0),
                city: Arc::from(city
                    .city
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en"))
                    .map(|s| s.as_ref())
                    .unwrap_or_default()),
                city_id: city
                    .city
                    .as_ref()
                    .and_then(|c| c.geoname_id)
                    .map(|id| id as i64)
                    .unwrap_or(0),
                provider: Arc::from(get_isp_name(ip)),
            }),
            Err(_) => None,
        }
    } else {
        None
    }
}

pub fn lookup_isp_name(ip: IpAddr) -> Arc<str> {
    Arc::from(get_isp_name(ip))
}

pub fn lookup_geo(ip: IpAddr) -> Option<GeoInfo> {
    lookup_geo_internal(ip)
}
