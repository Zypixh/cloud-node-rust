use maxminddb::geoip2;
use once_cell::sync::Lazy;
use std::net::IpAddr;
use tracing::warn;
use woothee::parser::Parser;
use std::sync::Mutex;
use lru::LruCache;
use std::num::NonZeroUsize;

pub struct GeoInfo {
    pub country: String,
    pub country_id: i64,
    pub region: String,
    pub region_id: i64,
    pub city: String,
    pub city_id: i64,
    pub provider: String,
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
    pub browser: String,
    pub os: String,
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

// Cache for GeoIP results (IP -> GeoInfo)
static GEO_CACHE: Lazy<Mutex<LruCache<IpAddr, Option<GeoInfo>>>> = Lazy::new(|| {
    Mutex::new(LruCache::new(NonZeroUsize::new(10000).unwrap()))
});

// Cache for User-Agent results (UA string -> (Browser, OS))
static UA_CACHE: Lazy<Mutex<LruCache<String, (String, String)>>> = Lazy::new(|| {
    Mutex::new(LruCache::new(NonZeroUsize::new(5000).unwrap()))
});

pub fn analyze_request(ip: IpAddr, ua: &str) -> RequestStats {
    let geo = {
        let mut cache = GEO_CACHE.lock().unwrap();
        if let Some(cached) = cache.get(&ip) {
            cached.clone()
        } else {
            let res = lookup_geo(ip);
            cache.put(ip, res.clone());
            res
        }
    };

    let (browser, os) = {
        let mut cache = UA_CACHE.lock().unwrap();
        if let Some(cached) = cache.get(ua) {
            cached.clone()
        } else {
            let parser = Parser::new();
            let parsed_ua = parser.parse(ua);
            let res = match parsed_ua {
                Some(p) => (p.name.to_string(), p.os.to_string()),
                None => ("Unknown".to_string(), "Unknown".to_string()),
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

pub fn lookup_geo(ip: IpAddr) -> Option<GeoInfo> {
    if let Some(reader) = &*GEO_CITY_READER {
        match reader.lookup::<geoip2::City>(ip) {
            Ok(city) => Some(GeoInfo {
                country: city
                    .country
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en"))
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                country_id: city
                    .country
                    .as_ref()
                    .and_then(|c| c.geoname_id)
                    .map(|id| id as i64)
                    .unwrap_or(0),
                region: city
                    .subdivisions
                    .as_ref()
                    .and_then(|s| s.first())
                    .and_then(|sd| sd.names.as_ref())
                    .and_then(|n| n.get("en"))
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                region_id: city
                    .subdivisions
                    .as_ref()
                    .and_then(|s| s.first())
                    .and_then(|sd| sd.geoname_id)
                    .map(|id| id as i64)
                    .unwrap_or(0),
                city: city
                    .city
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en"))
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                city_id: city
                    .city
                    .as_ref()
                    .and_then(|c| c.geoname_id)
                    .map(|id| id as i64)
                    .unwrap_or(0),
                provider: get_isp_name(ip),
            }),
            Err(_) => None,
        }
    } else {
        None
    }
}

pub fn lookup_isp_name(ip: IpAddr) -> String {
    get_isp_name(ip)
}
