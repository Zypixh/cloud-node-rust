use dashmap::DashMap;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::LazyLock as Lazy;

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct AggregationKey {
    pub server_id: i64,
    pub country: Arc<str>,
    pub country_id: i64,
    pub province: Arc<str>,
    pub province_id: i64,
    pub city: Arc<str>,
    pub city_id: i64,
    pub provider: Arc<str>,
    pub browser: Arc<str>,
    pub os: Arc<str>,
    pub waf_group_id: i64,
    pub waf_action: Arc<str>,
    pub provider_id: i64,
    pub browser_version: Arc<str>,
    pub os_version: Arc<str>,
    pub request_attrs: Arc<BTreeMap<String, String>>,
}

impl AggregationKey {
    pub fn resolve_metric_key(&self, configured_key: &str) -> String {
        let request_context = crate::metrics::MetricRequestContext {
            values: self.request_attrs.as_ref().clone(),
        };

        crate::metrics::resolve_template_with(configured_key, |var_name| {
            let resolved = request_context.resolve_variable(var_name);
            if !resolved.is_empty() && resolved != format!("${{{var_name}}}") {
                return resolved;
            }

            match var_name {
                "country" | "geo.country.name" => self.country.to_string(),
                "province" | "geo.province.name" => self.province.to_string(),
                "city" | "geo.city.name" => self.city.to_string(),
                "provider" | "isp.name" => self.provider.to_string(),
                "browser" | "browser.name" => self.browser.to_string(),
                "browser.version" => self.browser_version.to_string(),
                "os" | "browser.os.name" => self.os.to_string(),
                "browser.os.version" => self.os_version.to_string(),
                "wafGroup" => self.waf_group_id.to_string(),
                "wafAction" => self.waf_action.to_string(),
                "geo.country.id" => self.country_id.to_string(),
                "geo.province.id" => self.province_id.to_string(),
                "geo.city.id" => self.city_id.to_string(),
                "isp.id" => self.provider_id.to_string(),
                _ => resolved,
            }
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct AggregatedValue {
    pub count: i64,
    pub count_attack: i64,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub attack_bytes: i64,
}

pub struct MetricAggregator {
    pub data: DashMap<AggregationKey, AggregatedValue>,
}

impl Default for MetricAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricAggregator {
    pub fn new() -> Self {
        Self {
            data: DashMap::with_shard_amount(64),
        }
    }

    pub fn record(
        &self,
        key: AggregationKey,
        bytes_sent: i64,
        bytes_received: i64,
        is_attack: bool,
    ) {
        let mut entry = self.data.entry(key).or_default();
        entry.count += 1;
        entry.bytes_sent += bytes_sent;
        entry.bytes_received += bytes_received;
        if is_attack {
            entry.count_attack += 1;
            entry.attack_bytes += bytes_sent;
        }
    }

    pub fn flush(&self) -> Vec<(AggregationKey, AggregatedValue)> {
        let mut samples = Vec::new();
        let keys: Vec<_> = self.data.iter().map(|e| e.key().clone()).collect();
        for k in keys {
            if let Some((key, val)) = self.data.remove(&k) {
                samples.push((key, val));
            }
        }
        samples
    }
}

pub static METRIC_STAT_AGGREGATOR: Lazy<Arc<MetricAggregator>> =
    Lazy::new(|| Arc::new(MetricAggregator::new()));

pub static HTTP_REQUEST_STAT_AGGREGATOR: Lazy<Arc<MetricAggregator>> =
    Lazy::new(|| Arc::new(MetricAggregator::new()));

#[cfg(test)]
mod tests {
    use super::AggregationKey;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[test]
    fn metric_key_resolves_request_and_dimension_templates() {
        let mut attrs = BTreeMap::new();
        attrs.insert("host".to_string(), "cdn.example.com".to_string());
        attrs.insert("status".to_string(), "403".to_string());

        let key = AggregationKey {
            server_id: 1,
            country: Arc::from("China"),
            country_id: 1,
            province: Arc::from("Guangdong"),
            province_id: 2,
            city: Arc::from("Shenzhen"),
            city_id: 3,
            provider: Arc::from("CMCC"),
            browser: Arc::from("Chrome"),
            os: Arc::from("macOS"),
            waf_group_id: 9,
            waf_action: Arc::from("block"),
            provider_id: 258,
            browser_version: Arc::from("126"),
            os_version: Arc::from("14"),
            request_attrs: Arc::new(attrs),
        };

        assert_eq!(
            key.resolve_metric_key("${host}-${status}-${geo.city.name}-${browser.version}"),
            "cdn.example.com-403-Shenzhen-126"
        );
        assert_eq!(key.resolve_metric_key("${unknownVar}"), "${unknownVar}");
    }
}
