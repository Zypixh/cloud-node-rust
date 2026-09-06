use dashmap::DashMap;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::LazyLock as Lazy;

#[derive(Debug, Clone)]
pub struct AggregationKey {
    pub category: Arc<str>,
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

impl PartialEq for AggregationKey {
    fn eq(&self, other: &Self) -> bool {
        self.category == other.category
            && self.server_id == other.server_id
            && self.country == other.country
            && self.country_id == other.country_id
            && self.province == other.province
            && self.province_id == other.province_id
            && self.city == other.city
            && self.city_id == other.city_id
            && self.provider == other.provider
            && self.browser == other.browser
            && self.os == other.os
            && self.waf_group_id == other.waf_group_id
            && self.waf_action == other.waf_action
            && self.provider_id == other.provider_id
            && self.browser_version == other.browser_version
            && self.os_version == other.os_version
    }
}

impl Eq for AggregationKey {}

impl Hash for AggregationKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.category.hash(state);
        self.server_id.hash(state);
        self.country.hash(state);
        self.country_id.hash(state);
        self.province.hash(state);
        self.province_id.hash(state);
        self.city.hash(state);
        self.city_id.hash(state);
        self.provider.hash(state);
        self.browser.hash(state);
        self.os.hash(state);
        self.waf_group_id.hash(state);
        self.waf_action.hash(state);
        self.provider_id.hash(state);
        self.browser_version.hash(state);
        self.os_version.hash(state);
    }
}

impl AggregationKey {
    pub fn resolve_metric_key(&self, configured_key: &str) -> String {
        self.resolve_metric_key_with_attrs(configured_key, self.request_attrs.as_ref())
    }

    pub fn resolve_metric_key_with_attrs(
        &self,
        configured_key: &str,
        request_attrs: &BTreeMap<String, String>,
    ) -> String {
        crate::metrics::resolve_template_with(configured_key, |var_name| {
            let resolved =
                crate::metrics::resolve_metric_variable_from_map(request_attrs, var_name);
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
pub struct AggregatedRequestValue {
    pub count: i64,
    pub count_attack: i64,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub attack_bytes: i64,
}

impl AggregatedRequestValue {
    fn add(&mut self, bytes_sent: i64, bytes_received: i64, is_attack: bool) {
        self.count += 1;
        self.bytes_sent += bytes_sent;
        self.bytes_received += bytes_received;
        if is_attack {
            self.count_attack += 1;
            self.attack_bytes += bytes_sent;
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct AggregatedValue {
    pub count: i64,
    pub count_attack: i64,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub attack_bytes: i64,
    pub request_samples: BTreeMap<Arc<BTreeMap<String, String>>, AggregatedRequestValue>,
}

impl AggregatedValue {
    fn add(&mut self, bytes_sent: i64, bytes_received: i64, is_attack: bool) {
        self.count += 1;
        self.bytes_sent += bytes_sent;
        self.bytes_received += bytes_received;
        if is_attack {
            self.count_attack += 1;
            self.attack_bytes += bytes_sent;
        }
    }

    fn add_request_sample(
        &mut self,
        request_attrs: Arc<BTreeMap<String, String>>,
        bytes_sent: i64,
        bytes_received: i64,
        is_attack: bool,
    ) {
        self.request_samples.entry(request_attrs).or_default().add(
            bytes_sent,
            bytes_received,
            is_attack,
        );
    }
}

pub struct MetricAggregator {
    pub data: DashMap<AggregationKey, AggregatedValue>,
    preserve_request_samples: bool,
}

impl Default for MetricAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricAggregator {
    pub fn new() -> Self {
        Self::with_request_samples(false)
    }

    pub fn with_request_samples(preserve_request_samples: bool) -> Self {
        Self {
            data: DashMap::with_shard_amount(64),
            preserve_request_samples,
        }
    }

    pub fn record(
        &self,
        key: AggregationKey,
        bytes_sent: i64,
        bytes_received: i64,
        is_attack: bool,
    ) {
        let request_attrs = self
            .preserve_request_samples
            .then(|| Arc::clone(&key.request_attrs));
        let mut entry = self.data.entry(key).or_default();
        entry.add(bytes_sent, bytes_received, is_attack);
        if let Some(request_attrs) = request_attrs {
            entry.add_request_sample(request_attrs, bytes_sent, bytes_received, is_attack);
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

    pub fn restore(&self, samples: Vec<(AggregationKey, AggregatedValue)>) {
        for (key, value) in samples {
            let mut entry = self.data.entry(key).or_default();
            entry.count += value.count;
            entry.count_attack += value.count_attack;
            entry.bytes_sent += value.bytes_sent;
            entry.bytes_received += value.bytes_received;
            entry.attack_bytes += value.attack_bytes;
            for (attrs, request_value) in value.request_samples {
                let target = entry.request_samples.entry(attrs).or_default();
                target.count += request_value.count;
                target.count_attack += request_value.count_attack;
                target.bytes_sent += request_value.bytes_sent;
                target.bytes_received += request_value.bytes_received;
                target.attack_bytes += request_value.attack_bytes;
            }
        }
    }

    pub fn approximate_bytes(&self) -> u64 {
        self.data
            .iter()
            .map(|entry| {
                let key = entry.key();
                let value = entry.value();
                256u64
                    .saturating_add(key.category.len() as u64)
                    .saturating_add(key.country.len() as u64)
                    .saturating_add(key.province.len() as u64)
                    .saturating_add(key.city.len() as u64)
                    .saturating_add(key.provider.len() as u64)
                    .saturating_add(key.browser.len() as u64)
                    .saturating_add(key.os.len() as u64)
                    .saturating_add((value.request_samples.len() as u64).saturating_mul(128))
            })
            .sum()
    }
}

pub static METRIC_STAT_AGGREGATOR: Lazy<Arc<MetricAggregator>> =
    Lazy::new(|| Arc::new(MetricAggregator::with_request_samples(true)));

pub static HTTP_REQUEST_STAT_AGGREGATOR: Lazy<Arc<MetricAggregator>> =
    Lazy::new(|| Arc::new(MetricAggregator::new()));

#[cfg(test)]
mod tests {
    use super::{AggregationKey, MetricAggregator};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[test]
    fn metric_key_resolves_request_and_dimension_templates() {
        let mut attrs = BTreeMap::new();
        attrs.insert("host".to_string(), "cdn.example.com".to_string());
        attrs.insert("status".to_string(), "403".to_string());

        let key = AggregationKey {
            category: Arc::from(crate::metrics::METRIC_CATEGORY_HTTP),
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

    #[test]
    fn metric_category_separates_otherwise_identical_rows() {
        let request_attrs = Arc::new(BTreeMap::new());
        let http_key = AggregationKey {
            category: Arc::from(crate::metrics::METRIC_CATEGORY_HTTP),
            server_id: 1,
            country: Arc::from(""),
            country_id: 0,
            province: Arc::from(""),
            province_id: 0,
            city: Arc::from(""),
            city_id: 0,
            provider: Arc::from("Unknown"),
            browser: Arc::from(""),
            os: Arc::from(""),
            waf_group_id: 0,
            waf_action: Arc::from(""),
            provider_id: 0,
            browser_version: Arc::from(""),
            os_version: Arc::from(""),
            request_attrs: Arc::clone(&request_attrs),
        };
        let tcp_key = AggregationKey {
            category: Arc::from(crate::metrics::METRIC_CATEGORY_TCP),
            request_attrs,
            ..http_key.clone()
        };

        assert_ne!(http_key, tcp_key);
    }

    #[test]
    fn request_attrs_do_not_split_stable_aggregation_key() {
        let mut attrs_a = BTreeMap::new();
        attrs_a.insert("remoteAddr".to_string(), "203.0.113.1".to_string());
        attrs_a.insert("requestId".to_string(), "a".to_string());
        let mut attrs_b = BTreeMap::new();
        attrs_b.insert("remoteAddr".to_string(), "203.0.113.1".to_string());
        attrs_b.insert("requestId".to_string(), "b".to_string());

        let base = AggregationKey {
            category: Arc::from(crate::metrics::METRIC_CATEGORY_HTTP),
            server_id: 1,
            country: Arc::from(""),
            country_id: 0,
            province: Arc::from(""),
            province_id: 0,
            city: Arc::from(""),
            city_id: 0,
            provider: Arc::from("Unknown"),
            browser: Arc::from(""),
            os: Arc::from(""),
            waf_group_id: 0,
            waf_action: Arc::from(""),
            provider_id: 0,
            browser_version: Arc::from(""),
            os_version: Arc::from(""),
            request_attrs: Arc::new(attrs_a),
        };
        let other = AggregationKey {
            request_attrs: Arc::new(attrs_b),
            ..base.clone()
        };

        assert_eq!(base, other);
    }

    #[test]
    fn metric_stat_aggregator_preserves_request_samples_for_later_key_grouping() {
        let aggregator = crate::metrics::aggregator::MetricAggregator::with_request_samples(true);
        let mut attrs_a = BTreeMap::new();
        attrs_a.insert("remoteAddr".to_string(), "203.0.113.1".to_string());
        attrs_a.insert("requestId".to_string(), "a".to_string());
        let mut attrs_b = BTreeMap::new();
        attrs_b.insert("remoteAddr".to_string(), "203.0.113.1".to_string());
        attrs_b.insert("requestId".to_string(), "b".to_string());

        let base = AggregationKey {
            category: Arc::from(crate::metrics::METRIC_CATEGORY_HTTP),
            server_id: 1,
            country: Arc::from(""),
            country_id: 0,
            province: Arc::from(""),
            province_id: 0,
            city: Arc::from(""),
            city_id: 0,
            provider: Arc::from("Unknown"),
            browser: Arc::from(""),
            os: Arc::from(""),
            waf_group_id: 0,
            waf_action: Arc::from(""),
            provider_id: 0,
            browser_version: Arc::from(""),
            os_version: Arc::from(""),
            request_attrs: Arc::new(attrs_a),
        };
        let other = AggregationKey {
            request_attrs: Arc::new(attrs_b),
            ..base.clone()
        };

        aggregator.record(base, 10, 1, false);
        aggregator.record(other, 20, 2, false);

        let rows = aggregator.flush();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1.count, 2);
        assert_eq!(rows[0].1.bytes_sent, 30);
        assert_eq!(rows[0].1.request_samples.len(), 2);
    }

    #[test]
    fn flushed_samples_can_be_restored_without_changing_totals() {
        let aggregator = MetricAggregator::with_request_samples(true);
        let key = AggregationKey {
            category: Arc::from(crate::metrics::METRIC_CATEGORY_HTTP),
            server_id: 1,
            country: Arc::from(""),
            country_id: 0,
            province: Arc::from(""),
            province_id: 0,
            city: Arc::from(""),
            city_id: 0,
            provider: Arc::from("Unknown"),
            browser: Arc::from(""),
            os: Arc::from(""),
            waf_group_id: 0,
            waf_action: Arc::from(""),
            provider_id: 0,
            browser_version: Arc::from(""),
            os_version: Arc::from(""),
            request_attrs: Arc::new(BTreeMap::new()),
        };
        aggregator.record(key.clone(), 11, 7, true);
        let samples = aggregator.flush();
        assert_eq!(samples.len(), 1);
        assert!(aggregator.data.is_empty());
        aggregator.restore(samples);
        let restored = aggregator.flush();
        assert_eq!(restored[0].0, key);
        assert_eq!(restored[0].1.count, 1);
        assert_eq!(restored[0].1.bytes_sent, 11);
        assert_eq!(restored[0].1.bytes_received, 7);
        assert_eq!(restored[0].1.count_attack, 1);
    }
}
