use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::sync::Arc;

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct AggregationKey {
    pub server_id: i64,
    pub country: String,
    pub country_id: i64,
    pub province: String,
    pub province_id: i64,
    pub city: String,
    pub city_id: i64,
    pub provider: String,
    pub browser: String,
    pub os: String,
    pub waf_group_id: i64,
    pub waf_action: String,
}

#[derive(Debug, Default, Clone)]
pub struct AggregatedValue {
    pub count: i64,
    pub count_attack: i64,
    pub bytes_sent: i64,
}

pub struct MetricAggregator {
    samples: DashMap<AggregationKey, AggregatedValue>,
}

impl Default for MetricAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricAggregator {
    pub fn new() -> Self {
        Self {
            samples: DashMap::new(),
        }
    }

    pub fn record(&self, key: AggregationKey, bytes: i64, is_attack: bool) {
        let mut entry = self
            .samples
            .entry(key)
            .or_default();
        entry.count += 1;
        entry.bytes_sent += bytes;
        if is_attack {
            entry.count_attack += 1;
        }
    }

    /// Flushes the current samples and returns them as a Vec
    pub fn flush(&self) -> Vec<(AggregationKey, AggregatedValue)> {
        let mut results = Vec::new();
        // We use remove_if to drain the map safely
        let keys: Vec<AggregationKey> = self.samples.iter().map(|kv| kv.key().clone()).collect();
        for key in keys {
            if let Some((_, val)) = self.samples.remove(&key) {
                results.push((key, val));
            }
        }
        results
    }
}

pub static METRIC_STAT_AGGREGATOR: Lazy<Arc<MetricAggregator>> =
    Lazy::new(|| Arc::new(MetricAggregator::new()));

pub static HTTP_REQUEST_STAT_AGGREGATOR: Lazy<Arc<MetricAggregator>> =
    Lazy::new(|| Arc::new(MetricAggregator::new()));
