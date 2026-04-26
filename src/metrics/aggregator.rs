use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::sync::Arc;

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
}

#[derive(Debug, Default, Clone)]
pub struct AggregatedValue {
    pub count: i64,
    pub count_attack: i64,
    pub bytes_sent: i64,
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

    pub fn record(&self, key: AggregationKey, bytes_sent: i64, is_attack: bool) {
        let mut entry = self.data.entry(key).or_default();
        entry.count += 1;
        entry.bytes_sent += bytes_sent;
        if is_attack {
            entry.count_attack += 1;
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
