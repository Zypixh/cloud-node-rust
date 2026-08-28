use crate::config_models::LocationConfig;
use dashmap::DashMap;
use regex::Regex;
use std::sync::Arc;
use std::sync::LazyLock as Lazy;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub enum PatternType {
    Prefix,
    Exact,
    Regex,
}

#[derive(Debug)]
pub struct CompiledLocation {
    pub pattern_type: PatternType,
    pub pattern: String,
    pub regex: Option<Regex>,
    pub priority: i32,
    pub config: Arc<LocationConfig>,
}

pub fn compile_locations(raw: &[LocationConfig]) -> Vec<CompiledLocation> {
    let mut out = Vec::with_capacity(raw.len());
    for loc in raw {
        if !loc.is_on || loc.pattern.is_empty() {
            continue;
        }
        let pattern_type = match loc.pattern_type.as_str() {
            "exact" => PatternType::Exact,
            "regex" => PatternType::Regex,
            _ => PatternType::Prefix,
        };
        let regex = if matches!(pattern_type, PatternType::Regex) {
            match Regex::new(&loc.pattern) {
                Ok(r) => Some(r),
                Err(_) => continue,
            }
        } else {
            None
        };
        out.push(CompiledLocation {
            pattern_type,
            pattern: loc.pattern.clone(),
            regex,
            priority: loc.priority,
            config: Arc::new(loc.clone()),
        });
    }
    out.sort_by(|a, b| {
        type_order(&a.pattern_type)
            .cmp(&type_order(&b.pattern_type))
            .then_with(|| match (&a.pattern_type, &b.pattern_type) {
                (PatternType::Prefix, PatternType::Prefix) => b.pattern.len().cmp(&a.pattern.len()),
                _ => std::cmp::Ordering::Equal,
            })
            .then(b.priority.cmp(&a.priority))
    });
    out
}

fn type_order(t: &PatternType) -> u8 {
    match t {
        PatternType::Exact => 0,
        PatternType::Regex => 1,
        PatternType::Prefix => 2,
    }
}

pub fn match_location<'a>(
    compiled: &'a [CompiledLocation],
    path: &str,
) -> Option<&'a CompiledLocation> {
    for loc in compiled {
        let hit = match loc.pattern_type {
            PatternType::Exact => loc.pattern == path,
            PatternType::Regex => loc.regex.as_ref().is_some_and(|r| r.is_match(path)),
            PatternType::Prefix => path.starts_with(&loc.pattern),
        };
        if hit {
            return Some(loc);
        }
    }
    None
}

static COMPILED_CACHE: Lazy<DashMap<(u64, i64, usize), Arc<Vec<CompiledLocation>>>> =
    Lazy::new(DashMap::new);
static COMPILED_CACHE_GENERATION: AtomicU64 = AtomicU64::new(0);

pub fn get_compiled_locations(
    server_id: i64,
    raw: &[LocationConfig],
) -> Arc<Vec<CompiledLocation>> {
    let cache_generation = COMPILED_CACHE_GENERATION.load(Ordering::Acquire);
    let cache_key = (cache_generation, server_id, raw.as_ptr() as usize);
    if let Some(entry) = COMPILED_CACHE.get(&cache_key) {
        return entry.clone();
    }
    let compiled = Arc::new(compile_locations(raw));
    COMPILED_CACHE.insert(cache_key, compiled.clone());
    compiled
}

pub fn clear_compiled_locations() {
    COMPILED_CACHE_GENERATION.fetch_add(1, Ordering::AcqRel);
    COMPILED_CACHE.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn location(pattern: &str) -> LocationConfig {
        LocationConfig {
            is_on: true,
            pattern: pattern.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn cache_entries_do_not_cross_server_config_instances() {
        clear_compiled_locations();
        let old = vec![location("/old")];
        let new = vec![location("/new")];

        let old_compiled = get_compiled_locations(42, &old);
        clear_compiled_locations();
        let new_compiled = get_compiled_locations(42, &new);
        let old_reinserted = get_compiled_locations(42, &old);
        let new_after_old_reinsert = get_compiled_locations(42, &new);

        assert_eq!(old_compiled[0].pattern, "/old");
        assert_eq!(old_reinserted[0].pattern, "/old");
        assert_eq!(new_compiled[0].pattern, "/new");
        assert!(Arc::ptr_eq(&new_compiled, &new_after_old_reinsert));
        clear_compiled_locations();
    }
}
