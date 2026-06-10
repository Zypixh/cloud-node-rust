use crate::config_models::LocationConfig;
use dashmap::DashMap;
use regex::Regex;
use std::sync::Arc;
use std::sync::LazyLock as Lazy;

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

static COMPILED_CACHE: Lazy<DashMap<i64, Arc<Vec<CompiledLocation>>>> = Lazy::new(DashMap::new);

pub fn get_compiled_locations(
    server_id: i64,
    raw: &[LocationConfig],
) -> Arc<Vec<CompiledLocation>> {
    if let Some(entry) = COMPILED_CACHE.get(&server_id) {
        return entry.clone();
    }
    let compiled = Arc::new(compile_locations(raw));
    COMPILED_CACHE.insert(server_id, compiled.clone());
    compiled
}

pub fn clear_compiled_locations() {
    COMPILED_CACHE.clear();
}
