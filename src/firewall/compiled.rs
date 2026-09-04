use crate::config_models::{
    HTTPFirewallPolicy, HTTPFirewallRegionConfig, HTTPFirewallRule, HTTPFirewallRuleGroup,
    HTTPFirewallRuleSet, HTTPParamFilter, ServerConfig, WAFCaptchaOptions, WAFJSCookieOptions,
};
use crate::firewall::{ActionResponse, MatchedAction, OutboundContext};
use aho_corasick::AhoCorasick;
use pingora_proxy::Session;
use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

const REGEX_SIZE_LIMIT: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Connector {
    And,
    Or,
}

impl Connector {
    fn compile(value: &str) -> Self {
        if value == "and" { Self::And } else { Self::Or }
    }
}

#[derive(Clone, Debug)]
pub struct CompiledFirewallPolicy {
    pub id: i64,
    pub raw: Arc<HTTPFirewallPolicy>,
    pub is_on: bool,
    pub mode: String,
    pub inbound: Option<CompiledFirewallDirection>,
    pub outbound: Option<CompiledFirewallDirection>,
    pub use_local_firewall: bool,
    pub uses_request_body: bool,
    pub uses_response_body: bool,
    region: Option<CompiledRegionDenyPlan>,
    stats: CompiledFirewallPolicyStats,
    request_prefilter: CompiledRequestPrefilterSummary,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompiledFirewallPolicyStats {
    pub inbound_groups: usize,
    pub inbound_sets: usize,
    pub inbound_rules: usize,
    pub inbound_fast_rules: usize,
    pub inbound_regex_prefilters: usize,
    pub outbound_groups: usize,
    pub outbound_sets: usize,
    pub outbound_rules: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompiledRequestPrefilterSummary {
    pub host_exact: Vec<String>,
    pub host_prefix: Vec<String>,
    pub host_suffix: Vec<String>,
    pub path_exact: Vec<String>,
    pub path_prefix: Vec<String>,
    pub path_suffix: Vec<String>,
    pub uri_exact: Vec<String>,
    pub uri_prefix: Vec<String>,
    pub uri_suffix: Vec<String>,
    pub method_exact: Vec<String>,
    pub header_exact: Vec<(String, String)>,
    pub ip_exact: Vec<String>,
    pub has_ip_range: bool,
}

impl CompiledFirewallPolicy {
    pub fn compile(policy: &HTTPFirewallPolicy) -> Self {
        let region = policy
            .inbound
            .as_ref()
            .and_then(|inbound| inbound.region.as_ref())
            .and_then(|region| {
                CompiledRegionDenyPlan::compile(region, policy.id, &policy.deny_country_html)
            });
        let inbound = policy
            .inbound
            .as_ref()
            .map(|inbound| CompiledFirewallDirection {
                is_on: inbound.is_on,
                groups: inbound
                    .groups
                    .iter()
                    .map(CompiledRuleGroup::compile)
                    .collect(),
            });
        let outbound = policy
            .outbound
            .as_ref()
            .map(|outbound| CompiledFirewallDirection {
                is_on: outbound.is_on,
                groups: outbound
                    .groups
                    .iter()
                    .map(CompiledRuleGroup::compile)
                    .collect(),
            });
        let uses_request_body = inbound
            .as_ref()
            .is_some_and(CompiledFirewallDirection::uses_request_body);
        let uses_response_body = outbound
            .as_ref()
            .is_some_and(CompiledFirewallDirection::uses_response_body);
        let stats =
            CompiledFirewallPolicyStats::from_directions(inbound.as_ref(), outbound.as_ref());
        let request_prefilter = CompiledRequestPrefilterSummary::from_inbound(inbound.as_ref());
        Self {
            id: policy.id,
            raw: Arc::new(policy.clone()),
            is_on: policy.is_on,
            mode: policy.mode.clone(),
            inbound,
            outbound,
            use_local_firewall: policy.use_local_firewall,
            uses_request_body,
            uses_response_body,
            region,
            stats,
            request_prefilter,
        }
    }

    pub fn stats(&self) -> CompiledFirewallPolicyStats {
        self.stats
    }

    pub fn request_prefilter(&self) -> &CompiledRequestPrefilterSummary {
        &self.request_prefilter
    }
}

impl CompiledFirewallPolicyStats {
    fn from_directions(
        inbound: Option<&CompiledFirewallDirection>,
        outbound: Option<&CompiledFirewallDirection>,
    ) -> Self {
        let mut stats = Self::default();
        if let Some(inbound) = inbound {
            stats.inbound_groups = inbound.groups.len();
            for group in &inbound.groups {
                stats.inbound_sets += group.sets.len();
                for set in &group.sets {
                    stats.inbound_rules += set.rules.len();
                    stats.inbound_fast_rules += set.fast_path.rules.len();
                    if set.regex_prefilter.is_some() {
                        stats.inbound_regex_prefilters += 1;
                    }
                }
            }
        }
        if let Some(outbound) = outbound {
            stats.outbound_groups = outbound.groups.len();
            for group in &outbound.groups {
                stats.outbound_sets += group.sets.len();
                for set in &group.sets {
                    stats.outbound_rules += set.rules.len();
                }
            }
        }
        stats
    }
}

impl CompiledRequestPrefilterSummary {
    fn from_inbound(inbound: Option<&CompiledFirewallDirection>) -> Self {
        let mut summary = Self::default();
        let Some(inbound) = inbound else {
            return summary;
        };
        for group in &inbound.groups {
            if !group.is_on {
                continue;
            }
            for set in &group.sets {
                if !set.is_on {
                    continue;
                }
                for fast_rule in &set.fast_path.rules {
                    match &fast_rule.condition {
                        CompiledFastCondition::HostEq(value) => {
                            summary.host_exact.push(value.clone())
                        }
                        CompiledFastCondition::HostPrefix(value) => {
                            summary.host_prefix.push(value.clone())
                        }
                        CompiledFastCondition::HostSuffix(value) => {
                            summary.host_suffix.push(value.clone())
                        }
                        CompiledFastCondition::UriEq(value) => {
                            summary.uri_exact.push(value.clone())
                        }
                        CompiledFastCondition::UriPrefix(value) => {
                            summary.uri_prefix.push(value.clone())
                        }
                        CompiledFastCondition::UriSuffix(value) => {
                            summary.uri_suffix.push(value.clone())
                        }
                        CompiledFastCondition::PathEq(value) => {
                            summary.path_exact.push(value.clone())
                        }
                        CompiledFastCondition::PathPrefix(value) => {
                            summary.path_prefix.push(value.clone())
                        }
                        CompiledFastCondition::PathSuffix(value) => {
                            summary.path_suffix.push(value.clone())
                        }
                        CompiledFastCondition::MethodEq(value) => {
                            summary.method_exact.push(value.clone())
                        }
                        CompiledFastCondition::HeaderEq { name, value } => {
                            summary.header_exact.push((name.clone(), value.clone()))
                        }
                        CompiledFastCondition::SrcIpEq(value) => {
                            summary.ip_exact.push(value.clone())
                        }
                        CompiledFastCondition::SrcIpRange { .. } => summary.has_ip_range = true,
                        CompiledFastCondition::HostContains(_)
                        | CompiledFastCondition::UriContains(_)
                        | CompiledFastCondition::PathContains(_)
                        | CompiledFastCondition::MethodPrefix(_)
                        | CompiledFastCondition::MethodSuffix(_)
                        | CompiledFastCondition::MethodContains(_)
                        | CompiledFastCondition::HeaderPrefix { .. }
                        | CompiledFastCondition::HeaderSuffix { .. }
                        | CompiledFastCondition::HeaderContains { .. } => {}
                    }
                }
            }
        }
        summary.dedup();
        summary
    }

    fn dedup(&mut self) {
        fn dedup_vec(values: &mut Vec<String>) {
            values.sort();
            values.dedup();
        }
        dedup_vec(&mut self.host_exact);
        dedup_vec(&mut self.host_prefix);
        dedup_vec(&mut self.host_suffix);
        dedup_vec(&mut self.path_exact);
        dedup_vec(&mut self.path_prefix);
        dedup_vec(&mut self.path_suffix);
        dedup_vec(&mut self.uri_exact);
        dedup_vec(&mut self.uri_prefix);
        dedup_vec(&mut self.uri_suffix);
        dedup_vec(&mut self.method_exact);
        self.header_exact.sort();
        self.header_exact.dedup();
        dedup_vec(&mut self.ip_exact);
    }
}

#[derive(Clone, Debug)]
struct CompiledRegionDenyPlan {
    policy_id: i64,
    allow_search_engine: bool,
    allow_countries: HashSet<&'static str>,
    deny_countries: HashSet<&'static str>,
    allow_province_ids: Vec<i64>,
    deny_province_ids: Vec<i64>,
    only_url_patterns: Vec<crate::config_models::URLPattern>,
    except_url_patterns: Vec<crate::config_models::URLPattern>,
    deny_country_body: String,
    deny_province_body: String,
}

fn geo_region_matches_id(geo: &crate::metrics::analyzer::GeoInfo, id: i64) -> bool {
    geo.region_id == id
        || legacy_province_id_to_name(id).is_some_and(|name| name == geo.region.as_ref())
}

impl CompiledRegionDenyPlan {
    fn compile(
        region: &HTTPFirewallRegionConfig,
        policy_id: i64,
        deny_html_fallback: &str,
    ) -> Option<Self> {
        if !region.is_on {
            return None;
        }
        let allow_countries = region
            .allow_country_ids
            .iter()
            .filter_map(|&id| legacy_country_id_to_iso(id))
            .collect();
        let deny_countries = region
            .deny_country_ids
            .iter()
            .filter_map(|&id| legacy_country_id_to_iso(id))
            .collect();
        let deny_country_body = if !region.deny_country_html.is_empty() {
            region.deny_country_html.clone()
        } else {
            deny_html_fallback.to_string()
        };
        let deny_country_body = if deny_country_body.is_empty() {
            "Access denied: your country is not allowed".to_string()
        } else {
            deny_country_body
        };
        let deny_province_body = if !region.deny_province_html.is_empty() {
            region.deny_province_html.clone()
        } else {
            deny_html_fallback.to_string()
        };
        let deny_province_body = if deny_province_body.is_empty() {
            "Access denied: your region is not allowed".to_string()
        } else {
            deny_province_body
        };
        Some(Self {
            policy_id,
            allow_search_engine: region.allow_search_engine,
            allow_countries,
            deny_countries,
            allow_province_ids: region.allow_province_ids.clone(),
            deny_province_ids: region.deny_province_ids.clone(),
            only_url_patterns: region.only_url_patterns.clone(),
            except_url_patterns: region.except_url_patterns.clone(),
            deny_country_body,
            deny_province_body,
        })
    }

    fn evaluate(&self, client_ip: IpAddr, user_agent: &str, url: &str) -> Option<MatchedAction> {
        if !self.matches_url(url)
            || (self.allow_search_engine
                && crate::client_agent::is_verified_search_engine_ip(client_ip, user_agent))
        {
            return None;
        }
        let geo = crate::metrics::analyzer::lookup_geo(client_ip)?;
        if !self.allow_countries.is_empty() || !self.deny_countries.is_empty() {
            let country_iso = geo.country_iso.as_ref();
            let country_blocked = if !self.allow_countries.is_empty() {
                !self.allow_countries.contains(country_iso)
            } else {
                self.deny_countries.contains(country_iso)
            };
            if country_blocked {
                return Some(self.block_action("denyCountry", self.deny_country_body.clone()));
            }
        }

        let country_iso = geo.country_iso.as_ref();
        let is_cn = country_iso == "CN";
        if is_cn && (!self.allow_province_ids.is_empty() || !self.deny_province_ids.is_empty()) {
            let province_blocked = if !self.allow_province_ids.is_empty() {
                !self
                    .allow_province_ids
                    .iter()
                    .any(|&id| geo_region_matches_id(&geo, id))
            } else {
                self.deny_province_ids
                    .iter()
                    .any(|&id| geo_region_matches_id(&geo, id))
            };
            if province_blocked {
                return Some(self.block_action("denyProvince", self.deny_province_body.clone()));
            }
        }
        None
    }

    fn matches_url(&self, url: &str) -> bool {
        if !self.except_url_patterns.is_empty()
            && self
                .except_url_patterns
                .iter()
                .any(|pattern| pattern.matches(url))
        {
            return false;
        }
        if self.only_url_patterns.is_empty() {
            return true;
        }
        self.only_url_patterns
            .iter()
            .any(|pattern| pattern.matches(url))
    }

    fn block_action(&self, tag: &str, body: String) -> MatchedAction {
        MatchedAction {
            action: ActionResponse::Block { status: 403, body },
            policy_id: self.policy_id,
            group_id: 0,
            set_id: 0,
            action_code: "block".to_string(),
            timeout_secs: Some(3600),
            max_timeout_secs: None,
            life_seconds: None,
            max_fails: None,
            fail_block_timeout: None,
            fail_global: None,
            scope: None,
            block_c_class: false,
            use_local_firewall: false,
            next_group_id: None,
            next_set_id: None,
            allow_scope: None,
            tags: vec![tag.to_string()],
            ip_list_id: 0,
            event_level: "error".to_string(),
            block_options: None,
            page_options: None,
            captcha_options: None,
            js_cookie_options: None,
            chained_actions: vec![],
            observe_only: false,
        }
    }
}

fn legacy_country_id_to_iso(id: i64) -> Option<&'static str> {
    match id {
        1 => Some("CN"),
        2 => Some("US"),
        3 => Some("JP"),
        4 => Some("KR"),
        5 => Some("GB"),
        6 => Some("DE"),
        7 => Some("FR"),
        8 => Some("RU"),
        9 => Some("SG"),
        10 => Some("AU"),
        11 => Some("IN"),
        12 => Some("CA"),
        13 => Some("BR"),
        14 => Some("TH"),
        15 => Some("VN"),
        16 => Some("MY"),
        17 => Some("PH"),
        18 => Some("ID"),
        19 => Some("NL"),
        20 => Some("IT"),
        261 => Some("HK"),
        262 => Some("TW"),
        263 => Some("MO"),
        264 => Some("CN"),
        _ => None,
    }
}

fn legacy_province_id_to_name(id: i64) -> Option<&'static str> {
    match id {
        1 => Some("Beijing"),
        2 => Some("Tianjin"),
        3 => Some("Hebei"),
        4 => Some("Shanxi"),
        5 => Some("Inner Mongolia"),
        6 => Some("Liaoning"),
        7 => Some("Jilin"),
        8 => Some("Heilongjiang"),
        9 => Some("Shanghai"),
        10 => Some("Jiangsu"),
        11 => Some("Zhejiang"),
        12 => Some("Anhui"),
        13 => Some("Fujian"),
        14 => Some("Jiangxi"),
        15 => Some("Shandong"),
        16 => Some("Henan"),
        17 => Some("Hubei"),
        18 => Some("Hunan"),
        19 => Some("Guangdong"),
        20 => Some("Guangxi"),
        21 => Some("Hainan"),
        22 => Some("Chongqing"),
        23 => Some("Sichuan"),
        24 => Some("Guizhou"),
        25 => Some("Yunnan"),
        26 => Some("Tibet"),
        27 => Some("Shaanxi"),
        28 => Some("Gansu"),
        29 => Some("Qinghai"),
        30 => Some("Ningxia"),
        31 => Some("Xinjiang"),
        32 => Some("Hong Kong"),
        33 => Some("Macau"),
        34 => Some("Taiwan"),
        _ => None,
    }
}

pub fn evaluate_compiled_region_deny(
    policy: &CompiledFirewallPolicy,
    client_ip: IpAddr,
    user_agent: &str,
    url: &str,
) -> Option<MatchedAction> {
    if !policy.is_on || policy.mode == "bypass" {
        return None;
    }
    let mut matched = policy
        .region
        .as_ref()
        .and_then(|region| region.evaluate(client_ip, user_agent, url))?;
    crate::firewall::apply_observe_mode(&policy.raw, &mut matched);
    Some(matched)
}

#[derive(Clone, Debug)]
pub struct CompiledFirewallDirection {
    pub is_on: bool,
    pub groups: Vec<CompiledRuleGroup>,
}

impl CompiledFirewallDirection {
    fn uses_request_body(&self) -> bool {
        self.is_on && self.groups.iter().any(CompiledRuleGroup::uses_request_body)
    }

    fn uses_response_body(&self) -> bool {
        self.is_on
            && self
                .groups
                .iter()
                .any(CompiledRuleGroup::uses_response_body)
    }
}

#[derive(Clone, Debug)]
pub struct CompiledRuleGroup {
    pub id: i64,
    pub is_on: bool,
    pub preset: Option<PresetGroup>,
    pub sets: Vec<CompiledRuleSet>,
    request_prefilter: CompiledGroupRequestPrefilter,
}

impl CompiledRuleGroup {
    fn compile(group: &HTTPFirewallRuleGroup) -> Self {
        let sets: Vec<_> = group.sets.iter().map(CompiledRuleSet::compile).collect();
        let request_prefilter = CompiledGroupRequestPrefilter::compile(&sets);
        Self {
            id: group.id,
            is_on: group.is_on,
            preset: group.code.as_deref().and_then(PresetGroup::compile),
            sets,
            request_prefilter,
        }
    }

    fn uses_request_body(&self) -> bool {
        self.is_on
            && (self.preset.is_some_and(PresetGroup::uses_request_body)
                || self.sets.iter().any(CompiledRuleSet::uses_request_body))
    }

    fn uses_response_body(&self) -> bool {
        self.is_on && self.sets.iter().any(CompiledRuleSet::uses_response_body)
    }
}

#[derive(Clone, Debug)]
pub struct CompiledRuleSet {
    pub id: i64,
    pub is_on: bool,
    pub connector: Connector,
    pub ignore_local: bool,
    pub ignore_search_engine: bool,
    pub rules: Vec<CompiledFirewallRule>,
    fast_path: CompiledSetFastPath,
    regex_prefilter: Option<CompiledRegexPrefilter>,
    compiled_actions: Arc<[CompiledAction]>,
}

#[derive(Clone, Debug, Default)]
struct CompiledGroupRequestPrefilter {
    exact: HashMap<PrefilterExactKey, Vec<usize>>,
    header_exact_names: Vec<String>,
    scans: Vec<(PrefilterScanKey, usize)>,
    always: Vec<usize>,
    indexed_count: usize,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum PrefilterExactKey {
    Host(String),
    Path(String),
    Uri(String),
    Method(String),
    Header { name: String, value: String },
    Ip(String),
}

#[derive(Clone, Debug)]
enum PrefilterScanKey {
    All(Vec<PrefilterScanKey>),
    HostEq(String),
    HostPrefix(String),
    HostSuffix(String),
    HostContains(String),
    PathEq(String),
    PathPrefix(String),
    PathSuffix(String),
    PathContains(String),
    UriEq(String),
    UriPrefix(String),
    UriSuffix(String),
    UriContains(String),
    MethodEq(String),
    MethodPrefix(String),
    MethodSuffix(String),
    MethodContains(String),
    HeaderEq { name: String, value: String },
    HeaderPrefix { name: String, value: String },
    HeaderSuffix { name: String, value: String },
    HeaderContains { name: String, value: String },
    IpEq(String),
    IpRange { items: Vec<IpMatcher>, not: bool },
}

#[derive(Clone, Debug)]
enum SetPrefilter {
    Always,
    Any(Vec<PrefilterScanKey>),
}

#[derive(Clone, Debug)]
struct CompiledRegexPrefilter {
    value: CompiledValueExpr,
    set: Arc<RegexSet>,
    rules: Vec<usize>,
}

#[derive(Clone, Debug)]
struct CompiledSetFastPath {
    all_rules_indexed: bool,
    rules: Vec<CompiledFastRule>,
}

#[derive(Clone, Debug)]
struct CompiledFastRule {
    rule_index: usize,
    condition: CompiledFastCondition,
}

#[derive(Clone, Debug)]
enum CompiledFastCondition {
    HostEq(String),
    HostPrefix(String),
    HostSuffix(String),
    HostContains(String),
    UriEq(String),
    UriPrefix(String),
    UriSuffix(String),
    UriContains(String),
    PathEq(String),
    PathPrefix(String),
    PathSuffix(String),
    PathContains(String),
    MethodEq(String),
    MethodPrefix(String),
    MethodSuffix(String),
    MethodContains(String),
    HeaderEq { name: String, value: String },
    HeaderPrefix { name: String, value: String },
    HeaderSuffix { name: String, value: String },
    HeaderContains { name: String, value: String },
    SrcIpEq(String),
    SrcIpRange { items: Vec<IpMatcher>, not: bool },
}

impl CompiledGroupRequestPrefilter {
    fn compile(sets: &[CompiledRuleSet]) -> Self {
        let mut prefilter = Self::default();
        for (set_index, set) in sets.iter().enumerate() {
            if !set.is_on || set.rules.is_empty() {
                continue;
            }
            match SetPrefilter::compile(set) {
                SetPrefilter::Always => prefilter.always.push(set_index),
                SetPrefilter::Any(keys) => {
                    prefilter.indexed_count += 1;
                    for key in keys {
                        match key.as_exact_key() {
                            Some(exact) => {
                                if let PrefilterExactKey::Header { name, value: _ } = &exact {
                                    prefilter.header_exact_names.push(name.clone());
                                }
                                prefilter.exact.entry(exact).or_default().push(set_index)
                            }
                            None => prefilter.scans.push((key, set_index)),
                        }
                    }
                }
            }
        }
        prefilter.header_exact_names.sort();
        prefilter.header_exact_names.dedup();
        prefilter
    }

    fn candidate_set_indexes<F: RequestPrefilterFacts + ?Sized>(
        &self,
        facts: &F,
        start_idx: usize,
    ) -> Option<Vec<usize>> {
        if self.indexed_count == 0 {
            return None;
        }

        let mut candidates = Vec::with_capacity(self.always.len().saturating_add(8));
        candidates.extend(self.always.iter().copied().filter(|idx| *idx >= start_idx));

        self.push_exact_candidates(&mut candidates, PrefilterExactKey::Host(facts.host()));
        self.push_exact_candidates(
            &mut candidates,
            PrefilterExactKey::Path(facts.request_path()),
        );
        self.push_exact_candidates(&mut candidates, PrefilterExactKey::Uri(facts.request_uri()));
        self.push_exact_candidates(
            &mut candidates,
            PrefilterExactKey::Method(facts.request_method()),
        );
        self.push_exact_candidates(&mut candidates, PrefilterExactKey::Ip(facts.remote_addr()));

        for name in &self.header_exact_names {
            let value = facts.request_header(name);
            self.push_exact_candidates(
                &mut candidates,
                PrefilterExactKey::Header {
                    name: name.clone(),
                    value,
                },
            );
        }

        for (key, set_index) in &self.scans {
            if *set_index >= start_idx && key.matches_request(facts) {
                candidates.push(*set_index);
            }
        }

        candidates.retain(|idx| *idx >= start_idx);
        candidates.sort_unstable();
        candidates.dedup();
        Some(candidates)
    }

    fn push_exact_candidates(&self, candidates: &mut Vec<usize>, key: PrefilterExactKey) {
        if let Some(indexes) = self.exact.get(&key) {
            candidates.extend(indexes.iter().copied());
        }
    }
}

impl SetPrefilter {
    fn compile(set: &CompiledRuleSet) -> Self {
        if should_use_and_prefilter(set.connector) {
            let keys = set
                .fast_path
                .rules
                .iter()
                .filter_map(|fast_rule| PrefilterScanKey::from_condition(&fast_rule.condition))
                .collect::<Vec<_>>();
            if keys.is_empty() {
                Self::Always
            } else {
                // For AND sets each indexed rule is a necessary condition.  If
                // any of these cheap predicates misses, the full set cannot
                // match; unindexed heavy rules still run after the prefilter.
                Self::Any(vec![PrefilterScanKey::All(keys)])
            }
        } else if set.fast_path.all_rules_indexed && !set.fast_path.rules.is_empty() {
            let keys = set
                .fast_path
                .rules
                .iter()
                .filter_map(|fast_rule| PrefilterScanKey::from_condition(&fast_rule.condition))
                .collect::<Vec<_>>();
            if keys.is_empty() {
                Self::Always
            } else {
                Self::Any(keys)
            }
        } else {
            Self::Always
        }
    }
}

fn should_use_and_prefilter(connector: Connector) -> bool {
    connector == Connector::And
}

impl PrefilterScanKey {
    fn from_condition(condition: &CompiledFastCondition) -> Option<Self> {
        match condition {
            CompiledFastCondition::HostEq(value) => Some(Self::HostEq(value.clone())),
            CompiledFastCondition::HostPrefix(value) => Some(Self::HostPrefix(value.clone())),
            CompiledFastCondition::HostSuffix(value) => Some(Self::HostSuffix(value.clone())),
            CompiledFastCondition::HostContains(value) => Some(Self::HostContains(value.clone())),
            CompiledFastCondition::UriEq(value) => Some(Self::UriEq(value.clone())),
            CompiledFastCondition::UriPrefix(value) => Some(Self::UriPrefix(value.clone())),
            CompiledFastCondition::UriSuffix(value) => Some(Self::UriSuffix(value.clone())),
            CompiledFastCondition::UriContains(value) => Some(Self::UriContains(value.clone())),
            CompiledFastCondition::PathEq(value) => Some(Self::PathEq(value.clone())),
            CompiledFastCondition::PathPrefix(value) => Some(Self::PathPrefix(value.clone())),
            CompiledFastCondition::PathSuffix(value) => Some(Self::PathSuffix(value.clone())),
            CompiledFastCondition::PathContains(value) => Some(Self::PathContains(value.clone())),
            CompiledFastCondition::MethodEq(value) => Some(Self::MethodEq(value.clone())),
            CompiledFastCondition::MethodPrefix(value) => Some(Self::MethodPrefix(value.clone())),
            CompiledFastCondition::MethodSuffix(value) => Some(Self::MethodSuffix(value.clone())),
            CompiledFastCondition::MethodContains(value) => {
                Some(Self::MethodContains(value.clone()))
            }
            CompiledFastCondition::HeaderEq { name, value } => Some(Self::HeaderEq {
                name: normalize_header_lookup_name(name),
                value: value.clone(),
            }),
            CompiledFastCondition::HeaderPrefix { name, value } => Some(Self::HeaderPrefix {
                name: normalize_header_lookup_name(name),
                value: value.clone(),
            }),
            CompiledFastCondition::HeaderSuffix { name, value } => Some(Self::HeaderSuffix {
                name: normalize_header_lookup_name(name),
                value: value.clone(),
            }),
            CompiledFastCondition::HeaderContains { name, value } => Some(Self::HeaderContains {
                name: normalize_header_lookup_name(name),
                value: value.clone(),
            }),
            CompiledFastCondition::SrcIpEq(value) => Some(Self::IpEq(value.clone())),
            CompiledFastCondition::SrcIpRange { items, not } => Some(Self::IpRange {
                items: items.clone(),
                not: *not,
            }),
        }
    }

    fn as_exact_key(&self) -> Option<PrefilterExactKey> {
        match self {
            Self::HostEq(value) => Some(PrefilterExactKey::Host(value.clone())),
            Self::PathEq(value) => Some(PrefilterExactKey::Path(value.clone())),
            Self::UriEq(value) => Some(PrefilterExactKey::Uri(value.clone())),
            Self::MethodEq(value) => Some(PrefilterExactKey::Method(value.clone())),
            Self::HeaderEq { name, value } => Some(PrefilterExactKey::Header {
                name: name.clone(),
                value: value.clone(),
            }),
            Self::IpEq(value) => Some(PrefilterExactKey::Ip(value.clone())),
            _ => None,
        }
    }

    fn matches_request<F: RequestPrefilterFacts + ?Sized>(&self, facts: &F) -> bool {
        match self {
            Self::All(keys) => keys.iter().all(|key| key.matches_request(facts)),
            Self::HostEq(expected) => facts.host() == *expected,
            Self::HostPrefix(expected) => facts.host().starts_with(expected),
            Self::HostSuffix(expected) => facts.host().ends_with(expected),
            Self::HostContains(expected) => facts.host().contains(expected),
            Self::PathEq(expected) => facts.request_path() == *expected,
            Self::PathPrefix(expected) => facts.request_path().starts_with(expected),
            Self::PathSuffix(expected) => facts.request_path().ends_with(expected),
            Self::PathContains(expected) => facts.request_path().contains(expected),
            Self::UriEq(expected) => facts.request_uri() == *expected,
            Self::UriPrefix(expected) => facts.request_uri().starts_with(expected),
            Self::UriSuffix(expected) => facts.request_uri().ends_with(expected),
            Self::UriContains(expected) => facts.request_uri().contains(expected),
            Self::MethodEq(expected) => facts.request_method() == *expected,
            Self::MethodPrefix(expected) => facts.request_method().starts_with(expected),
            Self::MethodSuffix(expected) => facts.request_method().ends_with(expected),
            Self::MethodContains(expected) => facts.request_method().contains(expected),
            Self::HeaderEq { name, value } => facts.request_header(name) == *value,
            Self::HeaderPrefix { name, value } => facts.request_header(name).starts_with(value),
            Self::HeaderSuffix { name, value } => facts.request_header(name).ends_with(value),
            Self::HeaderContains { name, value } => facts.request_header(name).contains(value),
            Self::IpEq(expected) => facts.remote_addr() == *expected,
            Self::IpRange { items, not } => {
                let actual = facts.remote_addr();
                let matched = ip_items_match(items, &actual);
                if *not { !matched } else { matched }
            }
        }
    }
}

trait RequestPrefilterFacts {
    fn host(&self) -> String;
    fn request_path(&self) -> String;
    fn request_uri(&self) -> String;
    fn request_method(&self) -> String;
    fn remote_addr(&self) -> String;
    fn request_header(&self, name: &str) -> String;
}

impl<'a> RequestPrefilterFacts for crate::firewall::matcher_plus::RequestFacts<'a> {
    fn host(&self) -> String {
        self.host()
    }

    fn request_path(&self) -> String {
        self.request_path()
    }

    fn request_uri(&self) -> String {
        self.request_uri()
    }

    fn request_method(&self) -> String {
        self.request_method()
    }

    fn remote_addr(&self) -> String {
        self.remote_addr()
    }

    fn request_header(&self, name: &str) -> String {
        self.request_header(name)
    }
}

fn normalize_header_lookup_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

#[derive(Clone, Debug)]
struct CompiledAction {
    action: ActionResponse,
    action_code: String,
    timeout_secs: Option<i64>,
    life_seconds: Option<i64>,
    max_fails: Option<i32>,
    fail_block_timeout: Option<i64>,
    fail_global: Option<bool>,
    scope: Option<String>,
    next_group_id: Option<i64>,
    next_set_id: Option<i64>,
    allow_scope: Option<String>,
    tags: Vec<String>,
    ip_list_id: i64,
    event_level: String,
    captcha_options: Option<WAFCaptchaOptions>,
    js_cookie_options: Option<WAFJSCookieOptions>,
}

impl CompiledAction {
    fn compile(action: &Value) -> Option<Self> {
        let code = action
            .get("code")
            .or_else(|| action.get("action"))
            .and_then(Value::as_str)
            .map(normalize_action_code)?;
        let options = action.get("options");
        match code.as_str() {
            "block" => Some(Self {
                action: ActionResponse::Block {
                    status: options
                        .and_then(|v| v.get("status"))
                        .and_then(Value::as_i64)
                        .unwrap_or(403) as i32,
                    body: options
                        .and_then(|v| v.get("body"))
                        .and_then(Value::as_str)
                        .unwrap_or("Blocked by WAF")
                        .to_string(),
                },
                timeout_secs: options
                    .and_then(|v| v.get("timeout"))
                    .and_then(Value::as_i64),
                fail_global: options
                    .and_then(|v| v.get("failBlockScopeAll"))
                    .and_then(Value::as_bool),
                scope: options
                    .and_then(|v| v.get("scope"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                ip_list_id: options
                    .and_then(|v| v.get("ipListId"))
                    .and_then(Value::as_i64)
                    .unwrap_or(0),
                event_level: crate::firewall::parse_action_event_level(options),
                ..Self::with_code(ActionResponse::Allow, "block")
            }),
            "allow" => Some(Self::allow(Some(
                options
                    .and_then(|v| v.get("scope"))
                    .and_then(Value::as_str)
                    .unwrap_or("group")
                    .to_string(),
            ))),
            "log" => Some(Self::with_code(ActionResponse::Allow, "log")),
            "tag" => {
                let tags = options
                    .and_then(|v| v.get("tags"))
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                Some(Self {
                    tags,
                    ..Self::with_code(ActionResponse::Allow, "tag")
                })
            }
            "notify" => Some(Self::with_code(ActionResponse::Allow, "notify")),
            "record_ip" => {
                let ip_type = options
                    .and_then(|v| v.get("type"))
                    .and_then(Value::as_str)
                    .unwrap_or("black")
                    .to_ascii_lowercase();
                let timeout_secs = options
                    .and_then(|v| v.get("timeout"))
                    .and_then(Value::as_i64);
                let scope = options
                    .and_then(|v| v.get("scope"))
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let ip_list_id = options
                    .and_then(|v| v.get("ipListId"))
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                let event_level = crate::firewall::parse_action_event_level(options);
                match ip_type.as_str() {
                    "black" | "deny" => Some(Self {
                        timeout_secs,
                        scope,
                        ip_list_id,
                        event_level,
                        ..Self::with_code(
                            ActionResponse::Block {
                                status: 403,
                                body: "Blocked by WAF".to_string(),
                            },
                            "record_ip",
                        )
                    }),
                    "white" | "allow" => Some(Self {
                        timeout_secs,
                        scope,
                        ip_list_id,
                        event_level,
                        ..Self::with_code(ActionResponse::Allow, "record_ip_white")
                    }),
                    "gray" | "grey" => Some(Self {
                        timeout_secs,
                        scope,
                        ip_list_id,
                        event_level,
                        ..Self::with_code(ActionResponse::Allow, "record_ip_gray")
                    }),
                    _ => None,
                }
            }
            "page" => Some(Self::with_code(
                ActionResponse::Page {
                    status: options
                        .and_then(|v| v.get("status"))
                        .and_then(Value::as_i64)
                        .unwrap_or(403) as i32,
                    body: options
                        .and_then(|v| v.get("body"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    content_type: "text/html; charset=utf-8".to_string(),
                },
                "page",
            )),
            "redirect" => Some(Self::with_code(
                ActionResponse::Redirect {
                    status: options
                        .and_then(|v| v.get("status"))
                        .and_then(Value::as_i64)
                        .unwrap_or(302) as i32,
                    location: options
                        .and_then(|v| v.get("url"))
                        .and_then(Value::as_str)
                        .unwrap_or("/")
                        .to_string(),
                },
                "redirect",
            )),
            "captcha" | "js_cookie" | "get_302" | "post_307" => {
                let life_seconds = options
                    .and_then(|v| v.get("life"))
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                let action = match code.as_str() {
                    "captcha" => ActionResponse::Captcha { life_seconds },
                    "js_cookie" => ActionResponse::JsCookie { life_seconds },
                    "get_302" => ActionResponse::Get302 { life_seconds },
                    _ => ActionResponse::Post307 { life_seconds },
                };
                Some(Self {
                    life_seconds: Some(life_seconds),
                    max_fails: options
                        .and_then(|v| v.get("maxFails"))
                        .and_then(Value::as_i64)
                        .map(|value| value as i32),
                    fail_block_timeout: options
                        .and_then(|v| v.get("failBlockTimeout"))
                        .and_then(Value::as_i64),
                    fail_global: options
                        .and_then(|v| v.get("failBlockScopeAll"))
                        .and_then(Value::as_bool),
                    captcha_options: options.and_then(|value| {
                        let mut parsed: WAFCaptchaOptions =
                            serde_json::from_value(value.clone()).ok()?;
                        crate::firewall::normalize_captcha_options(&mut parsed);
                        Some(parsed)
                    }),
                    js_cookie_options: options
                        .and_then(|value| serde_json::from_value(value.clone()).ok()),
                    ..Self::with_code(action, &code)
                })
            }
            "go_group" => Some(Self {
                next_group_id: options
                    .and_then(|v| v.get("groupId"))
                    .and_then(Value::as_i64),
                ..Self::with_code(ActionResponse::Allow, "go_group")
            }),
            "go_set" => Some(Self {
                next_group_id: options
                    .and_then(|v| v.get("groupId"))
                    .and_then(Value::as_i64),
                next_set_id: options
                    .and_then(|v| v.get("ruleSetId"))
                    .and_then(Value::as_i64),
                ..Self::with_code(ActionResponse::Allow, "go_set")
            }),
            _ => None,
        }
    }

    fn allow(allow_scope: Option<String>) -> Self {
        Self {
            allow_scope,
            ..Self::with_code(ActionResponse::Allow, "allow")
        }
    }

    fn with_code(action: ActionResponse, action_code: &str) -> Self {
        Self {
            action,
            action_code: action_code.to_string(),
            timeout_secs: None,
            life_seconds: None,
            max_fails: None,
            fail_block_timeout: None,
            fail_global: None,
            scope: None,
            next_group_id: None,
            next_set_id: None,
            allow_scope: None,
            tags: vec![],
            ip_list_id: 0,
            event_level: String::new(),
            captcha_options: None,
            js_cookie_options: None,
        }
    }

    fn to_matched(&self) -> MatchedAction {
        MatchedAction {
            action: self.action.clone(),
            policy_id: 0,
            group_id: 0,
            set_id: 0,
            action_code: self.action_code.clone(),
            timeout_secs: self.timeout_secs,
            max_timeout_secs: None,
            life_seconds: self.life_seconds,
            max_fails: self.max_fails,
            fail_block_timeout: self.fail_block_timeout,
            fail_global: self.fail_global,
            scope: self.scope.clone(),
            block_c_class: false,
            use_local_firewall: false,
            next_group_id: self.next_group_id,
            next_set_id: self.next_set_id,
            allow_scope: self.allow_scope.clone(),
            tags: self.tags.clone(),
            ip_list_id: self.ip_list_id,
            event_level: self.event_level.clone(),
            block_options: None,
            page_options: None,
            captcha_options: self.captcha_options.clone(),
            js_cookie_options: self.js_cookie_options.clone(),
            chained_actions: vec![],
            observe_only: false,
        }
    }
}

fn normalize_action_code(code: &str) -> String {
    match code.trim() {
        "jsCookie" | "js-cookie" | "jscookie" | "JSCookie" => "js_cookie".to_string(),
        other => other.to_ascii_lowercase(),
    }
}

fn is_response_action_code(action_code: &str) -> bool {
    matches!(
        action_code,
        "block"
            | "page"
            | "redirect"
            | "record_ip"
            | "captcha"
            | "js_cookie"
            | "jsCookie"
            | "jscookie"
            | "get_302"
            | "post_307"
    )
}

fn perform_compiled_actions(set: &CompiledRuleSet) -> Option<MatchedAction> {
    let ordered_actions: Vec<MatchedAction> = set
        .compiled_actions
        .iter()
        .map(CompiledAction::to_matched)
        .collect();
    let primary_index = ordered_actions
        .iter()
        .position(|action| is_response_action_code(&action.action_code))
        .unwrap_or(0);
    let mut primary = ordered_actions.get(primary_index)?.clone();
    primary.chained_actions = ordered_actions;
    Some(primary)
}

impl CompiledRegexPrefilter {
    fn compile(connector: Connector, rules: &[CompiledFirewallRule]) -> Option<Self> {
        if connector != Connector::Or || rules.is_empty() {
            return None;
        }
        let first_value = rules[0].value.clone();
        let mut patterns = Vec::with_capacity(rules.len());
        let mut rule_indexes = Vec::with_capacity(rules.len());
        for (index, rule) in rules.iter().enumerate() {
            if rule.reverse
                || rule.case_insensitive
                || rule.value.is_cc()
                || rule.value != first_value
            {
                return None;
            }
            let pattern = match &rule.operator {
                CompiledOperator::Regex(regex) => regex.as_str(),
                _ => return None,
            };
            patterns.push(pattern.to_string());
            rule_indexes.push(index);
        }
        RegexSetBuilder::new(patterns)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
            .ok()
            .map(|set| Self {
                value: first_value,
                set: Arc::new(set),
                rules: rule_indexes,
            })
    }

    fn matches_request(
        &self,
        rules: &[CompiledFirewallRule],
        facts: &crate::firewall::matcher_plus::RequestFacts<'_>,
    ) -> bool {
        let actual = self.value.evaluate(facts);
        for index in self.set.matches(&actual) {
            if rules[self.rules[index]].matches_value(&actual) {
                return true;
            }
        }
        false
    }
}

impl CompiledSetFastPath {
    fn compile(rules: &[CompiledFirewallRule]) -> Self {
        let mut fast_rules = Vec::new();
        let mut all_rules_indexed = !rules.is_empty();
        for (rule_index, rule) in rules.iter().enumerate() {
            if rule.value.is_cc() {
                all_rules_indexed = false;
                continue;
            }
            if let Some(condition) = CompiledFastCondition::compile(rule) {
                fast_rules.push(CompiledFastRule {
                    rule_index,
                    condition,
                });
            } else {
                all_rules_indexed = false;
            }
        }
        Self {
            all_rules_indexed,
            rules: fast_rules,
        }
    }

    fn evaluate_request(
        &self,
        rules: &[CompiledFirewallRule],
        connector: Connector,
        facts: &crate::firewall::matcher_plus::RequestFacts<'_>,
    ) -> Option<bool> {
        if self.rules.is_empty() {
            return None;
        }
        match connector {
            Connector::And => {
                for fast_rule in &self.rules {
                    if !fast_rule.condition.matches_request(facts) {
                        return Some(false);
                    }
                }
                self.all_rules_indexed.then_some(true)
            }
            Connector::Or => {
                for fast_rule in &self.rules {
                    if fast_rule.condition.matches_request(facts)
                        && rules[fast_rule.rule_index].matches_request(facts)
                    {
                        return Some(true);
                    }
                }
                self.all_rules_indexed.then_some(false)
            }
        }
    }
}

impl CompiledFastCondition {
    fn compile(rule: &CompiledFirewallRule) -> Option<Self> {
        let CompiledValueExpr::Variable(variable) = &rule.value else {
            return None;
        };
        let condition = match variable {
            CompiledVariable::Host => Self::compile_text(TextField::Host, rule),
            CompiledVariable::RequestUri => Self::compile_text(TextField::Uri, rule),
            CompiledVariable::RequestPath => Self::compile_text(TextField::Path, rule),
            CompiledVariable::RequestMethod => Self::compile_text(TextField::Method, rule),
            CompiledVariable::HeaderParam(name) => {
                Self::compile_header(&normalize_header_lookup_name(name), rule)
            }
            CompiledVariable::RemoteAddr => Self::compile_ip(rule),
            _ => None,
        }?;
        if rule.reverse {
            return None;
        }
        Some(condition)
    }

    fn compile_text(field: TextField, rule: &CompiledFirewallRule) -> Option<Self> {
        match &rule.operator {
            CompiledOperator::EqString(expected) if !rule.case_insensitive => match field {
                TextField::Host => Some(Self::HostEq(expected.clone())),
                TextField::Uri => Some(Self::UriEq(expected.clone())),
                TextField::Path => Some(Self::PathEq(expected.clone())),
                TextField::Method => Some(Self::MethodEq(expected.clone())),
            },
            CompiledOperator::Prefix(expected) if !rule.case_insensitive => match field {
                TextField::Host => Some(Self::HostPrefix(expected.clone())),
                TextField::Uri => Some(Self::UriPrefix(expected.clone())),
                TextField::Path => Some(Self::PathPrefix(expected.clone())),
                TextField::Method => Some(Self::MethodPrefix(expected.clone())),
            },
            CompiledOperator::Suffix(expected) if !rule.case_insensitive => match field {
                TextField::Host => Some(Self::HostSuffix(expected.clone())),
                TextField::Uri => Some(Self::UriSuffix(expected.clone())),
                TextField::Path => Some(Self::PathSuffix(expected.clone())),
                TextField::Method => Some(Self::MethodSuffix(expected.clone())),
            },
            CompiledOperator::Contains(expected) if !rule.case_insensitive => match field {
                TextField::Host => Some(Self::HostContains(expected.clone())),
                TextField::Uri => Some(Self::UriContains(expected.clone())),
                TextField::Path => Some(Self::PathContains(expected.clone())),
                TextField::Method => Some(Self::MethodContains(expected.clone())),
            },
            _ => None,
        }
    }

    fn compile_header(name: &str, rule: &CompiledFirewallRule) -> Option<Self> {
        match &rule.operator {
            CompiledOperator::EqString(expected) if !rule.case_insensitive => {
                Some(Self::HeaderEq {
                    name: name.to_string(),
                    value: expected.clone(),
                })
            }
            CompiledOperator::Prefix(expected) if !rule.case_insensitive => {
                Some(Self::HeaderPrefix {
                    name: name.to_string(),
                    value: expected.clone(),
                })
            }
            CompiledOperator::Suffix(expected) if !rule.case_insensitive => {
                Some(Self::HeaderSuffix {
                    name: name.to_string(),
                    value: expected.clone(),
                })
            }
            CompiledOperator::Contains(expected) if !rule.case_insensitive => {
                Some(Self::HeaderContains {
                    name: name.to_string(),
                    value: expected.clone(),
                })
            }
            _ => None,
        }
    }

    fn compile_ip(rule: &CompiledFirewallRule) -> Option<Self> {
        match &rule.operator {
            CompiledOperator::EqIp(expected) => Some(Self::SrcIpEq(expected.clone())),
            CompiledOperator::IpRange { items, not } => Some(Self::SrcIpRange {
                items: items.clone(),
                not: *not,
            }),
            CompiledOperator::InIpList(items) => Some(Self::SrcIpRange {
                items: items.clone(),
                not: false,
            }),
            _ => None,
        }
    }

    fn matches_request(&self, facts: &crate::firewall::matcher_plus::RequestFacts<'_>) -> bool {
        match self {
            Self::HostEq(expected) => facts.host() == *expected,
            Self::HostPrefix(expected) => facts.host().starts_with(expected),
            Self::HostSuffix(expected) => facts.host().ends_with(expected),
            Self::HostContains(expected) => facts.host().contains(expected),
            Self::UriEq(expected) => facts.request_uri() == *expected,
            Self::UriPrefix(expected) => facts.request_uri().starts_with(expected),
            Self::UriSuffix(expected) => facts.request_uri().ends_with(expected),
            Self::UriContains(expected) => facts.request_uri().contains(expected),
            Self::PathEq(expected) => facts.request_path() == *expected,
            Self::PathPrefix(expected) => facts.request_path().starts_with(expected),
            Self::PathSuffix(expected) => facts.request_path().ends_with(expected),
            Self::PathContains(expected) => facts.request_path().contains(expected),
            Self::MethodEq(expected) => facts.request_method() == *expected,
            Self::MethodPrefix(expected) => facts.request_method().starts_with(expected),
            Self::MethodSuffix(expected) => facts.request_method().ends_with(expected),
            Self::MethodContains(expected) => facts.request_method().contains(expected),
            Self::HeaderEq { name, value } => facts.request_header(name) == *value,
            Self::HeaderPrefix { name, value } => facts.request_header(name).starts_with(value),
            Self::HeaderSuffix { name, value } => facts.request_header(name).ends_with(value),
            Self::HeaderContains { name, value } => facts.request_header(name).contains(value),
            Self::SrcIpEq(expected) => facts.remote_addr() == *expected,
            Self::SrcIpRange { items, not } => {
                let actual = facts.remote_addr();
                let matched = ip_items_match(items, &actual);
                if *not { !matched } else { matched }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum TextField {
    Host,
    Uri,
    Path,
    Method,
}

impl CompiledRuleSet {
    fn compile(set: &HTTPFirewallRuleSet) -> Self {
        let rules: Vec<_> = set
            .rules
            .iter()
            .map(CompiledFirewallRule::compile)
            .collect();
        let connector = Connector::compile(&set.connector);
        let fast_path = CompiledSetFastPath::compile(&rules);
        let regex_prefilter = CompiledRegexPrefilter::compile(connector, &rules);
        Self {
            id: set.id,
            is_on: set.is_on,
            connector,
            ignore_local: set.ignore_local,
            ignore_search_engine: set.ignore_search_engine,
            rules,
            fast_path,
            regex_prefilter,
            compiled_actions: Arc::from(
                set.actions
                    .iter()
                    .filter_map(CompiledAction::compile)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            ),
        }
    }

    fn uses_request_body(&self) -> bool {
        self.is_on
            && self
                .rules
                .iter()
                .any(CompiledFirewallRule::uses_request_body)
    }

    fn uses_response_body(&self) -> bool {
        self.is_on
            && self
                .rules
                .iter()
                .any(CompiledFirewallRule::uses_response_body)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum PresetGroup {
    SqlInjection,
    SqlInjectionStrict,
    Xss,
    XssStrict,
    CmdInjection,
}

impl PresetGroup {
    fn compile(code: &str) -> Option<Self> {
        match code {
            "sqlInjection" => Some(Self::SqlInjection),
            "sqlInjectionStrict" => Some(Self::SqlInjectionStrict),
            "xss" => Some(Self::Xss),
            "xssStrict" => Some(Self::XssStrict),
            "cmdInjection" => Some(Self::CmdInjection),
            _ => None,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::SqlInjection => "sqlInjection",
            Self::SqlInjectionStrict => "sqlInjectionStrict",
            Self::Xss => "xss",
            Self::XssStrict => "xssStrict",
            Self::CmdInjection => "cmdInjection",
        }
    }

    fn uses_request_body(self) -> bool {
        crate::firewall::matcher_plus::preset_group_uses_request_body(self.code())
    }

    fn matches(self, facts: &crate::firewall::matcher_plus::RequestFacts<'_>) -> bool {
        crate::firewall::matcher_plus::preset_group_matches(self.code(), facts)
    }
}

#[derive(Clone, Debug)]
pub struct CompiledFirewallRule {
    pub param: String,
    pub checkpoint_options: Option<Value>,
    pub value_contains_response_body: bool,
    value: CompiledValueExpr,
    cc_plan: Option<CompiledCcPlan>,
    pub operator: CompiledOperator,
    operator_name: String,
    expected_value: String,
    pub reverse: bool,
    case_insensitive: bool,
    pub param_filters: Vec<HTTPParamFilter>,
}

#[derive(Clone, Debug)]
struct CompiledCcPlan {
    param: String,
    period: i64,
    is_cc2: bool,
    key_templates: Vec<CompiledValueExpr>,
}

impl CompiledCcPlan {
    fn compile(param: &str, value: &CompiledValueExpr, options: Option<&Value>) -> Option<Self> {
        let is_cc2 = match value {
            CompiledValueExpr::Variable(CompiledVariable::Cc) => false,
            CompiledValueExpr::Variable(CompiledVariable::Cc2) => true,
            _ => return None,
        };
        let period = options
            .and_then(|v| v.get("period"))
            .and_then(Value::as_i64)
            .unwrap_or(60)
            .clamp(1, 7 * 86_400);
        let key_templates = if is_cc2 {
            options
                .and_then(|v| v.get("keys"))
                .and_then(Value::as_array)
                .map(|keys| {
                    keys.iter()
                        .filter_map(Value::as_str)
                        .map(CompiledValueExpr::compile)
                        .collect()
                })
                .unwrap_or_else(|| vec![CompiledValueExpr::compile("${remoteAddr}")])
        } else {
            Vec::new()
        };
        Some(Self {
            param: param.to_string(),
            period,
            is_cc2,
            key_templates,
        })
    }

    fn evaluate(&self, facts: &crate::firewall::matcher_plus::RequestFacts<'_>) -> String {
        let key = if self.is_cc2 {
            let key_values = self
                .key_templates
                .iter()
                .map(|template| template.evaluate(facts))
                .collect::<Vec<_>>();
            format!(
                "WAF-CC2-{}-{}:{}",
                self.param,
                self.period,
                key_values.join("@")
            )
        } else {
            format!(
                "WAF-CC:{}:{}",
                self.period,
                crate::firewall::matcher_plus::aggregate_ip_counter_key(facts.remote_ip())
            )
        };
        crate::firewall::matcher_plus::increase_counter(key, self.period).to_string()
    }
}

#[derive(Clone, Debug, PartialEq)]
enum CompiledValueExpr {
    Literal(String),
    Variable(CompiledVariable),
    Template(Vec<CompiledValuePart>),
}

#[derive(Clone, Debug, PartialEq)]
enum CompiledValuePart {
    Literal(String),
    Variable(CompiledVariable),
}

#[derive(Clone, Debug, PartialEq)]
enum CompiledVariable {
    RemoteAddr,
    RawRemoteAddr,
    RemotePort,
    RemoteUser,
    RequestUri,
    RequestPath,
    RequestUrl,
    RequestFileExtension,
    RequestLength,
    RequestBody,
    RequestAll,
    RequestMethod,
    Scheme,
    Proto,
    Host,
    RefererOrigin,
    Referer,
    UserAgent,
    ContentType,
    Cookies,
    Args,
    Headers,
    HeaderNames,
    HeaderMaxLength,
    RequestGeneralHeaderLength,
    RequestPathLowerExtension,
    CommonAiBot,
    CommonBot,
    GeoCountryName,
    GeoProvinceName,
    GeoCityName,
    GeoAsn,
    GeoAsnNumber,
    IspName,
    ServerAddr,
    ServerPort,
    ResponseStatus,
    ResponseBody,
    BytesSent,
    ResponseGeneralHeaderLength,
    QueryParam(String),
    HeaderParam(String),
    CookieParam(String),
    FormParam(String),
    JsonParam(String),
    UploadSummary,
    UploadParam(String),
    ResponseHeaderParam(String),
    Cc,
    Cc2,
    Empty,
    Raw(String),
}

fn dotted_arg<'a>(inner: &'a str, prefixes: &[&str]) -> Option<&'a str> {
    prefixes.iter().find_map(|prefix| {
        inner
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix('.'))
    })
}

fn colon_arg<'a>(inner: &'a str, prefixes: &[&str]) -> Option<&'a str> {
    prefixes
        .iter()
        .find_map(|prefix| inner.strip_prefix(&format!("{prefix}:")))
}

impl CompiledVariable {
    fn compile(inner: &str) -> Self {
        match inner {
            "remoteAddr" => Self::RemoteAddr,
            "rawRemoteAddr" => Self::RawRemoteAddr,
            "remotePort" => Self::RemotePort,
            "remoteUser" => Self::RemoteUser,
            "requestURI" => Self::RequestUri,
            "requestPath" => Self::RequestPath,
            "requestURL" => Self::RequestUrl,
            "requestFileExtension" => Self::RequestFileExtension,
            "requestLength" => Self::RequestLength,
            "requestBody" => Self::RequestBody,
            "requestAll" => Self::RequestAll,
            "requestMethod" => Self::RequestMethod,
            "scheme" => Self::Scheme,
            "proto" => Self::Proto,
            "host" | "requestHost" => Self::Host,
            "refererOrigin" => Self::RefererOrigin,
            "referer" => Self::Referer,
            "userAgent" => Self::UserAgent,
            "contentType" => Self::ContentType,
            "cookies" => Self::Cookies,
            "args" => Self::Args,
            "headers" => Self::Headers,
            "headerNames" => Self::HeaderNames,
            "headerMaxLength" => Self::HeaderMaxLength,
            "requestGeneralHeaderLength" => Self::RequestGeneralHeaderLength,
            "requestPathLowerExtension" => Self::RequestPathLowerExtension,
            "commonAIBot" => Self::CommonAiBot,
            "commonBot" => Self::CommonBot,
            "geoCountryName" => Self::GeoCountryName,
            "geoProvinceName" => Self::GeoProvinceName,
            "geoCityName" => Self::GeoCityName,
            "geoAsn" | "asn" => Self::GeoAsn,
            "geoAsnNumber" | "asnNumber" => Self::GeoAsnNumber,
            "ispName" => Self::IspName,
            "serverAddr" => Self::ServerAddr,
            "serverPort" => Self::ServerPort,
            "status" => Self::ResponseStatus,
            "responseBody" => Self::ResponseBody,
            "bytesSent" => Self::BytesSent,
            "responseGeneralHeaderLength" => Self::ResponseGeneralHeaderLength,
            "requestUpload" => Self::UploadSummary,
            "cc" => Self::Cc,
            "cc2" => Self::Cc2,
            "refererBlock" => Self::Empty,
            "cname" => Self::Raw("cname".to_string()),
            "isCNAME" => Self::Raw("isCNAME".to_string()),
            _ => {
                if dotted_arg(inner, &["cc"]).is_some() {
                    return Self::Cc;
                }
                if dotted_arg(inner, &["cc2"]).is_some() {
                    return Self::Cc2;
                }
                if let Some(name) = dotted_arg(inner, &["arg", "requestArg"]) {
                    return Self::QueryParam(name.to_string());
                }
                if let Some(name) = dotted_arg(inner, &["header", "requestHeader"]) {
                    return Self::HeaderParam(name.to_string());
                }
                if let Some(name) = dotted_arg(inner, &["cookie", "requestCookie"]) {
                    return Self::CookieParam(name.to_string());
                }
                if let Some(name) = dotted_arg(inner, &["requestForm", "form"]) {
                    return Self::FormParam(name.to_string());
                }
                if let Some(path) = dotted_arg(inner, &["requestJSON", "json"]) {
                    return Self::JsonParam(path.to_string());
                }
                if let Some(name) = dotted_arg(inner, &["requestUpload"]) {
                    return Self::UploadParam(name.to_string());
                }
                if colon_arg(inner, &["cc"]).is_some() {
                    return Self::Cc;
                }
                if colon_arg(inner, &["cc2"]).is_some() {
                    return Self::Cc2;
                }
                if let Some(name) = colon_arg(inner, &["arg"]) {
                    return Self::QueryParam(name.to_string());
                }
                if let Some(name) = colon_arg(inner, &["header"]) {
                    return Self::HeaderParam(name.to_string());
                }
                if let Some(name) = colon_arg(inner, &["cookie"]) {
                    return Self::CookieParam(name.to_string());
                }
                if let Some(name) = dotted_arg(inner, &["responseHeader"]) {
                    return Self::ResponseHeaderParam(name.to_string());
                }
                if let Some(name) = colon_arg(inner, &["responseHeader"]) {
                    return Self::ResponseHeaderParam(name.to_string());
                }
                Self::Raw(inner.to_string())
            }
        }
    }

    fn is_cc(&self) -> bool {
        matches!(self, Self::Cc | Self::Cc2)
    }

    fn evaluate(&self, facts: &crate::firewall::matcher_plus::RequestFacts<'_>) -> String {
        match self {
            Self::RemoteAddr => facts.remote_addr(),
            Self::RawRemoteAddr => facts.raw_remote_addr(),
            Self::RemotePort => facts.remote_port(),
            Self::RemoteUser => facts.remote_user(),
            Self::RequestUri => facts.request_uri(),
            Self::RequestPath => facts.request_path(),
            Self::RequestUrl => facts.request_url(),
            Self::RequestFileExtension => facts.request_file_extension(),
            Self::RequestLength => facts.request_length(),
            Self::RequestBody => facts.request_body_text(),
            Self::RequestAll => facts.request_all(),
            Self::RequestMethod => facts.request_method(),
            Self::Scheme => facts.scheme(),
            Self::Proto => facts.proto(),
            Self::Host => facts.host(),
            Self::RefererOrigin => facts.referer_origin(),
            Self::Referer => facts.request_header("referer"),
            Self::UserAgent => facts.request_header("user-agent"),
            Self::ContentType => facts.request_header("content-type"),
            Self::Cookies => facts.cookies_normalized(),
            Self::Args => facts.request_args(),
            Self::Headers => facts.headers(),
            Self::HeaderNames => facts.header_names(),
            Self::HeaderMaxLength => facts.header_max_length().to_string(),
            Self::RequestGeneralHeaderLength => facts.general_header_length().to_string(),
            Self::RequestPathLowerExtension => facts.request_path_lower_extension(),
            Self::CommonAiBot => facts.common_ai_bot(),
            Self::CommonBot => facts.common_bot(),
            Self::GeoCountryName => facts.geo_country_name(),
            Self::GeoProvinceName => facts.geo_province_name(),
            Self::GeoCityName => facts.geo_city_name(),
            Self::GeoAsn => facts.geo_asn(),
            Self::GeoAsnNumber => facts.geo_asn_number(),
            Self::IspName => facts.isp_name(),
            Self::ServerAddr => facts.local_addr(),
            Self::ServerPort => facts.local_port(),
            Self::QueryParam(name) => facts.query_param(name),
            Self::HeaderParam(name) => facts.request_header(name),
            Self::CookieParam(name) => facts.cookie_param(name),
            Self::FormParam(name) => facts.form_param(name),
            Self::JsonParam(path) => facts.json_param(path),
            Self::UploadSummary => facts.upload_summary(),
            Self::UploadParam(name) => facts.upload_param(name),
            Self::Empty => String::new(),
            Self::Cc | Self::Cc2 => String::new(),
            Self::ResponseStatus
            | Self::ResponseBody
            | Self::BytesSent
            | Self::ResponseGeneralHeaderLength
            | Self::ResponseHeaderParam(_) => String::new(),
            Self::Raw(value) => {
                crate::firewall::matcher_plus::resolve_variable_with_facts(value, facts)
            }
        }
    }

    fn evaluate_response(
        &self,
        facts: &crate::firewall::matcher_plus::ResponseFacts<'_, '_, '_>,
    ) -> String {
        match self {
            Self::ResponseStatus => facts.status(),
            Self::ResponseBody => facts.response_body_text(),
            Self::BytesSent => facts.bytes_sent(),
            Self::ResponseGeneralHeaderLength => facts.response_general_header_length().to_string(),
            Self::ResponseHeaderParam(name) => facts.response_header(name),
            Self::Raw(value) => {
                crate::firewall::matcher_plus::resolve_response_variable_with_facts(value, facts)
            }
            _ => self.evaluate(facts.request()),
        }
    }
}

impl CompiledValueExpr {
    fn compile(param: &str) -> Self {
        if !param.contains("${") {
            return Self::Literal(param.to_string());
        }
        if let Some(inner) = param
            .strip_prefix("${")
            .and_then(|value| value.strip_suffix('}'))
        {
            return Self::Variable(CompiledVariable::compile(inner));
        }

        let mut parts = Vec::new();
        let mut rest = param;
        while let Some(start) = rest.find("${") {
            if start > 0 {
                parts.push(CompiledValuePart::Literal(rest[..start].to_string()));
            }
            let after_start = &rest[start + 2..];
            let Some(end) = after_start.find('}') else {
                parts.push(CompiledValuePart::Literal(rest[start..].to_string()));
                rest = "";
                break;
            };
            parts.push(CompiledValuePart::Variable(CompiledVariable::compile(
                &after_start[..end],
            )));
            rest = &after_start[end + 1..];
        }
        if !rest.is_empty() {
            parts.push(CompiledValuePart::Literal(rest.to_string()));
        }
        if parts.is_empty() {
            Self::Literal(String::new())
        } else {
            Self::Template(parts)
        }
    }

    fn is_cc(&self) -> bool {
        matches!(self, Self::Variable(value) if value.is_cc())
    }

    fn evaluate(&self, facts: &crate::firewall::matcher_plus::RequestFacts<'_>) -> String {
        match self {
            Self::Literal(value) => value.clone(),
            Self::Variable(value) => value.evaluate(facts),
            Self::Template(parts) => {
                let mut output = String::new();
                for part in parts {
                    match part {
                        CompiledValuePart::Literal(value) => output.push_str(value),
                        CompiledValuePart::Variable(value) => {
                            output.push_str(&value.evaluate(facts))
                        }
                    }
                }
                output
            }
        }
    }

    fn evaluate_response(
        &self,
        facts: &crate::firewall::matcher_plus::ResponseFacts<'_, '_, '_>,
    ) -> String {
        match self {
            Self::Literal(value) => value.clone(),
            Self::Variable(value) => value.evaluate_response(facts),
            Self::Template(parts) => {
                let mut output = String::new();
                for part in parts {
                    match part {
                        CompiledValuePart::Literal(value) => output.push_str(value),
                        CompiledValuePart::Variable(value) => {
                            output.push_str(&value.evaluate_response(facts));
                        }
                    }
                }
                output
            }
        }
    }
}

impl CompiledFirewallRule {
    pub fn compile(rule: &HTTPFirewallRule) -> Self {
        let value = CompiledValueExpr::compile(&rule.param);
        let cc_plan =
            CompiledCcPlan::compile(&rule.param, &value, rule.checkpoint_options.as_ref());
        Self {
            param: rule.param.clone(),
            checkpoint_options: rule.checkpoint_options.clone(),
            value_contains_response_body:
                crate::firewall::matcher_plus::expression_uses_response_body(&rule.value),
            value,
            cc_plan,
            operator: CompiledOperator::compile(
                &rule.operator,
                &rule.value,
                rule.is_case_insensitive,
            ),
            operator_name: rule.operator.clone(),
            expected_value: rule.value.clone(),
            reverse: rule.is_reverse,
            case_insensitive: rule.is_case_insensitive,
            param_filters: rule.param_filters.clone(),
        }
    }

    pub fn matches_value(&self, actual_value: &str) -> bool {
        let actual = if self.case_insensitive {
            Cow::Owned(actual_value.to_lowercase())
        } else {
            Cow::Borrowed(actual_value)
        };
        let matched = self.operator.evaluate(&actual);
        if self.reverse { !matched } else { matched }
    }

    fn matches_request(&self, facts: &crate::firewall::matcher_plus::RequestFacts<'_>) -> bool {
        crate::metrics::METRICS.waf.record_rule_evaluation();
        if self.param_filters.is_empty()
            && self.cc_plan.is_none()
            && self.value == CompiledValueExpr::Variable(CompiledVariable::RequestBody)
        {
            let matched = crate::firewall::matcher::evaluate_operator_bytes(
                facts.request_body_bytes(),
                &self.operator_name,
                &self.expected_value,
                self.case_insensitive,
            );
            return if self.reverse { !matched } else { matched };
        }
        let raw = if let Some(cc_plan) = &self.cc_plan {
            cc_plan.evaluate(facts)
        } else {
            self.value.evaluate(facts)
        };
        let value = if self.param_filters.is_empty() {
            raw
        } else {
            crate::firewall::matcher_plus::apply_param_filters(&raw, &self.param_filters)
        };
        self.matches_value(&value)
    }

    fn matches_response(
        &self,
        facts: &crate::firewall::matcher_plus::ResponseFacts<'_, '_, '_>,
    ) -> bool {
        crate::metrics::METRICS.waf.record_rule_evaluation();
        if self.param_filters.is_empty()
            && self.cc_plan.is_none()
            && self.value == CompiledValueExpr::Variable(CompiledVariable::ResponseBody)
        {
            let matched = crate::firewall::matcher::evaluate_operator_bytes(
                facts.response_body_bytes(),
                &self.operator_name,
                &self.expected_value,
                self.case_insensitive,
            );
            return if self.reverse { !matched } else { matched };
        }
        let raw = if let Some(cc_plan) = &self.cc_plan {
            cc_plan.evaluate(facts.request())
        } else {
            self.value.evaluate_response(facts)
        };
        let value = if self.param_filters.is_empty() {
            raw
        } else {
            crate::firewall::matcher_plus::apply_param_filters(&raw, &self.param_filters)
        };
        self.matches_value(&value)
    }

    fn uses_request_body(&self) -> bool {
        crate::firewall::matcher_plus::expression_uses_request_body(&self.param)
            || self
                .checkpoint_options
                .as_ref()
                .is_some_and(crate::firewall::matcher_plus::value_uses_request_body)
    }

    fn uses_response_body(&self) -> bool {
        crate::firewall::matcher_plus::expression_uses_response_body(&self.param)
            || self.value_contains_response_body
            || self
                .checkpoint_options
                .as_ref()
                .is_some_and(crate::firewall::matcher_plus::value_uses_response_body)
    }
}

pub fn evaluate_compiled_policy(
    policy: &CompiledFirewallPolicy,
    session: &Session,
    request_body: &[u8],
    scheme: &str,
) -> Option<MatchedAction> {
    evaluate_compiled_policy_with_server(policy, session, request_body, scheme, None)
}

pub fn evaluate_compiled_policy_with_server(
    policy: &CompiledFirewallPolicy,
    session: &Session,
    request_body: &[u8],
    scheme: &str,
    server: Option<&ServerConfig>,
) -> Option<MatchedAction> {
    let started = Instant::now();
    let matched = evaluate_compiled_policy_inner(policy, session, request_body, scheme, server);
    crate::metrics::METRICS
        .waf
        .record_compiled_evaluation(matched.is_some(), started.elapsed());
    matched
}

fn evaluate_compiled_policy_inner(
    policy: &CompiledFirewallPolicy,
    session: &Session,
    request_body: &[u8],
    scheme: &str,
    server: Option<&ServerConfig>,
) -> Option<MatchedAction> {
    if !policy.is_on || policy.mode == "bypass" {
        return None;
    }
    let inbound = policy.inbound.as_ref()?;
    if !inbound.is_on {
        return None;
    }

    let facts = crate::firewall::matcher_plus::RequestFacts::new_with_server(
        session,
        request_body,
        scheme,
        server,
    );
    let mut current_group_idx = 0;
    // Track the precise set id requested by a GO_SET so the next match_group
    // call lands on the named set rather than restarting the group from the
    // top (the previous behavior silently re-matched earlier sets).
    let mut next_start_set_id: Option<i64> = None;
    // Same cycle-defuse as the legacy evaluator: bound the total number of
    // flow-control jumps so a misconfigured GO_GROUP/GO_SET loop can't pin a
    // worker thread.
    let mut remaining_jumps: usize = inbound.groups.len().saturating_mul(8).max(64);
    while current_group_idx < inbound.groups.len() {
        if remaining_jumps == 0 {
            tracing::warn!(
                "WAF(compiled): aborting policy {} due to flow-control jump limit",
                policy.id
            );
            return None;
        }
        remaining_jumps -= 1;
        let group = &inbound.groups[current_group_idx];
        if !group.is_on {
            current_group_idx += 1;
            next_start_set_id = None;
            continue;
        }

        let start_set = next_start_set_id.take();
        if let Some(result) = match_group_from(group, session, request_body, &facts, start_set) {
            if let Some(set) = result.set
                && let Some(mut matched) = perform_compiled_actions(set)
            {
                fill_action_from_policy(&mut matched, policy, group.id, set.id);
                crate::firewall::apply_observe_mode(&policy.raw, &mut matched);

                if matched.action_code == "allow" {
                    match matched.allow_scope.as_deref() {
                        Some("group") => {
                            current_group_idx += 1;
                            continue;
                        }
                        Some("server") | Some("policy") => return Some(matched),
                        _ => {}
                    }
                }

                if let Some(next_gid) = matched.next_group_id
                    && let Some(idx) = inbound.groups.iter().position(|g| g.id == next_gid)
                {
                    current_group_idx = idx;
                    continue;
                }

                if let Some(next_sid) = matched.next_set_id {
                    let target = inbound.groups.iter().enumerate().find_map(|(idx, g)| {
                        g.sets.iter().any(|set| set.id == next_sid).then_some(idx)
                    });
                    if let Some(idx) = target {
                        current_group_idx = idx;
                        next_start_set_id = Some(next_sid);
                        continue;
                    }
                }

                if matched.action_code == "log" {
                    current_group_idx += 1;
                    continue;
                }

                return Some(matched);
            }
            if result.matched {
                let mut action = crate::firewall::default_block_action(policy.id, group.id);
                crate::firewall::apply_observe_mode(&policy.raw, &mut action);
                return Some(action);
            }
        }
        current_group_idx += 1;
    }
    None
}

pub fn evaluate_compiled_outbound_policy(
    policy: &CompiledFirewallPolicy,
    session: &Session,
    request_body: &[u8],
    response: &OutboundContext<'_>,
    scheme: &str,
) -> Option<MatchedAction> {
    evaluate_compiled_outbound_policy_with_server(
        policy,
        session,
        request_body,
        response,
        scheme,
        None,
    )
}

pub fn evaluate_compiled_outbound_policy_with_server(
    policy: &CompiledFirewallPolicy,
    session: &Session,
    request_body: &[u8],
    response: &OutboundContext<'_>,
    scheme: &str,
    server: Option<&ServerConfig>,
) -> Option<MatchedAction> {
    let started = Instant::now();
    let matched = evaluate_compiled_outbound_policy_inner(
        policy,
        session,
        request_body,
        response,
        scheme,
        server,
    );
    crate::metrics::METRICS
        .waf
        .record_compiled_evaluation(matched.is_some(), started.elapsed());
    matched
}

fn evaluate_compiled_outbound_policy_inner(
    policy: &CompiledFirewallPolicy,
    session: &Session,
    request_body: &[u8],
    response: &OutboundContext<'_>,
    scheme: &str,
    server: Option<&ServerConfig>,
) -> Option<MatchedAction> {
    if !policy.is_on || policy.mode == "bypass" {
        return None;
    }
    let outbound = policy.outbound.as_ref()?;
    if !outbound.is_on {
        return None;
    }

    let facts = crate::firewall::matcher_plus::ResponseFacts::new_with_server(
        session,
        request_body,
        response,
        scheme,
        server,
    );
    for group in &outbound.groups {
        if !group.is_on {
            continue;
        }
        if let Some(result) = match_group_response(group, session, &facts) {
            if let Some(set) = result.set
                && let Some(mut matched) = perform_compiled_actions(set)
            {
                fill_action_from_policy(&mut matched, policy, group.id, set.id);
                crate::firewall::apply_observe_mode(&policy.raw, &mut matched);
                return Some(matched);
            }
            if result.matched {
                let mut action = crate::firewall::default_block_action(policy.id, group.id);
                crate::firewall::apply_observe_mode(&policy.raw, &mut action);
                return Some(action);
            }
        }
    }
    None
}

pub fn compiled_policy_uses_request_body(policy: &CompiledFirewallPolicy) -> bool {
    policy.is_on && policy.mode != "bypass" && policy.uses_request_body
}

pub fn compiled_policy_uses_response_body(policy: &CompiledFirewallPolicy) -> bool {
    policy.is_on && policy.mode != "bypass" && policy.uses_response_body
}

struct MatchResult<'a> {
    matched: bool,
    set: Option<&'a CompiledRuleSet>,
}

fn match_group_from<'a>(
    group: &'a CompiledRuleGroup,
    session: &Session,
    _request_body: &[u8],
    facts: &crate::firewall::matcher_plus::RequestFacts<'_>,
    start_set_id: Option<i64>,
) -> Option<MatchResult<'a>> {
    // Preset matchers live outside the set list; only consult them when
    // iteration starts from the top (consistent with the legacy evaluator).
    if start_set_id.is_none() && group.preset.is_some_and(|preset| preset.matches(facts)) {
        return Some(MatchResult {
            matched: true,
            set: None,
        });
    }

    let start_idx = match start_set_id {
        Some(sid) => group
            .sets
            .iter()
            .position(|s| s.id == sid)
            .unwrap_or(group.sets.len()),
        None => 0,
    };

    if let Some(candidate_indexes) = group
        .request_prefilter
        .candidate_set_indexes(facts, start_idx)
    {
        for set_index in candidate_indexes {
            let Some(set) = group.sets.get(set_index) else {
                continue;
            };
            if match_set(set, session, facts) {
                return Some(MatchResult {
                    matched: true,
                    set: Some(set),
                });
            }
        }
        return None;
    }

    for set in group.sets.iter().skip(start_idx) {
        if match_set(set, session, facts) {
            return Some(MatchResult {
                matched: true,
                set: Some(set),
            });
        }
    }
    None
}

fn match_group_response<'a>(
    group: &'a CompiledRuleGroup,
    session: &Session,
    facts: &crate::firewall::matcher_plus::ResponseFacts<'_, '_, '_>,
) -> Option<MatchResult<'a>> {
    for set in &group.sets {
        if match_set_response(set, session, facts) {
            return Some(MatchResult {
                matched: true,
                set: Some(set),
            });
        }
    }
    None
}

fn match_set(
    set: &CompiledRuleSet,
    _session: &Session,
    facts: &crate::firewall::matcher_plus::RequestFacts<'_>,
) -> bool {
    if !set.is_on || set.rules.is_empty() {
        return false;
    }
    if should_bypass_set(set, facts) {
        return false;
    }
    if let Some(result) = set
        .fast_path
        .evaluate_request(&set.rules, set.connector, facts)
    {
        return result;
    }
    if let Some(prefilter) = &set.regex_prefilter {
        return prefilter.matches_request(&set.rules, facts);
    }
    match set.connector {
        Connector::And => set.rules.iter().all(|rule| rule.matches_request(facts)),
        Connector::Or => set.rules.iter().any(|rule| rule.matches_request(facts)),
    }
}

fn match_set_response(
    set: &CompiledRuleSet,
    _session: &Session,
    facts: &crate::firewall::matcher_plus::ResponseFacts<'_, '_, '_>,
) -> bool {
    if !set.is_on || set.rules.is_empty() {
        return false;
    }
    if should_bypass_set(set, facts.request()) {
        return false;
    }
    match set.connector {
        Connector::And => set.rules.iter().all(|rule| rule.matches_response(facts)),
        Connector::Or => set.rules.iter().any(|rule| rule.matches_response(facts)),
    }
}

fn should_bypass_set(
    set: &CompiledRuleSet,
    facts: &crate::firewall::matcher_plus::RequestFacts<'_>,
) -> bool {
    let ip = facts.remote_ip();
    let user_agent = facts.request_header("user-agent");
    (set.ignore_local && crate::firewall::matcher_plus::is_local_ip(&ip))
        || (set.ignore_search_engine
            && crate::client_agent::is_verified_search_engine_ip(ip, &user_agent))
}

fn fill_action_from_policy(
    matched: &mut MatchedAction,
    policy: &CompiledFirewallPolicy,
    group_id: i64,
    set_id: i64,
) {
    crate::firewall::fill_action_context(
        matched,
        policy.id,
        group_id,
        set_id,
        policy.use_local_firewall,
    );
    crate::firewall::fill_action_options(&policy.raw, matched);
}

#[derive(Clone, Debug)]
pub enum CompiledOperator {
    EqString(String),
    NeqString(String),
    Regex(Arc<Regex>),
    NotRegex(Arc<Regex>),
    Wildcard(Arc<Regex>),
    NotWildcard(Arc<Regex>),
    Contains(String),
    NotContains(String),
    Prefix(String),
    Suffix(String),
    ContainsAny(CompiledMultiContains),
    ContainsAll(CompiledMultiContains),
    ContainsAnyWord(Vec<CompiledWordTerm>),
    ContainsAllWords(Vec<CompiledWordTerm>),
    NotContainsAnyWord(Vec<CompiledWordTerm>),
    Number { op: NumberOp, expected: f64 },
    EqIp(String),
    NeqIp(String),
    InIpList(Vec<IpMatcher>),
    IpRange { items: Vec<IpMatcher>, not: bool },
    CompareIp { op: IpCompareOp, expected: IpAddr },
    ContainsBinary(Vec<u8>),
    NotContainsBinary(Vec<u8>),
    HasKey(HasKey),
    Version { op: VersionOp, expected: String },
    ContainsSqli { strict: bool, expected: String },
    ContainsXss { strict: bool, expected: String },
    ContainsCmd { expected: String },
    CommonBot { expected: String },
    CommonAiBot { expected: String },
    IpMod { divisor: u128, remainder: u128 },
    NeverMatch,
}

impl CompiledOperator {
    pub fn compile(operator: &str, expected_value: &str, case_insensitive: bool) -> Self {
        let operator = normalize_operator(operator);
        let expected = if case_insensitive {
            Cow::Owned(expected_value.to_lowercase())
        } else {
            Cow::Borrowed(expected_value)
        };

        match operator.as_ref() {
            "eq string" => Self::EqString(expected.into_owned()),
            "neq string" => Self::NeqString(expected.into_owned()),
            "match" | "matches" | "regexp" => compile_regex(&expected)
                .map(Self::Regex)
                .unwrap_or(Self::NeverMatch),
            "not match" | "notmatches" | "notregexp" => compile_regex(&expected)
                .map(Self::NotRegex)
                .unwrap_or(Self::NeverMatch),
            "wildcard match" => compile_wildcard(&expected)
                .map(Self::Wildcard)
                .unwrap_or(Self::NeverMatch),
            "wildcard not match" => compile_wildcard(&expected)
                .map(Self::NotWildcard)
                .unwrap_or(Self::NeverMatch),
            "contains" | "containsstring" => Self::Contains(expected.into_owned()),
            "not contains" | "notcontains" => Self::NotContains(expected.into_owned()),
            "prefix" | "hasprefix" => Self::Prefix(expected.into_owned()),
            "suffix" | "hassuffix" => Self::Suffix(expected.into_owned()),
            "contains any" => Self::ContainsAny(CompiledMultiContains::compile_any(&expected)),
            "contains all" => Self::ContainsAll(CompiledMultiContains::compile_all(&expected)),
            "contains any word" => Self::ContainsAnyWord(compile_word_terms(&expected)),
            "contains all words" => Self::ContainsAllWords(compile_word_terms(&expected)),
            "not contains any word" => Self::NotContainsAnyWord(compile_word_terms(&expected)),
            "eq" | "neq" | "gt" | "gte" | "lt" | "lte" => expected
                .parse::<f64>()
                .ok()
                .map(|expected| Self::Number {
                    op: NumberOp::from_operator(&operator),
                    expected,
                })
                .unwrap_or(Self::NeverMatch),
            "eq ip" => Self::EqIp(expected.into_owned()),
            "neq ip" => Self::NeqIp(expected.into_owned()),
            "in ip list" => Self::InIpList(
                expected
                    .lines()
                    .filter_map(|line| compile_ip_matcher(line.trim()))
                    .collect(),
            ),
            "ip range" | "not ip range" => Self::IpRange {
                items: expected
                    .split(',')
                    .filter_map(|part| compile_ip_matcher(part.trim()))
                    .collect(),
                not: operator.as_ref() == "not ip range",
            },
            "gt ip" | "gte ip" | "lt ip" | "lte ip" => expected
                .parse::<IpAddr>()
                .ok()
                .map(|expected| Self::CompareIp {
                    op: IpCompareOp::from_operator(&operator),
                    expected,
                })
                .unwrap_or(Self::NeverMatch),
            "contains sql injection" | "contains sql injection strictly" => Self::ContainsSqli {
                strict: operator.contains("strictly"),
                expected: expected.into_owned(),
            },
            "contains xss" | "contains xss strictly" => Self::ContainsXss {
                strict: operator.contains("strictly"),
                expected: expected.into_owned(),
            },
            "contains binary" => decode_base64(&expected)
                .map(Self::ContainsBinary)
                .unwrap_or(Self::NeverMatch),
            "not contains binary" => decode_base64(&expected)
                .map(Self::NotContainsBinary)
                .unwrap_or(Self::NeverMatch),
            "has key" => Self::HasKey(HasKey::compile(&expected)),
            "version gt" => Self::Version {
                op: VersionOp::Gt,
                expected: expected.into_owned(),
            },
            "version lt" => Self::Version {
                op: VersionOp::Lt,
                expected: expected.into_owned(),
            },
            "version range" => Self::Version {
                op: VersionOp::Range,
                expected: expected.into_owned(),
            },
            "contains cmd injection" | "contains cmd injection strictly" => Self::ContainsCmd {
                expected: expected.into_owned(),
            },
            "is bot" | "common bot" => Self::CommonBot {
                expected: expected.into_owned(),
            },
            "common ai bot" => Self::CommonAiBot {
                expected: expected.into_owned(),
            },
            "ip mod" => compile_ip_mod(&expected, 10),
            "ip mod 10" => compile_fixed_ip_mod(&expected, 10),
            "ip mod 100" => compile_fixed_ip_mod(&expected, 100),
            _ => Self::NeverMatch,
        }
    }

    pub fn evaluate(&self, actual: &str) -> bool {
        match self {
            Self::EqString(expected) => actual == expected,
            Self::NeqString(expected) => actual != expected,
            Self::Regex(re) => re.is_match(actual),
            Self::NotRegex(re) => !re.is_match(actual),
            Self::Wildcard(re) => re.is_match(actual),
            Self::NotWildcard(re) => !re.is_match(actual),
            Self::Contains(expected) => actual.contains(expected),
            Self::NotContains(expected) => !actual.contains(expected),
            Self::Prefix(expected) => actual.starts_with(expected),
            Self::Suffix(expected) => actual.ends_with(expected),
            Self::ContainsAny(expected) => expected.matches_any(actual),
            Self::ContainsAll(expected) => expected.matches_all(actual),
            Self::ContainsAnyWord(expected) => expected.iter().any(|term| term.matches(actual)),
            Self::ContainsAllWords(expected) => expected.iter().all(|term| term.matches(actual)),
            Self::NotContainsAnyWord(expected) => !expected.iter().any(|term| term.matches(actual)),
            Self::Number { op, expected } => actual
                .parse::<f64>()
                .ok()
                .is_some_and(|actual| op.evaluate(actual, *expected)),
            Self::EqIp(expected) => actual == expected,
            Self::NeqIp(expected) => actual != expected,
            Self::InIpList(items) => ip_items_match(items, actual),
            Self::IpRange { items, not } => {
                let matched = ip_items_match(items, actual);
                if *not { !matched } else { matched }
            }
            Self::CompareIp { op, expected } => actual
                .parse::<IpAddr>()
                .ok()
                .is_some_and(|actual| op.evaluate(compare_ip_bytes(actual, *expected))),
            Self::ContainsBinary(needle) => contains_bytes(actual.as_bytes(), needle),
            Self::NotContainsBinary(needle) => !contains_bytes(actual.as_bytes(), needle),
            Self::HasKey(key) => key.evaluate(actual),
            Self::Version { op, expected } => op.evaluate(actual, expected),
            Self::ContainsSqli { strict, .. } => {
                crate::firewall::matcher::contains_sqli(actual, *strict)
            }
            Self::ContainsXss { strict, .. } => {
                crate::firewall::matcher::contains_xss(actual, *strict)
            }
            Self::ContainsCmd { .. } => crate::firewall::matcher::contains_cmd(actual),
            Self::CommonBot { expected } => {
                crate::firewall::matcher::evaluate_operator(actual, "common bot", expected, false)
            }
            Self::CommonAiBot { expected } => crate::firewall::matcher::evaluate_operator(
                actual,
                "common ai bot",
                expected,
                false,
            ),
            Self::IpMod { divisor, remainder } => actual
                .parse::<IpAddr>()
                .ok()
                .map(ip_to_u128)
                .is_some_and(|ip_num| *divisor != 0 && ip_num % *divisor == *remainder),
            Self::NeverMatch => false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum NumberOp {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
}

impl NumberOp {
    fn from_operator(operator: &str) -> Self {
        match operator {
            "neq" => Self::Neq,
            "gt" => Self::Gt,
            "gte" => Self::Gte,
            "lt" => Self::Lt,
            "lte" => Self::Lte,
            _ => Self::Eq,
        }
    }

    fn evaluate(self, actual: f64, expected: f64) -> bool {
        match self {
            Self::Eq => (actual - expected).abs() < f64::EPSILON,
            Self::Neq => (actual - expected).abs() > f64::EPSILON,
            Self::Gt => actual > expected,
            Self::Gte => actual >= expected,
            Self::Lt => actual < expected,
            Self::Lte => actual <= expected,
        }
    }
}

#[derive(Clone, Debug)]
pub enum IpMatcher {
    Exact(String),
    Net(ipnet::IpNet),
}

impl IpMatcher {
    fn matches(&self, actual: &str, parsed: Option<IpAddr>) -> bool {
        match self {
            Self::Exact(expected) => expected == actual,
            Self::Net(net) => parsed.is_some_and(|addr| net.contains(&addr)),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum IpCompareOp {
    Gt,
    Gte,
    Lt,
    Lte,
}

impl IpCompareOp {
    fn from_operator(operator: &str) -> Self {
        match operator {
            "gte ip" => Self::Gte,
            "lt ip" => Self::Lt,
            "lte ip" => Self::Lte,
            _ => Self::Gt,
        }
    }

    fn evaluate(self, ordering: std::cmp::Ordering) -> bool {
        match self {
            Self::Gt => ordering.is_gt(),
            Self::Gte => ordering.is_gt() || ordering.is_eq(),
            Self::Lt => ordering.is_lt(),
            Self::Lte => ordering.is_lt() || ordering.is_eq(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum HasKey {
    Index(usize),
    Name(String),
}

impl HasKey {
    fn compile(expected: &str) -> Self {
        expected
            .parse::<usize>()
            .map(Self::Index)
            .unwrap_or_else(|_| Self::Name(expected.to_string()))
    }

    fn evaluate(&self, actual: &str) -> bool {
        match self {
            Self::Index(index) => actual.lines().nth(*index).is_some(),
            Self::Name(expected) => {
                actual.lines().any(|line| {
                    line.split_once('=')
                        .map(|(key, _)| key.trim() == expected)
                        .unwrap_or(false)
                }) || actual.lines().any(|line| {
                    line.split_once(':')
                        .map(|(key, _)| key.trim() == expected)
                        .unwrap_or(false)
                })
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum VersionOp {
    Gt,
    Lt,
    Range,
}

impl VersionOp {
    fn evaluate(self, actual: &str, expected: &str) -> bool {
        match self {
            Self::Gt => compare_versions(actual, expected).is_some_and(|o| o.is_gt()),
            Self::Lt => compare_versions(actual, expected).is_some_and(|o| o.is_lt()),
            Self::Range => match expected.split_once(',') {
                Some((min, max)) => {
                    let min = min.trim();
                    let max = max.trim();
                    let ge_min = min.is_empty()
                        || compare_versions(actual, min).is_some_and(|o| o.is_gt() || o.is_eq());
                    let le_max = max.is_empty()
                        || compare_versions(actual, max).is_some_and(|o| o.is_lt() || o.is_eq());
                    ge_min && le_max
                }
                None => compare_versions(actual, expected).is_some_and(|o| o.is_gt() || o.is_eq()),
            },
        }
    }
}

fn compile_regex(pattern: &str) -> Option<Arc<Regex>> {
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .ok()
        .map(Arc::new)
}

fn compile_wildcard(pattern: &str) -> Option<Arc<Regex>> {
    let escaped = regex::escape(pattern).replace("\\*", ".*");
    compile_regex(&format!("^{}$", escaped))
}

fn compile_ip_matcher(item: &str) -> Option<IpMatcher> {
    if item.is_empty() {
        return None;
    }
    item.parse::<ipnet::IpNet>()
        .map(IpMatcher::Net)
        .or_else(|_| Ok::<_, std::convert::Infallible>(IpMatcher::Exact(item.to_string())))
        .ok()
}

fn ip_items_match(items: &[IpMatcher], actual: &str) -> bool {
    let parsed = actual.parse::<IpAddr>().ok();
    items.iter().any(|item| item.matches(actual, parsed))
}

fn compile_ip_mod(expected: &str, default_divisor: u128) -> CompiledOperator {
    match expected.split_once(',') {
        Some((divisor, remainder)) => divisor
            .trim()
            .parse::<u128>()
            .ok()
            .zip(remainder.trim().parse::<u128>().ok())
            .map(|(divisor, remainder)| CompiledOperator::IpMod { divisor, remainder })
            .unwrap_or(CompiledOperator::NeverMatch),
        None => expected
            .trim()
            .parse::<u128>()
            .ok()
            .map(|remainder| CompiledOperator::IpMod {
                divisor: default_divisor,
                remainder,
            })
            .unwrap_or(CompiledOperator::NeverMatch),
    }
}

fn compile_fixed_ip_mod(expected: &str, divisor: u128) -> CompiledOperator {
    expected
        .trim()
        .parse::<u128>()
        .ok()
        .map(|remainder| CompiledOperator::IpMod { divisor, remainder })
        .unwrap_or(CompiledOperator::NeverMatch)
}

fn normalize_operator(operator: &str) -> Cow<'_, str> {
    let operator = operator.trim();
    if operator.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(operator.to_ascii_lowercase())
    } else {
        Cow::Borrowed(operator)
    }
}

fn split_terms(expected: &str) -> Vec<String> {
    expected
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[derive(Clone, Debug)]
pub struct CompiledMultiContains {
    patterns: Vec<String>,
    automaton: Option<Arc<AhoCorasick>>,
}

impl CompiledMultiContains {
    fn compile_any(expected: &str) -> Self {
        Self::compile(expected)
    }

    fn compile_all(expected: &str) -> Self {
        Self::compile(expected)
    }

    fn compile(expected: &str) -> Self {
        let patterns: Vec<String> = expected.lines().map(str::to_string).collect();
        let automaton = if patterns.iter().any(|pattern| pattern.is_empty()) {
            None
        } else {
            AhoCorasick::new(&patterns).ok().map(Arc::new)
        };
        Self {
            patterns,
            automaton,
        }
    }

    fn matches_any(&self, actual: &str) -> bool {
        self.automaton
            .as_ref()
            .map(|automaton| automaton.is_match(actual))
            .unwrap_or_else(|| self.patterns.iter().any(|pattern| actual.contains(pattern)))
    }

    fn matches_all(&self, actual: &str) -> bool {
        if self.patterns.is_empty() {
            return true;
        }
        if let Some(automaton) = &self.automaton {
            let mut matched = vec![false; self.patterns.len()];
            let mut count = 0usize;
            for mat in automaton.find_iter(actual) {
                let index = mat.pattern().as_usize();
                if !matched[index] {
                    matched[index] = true;
                    count += 1;
                    if count == self.patterns.len() {
                        return true;
                    }
                }
            }
            false
        } else {
            self.patterns.iter().all(|pattern| actual.contains(pattern))
        }
    }
}

#[derive(Clone, Debug)]
pub struct CompiledWordTerm {
    term: String,
    regex: Option<Arc<Regex>>,
}

impl CompiledWordTerm {
    fn compile(term: String) -> Self {
        let regex = if term
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            let pattern = format!(r"\b{}\b", regex::escape(&term));
            compile_regex(&pattern)
        } else {
            None
        };
        Self { term, regex }
    }

    fn matches(&self, actual: &str) -> bool {
        self.regex
            .as_ref()
            .map(|regex| regex.is_match(actual))
            .unwrap_or_else(|| actual.contains(&self.term))
    }
}

fn compile_word_terms(expected: &str) -> Vec<CompiledWordTerm> {
    split_terms(expected)
        .into_iter()
        .map(CompiledWordTerm::compile)
        .collect()
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .ok()
}

fn contains_bytes(actual: &[u8], needle: &[u8]) -> bool {
    actual.len() >= needle.len() && actual.windows(needle.len()).any(|part| part == needle)
}

fn compare_ip_bytes(left: IpAddr, right: IpAddr) -> std::cmp::Ordering {
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) => left.octets().cmp(&right.octets()),
        (IpAddr::V6(left), IpAddr::V6(right)) => left.octets().cmp(&right.octets()),
        (IpAddr::V4(left), IpAddr::V6(right)) => {
            left.octets().as_slice().cmp(right.octets().as_slice())
        }
        (IpAddr::V6(left), IpAddr::V4(right)) => {
            left.octets().as_slice().cmp(right.octets().as_slice())
        }
    }
}

fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()) as u128,
        IpAddr::V6(v6) => u128::from_be_bytes(v6.octets()),
    }
}

fn compare_versions(actual: &str, expected: &str) -> Option<std::cmp::Ordering> {
    let left = parse_version(actual)?;
    let right = parse_version(expected)?;
    Some(left.cmp(&right))
}

fn parse_version(input: &str) -> Option<Vec<u64>> {
    let mut parts = Vec::new();
    for piece in input.split(['.', '-', '_']) {
        if piece.is_empty() {
            continue;
        }
        let digits: String = piece.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            break;
        }
        parts.push(digits.parse().ok()?);
    }
    if parts.is_empty() { None } else { Some(parts) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_parity(actual: &str, operator: &str, expected: &str, case_insensitive: bool) {
        let compiled = CompiledOperator::compile(operator, expected, case_insensitive);
        let actual_for_compiled = if case_insensitive {
            Cow::Owned(actual.to_lowercase())
        } else {
            Cow::Borrowed(actual)
        };
        assert_eq!(
            compiled.evaluate(&actual_for_compiled),
            crate::firewall::matcher::evaluate_operator(
                actual,
                operator,
                expected,
                case_insensitive
            ),
            "operator={operator:?} actual={actual:?} expected={expected:?} case_insensitive={case_insensitive}"
        );
    }

    #[test]
    fn compiled_operator_matches_legacy_string_and_regex() {
        for (actual, operator, expected, ci) in [
            ("Hello", "eq string", "hello", true),
            ("Hello", "neq string", "world", false),
            ("abc123", "regexp", "^[a-z]+\\d+$", false),
            ("abc123", "notregexp", "^z", false),
            ("/assets/app.js", "wildcard match", "/assets/*.js", false),
            (
                "/assets/app.css",
                "wildcard not match",
                "/assets/*.js",
                false,
            ),
            ("abcdef", "contains", "cd", false),
            ("abcdef", "not contains", "zz", false),
            ("abcdef", "contains any", "zz\ncd", false),
            ("abcdef", "contains all", "abc\ndef", false),
            ("abcdef", "contains all", "abc\nzz", false),
            ("abcdef", "contains any", "\nzz", false),
            ("abcdef", "contains all", "\nabc", false),
            ("abcdef", "contains all", "", false),
            ("abcdef", "prefix", "abc", false),
            ("abcdef", "suffix", "def", false),
            ("alpha beta", "contains any word", "gamma\nbeta", false),
            ("alpha beta", "contains all words", "alpha\nbeta", false),
            ("alpha beta", "not contains any word", "gamma\ndelta", false),
        ] {
            assert_parity(actual, operator, expected, ci);
        }
    }

    #[test]
    fn compiled_operator_matches_legacy_numeric_ip_binary_and_version() {
        for (actual, operator, expected) in [
            ("10", "eq", "10"),
            ("11", "gt", "10"),
            ("10", "gte", "10"),
            ("9", "lt", "10"),
            ("10", "lte", "10"),
            ("192.168.1.10", "eq ip", "192.168.1.10"),
            ("192.168.1.10", "neq ip", "192.168.1.11"),
            ("192.168.1.10", "in ip list", "10.0.0.0/8\n192.168.1.0/24"),
            ("192.168.1.10", "ip range", "10.0.0.0/8,192.168.1.0/24"),
            ("192.168.1.10", "not ip range", "10.0.0.0/8"),
            ("192.168.1.10", "gt ip", "192.168.1.1"),
            ("192.168.1.10", "lte ip", "192.168.1.10"),
            ("abcdef", "contains binary", "YmNk"),
            ("abcdef", "not contains binary", "eHl6"),
            ("1.2.3", "version gt", "1.2.2"),
            ("1.2.3", "version lt", "1.2.4"),
            ("1.2.3", "version range", "1.2.0,1.3.0"),
            ("192.168.1.11", "ip mod", "10,3"),
            ("192.168.1.11", "ip mod 10", "3"),
        ] {
            assert_parity(actual, operator, expected, false);
        }
    }

    #[test]
    fn compiled_operator_matches_legacy_invalid_config() {
        for (actual, operator, expected) in [
            ("abc", "regexp", "["),
            ("abc", "notregexp", "["),
            ("abc", "eq", "NaN?"),
            ("abc", "contains binary", "not-base64***"),
            ("abc", "not contains binary", "not-base64***"),
            ("192.168.1.10", "gt ip", "not-ip"),
            ("192.168.1.10", "ip mod", "0,1"),
        ] {
            assert_parity(actual, operator, expected, false);
        }
        assert_parity("192.168.1.10", "not ip range", "bad-cidr", false);
    }

    #[test]
    fn compiled_firewall_rule_applies_reverse_after_operator() {
        let rule = HTTPFirewallRule {
            param: "${requestURI}".to_string(),
            operator: "contains".to_string(),
            value: "admin".to_string(),
            checkpoint_options: None,
            is_reverse: true,
            is_case_insensitive: false,
            param_filters: vec![],
        };
        let compiled = CompiledFirewallRule::compile(&rule);
        assert!(!compiled.matches_value("/admin"));
        assert!(compiled.matches_value("/public"));
    }

    #[test]
    fn compiled_preset_groups_require_request_body() {
        for code in [
            "sqlInjection",
            "sqlInjectionStrict",
            "xss",
            "xssStrict",
            "cmdInjection",
        ] {
            let group = CompiledRuleGroup::compile(&HTTPFirewallRuleGroup {
                id: 1,
                is_on: true,
                name: String::new(),
                code: Some(code.to_string()),
                sets: vec![],
            });
            assert!(
                group.uses_request_body(),
                "preset {code} should read request body"
            );
        }
    }

    use crate::config_models::HTTPFirewallInboundConfig;
    use serde_json::json;

    fn assert_action_response_eq(expected: &ActionResponse, actual: &ActionResponse) {
        match (expected, actual) {
            (ActionResponse::Allow, ActionResponse::Allow) => {}
            (
                ActionResponse::Block {
                    status: expected_status,
                    body: expected_body,
                },
                ActionResponse::Block {
                    status: actual_status,
                    body: actual_body,
                },
            ) => {
                assert_eq!(expected_status, actual_status);
                assert_eq!(expected_body, actual_body);
            }
            (
                ActionResponse::Page {
                    status: expected_status,
                    body: expected_body,
                    content_type: expected_content_type,
                },
                ActionResponse::Page {
                    status: actual_status,
                    body: actual_body,
                    content_type: actual_content_type,
                },
            ) => {
                assert_eq!(expected_status, actual_status);
                assert_eq!(expected_body, actual_body);
                assert_eq!(expected_content_type, actual_content_type);
            }
            (
                ActionResponse::Captcha {
                    life_seconds: expected_life,
                },
                ActionResponse::Captcha {
                    life_seconds: actual_life,
                },
            ) => assert_eq!(expected_life, actual_life),
            (
                ActionResponse::JsCookie {
                    life_seconds: expected_life,
                },
                ActionResponse::JsCookie {
                    life_seconds: actual_life,
                },
            ) => assert_eq!(expected_life, actual_life),
            (
                ActionResponse::Redirect {
                    status: expected_status,
                    location: expected_location,
                },
                ActionResponse::Redirect {
                    status: actual_status,
                    location: actual_location,
                },
            ) => {
                assert_eq!(expected_status, actual_status);
                assert_eq!(expected_location, actual_location);
            }
            (
                ActionResponse::Get302 {
                    life_seconds: expected_life,
                },
                ActionResponse::Get302 {
                    life_seconds: actual_life,
                },
            ) => assert_eq!(expected_life, actual_life),
            (
                ActionResponse::Post307 {
                    life_seconds: expected_life,
                },
                ActionResponse::Post307 {
                    life_seconds: actual_life,
                },
            ) => assert_eq!(expected_life, actual_life),
            _ => panic!("action response mismatch"),
        }
    }

    fn assert_matched_action_eq(expected: &MatchedAction, actual: &MatchedAction) {
        assert_action_response_eq(&expected.action, &actual.action);
        assert_eq!(expected.policy_id, actual.policy_id);
        assert_eq!(expected.group_id, actual.group_id);
        assert_eq!(expected.set_id, actual.set_id);
        assert_eq!(expected.action_code, actual.action_code);
        assert_eq!(expected.timeout_secs, actual.timeout_secs);
        assert_eq!(expected.max_timeout_secs, actual.max_timeout_secs);
        assert_eq!(expected.life_seconds, actual.life_seconds);
        assert_eq!(expected.max_fails, actual.max_fails);
        assert_eq!(expected.fail_block_timeout, actual.fail_block_timeout);
        assert_eq!(expected.fail_global, actual.fail_global);
        assert_eq!(expected.scope, actual.scope);
        assert_eq!(expected.block_c_class, actual.block_c_class);
        assert_eq!(expected.use_local_firewall, actual.use_local_firewall);
        assert_eq!(expected.next_group_id, actual.next_group_id);
        assert_eq!(expected.next_set_id, actual.next_set_id);
        assert_eq!(expected.allow_scope, actual.allow_scope);
        assert_eq!(expected.tags, actual.tags);
        assert_eq!(expected.ip_list_id, actual.ip_list_id);
        assert_eq!(expected.event_level, actual.event_level);
        assert_eq!(
            expected
                .captcha_options
                .as_ref()
                .map(|opts| opts.method.as_str()),
            actual
                .captcha_options
                .as_ref()
                .map(|opts| opts.method.as_str())
        );
    }

    fn assert_action_option_eq(expected: Option<MatchedAction>, actual: Option<MatchedAction>) {
        match (expected, actual) {
            (Some(expected), Some(actual)) => assert_matched_action_eq(&expected, &actual),
            (None, None) => {}
            (expected, actual) => panic!(
                "action option mismatch: expected_some={} actual_some={}",
                expected.is_some(),
                actual.is_some()
            ),
        }
    }

    fn compiled_action(action: &Value) -> MatchedAction {
        CompiledAction::compile(action).unwrap().to_matched()
    }

    fn legacy_action(action: &Value) -> MatchedAction {
        crate::firewall::perform_actions(std::slice::from_ref(action)).unwrap()
    }

    fn assert_action_compile_parity(action: &Value) {
        assert_matched_action_eq(&legacy_action(action), &compiled_action(action));
    }

    fn test_rule(param: &str) -> HTTPFirewallRule {
        HTTPFirewallRule {
            param: param.to_string(),
            operator: "contains".to_string(),
            value: "needle".to_string(),
            checkpoint_options: None,
            is_reverse: false,
            is_case_insensitive: false,
            param_filters: vec![],
        }
    }

    fn test_set(id: i64, rules: Vec<HTTPFirewallRule>) -> HTTPFirewallRuleSet {
        HTTPFirewallRuleSet {
            id,
            is_on: true,
            name: String::new(),
            rules,
            connector: "or".to_string(),
            actions: vec![],
            ignore_local: false,
            ignore_search_engine: false,
        }
    }

    fn test_group(code: Option<&str>, sets: Vec<HTTPFirewallRuleSet>) -> HTTPFirewallRuleGroup {
        HTTPFirewallRuleGroup {
            id: 10,
            is_on: true,
            name: String::new(),
            code: code.map(str::to_string),
            sets,
        }
    }

    fn test_policy(inbound: HTTPFirewallInboundConfig) -> HTTPFirewallPolicy {
        HTTPFirewallPolicy {
            id: 42,
            is_on: true,
            name: String::new(),
            inbound: Some(inbound),
            outbound: None,
            empty_connection_flood: None,
            tls_exhaustion_attack: None,
            cc_config: None,
            block_options: None,
            page_options: None,
            captcha_options: None,
            js_cookie_options: None,
            max_request_body_size: 0,
            deny_country_html: String::new(),
            deny_province_html: String::new(),
            use_local_firewall: false,
            syn_flood: None,
            mode: "defense".to_string(),
            candidate_rules: None,
            candidate_traffic_pct: 0,
            candidate_version: 0,
        }
    }

    fn inbound_with_groups(groups: Vec<HTTPFirewallRuleGroup>) -> HTTPFirewallInboundConfig {
        HTTPFirewallInboundConfig {
            is_on: true,
            groups,
            region: None,
        }
    }

    fn policy_with_rule_param(param: &str) -> HTTPFirewallPolicy {
        test_policy(inbound_with_groups(vec![test_group(
            None,
            vec![test_set(20, vec![test_rule(param)])],
        )]))
    }

    #[test]
    fn compiled_action_metadata_matches_legacy_for_scope_and_flow_actions() {
        for scope in ["group", "server", "policy"] {
            assert_action_compile_parity(&json!({"code":"allow","options":{"scope":scope}}));
        }

        assert_action_compile_parity(&json!({"code":"go_group","options":{"groupId":123}}));
        assert_action_compile_parity(
            &json!({"code":"go_set","options":{"groupId":123,"ruleSetId":456}}),
        );
        assert_action_compile_parity(&json!({
            "code":"page",
            "options":{
                "status":451,
                "body":"blocked"
            }
        }));
        assert_action_compile_parity(&json!({
            "code":"page",
            "options":{
                "status":403,
                "body":"default page"
            }
        }));
        assert_action_compile_parity(&json!({
            "code":"block",
            "options":{
                "timeout":77,
                "scope":"global",
                "ipListId":8,
                "eventLevel":"warning"
            }
        }));
        assert_action_compile_parity(&json!({
            "code":"record_ip",
            "options":{
                "type":"black",
                "timeout":77,
                "scope":"global",
                "ipListId":8,
                "eventLevel":"warning"
            }
        }));
        assert_action_compile_parity(&json!({
            "code":"record_ip",
            "options":{
                "type":"black",
                "eventLevel":"严重"
            }
        }));
        assert_eq!(
            compiled_action(&json!({
                "code":"record_ip",
                "options":{
                    "type":"white",
                    "eventLevel":{"value":"通知"}
                }
            }))
            .event_level,
            "notice"
        );
        assert_eq!(
            compiled_action(&json!({
                "code":"record_ip",
                "options":{"type":"black","scope":"global"}
            }))
            .scope
            .as_deref(),
            Some("global")
        );
    }

    #[test]
    fn compiled_action_metadata_matches_legacy_for_challenge_fail_block_actions() {
        for code in ["captcha", "jsCookie", "get_302", "post_307"] {
            assert_action_compile_parity(&json!({
                "code":code,
                "options":{
                    "life":120,
                    "captchaType":"click",
                    "maxFails":3,
                    "failBlockTimeout":600,
                    "failBlockScopeAll":true
                }
            }));
        }
    }

    #[test]
    fn action_captcha_options_do_not_blank_policy_defaults() {
        let action = json!({
            "code":"captcha",
            "options":{"captchaType":"click"}
        });
        let mut policy = test_policy(inbound_with_groups(vec![]));
        policy.captcha_options = Some(WAFCaptchaOptions {
            method: "slider".to_string(),
            life_seconds: 120,
            max_fails: 3,
            fail_block_timeout: 600,
            fail_global: true,
            challenge_lang: "zh-CN".to_string(),
            challenge_difficulty: 6,
            ..Default::default()
        });

        let mut legacy = legacy_action(&action);
        crate::firewall::fill_action_options(&policy, &mut legacy);
        assert_eq!(
            legacy
                .captcha_options
                .as_ref()
                .map(|opts| opts.method.as_str()),
            Some("click")
        );
        assert_eq!(
            legacy
                .captcha_options
                .as_ref()
                .map(|opts| opts.life_seconds),
            Some(120)
        );
        assert_eq!(
            legacy.captcha_options.as_ref().map(|opts| opts.max_fails),
            Some(3)
        );
        assert_eq!(
            legacy
                .captcha_options
                .as_ref()
                .map(|opts| opts.fail_block_timeout),
            Some(600)
        );
        assert_eq!(
            legacy.captcha_options.as_ref().map(|opts| opts.fail_global),
            Some(true)
        );
        assert_eq!(
            legacy.captcha_options.as_ref().map(|opts| opts.use_geetest),
            Some(false)
        );
        assert_eq!(
            legacy
                .captcha_options
                .as_ref()
                .map(|opts| opts.challenge_lang.as_str()),
            Some("zh-CN")
        );
        assert_eq!(
            legacy
                .captcha_options
                .as_ref()
                .map(|opts| opts.challenge_difficulty),
            Some(6)
        );

        let compiled = CompiledFirewallPolicy::compile(&policy);
        let mut compiled_action = compiled_action(&action);
        super::fill_action_from_policy(&mut compiled_action, &compiled, 10, 20);
        assert_eq!(
            compiled_action
                .captcha_options
                .as_ref()
                .map(|opts| opts.method.as_str()),
            Some("click")
        );
        assert_eq!(
            compiled_action
                .captcha_options
                .as_ref()
                .map(|opts| opts.life_seconds),
            Some(120)
        );
        assert_eq!(
            compiled_action
                .captcha_options
                .as_ref()
                .map(|opts| opts.max_fails),
            Some(3)
        );
        assert_eq!(
            compiled_action
                .captcha_options
                .as_ref()
                .map(|opts| opts.fail_block_timeout),
            Some(600)
        );
        assert_eq!(
            compiled_action
                .captcha_options
                .as_ref()
                .map(|opts| opts.fail_global),
            Some(true)
        );
        assert_eq!(
            compiled_action
                .captcha_options
                .as_ref()
                .map(|opts| opts.use_geetest),
            Some(false)
        );
        assert_eq!(
            compiled_action
                .captcha_options
                .as_ref()
                .map(|opts| opts.challenge_lang.as_str()),
            Some("zh-CN")
        );
        assert_eq!(
            compiled_action
                .captcha_options
                .as_ref()
                .map(|opts| opts.challenge_difficulty),
            Some(6)
        );
    }

    #[test]
    fn explicit_action_captcha_method_does_not_inherit_policy_geetest() {
        let action = json!({
            "code":"captcha",
            "options":{"captchaType":"click"}
        });
        let mut policy = test_policy(inbound_with_groups(vec![]));
        policy.captcha_options = Some(WAFCaptchaOptions {
            method: "slider".to_string(),
            use_geetest: true,
            ..Default::default()
        });

        let mut legacy = legacy_action(&action);
        crate::firewall::fill_action_options(&policy, &mut legacy);
        assert_eq!(
            legacy
                .captcha_options
                .as_ref()
                .map(|opts| opts.method.as_str()),
            Some("click")
        );
        assert_eq!(
            legacy.captcha_options.as_ref().map(|opts| opts.use_geetest),
            Some(false)
        );

        let compiled = CompiledFirewallPolicy::compile(&policy);
        let mut compiled_action = compiled_action(&action);
        super::fill_action_from_policy(&mut compiled_action, &compiled, 10, 20);
        assert_eq!(
            compiled_action
                .captcha_options
                .as_ref()
                .map(|opts| opts.method.as_str()),
            Some("click")
        );
        assert_eq!(
            compiled_action
                .captcha_options
                .as_ref()
                .map(|opts| opts.use_geetest),
            Some(false)
        );
    }

    #[test]
    fn default_action_captcha_method_inherits_policy_geetest() {
        let action = json!({
            "code":"captcha",
            "options":{"captchaType":"default"}
        });
        let mut policy = test_policy(inbound_with_groups(vec![]));
        policy.captcha_options = Some(WAFCaptchaOptions {
            method: "slider".to_string(),
            use_geetest: true,
            ..Default::default()
        });

        let mut legacy = legacy_action(&action);
        crate::firewall::fill_action_options(&policy, &mut legacy);
        assert_eq!(
            legacy
                .captcha_options
                .as_ref()
                .map(|opts| opts.method.as_str()),
            Some("geetest")
        );
        assert_eq!(
            legacy.captcha_options.as_ref().map(|opts| opts.use_geetest),
            Some(true)
        );

        let compiled = CompiledFirewallPolicy::compile(&policy);
        let mut compiled_action = compiled_action(&action);
        super::fill_action_from_policy(&mut compiled_action, &compiled, 10, 20);
        assert_eq!(
            compiled_action
                .captcha_options
                .as_ref()
                .map(|opts| opts.method.as_str()),
            Some("geetest")
        );
        assert_eq!(
            compiled_action
                .captcha_options
                .as_ref()
                .map(|opts| opts.use_geetest),
            Some(true)
        );
    }

    #[test]
    fn real_control_plane_captcha_fields_select_site_method() {
        let action = json!({
            "code":"captcha",
            "options":{
                "captchaType":"click",
                "life":600,
                "maxFails":100,
                "failBlockTimeout":3600,
                "failBlockScopeAll":true,
                "countLetters":6,
                "geeTestConfig":{
                    "isOn":false,
                    "captchaId":"",
                    "captchaKey":""
                },
                "lang":""
            }
        });
        let mut policy = test_policy(inbound_with_groups(vec![]));
        policy.captcha_options = Some(WAFCaptchaOptions {
            method: "geetest".to_string(),
            use_geetest: true,
            ..Default::default()
        });

        let mut legacy = legacy_action(&action);
        crate::firewall::fill_action_options(&policy, &mut legacy);
        let opts = legacy.captcha_options.as_ref().unwrap();
        assert_eq!(opts.method, "click");
        assert!(!opts.use_geetest);
        assert_eq!(opts.life_seconds, 600);
        assert_eq!(opts.max_fails, 100);
        assert_eq!(opts.fail_block_timeout, 3600);
        assert!(opts.fail_global);
        assert_eq!(opts.count, 6);

        let compiled = CompiledFirewallPolicy::compile(&policy);
        let mut compiled_action = compiled_action(&action);
        super::fill_action_from_policy(&mut compiled_action, &compiled, 10, 20);
        let opts = compiled_action.captcha_options.as_ref().unwrap();
        assert_eq!(opts.method, "click");
        assert!(!opts.use_geetest);
        assert_eq!(opts.life_seconds, 600);
        assert_eq!(opts.max_fails, 100);
        assert_eq!(opts.fail_block_timeout, 3600);
        assert!(opts.fail_global);
        assert_eq!(opts.count, 6);
    }

    #[test]
    fn real_control_plane_geetest_fields_enable_geetest() {
        let action = json!({
            "code":"captcha",
            "options":{}
        });
        let mut policy = test_policy(inbound_with_groups(vec![]));
        policy.captcha_options = serde_json::from_value(json!({
            "captchaType":"geetest",
            "life":300,
            "geeTestConfig":{
                "isOn":true,
                "captchaId":"gid",
                "captchaKey":"gkey"
            }
        }))
        .ok();
        if let Some(options) = policy.captcha_options.as_mut() {
            crate::firewall::normalize_captcha_options(options);
        }

        let mut legacy = legacy_action(&action);
        crate::firewall::fill_action_options(&policy, &mut legacy);
        let opts = legacy.captcha_options.as_ref().unwrap();
        assert_eq!(opts.method, "geetest");
        assert!(opts.use_geetest);
        assert_eq!(opts.geetest_id, "gid");
        assert_eq!(opts.geetest_key, "gkey");
        assert_eq!(opts.life_seconds, 300);
    }

    #[test]
    fn empty_action_captcha_options_inherit_policy_geetest() {
        let action = json!({
            "code":"captcha",
            "options":{}
        });
        let mut policy = test_policy(inbound_with_groups(vec![]));
        policy.captcha_options = Some(WAFCaptchaOptions {
            method: "slider".to_string(),
            use_geetest: true,
            ..Default::default()
        });

        let mut legacy = legacy_action(&action);
        crate::firewall::fill_action_options(&policy, &mut legacy);
        assert_eq!(
            legacy
                .captcha_options
                .as_ref()
                .map(|opts| opts.method.as_str()),
            Some("geetest")
        );

        let compiled = CompiledFirewallPolicy::compile(&policy);
        let mut compiled_action = compiled_action(&action);
        super::fill_action_from_policy(&mut compiled_action, &compiled, 10, 20);
        assert_eq!(
            compiled_action
                .captcha_options
                .as_ref()
                .map(|opts| opts.method.as_str()),
            Some("geetest")
        );
    }

    #[test]
    fn action_js_cookie_options_do_not_blank_policy_defaults() {
        let action = json!({
            "code":"jsCookie",
            "options":{}
        });
        let mut policy = test_policy(inbound_with_groups(vec![]));
        policy.js_cookie_options = Some(WAFJSCookieOptions {
            life_seconds: 180,
            max_fails: 4,
            fail_block_timeout: 900,
            fail_global: true,
        });

        let mut legacy = legacy_action(&action);
        crate::firewall::fill_action_options(&policy, &mut legacy);
        assert_eq!(
            legacy
                .js_cookie_options
                .as_ref()
                .map(|opts| opts.life_seconds),
            Some(180)
        );
        assert_eq!(
            legacy.js_cookie_options.as_ref().map(|opts| opts.max_fails),
            Some(4)
        );
        assert_eq!(
            legacy
                .js_cookie_options
                .as_ref()
                .map(|opts| opts.fail_block_timeout),
            Some(900)
        );
        assert_eq!(
            legacy
                .js_cookie_options
                .as_ref()
                .map(|opts| opts.fail_global),
            Some(true)
        );

        let compiled = CompiledFirewallPolicy::compile(&policy);
        let mut compiled_action = compiled_action(&action);
        super::fill_action_from_policy(&mut compiled_action, &compiled, 10, 20);
        assert_eq!(
            compiled_action
                .js_cookie_options
                .as_ref()
                .map(|opts| opts.life_seconds),
            Some(180)
        );
        assert_eq!(
            compiled_action
                .js_cookie_options
                .as_ref()
                .map(|opts| opts.max_fails),
            Some(4)
        );
        assert_eq!(
            compiled_action
                .js_cookie_options
                .as_ref()
                .map(|opts| opts.fail_block_timeout),
            Some(900)
        );
        assert_eq!(
            compiled_action
                .js_cookie_options
                .as_ref()
                .map(|opts| opts.fail_global),
            Some(true)
        );
    }

    #[test]
    fn compiled_and_legacy_request_body_dependency_detection_match() {
        for param in [
            "${requestBody}",
            "${requestAll}",
            "${requestForm.token}",
            "${form.token}",
            "${requestJSON.user.id}",
            "${json.user.id}",
            "${requestUpload.file}",
        ] {
            let policy = policy_with_rule_param(param);
            let compiled = CompiledFirewallPolicy::compile(&policy);
            assert!(
                crate::firewall::inbound_policy_uses_request_body(&policy),
                "legacy missed {param}"
            );
            assert!(
                compiled_policy_uses_request_body(&compiled),
                "compiled missed {param}"
            );
        }

        let policy = policy_with_rule_param("${requestURI}");
        let compiled = CompiledFirewallPolicy::compile(&policy);
        assert!(!crate::firewall::inbound_policy_uses_request_body(&policy));
        assert!(!compiled_policy_uses_request_body(&compiled));

        let mut rule = test_rule("${requestURI}");
        rule.checkpoint_options = Some(json!({
            "keys":["${requestJSON.user.id}", "${requestUpload.file}"],
            "nested":{"form":"${form.token}"}
        }));
        let policy = test_policy(inbound_with_groups(vec![test_group(
            None,
            vec![test_set(21, vec![rule])],
        )]));
        let compiled = CompiledFirewallPolicy::compile(&policy);
        assert!(crate::firewall::inbound_policy_uses_request_body(&policy));
        assert!(compiled_policy_uses_request_body(&compiled));

        let policy = test_policy(inbound_with_groups(vec![test_group(
            Some("sqlInjection"),
            vec![],
        )]));
        let compiled = CompiledFirewallPolicy::compile(&policy);
        assert!(crate::firewall::inbound_policy_uses_request_body(&policy));
        assert!(compiled_policy_uses_request_body(&compiled));
    }

    #[test]
    fn compiled_operator_matches_legacy_p0_regex_wildcard_and_cidr_aliases() {
        for (actual, operator, expected) in [
            ("ABCDEF", "contains any", "zz\ncd"),
            ("ABCDEF", "contains all", "abc\ndef"),
            ("ABCDEF", "contains all", "abc\nzz"),
            ("abc123", "match", "^[a-z]+\\d+$"),
            ("abc123", "matches", "^[a-z]+\\d+$"),
            ("abc123", "not match", "^z"),
            ("abc123", "notmatches", "^z"),
            ("/assets/app.js", "wildcard match", "/assets/*.js"),
            ("/assets/app.css", "wildcard not match", "/assets/*.js"),
            ("2001:db8::1", "in ip list", "2001:db8::/32"),
            ("2001:db8::1", "ip range", "2001:db8::/32"),
            ("2001:db8::1", "not ip range", "2001:db9::/32"),
        ] {
            assert_parity(actual, operator, expected, false);
        }
    }

    fn custom_rule(param: &str, operator: &str, value: &str) -> HTTPFirewallRule {
        HTTPFirewallRule {
            param: param.to_string(),
            operator: operator.to_string(),
            value: value.to_string(),
            checkpoint_options: None,
            is_reverse: false,
            is_case_insensitive: false,
            param_filters: vec![],
        }
    }

    #[derive(Default)]
    struct TestFacts<'a> {
        host: &'a str,
        path: &'a str,
        uri: &'a str,
        method: &'a str,
        ip: &'a str,
        header_name: &'a str,
        header_value: &'a str,
    }

    impl RequestPrefilterFacts for TestFacts<'_> {
        fn host(&self) -> String {
            self.host.to_string()
        }

        fn request_path(&self) -> String {
            self.path.to_string()
        }

        fn request_uri(&self) -> String {
            if self.uri.is_empty() {
                self.path.to_string()
            } else {
                self.uri.to_string()
            }
        }

        fn request_method(&self) -> String {
            if self.method.is_empty() {
                "GET".to_string()
            } else {
                self.method.to_string()
            }
        }

        fn remote_addr(&self) -> String {
            self.ip.to_string()
        }

        fn request_header(&self, name: &str) -> String {
            if self.header_name.eq_ignore_ascii_case(name) {
                self.header_value.to_string()
            } else {
                String::new()
            }
        }
    }

    fn assert_fast_rule_parity(rule: HTTPFirewallRule, actual: &str) {
        let compiled = CompiledFirewallRule::compile(&rule);
        let fast =
            CompiledFastCondition::compile(&compiled).expect("rule should be fast-indexable");
        let fast_matched = match fast {
            CompiledFastCondition::HostEq(expected)
            | CompiledFastCondition::UriEq(expected)
            | CompiledFastCondition::PathEq(expected)
            | CompiledFastCondition::MethodEq(expected)
            | CompiledFastCondition::SrcIpEq(expected) => actual == expected,
            CompiledFastCondition::HostPrefix(expected)
            | CompiledFastCondition::UriPrefix(expected)
            | CompiledFastCondition::PathPrefix(expected)
            | CompiledFastCondition::MethodPrefix(expected) => actual.starts_with(&expected),
            CompiledFastCondition::HostSuffix(expected)
            | CompiledFastCondition::UriSuffix(expected)
            | CompiledFastCondition::PathSuffix(expected)
            | CompiledFastCondition::MethodSuffix(expected) => actual.ends_with(&expected),
            CompiledFastCondition::HostContains(expected)
            | CompiledFastCondition::UriContains(expected)
            | CompiledFastCondition::PathContains(expected)
            | CompiledFastCondition::MethodContains(expected) => actual.contains(&expected),
            CompiledFastCondition::HeaderEq { name: _, value } => actual == value,
            CompiledFastCondition::HeaderPrefix { name: _, value } => actual.starts_with(&value),
            CompiledFastCondition::HeaderSuffix { name: _, value } => actual.ends_with(&value),
            CompiledFastCondition::HeaderContains { name: _, value } => actual.contains(&value),
            CompiledFastCondition::SrcIpRange { items, not } => {
                let matched = ip_items_match(&items, actual);
                if not { !matched } else { matched }
            }
        };
        assert_eq!(fast_matched, compiled.matches_value(actual));
    }

    #[test]
    fn compiled_variable_types_dynamic_request_and_response_variables() {
        match CompiledVariable::compile("arg.token") {
            CompiledVariable::QueryParam(name) => assert_eq!(name, "token"),
            other => panic!("unexpected variable: {other:?}"),
        }
        match CompiledVariable::compile("arg:token") {
            CompiledVariable::QueryParam(name) => assert_eq!(name, "token"),
            other => panic!("unexpected variable: {other:?}"),
        }
        match CompiledVariable::compile("requestArg.token") {
            CompiledVariable::QueryParam(name) => assert_eq!(name, "token"),
            other => panic!("unexpected variable: {other:?}"),
        }
        match CompiledVariable::compile("header.User-Agent") {
            CompiledVariable::HeaderParam(name) => assert_eq!(name, "User-Agent"),
            other => panic!("unexpected variable: {other:?}"),
        }
        match CompiledVariable::compile("header:User-Agent") {
            CompiledVariable::HeaderParam(name) => assert_eq!(name, "User-Agent"),
            other => panic!("unexpected variable: {other:?}"),
        }
        match CompiledVariable::compile("requestHeader.User-Agent") {
            CompiledVariable::HeaderParam(name) => assert_eq!(name, "User-Agent"),
            other => panic!("unexpected variable: {other:?}"),
        }
        match CompiledVariable::compile("cookie.sid") {
            CompiledVariable::CookieParam(name) => assert_eq!(name, "sid"),
            other => panic!("unexpected variable: {other:?}"),
        }
        match CompiledVariable::compile("requestCookie.sid") {
            CompiledVariable::CookieParam(name) => assert_eq!(name, "sid"),
            other => panic!("unexpected variable: {other:?}"),
        }
        match CompiledVariable::compile("requestForm.token") {
            CompiledVariable::FormParam(name) => assert_eq!(name, "token"),
            other => panic!("unexpected variable: {other:?}"),
        }
        match CompiledVariable::compile("form.token") {
            CompiledVariable::FormParam(name) => assert_eq!(name, "token"),
            other => panic!("unexpected variable: {other:?}"),
        }
        match CompiledVariable::compile("requestJSON.user.id") {
            CompiledVariable::JsonParam(path) => assert_eq!(path, "user.id"),
            other => panic!("unexpected variable: {other:?}"),
        }
        match CompiledVariable::compile("json.user.id") {
            CompiledVariable::JsonParam(path) => assert_eq!(path, "user.id"),
            other => panic!("unexpected variable: {other:?}"),
        }
        match CompiledVariable::compile("requestUpload.file") {
            CompiledVariable::UploadParam(name) => assert_eq!(name, "file"),
            other => panic!("unexpected variable: {other:?}"),
        }
        match CompiledVariable::compile("responseHeader.Content-Type") {
            CompiledVariable::ResponseHeaderParam(name) => assert_eq!(name, "Content-Type"),
            other => panic!("unexpected variable: {other:?}"),
        }
        match CompiledVariable::compile("responseHeader:Content-Type") {
            CompiledVariable::ResponseHeaderParam(name) => assert_eq!(name, "Content-Type"),
            other => panic!("unexpected variable: {other:?}"),
        }
        std::assert_matches!(
            CompiledVariable::compile("remoteUser"),
            CompiledVariable::RemoteUser
        );
        std::assert_matches!(
            CompiledVariable::compile("requestFileExtension"),
            CompiledVariable::RequestFileExtension
        );
        std::assert_matches!(
            CompiledVariable::compile("refererOrigin"),
            CompiledVariable::RefererOrigin
        );
        std::assert_matches!(
            CompiledVariable::compile("commonAIBot"),
            CompiledVariable::CommonAiBot
        );
        std::assert_matches!(
            CompiledVariable::compile("commonBot"),
            CompiledVariable::CommonBot
        );
        std::assert_matches!(
            CompiledVariable::compile("geoCountryName"),
            CompiledVariable::GeoCountryName
        );
        std::assert_matches!(
            CompiledVariable::compile("geoProvinceName"),
            CompiledVariable::GeoProvinceName
        );
        std::assert_matches!(
            CompiledVariable::compile("geoCityName"),
            CompiledVariable::GeoCityName
        );
        std::assert_matches!(
            CompiledVariable::compile("geoAsn"),
            CompiledVariable::GeoAsn
        );
        std::assert_matches!(
            CompiledVariable::compile("geoAsnNumber"),
            CompiledVariable::GeoAsnNumber
        );
        std::assert_matches!(CompiledVariable::compile("asn"), CompiledVariable::GeoAsn);
        std::assert_matches!(
            CompiledVariable::compile("ispName"),
            CompiledVariable::IspName
        );
        std::assert_matches!(
            CompiledVariable::compile("refererBlock"),
            CompiledVariable::Empty
        );
        std::assert_matches!(
            CompiledVariable::compile("cname"),
            CompiledVariable::Raw(value) if value == "cname"
        );
        std::assert_matches!(
            CompiledVariable::compile("isCNAME"),
            CompiledVariable::Raw(value) if value == "isCNAME"
        );
        std::assert_matches!(CompiledVariable::compile("cc"), CompiledVariable::Cc);
        std::assert_matches!(CompiledVariable::compile("cc.limit"), CompiledVariable::Cc);
        std::assert_matches!(CompiledVariable::compile("cc2"), CompiledVariable::Cc2);
        std::assert_matches!(
            CompiledVariable::compile("cc2.limit"),
            CompiledVariable::Cc2
        );
        std::assert_matches!(
            CompiledVariable::compile("unknownVariable"),
            CompiledVariable::Raw(value) if value == "unknownVariable"
        );
    }

    #[test]
    fn compiled_cc_plan_precompiles_period_and_key_templates() {
        let rule = HTTPFirewallRule {
            param: "${cc2.rate}".to_string(),
            operator: "gt".to_string(),
            value: "10".to_string(),
            checkpoint_options: Some(json!({
                "period": 120,
                "keys": ["${remoteAddr}", "${header.User-Agent}"]
            })),
            is_reverse: false,
            is_case_insensitive: false,
            param_filters: vec![],
        };
        let compiled = CompiledFirewallRule::compile(&rule);
        let cc_plan = compiled.cc_plan.expect("cc2 should compile a counter plan");
        assert_eq!(cc_plan.param, "${cc2.rate}");
        assert_eq!(cc_plan.period, 120);
        assert!(cc_plan.is_cc2);
        assert_eq!(cc_plan.key_templates.len(), 2);
        std::assert_matches!(
            cc_plan.key_templates[0],
            CompiledValueExpr::Variable(CompiledVariable::RemoteAddr)
        );
        std::assert_matches!(
            cc_plan.key_templates[1],
            CompiledValueExpr::Variable(CompiledVariable::HeaderParam(ref name)) if name == "User-Agent"
        );

        let default_rule = HTTPFirewallRule {
            param: "${cc}".to_string(),
            operator: "gt".to_string(),
            value: "10".to_string(),
            checkpoint_options: None,
            is_reverse: false,
            is_case_insensitive: false,
            param_filters: vec![],
        };
        let compiled = CompiledFirewallRule::compile(&default_rule);
        let cc_plan = compiled.cc_plan.expect("cc should compile a counter plan");
        assert_eq!(cc_plan.period, 60);
        assert!(!cc_plan.is_cc2);
        assert!(cc_plan.key_templates.is_empty());
    }

    #[test]
    fn compiled_set_fast_path_conditions_match_full_rule_results() {
        for (param, operator, expected, actual) in [
            ("${host}", "eq string", "example.com", "example.com"),
            ("${requestHost}", "prefix", "api.", "api.example.com"),
            ("${host}", "suffix", ".example.com", "cdn.example.com"),
            ("${host}", "contains", "example", "cdn.example.com"),
            (
                "${requestURI}",
                "eq string",
                "/static/app.js",
                "/static/app.js",
            ),
            ("${requestURI}", "prefix", "/static/", "/static/app.js"),
            ("${requestURI}", "contains", "app", "/static/app.js"),
            (
                "${requestPath}",
                "eq string",
                "/static/app.js",
                "/static/app.js",
            ),
            ("${requestPath}", "prefix", "/static/", "/static/app.js"),
            ("${requestPath}", "contains", "app", "/static/app.js"),
            ("${remoteAddr}", "eq ip", "192.168.1.10", "192.168.1.10"),
            (
                "${remoteAddr}",
                "ip range",
                "192.168.1.0/24",
                "192.168.1.10",
            ),
            (
                "${remoteAddr}",
                "not ip range",
                "10.0.0.0/8",
                "192.168.1.10",
            ),
        ] {
            assert_fast_rule_parity(custom_rule(param, operator, expected), actual);
        }
    }

    #[test]
    fn compiled_regex_prefilter_only_indexes_safe_same_value_or_sets() {
        let rules = [
            custom_rule("${requestURI}", "regexp", "^/api/"),
            custom_rule("${requestURI}", "regexp", "^/static/"),
        ];
        let prefilter = CompiledRegexPrefilter::compile(
            Connector::Or,
            &rules
                .iter()
                .map(CompiledFirewallRule::compile)
                .collect::<Vec<_>>(),
        );
        assert!(prefilter.is_some());

        let mixed_values = [
            custom_rule("${requestURI}", "regexp", "^/api/"),
            custom_rule("${host}", "regexp", "example\\.com$"),
        ];
        let prefilter = CompiledRegexPrefilter::compile(
            Connector::Or,
            &mixed_values
                .iter()
                .map(CompiledFirewallRule::compile)
                .collect::<Vec<_>>(),
        );
        assert!(prefilter.is_none());

        let mixed_operator = [
            custom_rule("${requestURI}", "regexp", "^/api/"),
            custom_rule("${requestURI}", "contains", "/static/"),
        ];
        let prefilter = CompiledRegexPrefilter::compile(
            Connector::Or,
            &mixed_operator
                .iter()
                .map(CompiledFirewallRule::compile)
                .collect::<Vec<_>>(),
        );
        assert!(prefilter.is_none());

        let prefilter = CompiledRegexPrefilter::compile(
            Connector::And,
            &rules
                .iter()
                .map(CompiledFirewallRule::compile)
                .collect::<Vec<_>>(),
        );
        assert!(prefilter.is_none());
    }

    #[test]
    fn compiled_policy_stats_expose_prefilter_coverage() {
        let policy = test_policy(inbound_with_groups(vec![test_group(
            None,
            vec![
                test_set(
                    20,
                    vec![
                        custom_rule("${host}", "eq string", "example.com"),
                        custom_rule("${requestPath}", "prefix", "/static/"),
                        custom_rule("${requestURI}", "prefix", "/assets/"),
                        custom_rule("${remoteAddr}", "eq ip", "192.0.2.1"),
                    ],
                ),
                test_set(
                    21,
                    vec![
                        custom_rule("${requestURI}", "regexp", "^/api/"),
                        custom_rule("${requestURI}", "regexp", "^/v1/"),
                    ],
                ),
            ],
        )]));
        let compiled = CompiledFirewallPolicy::compile(&policy);
        let stats = compiled.stats();

        assert_eq!(stats.inbound_groups, 1);
        assert_eq!(stats.inbound_sets, 2);
        assert_eq!(stats.inbound_rules, 6);
        assert_eq!(stats.inbound_fast_rules, 4);
        assert_eq!(stats.inbound_regex_prefilters, 1);

        let prefilter = compiled.request_prefilter();
        assert_eq!(prefilter.host_exact, vec!["example.com"]);
        assert_eq!(prefilter.path_prefix, vec!["/static/"]);
        assert_eq!(prefilter.uri_prefix, vec!["/assets/"]);
        assert_eq!(prefilter.ip_exact, vec!["192.0.2.1"]);
    }

    #[test]
    fn compiled_request_prefilter_indexes_method_and_headers() {
        let policy = test_policy(inbound_with_groups(vec![test_group(
            None,
            vec![test_set(
                20,
                vec![
                    custom_rule("${requestMethod}", "eq string", "POST"),
                    custom_rule("${header.User-Agent}", "eq string", "curl/8"),
                ],
            )],
        )]));
        let compiled = CompiledFirewallPolicy::compile(&policy);
        let prefilter = compiled.request_prefilter();
        assert_eq!(prefilter.method_exact, vec!["POST"]);
        assert_eq!(
            prefilter.header_exact,
            vec![("user-agent".to_string(), "curl/8".to_string())]
        );

        let group = &compiled.inbound.as_ref().unwrap().groups[0];
        let header_hit = TestFacts {
            method: "GET",
            header_name: "user-agent",
            header_value: "curl/8",
            ..Default::default()
        };
        assert_eq!(
            group
                .request_prefilter
                .candidate_set_indexes(&header_hit, 0)
                .unwrap(),
            vec![0]
        );

        let method_hit = TestFacts {
            method: "POST",
            ..Default::default()
        };
        assert_eq!(
            group
                .request_prefilter
                .candidate_set_indexes(&method_hit, 0)
                .unwrap(),
            vec![0]
        );

        let miss = TestFacts {
            method: "GET",
            header_name: "User-Agent",
            header_value: "Mozilla",
            ..Default::default()
        };
        assert_eq!(
            group
                .request_prefilter
                .candidate_set_indexes(&miss, 0)
                .unwrap(),
            Vec::<usize>::new()
        );

        let mut and_set = test_set(
            21,
            vec![
                custom_rule("${requestMethod}", "eq string", "POST"),
                custom_rule("${header.User-Agent}", "eq string", "curl/8"),
            ],
        );
        and_set.connector = "and".to_string();
        let group = CompiledRuleGroup::compile(&test_group(None, vec![and_set]));
        assert_eq!(
            group
                .request_prefilter
                .candidate_set_indexes(&header_hit, 0)
                .unwrap(),
            Vec::<usize>::new()
        );
        let both_hit = TestFacts {
            method: "POST",
            header_name: "User-Agent",
            header_value: "curl/8",
            ..Default::default()
        };
        assert_eq!(
            group
                .request_prefilter
                .candidate_set_indexes(&both_hit, 0)
                .unwrap(),
            vec![0]
        );
    }

    #[test]
    fn compiled_group_prefilter_keeps_unindexed_or_sets_and_filters_indexed_sets() {
        let indexed = test_set(
            20,
            vec![custom_rule("${requestPath}", "prefix", "/static/")],
        );
        let heavy = test_set(
            21,
            vec![custom_rule("${requestBody}", "contains", "needle")],
        );
        let group = CompiledRuleGroup::compile(&test_group(None, vec![indexed, heavy]));
        let facts = TestFacts {
            path: "/api/item",
            ..Default::default()
        };

        let candidates = group
            .request_prefilter
            .candidate_set_indexes(&facts, 0)
            .expect("mixed indexed/unindexed group should use candidate scan");
        assert_eq!(candidates, vec![1]);
    }

    #[test]
    fn compiled_group_prefilter_uses_and_rules_as_necessary_conditions_only() {
        let mut set = test_set(
            20,
            vec![
                custom_rule("${requestPath}", "prefix", "/admin/"),
                custom_rule("${requestBody}", "contains", "token"),
            ],
        );
        set.connector = "and".to_string();
        let group = CompiledRuleGroup::compile(&test_group(None, vec![set]));

        let miss = TestFacts {
            path: "/public/",
            ..Default::default()
        };
        assert_eq!(
            group
                .request_prefilter
                .candidate_set_indexes(&miss, 0)
                .unwrap(),
            Vec::<usize>::new()
        );

        let hit = TestFacts {
            path: "/admin/",
            ..Default::default()
        };
        assert_eq!(
            group
                .request_prefilter
                .candidate_set_indexes(&hit, 0)
                .unwrap(),
            vec![0]
        );
    }

    #[test]
    fn compiled_set_fast_path_rejects_side_effect_and_reversed_rules() {
        let cc = CompiledFirewallRule::compile(&custom_rule("${cc}", "gt", "1"));
        assert!(CompiledFastCondition::compile(&cc).is_none());

        let mut reversed = custom_rule("${host}", "eq string", "example.com");
        reversed.is_reverse = true;
        let reversed = CompiledFirewallRule::compile(&reversed);
        assert!(CompiledFastCondition::compile(&reversed).is_none());
    }

    #[test]
    fn compiled_region_deny_matches_legacy_for_stable_paths() {
        let region = HTTPFirewallRegionConfig {
            is_on: true,
            deny_country_ids: vec![2],
            allow_search_engine: true,
            only_url_patterns: vec![crate::config_models::URLPattern {
                type_name: "prefix".to_string(),
                pattern: "/restricted".to_string(),
                ..Default::default()
            }],
            except_url_patterns: vec![crate::config_models::URLPattern {
                type_name: "prefix".to_string(),
                pattern: "/restricted/open".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        region.compile_url_patterns();
        let policy = test_policy(HTTPFirewallInboundConfig {
            is_on: true,
            groups: vec![],
            region: Some(region.clone()),
        });
        let compiled = CompiledFirewallPolicy::compile(&policy);
        let bot_ip = "8.8.8.8".parse().unwrap();
        assert_action_option_eq(
            crate::firewall::check_region_deny(
                &region,
                bot_ip,
                policy.id,
                &policy.deny_country_html,
                "Googlebot",
                "/restricted/page",
            ),
            evaluate_compiled_region_deny(&compiled, bot_ip, "Googlebot", "/restricted/page"),
        );

        let local_ip = "127.0.0.1".parse().unwrap();
        assert_action_option_eq(
            crate::firewall::check_region_deny(
                &region,
                local_ip,
                policy.id,
                &policy.deny_country_html,
                "curl/8",
                "/restricted/page",
            ),
            evaluate_compiled_region_deny(&compiled, local_ip, "curl/8", "/restricted/page"),
        );

        assert_action_option_eq(
            crate::firewall::check_region_deny(
                &region,
                local_ip,
                policy.id,
                &policy.deny_country_html,
                "curl/8",
                "/public",
            ),
            evaluate_compiled_region_deny(&compiled, local_ip, "curl/8", "/public"),
        );
        assert_action_option_eq(
            crate::firewall::check_region_deny(
                &region,
                local_ip,
                policy.id,
                &policy.deny_country_html,
                "curl/8",
                "/restricted/open/page",
            ),
            evaluate_compiled_region_deny(&compiled, local_ip, "curl/8", "/restricted/open/page"),
        );
    }
}
